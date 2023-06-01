use std::path::Path;

use anyhow::{Context, Result};
use ton_block::{AddSub, Serializable};
use ton_types::UInt256;

use crate::ed25519::*;
use crate::file::serialize_to_file;
use crate::models::global_config::ValidatorConfigGlobal;
use crate::models::*;
use crate::system_accounts::*;
use crate::zerostate::config_generator::build_configs;

pub fn prepare_zerostates<P: AsRef<Path>>(
    path: P,
    config: &str,
    zerostate_folder: &Path,
) -> Result<String> {
    let zerostate_config =
        serde_json::from_str::<ZerostateConfig>(config).context("Failed to parse state config")?;

    let validators_config = zerostate_config.validators.clone();
    let (pubkeys, global_config) = match validators_config.kind {
        ValidatorsConfigType::Generate => {
            let (validators_pubkeys, global_config) =
                build_configs(&validators_config, path.as_ref())?;

            let pubkeys = validators_pubkeys
                .into_iter()
                .map(|it| UInt256::from_slice(it.as_bytes()))
                .collect();

            (pubkeys, Some(global_config))
        }
        // TODO required implementation for static pubkeys
        _ => (vec![], None),
    };

    let mut mc_zerstate = prepare_mc_zerostate(zerostate_config, pubkeys)
        .context("Failed to prepare masterchain zerostate")?;

    let now = mc_zerstate.gen_time();

    let mut ex = mc_zerstate
        .read_custom()
        .context("Failed to read McStateExtra")?
        .context("McStateExtra not found")?;

    let mut workchains = ex.config.workchains()?;
    workchains
        .clone()
        .iterate_with_keys(|workchain_id, mut descr| {
            let shard =
                ton_block::ShardIdent::with_tagged_prefix(workchain_id, ton_block::SHARD_FULL)?;

            let mut state = ton_block::ShardStateUnsplit::with_ident(shard);
            state.set_gen_time(now);
            state.set_global_id(mc_zerstate.global_id());
            state.set_min_ref_mc_seqno(u32::MAX);

            let cell = state
                .serialize()
                .context("Failed to serialize workchain state")?;
            descr.zerostate_root_hash = cell.repr_hash();
            let bytes = ton_types::serialize_toc(&cell)?;
            descr.zerostate_file_hash = UInt256::calc_file_hash(&bytes);

            workchains
                .set(&workchain_id, &descr)
                .context("Failed to update workchain info")?;

            let path = zerostate_folder.join(format!("{:x}.boc", descr.zerostate_file_hash));

            std::fs::write(path, bytes).context("Failed to write workchain zerostate")?;

            Ok(true)
        })?;

    ex.config
        .config_params
        .setref(12u32.serialize()?.into(), &workchains.serialize()?)?;

    let catchain_config = ex
        .config
        .catchain_config()
        .context("Failed to read catchain config")?;
    let current_validators = ex
        .config
        .validator_set()
        .context("Failed to read validator set")?;

    let hash_short = current_validators
        .calc_subset(
            &catchain_config,
            ton_block::SHARD_FULL,
            ton_block::MASTERCHAIN_ID,
            0,
            ton_block::UnixTime32(now),
        )
        .context("Failed to compute validator subset")?
        .1;

    ex.validator_info.validator_list_hash_short = hash_short;
    ex.validator_info.nx_cc_updated = true;
    ex.validator_info.catchain_seqno = 0;

    mc_zerstate
        .write_custom(Some(&ex))
        .context("Failed to write custom")?;

    mc_zerstate
        .update_config_smc()
        .context("Failed to update config smc")?;

    // serialize
    let cell = mc_zerstate
        .serialize()
        .context("Failed to serialize masterchain zerostate")?;
    let bytes =
        ton_types::serialize_toc(&cell).context("Failed to serialize masterchain zerostate")?;
    let file_hash = UInt256::calc_file_hash(&bytes);

    {
        let path = zerostate_folder.join(format!("{file_hash:x}.boc"));
        std::fs::write(&path, bytes).context("Failed to write masterchain zerostate")?;
    }

    let shard_id = ton_block::SHARD_FULL as i64;
    let json = serde_json::json!({
        "@type": "validator.config.global",
        "zero_state": {
            "workchain": -1,
            "shard": shard_id,
            "seqno": 0,
            "root_hash": base64::encode(cell.repr_hash().as_slice()),
            "file_hash": base64::encode(file_hash.as_slice()),
        }
    });

    if validators_config.kind == ValidatorsConfigType::Generate {
        if let Some(mut global_config) = global_config {
            let validator_config_global =
                serde_json::from_value::<ValidatorConfigGlobal>(json.clone())?;
            global_config.validator = validator_config_global;

            for node in validators_config.nodes.iter() {
                let path = &path
                    .as_ref()
                    .join("nodes")
                    .join(node.0)
                    .join("ton-global.config.json");

                serialize_to_file(&global_config, path)?;
            }

            serialize_to_file(
                &global_config,
                &path.as_ref().join("ton-global.config.json"),
            )?;
        }
    }

    Ok(serde_json::to_string_pretty(&json).expect("Shouldn't fail"))
}

fn prepare_mc_zerostate(
    data: ZerostateConfig,
    validators_public_keys: Vec<UInt256>,
) -> Result<ton_block::ShardStateUnsplit> {
    let mut data = data;

    let minter_public_key = PublicKey::from_bytes(*data.minter_public_key.as_slice())
        .context("Invalid minter public key")?;
    let config_public_key = PublicKey::from_bytes(*data.config_public_key.as_slice())
        .context("Invalid config public key")?;

    let mut state = ton_block::ShardStateUnsplit::with_ident(ton_block::ShardIdent::masterchain());
    let mut ex = ton_block::McStateExtra::default();

    data.add_account(
        Default::default(),
        build_minter(minter_public_key).context("Failed to build minter state")?,
    )?;

    data.add_account(
        data.config.config_address,
        build_config_state(data.config.config_address, config_public_key)
            .context("Failed to build config state")?,
    )?;

    data.add_account(
        data.config.elector_address,
        build_elector_state(data.config.elector_address).context("Failed to build config state")?,
    )?;

    let mut total_balance = ton_block::CurrencyCollection::default();
    for (address, account) in &data.accounts {
        match &account {
            ton_block::Account::Account(account) => {
                total_balance
                    .add(&account.storage.balance)
                    .context("Failed to get total balance")?;
            }
            _ => continue,
        }

        state
            .insert_account(
                address,
                &ton_block::ShardAccount::with_params(account, UInt256::default(), 0)
                    .context("Failed to create shard account")?,
            )
            .context("Failed to insert account")?;
    }

    state.set_min_ref_mc_seqno(u32::MAX);

    state.set_global_id(data.global_id);
    state.set_gen_time(data.gen_utime);
    state.set_total_balance(total_balance.clone());

    let config = data.config;

    ex.config.config_addr = config.config_address;

    // 0
    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam0(
            ton_block::ConfigParam0 {
                config_addr: config.config_address,
            },
        ))?;

    // 1
    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam1(
            ton_block::ConfigParam1 {
                elector_addr: config.elector_address,
            },
        ))?;

    // 2
    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam2(
            ton_block::ConfigParam2 {
                minter_addr: config.minter_address,
            },
        ))?;

    // 7
    let mut currencies = ton_block::ExtraCurrencyCollection::default();
    for currency in config.currencies {
        currencies
            .set(&currency.id, &currency.total_supply.into())
            .context("Failed to set currency")?;
    }
    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam7(
            ton_block::ConfigParam7 {
                to_mint: currencies,
            },
        ))?;

    // 8
    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam8(
            GlobalVersion {
                global_version: config.global_version,
                global_capabilities: config.global_capabilities,
            }
            .build(),
        ))?;

    // 9

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam9(
            ton_block::ConfigParam9 {
                mandatory_params: config.mandatory_params.build()?,
            },
        ))?;

    // 10

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam10(
            ton_block::ConfigParam10 {
                critical_params: config.critical_params.build()?,
            },
        ))?;

    // 11

    if let Some(voting_setup) = config.voting_setup {
        let make_param = |params: ConfigVotingParams| -> ton_block::ConfigProposalSetup {
            ton_block::ConfigProposalSetup {
                min_tot_rounds: params.min_total_rounds,
                max_tot_rounds: params.max_total_rounds,
                min_wins: params.min_wins,
                max_losses: params.max_losses,
                min_store_sec: params.min_store_sec,
                max_store_sec: params.max_store_sec,
                bit_price: params.bit_price,
                cell_price: params.cell_price,
            }
        };

        ex.config
            .set_config(ton_block::ConfigParamEnum::ConfigParam11(
                ton_block::ConfigParam11::new(
                    &make_param(voting_setup.normal_params),
                    &make_param(voting_setup.critical_params),
                )
                .context("Failed to create config param 11")?,
            ))?;
    }

    // 12

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam12(
            config.workchains.build(ConfigBuildContext::Initial {
                gen_utime: data.gen_utime,
            })?,
        ))?;

    // 14

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam14(
            config.block_creation_fees.build(),
        ))?;

    // 15

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam15(
            config.elector_params.build(),
        ))?;

    // 16

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam16(
            config.validator_count.build(),
        ))?;

    // 17

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam17(
            config.stake_params.build(),
        ))?;

    // 18

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam18(
            config.storage_prices.build()?,
        ))?;

    // 20, 21

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam20(
            config.gas_prices.masterchain.build(),
        ))?;
    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam21(
            config.gas_prices.basechain.build(),
        ))?;

    // 22, 23

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam22(
            config.block_limits.masterchain.build()?,
        ))?;
    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam23(
            config.block_limits.basechain.build()?,
        ))?;

    // 24, 25

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam24(
            config.msg_forward_prices.masterchain.build(),
        ))?;
    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam25(
            config.msg_forward_prices.basechain.build(),
        ))?;

    // 28

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam28(
            config.catchain_params.build(),
        ))?;

    // 29

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam29(
            config.consensus_params.build(),
        ))?;

    // 31

    let mut fundamental_smc_addr = ton_block::FundamentalSmcAddresses::default();
    for address in config.fundamental_addresses {
        fundamental_smc_addr.set(&address, &())?;
    }

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam31(
            ton_block::ConfigParam31 {
                fundamental_smc_addr,
            },
        ))?;

    // 34

    let validators = validators_public_keys
        .into_iter()
        .map(|validator| {
            let public_key = ton_block::SigPubKey::from_bytes(validator.as_slice())?;
            Ok(ton_block::ValidatorDescr::with_params(
                public_key, 0x11, None,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    let cur_validators = ton_block::ValidatorSet::new(
        data.gen_utime,
        data.gen_utime,
        validators.len() as u16,
        validators,
    )
    .context("Failed to build validators list")?;

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam34(
            ton_block::ConfigParam34 { cur_validators },
        ))?;

    // Other
    ex.validator_info.validator_list_hash_short = 0;
    ex.validator_info.catchain_seqno = 0;
    ex.validator_info.nx_cc_updated = true;
    ex.global_balance.grams = total_balance.clone().grams;
    ex.after_key_block = true;
    state
        .write_custom(Some(&ex))
        .context("Failed to write McStateExtra")?;

    Ok(state)
}

impl ZerostateConfig {
    pub fn add_account(&mut self, address: UInt256, mut account: ton_block::Account) -> Result<()> {
        if let ton_block::Account::Account(account) = &mut account {
            account.addr = ton_block::MsgAddressInt::AddrStd(ton_block::MsgAddrStd::with_address(
                None,
                ton_block::MASTERCHAIN_ID as i8,
                address.into(),
            ));
        }

        account
            .update_storage_stat()
            .context("Failed to update storage stat for explicit account")?;

        self.accounts.insert(address, account);

        Ok(())
    }
}

mod config_generator {
    use crate::dht::generate_dht_config;
    use crate::file::{load_object_from_file, save_to_file, serialize_to_file};
    use crate::models::global_config::{ConfigGlobal, DhtNode};
    use crate::models::node_config::TonNodeConfig;
    use crate::models::{Node, ValidatorsConfig};
    use anyhow::anyhow;
    use everscale_crypto::ed25519::{PublicKey, SecretKey};
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn generate_log_config(
        log_template: &Path,
        output: &Path,
        node_name: &str,
    ) -> anyhow::Result<()> {
        let log_cfg = fs::read_to_string(log_template)?;
        let log_cfg = log_cfg.replace("{NODE_NAME}", node_name);
        save_to_file(
            &log_cfg,
            &output.join("nodes").join(node_name).join("log_cfg.yml"),
        )?;
        Ok(())
    }

    fn generate_node_config(
        node: &Node,
        node_name: &str,
        output: &Path,
        current_time_ms: u64,
        nodes_config: &ValidatorsConfig,
    ) -> anyhow::Result<TonNodeConfig> {
        // Initialization node config
        let mut node_config: TonNodeConfig =
            load_object_from_file::<TonNodeConfig>(&nodes_config.node_config)?;
        node_config.init_adnl(&format!("{}:{}", node.adnl_addr, node.adnl_port))?;
        node_config.init_validator_keys(current_time_ms as i32)?;
        serialize_to_file(
            &node_config,
            &output.join("nodes").join(node_name).join("config.json"),
        )?;
        Ok(node_config)
    }

    fn generate_global_config(
        node: &Node,
        node_config: &TonNodeConfig,
        global_config: &mut ConfigGlobal,
    ) -> anyhow::Result<()> {
        let node_adnl_pvt_key = node_config
            .get_first_adnl_node_pvt_key()
            .ok_or(anyhow!("ADNL pvt key can't be null"))?;
        let secret_key = get_key_by_base64_private(&node_adnl_pvt_key)?;
        let ip: Ipv4Addr = node.adnl_addr.parse()?;
        let addr = SocketAddrV4::new(ip, node.adnl_port);
        let dht_node = generate_dht_config(addr, &secret_key);
        let dht_node = serde_json::from_str::<DhtNode>(&dht_node)?;
        global_config.dht.static_nodes.nodes.push(dht_node);
        Ok(())
    }

    pub fn build_configs(
        validators_config: &ValidatorsConfig,
        output: &Path,
    ) -> anyhow::Result<(Vec<PublicKey>, ConfigGlobal)> {
        let mut validators_pubkeys: Vec<PublicKey> = vec![];
        let current_time_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut global_config = ConfigGlobal::default();
        for node in validators_config.nodes.iter() {
            generate_log_config(&validators_config.log_template, output, node.0)?;
            let node_config =
                generate_node_config(node.1, node.0, output, current_time_ms, validators_config)?;

            let pvt_key = node_config
                .get_validator_key_ring_pvt_key()?
                .ok_or(anyhow!("validator pvt key is required for validator"))?;

            let secret_key = get_key_by_base64_private(&pvt_key)?;
            let pubkey = PublicKey::from(&secret_key);
            validators_pubkeys.push(pubkey);
            generate_global_config(node.1, &node_config, &mut global_config)?;
        }

        Ok((validators_pubkeys, global_config))
    }

    fn get_key_by_base64_private(base64_string: &str) -> anyhow::Result<SecretKey> {
        let bytes = base64::decode(base64_string)?;
        let mut array = [0; 32];
        array.copy_from_slice(&bytes);
        let secret_key = SecretKey::from_bytes(array);
        Ok(secret_key)
    }
}

use std::path::Path;

use anyhow::{Context, Result};
use ton_block::{AddSub, Serializable};

use self::models::*;
use crate::ed25519::*;
use crate::system_accounts::*;

pub mod models;

pub fn prepare_zerostates<P: AsRef<Path>>(path: P, config: &str) -> Result<String> {
    let mut mc_zerstate =
        prepare_mc_zerostate(config).context("Failed to prepare masterchain zerostate")?;
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
            descr.zerostate_file_hash = ton_types::UInt256::calc_file_hash(&bytes);

            workchains
                .set(&workchain_id, &descr)
                .context("Failed to update workchain info")?;

            let path = path
                .as_ref()
                .join(format!("{:x}.boc", descr.zerostate_file_hash));

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
    let file_hash = ton_types::UInt256::calc_file_hash(&bytes);

    let path = path.as_ref().join(format!("{:x}.boc", file_hash));
    std::fs::write(path, bytes).context("Failed to write masterchain zerostate")?;

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

    Ok(serde_json::to_string_pretty(&json).expect("Shouldn't fail"))
}

fn prepare_mc_zerostate(config: &str) -> Result<ton_block::ShardStateUnsplit> {
    let jd = &mut serde_json::Deserializer::from_str(config);
    let mut data = serde_path_to_error::deserialize::<_, ZerostateConfig>(jd)
        .context("Failed to parse state config")?;

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
    for (address, account) in data.accounts {
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
                &address,
                &ton_block::ShardAccount::with_params(&account, ton_types::UInt256::default(), 0)
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
            ton_block::ConfigParam8 {
                global_version: ton_block::GlobalVersion {
                    version: config.global_version,
                    capabilities: config.global_capabilities,
                },
            },
        ))?;

    // 9

    let mut mandatory_params = ton_block::MandatoryParams::default();
    for param in config.mandatory_params {
        mandatory_params
            .set(&param, &())
            .context("Failed to construct mandatory params")?;
    }

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam9(
            ton_block::ConfigParam9 { mandatory_params },
        ))?;

    // 10

    let mut critical_params = ton_block::MandatoryParams::default();
    for param in config.critical_params {
        critical_params
            .set(&param, &())
            .context("Failed to construct critical params")?;
    }

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam10(
            ton_block::ConfigParam10 { critical_params },
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

    let mut workchains = ton_block::Workchains::default();
    for workchain in config.workchains {
        let mut descr = ton_block::WorkchainDescr::default();
        descr.enabled_since = workchain.enabled_since.unwrap_or(data.gen_utime);
        descr
            .set_min_split(workchain.min_split)
            .context("Failed to set workchain min split")?;
        descr
            .set_max_split(workchain.max_split)
            .context("Failed to set workchain max split")?;
        descr.flags = workchain.flags;
        descr.active = workchain.active;
        descr.accept_msgs = workchain.accept_msgs;

        descr.format = ton_block::WorkchainFormat::Basic(ton_block::WorkchainFormat1::with_params(
            workchain.vm_version,
            workchain.vm_mode,
        ));

        workchains
            .set(&workchain.workchain_id, &descr)
            .context("Failed to set workchain")?;
    }
    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam12(
            ton_block::ConfigParam12 { workchains },
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

    let mut prices = ton_block::ConfigParam18Map::default();
    for (i, item) in config.storage_prices.iter().enumerate() {
        prices.set(
            &(i as u32),
            &ton_block::StoragePrices {
                utime_since: item.utime_since,
                bit_price_ps: item.bit_price_ps,
                cell_price_ps: item.cell_price_ps,
                mc_bit_price_ps: item.mc_bit_price_ps,
                mc_cell_price_ps: item.mc_cell_price_ps,
            },
        )?;
    }
    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam18(
            ton_block::ConfigParam18 { map: prices },
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
            ton_block::CatchainConfig {
                isolate_mc_validators: config.catchain_params.isolate_mc_validators,
                shuffle_mc_validators: config.catchain_params.shuffle_mc_validators,
                mc_catchain_lifetime: config.catchain_params.mc_catchain_lifetime,
                shard_catchain_lifetime: config.catchain_params.shard_catchain_lifetime,
                shard_validators_lifetime: config.catchain_params.shard_validators_lifetime,
                shard_validators_num: config.catchain_params.shard_validators_num,
            },
        ))?;

    // 29

    ex.config
        .set_config(ton_block::ConfigParamEnum::ConfigParam29(
            ton_block::ConfigParam29 {
                consensus_config: ton_block::ConsensusConfig {
                    new_catchain_ids: config.consensus_params.new_catchain_ids,
                    round_candidates: config.consensus_params.round_candidates,
                    next_candidate_delay_ms: config.consensus_params.next_candidate_delay_ms,
                    consensus_timeout_ms: config.consensus_params.consensus_timeout_ms,
                    fast_attempts: config.consensus_params.fast_attempts,
                    attempt_duration: config.consensus_params.attempt_duration,
                    catchain_max_deps: config.consensus_params.catchain_max_deps,
                    max_block_bytes: config.consensus_params.max_block_bytes,
                    max_collated_bytes: config.consensus_params.max_collated_bytes,
                },
            },
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

    let validators = config
        .validators_public_keys
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
    pub fn add_account(
        &mut self,
        address: ton_types::UInt256,
        mut account: ton_block::Account,
    ) -> Result<()> {
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

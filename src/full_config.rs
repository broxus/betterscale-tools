use crate::dht::generate_dht_config;
use crate::full_config::file::{load_object_from_file, save_to_file, serialize_to_file};
use crate::full_config::models::global_config::{ConfigGlobal, DhtNode};
use crate::full_config::models::nodes_config::{Node, NodesConfig};
use crate::full_config::models::{AdnlClientConfigJson, Console, KeyOptionJson, TonNodeConfig};

use anyhow::anyhow;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

use crate::crypto::get_pubkey_by_base64_private;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[macro_export]
macro_rules! key_option_public_key {
    ($key: expr) => {
        serde_json::json!({
            "type_id": 1209251014,
            "pub_key": $key
        })
    };
}

pub mod models {
    pub const LOCAL_HOST: &str = "127.0.0.1";
    pub const TAG_DHT_KEY: usize = 1;
    pub const TAG_OVERLAY_KEY: usize = 2;

    use crate::crypto::{Ed25519KeyOption, KeyOption};

    use anyhow::anyhow;
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct TonNodeConfig {
        log_config_name: Option<String>,
        ton_global_config_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        workchain: Option<i32>,
        internal_db_path: Option<String>,
        unsafe_catchain_patches_path: Option<String>,
        adnl_node: Option<AdnlNodeConfigJson>,
        #[serde(skip_serializing_if = "Option::is_none")]
        extensions: Option<serde_json::Value>,
        validator_keys: Option<Vec<ValidatorKeysJson>>,
        control_server: Option<AdnlServerConfigJson>,
        kafka_consumer_config: Option<serde_json::Value>,
        external_db_config: Option<serde_json::Value>,
        default_rldp_roundtrip_ms: Option<u32>,
        #[serde(default)]
        test_bundles_config: serde_json::Value,
        #[serde(default)]
        connectivity_check_config: serde_json::Value,
        gc: Option<serde_json::Value>,
        validator_key_ring: Option<HashMap<String, KeyOptionJson>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        remp: Option<serde_json::Value>,
        #[serde(default)]
        low_memory_mode: bool,
        #[serde(default)]
        cells_db_config: serde_json::Value,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct Console {
        pub config: Option<AdnlClientConfigJson>,
        wallet_id: Option<String>,
        max_factor: Option<i32>,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct ConsoleConfigParams {
        config: Option<serde_json::Value>,
        wallet_id: Option<String>,
        max_factor: Option<i32>,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct AdnlClientConfigJson {
        client_key: Option<KeyOptionJson>,
        server_address: String,
        server_key: KeyOptionJson,
        timeouts: Option<Timeouts>,
    }

    #[derive(serde::Deserialize, serde::Serialize, Debug)]
    pub struct AdnlNodeConfigJson {
        ip_address: String,
        keys: Vec<AdnlNodeKeyJson>,
        recv_pipeline_pool: Option<u8>,
        recv_priority_pool: Option<u8>,
        throughput: Option<u32>,
    }

    impl AdnlClientConfigJson {
        pub fn new(
            server_address: String,
            server_key: KeyOptionJson,
            timeouts: Option<Timeouts>,
            client_key: Option<KeyOptionJson>,
        ) -> Self {
            AdnlClientConfigJson {
                client_key,
                server_address,
                server_key,
                timeouts,
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    pub struct PublicKeyInfo {
        pub public_key: String,
        pub weight: String,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    pub struct P34 {
        pub utime_since: u64,
        pub utime_until: u64,
        pub total: u32,
        pub main: u32,
        pub total_weight: u32,
        pub list: Vec<PublicKeyInfo>,
    }

    impl TonNodeConfig {
        pub(crate) fn init_adnl(&mut self, ip_address: &str) -> anyhow::Result<&mut Self> {
            let adnl_config = AdnlNodeConfigJson::with_ip_address_and_private_key_tags(
                ip_address,
                vec![TAG_DHT_KEY, TAG_OVERLAY_KEY],
            )?;
            self.adnl_node = Some(adnl_config);
            Ok(self)
        }

        pub(crate) fn init_validator_keys(
            &mut self,
            election_id: i32,
        ) -> anyhow::Result<&mut Self> {
            #[cfg(feature = "workchains")]
            let (private, public) =
                crate::validator::validator_utils::mine_key_for_workchain(self.workchain);

            #[cfg(not(feature = "workchains"))]
            let (private, public) = Ed25519KeyOption::generate_with_json()?;

            let key_ring = self.validator_key_ring.get_or_insert_with(HashMap::new);
            let key_id = public.id().data();

            key_ring.insert(base64::encode(key_id), private);
            self.add_validator_key(key_id, election_id);

            Ok(self)
        }

        pub(crate) fn init_console_config(
            &mut self,
            client_keys: Option<KeyOptionJson>,
            control_server_port: Option<u16>,
        ) -> anyhow::Result<(&mut Self, Option<AdnlClientConfigJson>)> {
            let server_address = if let Some(port) = control_server_port {
                format!("{LOCAL_HOST}:{port}")
            } else {
                println!("Can`t generate console_config. control_server_port is not present.");
                return Ok((self, None));
            };

            let (server_private_key, server_key) = Ed25519KeyOption::generate_with_json()?;

            let console_client_config = AdnlClientConfigJson::new(
                server_address.clone(),
                serde_json::from_value(key_option_public_key!(base64::encode(
                    server_key.pub_key()?
                )))?,
                None,
                None,
            );

            let client_keys = client_keys.map_or(vec![], |keys| vec![keys]);

            let console_server_config =
                AdnlServerConfigJson::new(server_address, server_private_key, client_keys, None);

            self.control_server = Some(console_server_config);

            Ok((self, Some(console_client_config)))
        }

        fn add_validator_key(&mut self, key_id: &[u8; 32], election_id: i32) {
            let key_info = ValidatorKeysJson {
                election_id,
                validator_key_id: base64::encode(key_id),
                validator_adnl_key_id: None,
            };

            let validator_keys = self.validator_keys.get_or_insert(Vec::new());
            validator_keys.push(key_info)
        }

        pub(crate) fn get_control_server(&self) -> Option<&AdnlServerConfigJson> {
            self.control_server.as_ref()
        }

        pub(crate) fn get_first_adnl_node_pvt_key(&self) -> Option<String> {
            self.adnl_node.as_ref()?.keys.first()?.data.pvt_key.clone()
        }

        pub(crate) fn set_log_config_name(&mut self, value: Option<String>) {
            self.log_config_name = value
        }

        pub(crate) fn set_ton_global_config_name(&mut self, value: Option<String>) {
            self.ton_global_config_name = value
        }

        pub(crate) fn get_validator_key_ring_pvt_key(&self) -> anyhow::Result<Option<String>> {
            let pair = self
                .validator_key_ring
                .as_ref()
                .ok_or(anyhow!("validator_key_ring should be present"))?
                .iter()
                .next()
                .ok_or(anyhow!("validator_key_ring pvt key should be present"))?;
            Ok(pair.1.pvt_key.clone())
        }
    }

    impl AdnlNodeConfigJson {
        pub fn with_ip_address_and_private_key_tags(
            ip_address: &str,
            tags: Vec<usize>,
        ) -> anyhow::Result<AdnlNodeConfigJson> {
            let mut keys = Vec::new();
            for tag in tags {
                let (json, key) = Ed25519KeyOption::generate_with_json()?;
                keys.push((json, key as Arc<dyn KeyOption>, tag))
            }
            Self::create_configs(ip_address, keys)
        }

        fn create_configs(
            ip_address: &str,
            keys: Vec<(KeyOptionJson, Arc<dyn KeyOption>, usize)>,
        ) -> anyhow::Result<AdnlNodeConfigJson> {
            let mut json_keys = Vec::new();
            let mut tags_keys = Vec::new();
            for (json, key, tag) in keys {
                json_keys.push(AdnlNodeKeyJson { tag, data: json });
                tags_keys.push((key, tag));
            }
            let json = AdnlNodeConfigJson {
                ip_address: ip_address.to_string(),
                keys: json_keys,
                recv_pipeline_pool: None,
                recv_priority_pool: None,
                throughput: None,
            };
            Ok(json)
        }
    }

    #[derive(serde::Deserialize, serde::Serialize, Debug)]
    pub struct AdnlNodeKeyJson {
        tag: usize,
        data: KeyOptionJson,
    }

    #[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
    pub struct KeyOptionJson {
        pub type_id: i32,
        pub pub_key: Option<String>,
        pub pvt_key: Option<String>,
    }

    #[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
    struct ValidatorKeysJson {
        election_id: i32,
        validator_key_id: String,
        validator_adnl_key_id: Option<String>,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct AdnlServerConfigJson {
        pub address: String,
        pub clients: AdnlServerClients,
        pub server_key: KeyOptionJson,
        pub timeouts: Option<Timeouts>,
    }

    impl AdnlServerConfigJson {
        pub fn new(
            address: String,
            server_key: KeyOptionJson,
            client_keys: Vec<KeyOptionJson>,
            timeouts: Option<Timeouts>,
        ) -> Self {
            AdnlServerConfigJson {
                address,
                clients: AdnlServerClients::List(client_keys),
                server_key,
                timeouts,
            }
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "lowercase")]
    pub enum AdnlServerClients {
        Any,
        List(Vec<KeyOptionJson>),
    }

    #[derive(Clone, serde::Deserialize, serde::Serialize)]
    pub struct Timeouts {
        read: Duration,
        write: Duration,
    }

    pub(crate) mod global_config {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Serialize, Deserialize)]
        pub struct ConfigGlobal {
            #[serde(rename = "@type")]
            pub type_field: String,
            pub dht: DhtConfigGlobal,
            pub validator: ValidatorConfigGlobal,
        }

        #[derive(Debug, Serialize, Deserialize)]
        pub struct DhtConfigGlobal {
            #[serde(rename = "@type")]
            pub type_field: String,
            pub k: i64,
            pub a: i64,
            pub static_nodes: DhtNodes,
        }

        #[derive(Debug, Serialize, Deserialize)]
        pub struct DhtNodes {
            #[serde(rename = "@type")]
            pub type_field: String,
            pub nodes: Vec<DhtNode>,
        }

        #[derive(Debug, Serialize, Deserialize)]
        pub struct DhtNode {
            #[serde(rename = "@type")]
            pub type_field: String,
            pub id: Id,
            pub addr_list: AddrList,
            pub version: i64,
            pub signature: String,
        }

        #[derive(Debug, Serialize, Deserialize)]
        pub struct Id {
            #[serde(rename = "@type")]
            pub type_field: String,
            pub key: String,
        }

        #[derive(Debug, Serialize, Deserialize)]
        pub struct AddrList {
            #[serde(rename = "@type")]
            pub type_field: String,
            pub addrs: Vec<Addr>,
            pub version: i64,
            pub reinit_date: i64,
            pub priority: i64,
            pub expire_at: i64,
        }

        #[derive(Debug, Serialize, Deserialize)]
        pub struct Addr {
            #[serde(rename = "@type")]
            pub type_field: String,
            pub ip: i64,
            pub port: i64,
        }

        #[derive(Debug, Serialize, Deserialize)]
        pub struct ValidatorConfigGlobal {
            #[serde(rename = "@type")]
            pub type_field: String,
            pub zero_state: ZeroState,
        }

        #[derive(Debug, Serialize, Deserialize)]
        pub struct ZeroState {
            pub workchain: i64,
            pub shard: i64,
            pub seqno: i64,
            pub root_hash: String,
            pub file_hash: String,
        }
    }

    pub(crate) mod nodes_config {
        use serde::Deserialize;
        use std::path::PathBuf;

        #[derive(Debug, Deserialize)]
        pub struct ConsoleClientKey {
            pub type_id: i32,
            pub pvt_key: String,
        }

        #[derive(Debug, Deserialize)]
        pub struct Node {
            pub is_validator: bool,
            pub adnl_addr: String,
            pub adnl_port: u16,
            pub control_server_port: u16,
            pub console_client_key: ConsoleClientKey,
        }

        #[derive(Debug, Deserialize)]
        pub struct NodesConfig {
            pub console_config: PathBuf,
            pub console: FromTo,
            pub node_config: FromTo,
            pub global_config: FromTo,
            pub zerostate_config: FromTo,
            pub log: FromTo,
            pub nodes: Vec<Node>,
        }

        #[derive(Debug, Deserialize)]
        pub struct FromTo {
            pub from: PathBuf,
            pub to: PathBuf,
        }
    }
}

fn format_path<P: AsRef<Path>>(output: P, folder: &str, filename: &Path) -> PathBuf {
    output.as_ref().join(folder).join(filename)
}

fn generate_log_config(
    log_template: &Path,
    output: &Path,
    base_folder: &str,
    nodes_config: &NodesConfig,
    i: usize,
) -> anyhow::Result<()> {
    let log_cfg = fs::read_to_string(log_template)?;
    let log_cfg = log_cfg.replace("{NODE_NUM}", &i.to_string());
    save_to_file(
        &log_cfg,
        &format_path(output, base_folder, &nodes_config.log.to),
    )?;
    Ok(())
}

fn generate_node_config(
    node: &Node,
    base_folder: &str,
    output: &Path,
    current_time_ms: u64,
    nodes_config: &NodesConfig,
) -> anyhow::Result<TonNodeConfig> {
    // Initialization node config
    let mut node_config: TonNodeConfig =
        load_object_from_file::<TonNodeConfig>(&nodes_config.node_config.from)?;
    node_config.init_adnl(&format!("{}:{}", node.adnl_addr, node.adnl_port))?;
    if node.is_validator {
        node_config.init_validator_keys(current_time_ms as i32)?;
    }
    node_config.set_log_config_name(Some(nodes_config.log.to.display().to_string()));
    node_config
        .set_ton_global_config_name(Some(nodes_config.global_config.to.display().to_string()));

    serialize_to_file(
        &node_config,
        &format_path(output, base_folder, &nodes_config.node_config.to),
    )?;
    Ok(node_config)
}

fn generate_console_config(
    node: &Node,
    base_folder: &str,
    output: &Path,
    node_config: &mut TonNodeConfig,
    nodes_config: &NodesConfig,
) -> anyhow::Result<()> {
    let client_key = Some(KeyOptionJson {
        type_id: node.console_client_key.type_id,
        pub_key: None,
        pvt_key: Some(node.console_client_key.pvt_key.to_string()),
    });

    let mut console = load_object_from_file::<Console>(&nodes_config.console.from)?;
    let client_config = node_config
        .init_console_config(client_key.clone(), Some(node.control_server_port))?
        .1;

    if let Some(client_config) = &client_config {
        serialize_to_file(
            client_config,
            &format_path(output, base_folder, &nodes_config.console_config),
        )?;
    }

    if let Some(control_server) = node_config.get_control_server() {
        console.config = Some(AdnlClientConfigJson::new(
            control_server.address.clone(),
            control_server.server_key.clone(),
            control_server.timeouts.clone(),
            client_key,
        ));
    }
    serialize_to_file(
        &console,
        &format_path(output, base_folder, &nodes_config.console.to),
    )?;

    Ok(())
}

fn generate_global_config(
    node: &Node,
    node_config: &TonNodeConfig,
    global_config: &mut ConfigGlobal,
    _output: &Path,
) -> anyhow::Result<()> {
    if node.is_validator {
        let node_adnl_pvt_key = node_config
            .get_first_adnl_node_pvt_key()
            .ok_or(anyhow!("ADNL pvt key can't be null"))?;
        let bytes = base64::decode(node_adnl_pvt_key)?;
        let mut array = [0; 32];
        array.copy_from_slice(&bytes);
        let secret_key = everscale_crypto::ed25519::SecretKey::from_bytes(array);

        let ip: Ipv4Addr = node.adnl_addr.parse()?;
        let addr = SocketAddrV4::new(ip, node.adnl_port);

        let dht_node = generate_dht_config(addr, &secret_key);
        let dht_node = serde_json::from_str::<DhtNode>(&dht_node)?;
        global_config.dht.static_nodes.nodes.push(dht_node);
    }
    Ok(())
}

pub fn build_full_config(
    nodes_config: &NodesConfig,
    output: &Path,
) -> anyhow::Result<Vec<everscale_crypto::ed25519::PublicKey>> {
    let mut validators_pubkeys: Vec<everscale_crypto::ed25519::PublicKey> = vec![];

    let current_time_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut global_config =
        load_object_from_file::<ConfigGlobal>(&nodes_config.global_config.from)?;

    for (i, node) in nodes_config.nodes.iter().enumerate() {
        let base_folder = format!("node{}", i);

        generate_log_config(
            &nodes_config.log.from,
            output,
            &base_folder,
            nodes_config,
            i,
        )?;
        let mut node_config =
            generate_node_config(node, &base_folder, output, current_time_ms, nodes_config)?;
        generate_console_config(node, &base_folder, output, &mut node_config, nodes_config)?;

        if node.is_validator {
            let pvt_key = node_config
                .get_validator_key_ring_pvt_key()?
                .ok_or(anyhow!("validator pvt key is required for validator"))?;
            let pubkey = get_pubkey_by_base64_private(&pvt_key)?;
            validators_pubkeys.push(pubkey);
        }

        generate_global_config(node, &node_config, &mut global_config, output)?;
    }

    // save global config for each node folder
    for (i, _node) in nodes_config.nodes.iter().enumerate() {
        let base_folder = format!("node{}", i);
        serialize_to_file(
            &global_config,
            &format_path(output, &base_folder, &nodes_config.global_config.to),
        )?;
    }

    serialize_to_file(
        &global_config,
        &format_path(output, "", &nodes_config.global_config.to),
    )?;

    Ok(validators_pubkeys)
}

pub(crate) mod file {
    use anyhow::Result;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use std::fs;
    use std::fs::{create_dir_all, File};
    use std::path::Path;
    /// Load a JSON object from a file.
    pub(crate) fn load_object_from_file<T: DeserializeOwned>(path: &Path) -> Result<T> {
        let file = File::open(path)?;
        let value = serde_json::from_reader(file)?;
        Ok(value)
    }

    /// Serialize a data structure to a JSON file.
    pub(crate) fn serialize_to_file<T: Serialize>(data: &T, path: &Path) -> Result<()> {
        prepare_to_save(path)?;
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, data)?;
        Ok(())
    }

    /// Save a string to a file.
    pub(crate) fn save_to_file(data: &str, path: &Path) -> Result<()> {
        prepare_to_save(path)?;
        fs::write(path, data)?;
        Ok(())
    }

    /// Prepare to save to a file by creating necessary directories.
    pub(crate) fn prepare_to_save(path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            if !dir.exists() {
                create_dir_all(dir)?;
            }
        }
        Ok(())
    }
}

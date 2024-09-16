use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Ok, Result};
use num_bigint::BigUint;
use regex::Regex;
use serde::{Deserialize, Serialize};
use ton_block::{MsgAddrStd, MsgAddressInt, Serializable, StateInit};
use ton_types::{BuilderData, Cell, UInt256};

use super::jeton_utils::{cell_from_base_64, cell_from_hex, make_state_init, IBitstringExt};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompilationArtifacts {
    pub hash: String,
    pub hash_base64: String,
    pub hex: String,
}

pub fn get_address_from_init_data(
    jeton_wallet_code: impl AsRef<Path>,
    jeton_init_params: Vec<String>,
    jeton_init_data: Vec<String>,
) -> Result<()> {
    let code_text =
        std::fs::read_to_string(jeton_wallet_code).expect("Failed to read jeton wallet code");
    let compilation_artifacts = serde_json::from_str::<CompilationArtifacts>(&code_text)?;
    let init_data = string_params_to_cell(jeton_init_params, jeton_init_data, None, None)?;

    let init_state = make_state_init(
        cell_from_hex(&compilation_artifacts.hex).unwrap(),
        init_data,
    )?;

    let address = calculate_address(init_state, 0);
    println!("{}", address.unwrap().to_string());

    Ok(())
}

fn calculate_address(state_init: StateInit, workchain_id: i8) -> Result<MsgAddressInt> {
    let hash = state_init.serialize()?.repr_hash();
    Ok(MsgAddressInt::AddrStd(MsgAddrStd {
        anycast: None,
        workchain_id,
        address: hash.into(),
    }))
}

fn string_params_to_cell(
    params: Vec<String>,
    data: Vec<String>,
    nonce_idx: Option<usize>,
    nonce_value: Option<MsgAddrStd>,
) -> Result<Cell> {
    let mut builder = BuilderData::new();
    let input_re = Regex::new(
        r#"(?x)
        (coins) |
        (address) |
        (cell) |
        (uint)+(\d+)
        "#,
    )
    .unwrap();

    params
        .into_iter()
        .enumerate()
        .for_each(|(idx, param_type)| {
            let captures = input_re.captures(&param_type).map(|captures| {
                captures
                    .iter() // All the captured groups
                    .skip(1) // Skipping the complete match
                    .flat_map(|c| c) // Ignoring all empty optional matches
                    .map(|c| c.as_str()) // Grab the original strings
                    .collect::<Vec<_>>() // Create a vector
            });
            match captures.as_ref().map(|c| c.as_slice()) {
                Some(["uint", x]) => {
                    builder
                        .append_uint(
                            &BigUint::from_str(data[idx].as_str()).unwrap(),
                            x.parse::<usize>().unwrap(),
                        )
                        .unwrap();
                }
                Some(["coins"]) => {
                    print!("{}", param_type);
                    builder
                        .append_coins(&BigUint::from_str(data[idx].as_str()).unwrap())
                        .unwrap();
                }
                Some(["address"]) => {
                    if let (Some(nonce_idx), Some(nonce_value)) = (nonce_idx, nonce_value.clone()) {
                        if idx == nonce_idx {
                            builder
                                .append_address(&MsgAddressInt::AddrStd(nonce_value.into()))
                                .unwrap();
                        }
                    } else {
                        builder
                            .append_address(
                                &ton_block::MsgAddressInt::from_str(&data[idx]).unwrap(),
                            )
                            .unwrap();
                    }
                }
                Some(["cell"]) => {
                    builder
                        .checked_append_reference(cell_from_base_64(&data[idx]).unwrap())
                        .unwrap();
                }
                _ => {
                    panic!("Invalid param type: {} at idx {}", param_type, idx);
                }
            }
        });
    builder.into_cell()
}

#[derive(Clone)]
pub struct JetonConfig {
    pub wallet_code: Box<PathBuf>,
    pub init_params: Vec<String>,
    pub init_data: Vec<String>,
    pub nonce_address_idx: usize,
}
#[derive(Clone)]
pub struct JetonWallet {
    compilation_artifacts: CompilationArtifacts,
    jeton_init_params: Vec<String>,
    jeton_init_data: Vec<String>,
    nonce_address_idx: usize,
}

impl JetonWallet {
    pub fn new(jeton_config: JetonConfig) -> Result<Self> {
        println!("{:?}", jeton_config.wallet_code);
        let code_text = std::fs::read_to_string(jeton_config.wallet_code.as_ref())
            .expect("Failed to read jeton wallet code");
        let compilation_artifacts = serde_json::from_str::<CompilationArtifacts>(&code_text)?;

        if jeton_config.init_params[jeton_config.nonce_address_idx] != "address" {
            return Err(anyhow::anyhow!("Nonce field must have type `address`"));
        }

        Ok(Self {
            compilation_artifacts,
            jeton_init_params: jeton_config.init_params,
            jeton_init_data: jeton_config.init_data,
            nonce_address_idx: jeton_config.nonce_address_idx,
        })
    }

    pub fn compute_address(&self, nonce: &MsgAddrStd) -> Result<MsgAddressInt> {
        let init_data = string_params_to_cell(
            self.jeton_init_params.clone(),
            self.jeton_init_data.clone(),
            Some(self.nonce_address_idx),
            Some(nonce.clone()),
        )?;

        let init_state = make_state_init(
            cell_from_hex(&self.compilation_artifacts.hex).unwrap(),
            init_data,
        )?;
        calculate_address(init_state, 0)
        // Ok(init_state.serialize()?.repr_hash())
    }
}

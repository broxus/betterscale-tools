use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use anyhow::{Context, Ok, Result};
use generic_array::typenum::U256;
use num_bigint::BigUint;
use rand::prelude::Distribution;
use regex::Regex;
use serde::{Deserialize, Serialize};
use ton_abi::Uint;
use ton_block::{MsgAddrStd, MsgAddressInt, Serializable, StateInit};
use ton_types::{BuilderData, Cell, UInt256};

use crate::mine::affinity;

use super::jeton_utils::{cell_from_base_64, cell_from_hex, make_state_init, IBitstringExt};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompilationArtifacts {
    pub hash: String,
    pub hash_base64: String,
    pub hex: String,
}
pub fn mine_jeton_wallet_address(
    jeton_wallet_code: impl AsRef<Path>,
    jeton_init_params: Vec<String>,
    jeton_init_data: Vec<String>,
    target: ton_block::MsgAddressInt,
    nonce_idx: usize,
    min_affinity: Option<u8>,
) -> Result<()> {
    let code_text =
        std::fs::read_to_string(jeton_wallet_code).expect("Failed to read jeton wallet code");
    let compilation_artifacts = serde_json::from_str::<CompilationArtifacts>(&code_text)?;

    if jeton_init_params[nonce_idx] != "uint256" {
        return Err(anyhow::anyhow!("Nonce field must have type `uint256`"));
    }

    let global_max_affinity = Arc::new(AtomicU8::new(0));

    let mut threads = Vec::new();

    let thread_count = std::thread::available_parallelism()
        .context("Failed to get available parallelism")?
        .get();

    for _ in 0..thread_count {
        let workchain_id = target.workchain_id() as i8;
        let target = target.address().get_bytestring(0);
        let global_max_affinity = global_max_affinity.clone();

        let jeton_init_params = jeton_init_params.clone();
        let jeton_init_data = jeton_init_data.clone();
        let compilation_artifacts = compilation_artifacts.clone();

        threads.push(std::thread::spawn(move || -> Result<()> {
            let mut rng = rand::thread_rng();

            let distribution = num_bigint::RandomBits::new(256);

            let mut max_affinity = 0;

            loop {
                let nonce: num_bigint::BigUint = distribution.sample(&mut rng);
                let init_data = string_params_to_cell(
                    jeton_init_params.clone(),
                    jeton_init_data.clone(),
                    Some(nonce_idx),
                    Some(nonce.clone()),
                )?;

                let init_state = make_state_init(
                    cell_from_hex(&compilation_artifacts.hex).unwrap(),
                    init_data,
                )?;

                let current_address = compute_address(init_state, workchain_id)?;

                let mut address_affinity =
                    affinity(&current_address.address().get_bytestring(0), &target);

                if let Some(min_affinity) = min_affinity {
                    if address_affinity >= min_affinity {
                        println!(
                            "Bits: {} | Nonce: 0x{} | Address: {}",
                            address_affinity,
                            nonce.to_str_radix(16),
                            current_address.to_string(),
                        );
                    }
                } else {
                    if address_affinity <= max_affinity {
                        continue;
                    }

                    max_affinity = address_affinity;

                    if global_max_affinity.fetch_max(address_affinity, Ordering::SeqCst)
                        == max_affinity
                    {
                        println!(
                            "Bits: {} | Nonce: 0x{} | Address: {}",
                            address_affinity,
                            nonce.to_str_radix(16),
                            current_address.to_string(),
                        );
                    }
                }
            }
        }));
    }
    for thread in threads {
        thread
            .join()
            .expect("Failed to join thread")
            .context("Failed to mine address")?;
    }

    Ok(())
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

    let address = compute_address(init_state, 0);
    println!("{}", address.unwrap().to_string());

    Ok(())
}

fn compute_address(state_init: StateInit, workchain_id: i8) -> Result<MsgAddressInt> {
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
    nonce_value: Option<num_bigint::BigUint>,
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
                    if let (Some(nonce_idx), Some(nonce_value)) = (nonce_idx, nonce_value.clone()) {
                        if idx == nonce_idx && x == &"256" {
                            builder
                                .append_uint(&nonce_value, x.parse::<usize>().unwrap())
                                .unwrap();
                        }
                    } else {
                        builder
                            .append_uint(
                                &BigUint::from_str(data[idx].as_str()).unwrap(),
                                x.parse::<usize>().unwrap(),
                            )
                            .unwrap();
                    }
                }
                Some(["coins"]) => {
                    print!("{}", param_type);
                    builder
                        .append_coins(&BigUint::from_str(data[idx].as_str()).unwrap())
                        .unwrap();
                }
                Some(["address"]) => {
                    builder
                        .append_address(&ton_block::MsgAddressInt::from_str(&data[idx]).unwrap())
                        .unwrap();
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

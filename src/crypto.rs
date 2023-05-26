use crate::full_config::models::KeyOptionJson;
use anyhow::{Context, Result};
use ed25519_dalek::{ed25519, Verifier};

use everscale_crypto::ed25519::PublicKey;
use sha2::Digest;
use std::fmt::Debug;
use std::sync::Arc;
use ton_types::{error, fail};

/// ADNL key ID (node ID)
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
pub struct KeyId([u8; 32]);

impl KeyId {
    pub fn from_data(data: [u8; 32]) -> Arc<Self> {
        Arc::new(Self(data))
    }
    pub fn data(&self) -> &[u8; 32] {
        &self.0
    }
}

pub trait KeyOption: Sync + Send + Debug {
    fn id(&self) -> &Arc<KeyId>;
    fn type_id(&self) -> i32;
    fn pub_key(&self) -> Result<&[u8]>;
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()>;
    #[cfg(feature = "export_key")]
    fn export_key(&self) -> Result<&[u8]>;
    fn shared_secret(&self, other_pub_key: &[u8]) -> Result<[u8; 32]>;
}

#[derive(Debug)]
pub struct Ed25519KeyOption {
    id: Arc<KeyId>,
    pub_key: Option<[u8; Self::PUB_KEY_SIZE]>,
    exp_key: Option<[u8; Self::EXP_KEY_SIZE]>,
}

impl Ed25519KeyOption {
    pub const KEY_TYPE: i32 = 1209251014;
    pub const EXP_KEY_SIZE: usize = 64;
    pub const PVT_KEY_SIZE: usize = 32;
    pub const PUB_KEY_SIZE: usize = 32;

    pub fn generate_with_json() -> Result<(KeyOptionJson, Arc<dyn KeyOption>)> {
        Self::create_from_private_key_with_json(ed25519_dalek::SecretKey::generate(
            &mut rand07::thread_rng(),
        ))
    }

    fn create_from_expanded_key(
        exp_key: ed25519_dalek::ExpandedSecretKey,
    ) -> Result<Arc<dyn KeyOption>> {
        let pub_key = ed25519_dalek::PublicKey::from(&exp_key).to_bytes();
        let exp_key = exp_key.to_bytes();
        let ret = Self {
            id: Self::calc_id(Self::KEY_TYPE, &pub_key),
            pub_key: Some(pub_key),
            exp_key: Some(exp_key),
        };
        Ok(Arc::new(ret))
    }

    fn create_from_private_key_with_json(
        pvt_key: ed25519_dalek::SecretKey,
    ) -> Result<(KeyOptionJson, Arc<dyn KeyOption>)> {
        let ret = Self::create_from_expanded_key(ed25519_dalek::ExpandedSecretKey::from(&pvt_key))?;
        let json = KeyOptionJson {
            type_id: Self::KEY_TYPE,
            pub_key: None,
            pvt_key: Some(base64::encode(pvt_key.to_bytes())),
        };
        Ok((json, ret))
    }

    // Calculate key ID
    fn calc_id(type_id: i32, pub_key: &[u8; Self::PUB_KEY_SIZE]) -> Arc<KeyId> {
        let mut sha = sha2::Sha256::new();
        sha.update(type_id.to_le_bytes());
        sha.update(pub_key);
        KeyId::from_data(sha.finalize().into())
    }
}

impl KeyOption for Ed25519KeyOption {
    /// Get key id
    fn id(&self) -> &Arc<KeyId> {
        &self.id
    }

    /// Get type id
    fn type_id(&self) -> i32 {
        Self::KEY_TYPE
    }

    /// Get public key
    fn pub_key(&self) -> Result<&[u8]> {
        if let Some(pub_key) = self.pub_key.as_ref() {
            Ok(pub_key)
        } else {
            fail!("No public key set for key option {:?}", self.id())
        }
    }

    /// Calculate signature
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        // let exp_key = self.exp_key.context("key not found")?.as_ref();
        let binding = self.exp_key.context("key not found")?;
        let exp_key = binding.as_ref();
        let exp_key = ed25519_dalek::ExpandedSecretKey::from_bytes(exp_key)?;
        let pub_key = if let Ok(key) = self.pub_key() {
            ed25519_dalek::PublicKey::from_bytes(key)?
        } else {
            ed25519_dalek::PublicKey::from(&exp_key)
        };
        Ok(exp_key.sign(data, &pub_key).to_bytes().to_vec())
    }

    /// Verify signature
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let pub_key = ed25519_dalek::PublicKey::from_bytes(self.pub_key()?)?;
        pub_key.verify(data, &ed25519::Signature::from_bytes(signature)?)?;
        Ok(())
    }

    #[cfg(feature = "export_key")]
    fn export_key(&self) -> Result<&[u8]> {
        Ok(self.exp_key()?)
    }

    fn shared_secret(&self, other_pub_key: &[u8]) -> Result<[u8; 32]> {
        let point = curve25519_dalek_ng::edwards::CompressedEdwardsY(other_pub_key.try_into()?)
            .decompress()
            .ok_or_else(|| error!("Bad public key data"))?
            .to_montgomery()
            .to_bytes();
        let binding = self.exp_key.context("key not found")?;
        let exp_key = binding.as_ref();
        Ok(x25519_dalek::x25519(
            exp_key[..Self::PVT_KEY_SIZE].try_into()?,
            point,
        ))
    }
}

pub fn get_pubkey_by_base64_private(base64_string: &str) -> Result<PublicKey> {
    let hex_string = base64_to_hex(base64_string)?;
    let private_key_bytes = hex::decode(hex_string)?;
    let mut array = [0; 32];
    array.copy_from_slice(&private_key_bytes);
    let secret_key = everscale_crypto::ed25519::SecretKey::from_bytes(array);
    let public_key = PublicKey::from(&secret_key);
    Ok(public_key)
}

fn base64_to_hex(base64_string: &str) -> Result<String> {
    let bytes = base64::decode(base64_string)?;
    let hex_string = hex::encode(bytes);
    Ok(hex_string)
}

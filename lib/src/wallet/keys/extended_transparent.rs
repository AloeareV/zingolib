use std::io;

use byteorder::{ReadBytesExt, WriteBytesExt};
use lazy_static::lazy_static;
use ring::hmac::{self, Context, Key};
use secp256k1::{Error, PublicKey, Secp256k1, SecretKey, SignOnly};
use zcash_encoding::Vector;
use zingoconfig::ZingoConfig;

use crate::wallet::traits::ReadableWriteable;

lazy_static! {
    static ref SECP256K1_SIGN_ONLY: Secp256k1<SignOnly> = Secp256k1::signing_only();
    //static ref SECP256K1_VERIFY_ONLY: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
}
/// Random entropy, part of extended key.
type ChainCode = Vec<u8>;

const HARDENED_KEY_START_INDEX: u32 = 2_147_483_648; // 2 ** 31

/// KeyIndex indicates the key type and index of a child key.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyIndex {
    /// Normal key, index range is from 0 to 2 ** 31 - 1
    Normal(u32),
    /// Hardened key, index range is from 2 ** 31 to 2 ** 32 - 1
    Hardened(u32),
}

impl KeyIndex {
    /// Check index range.
    pub fn is_valid(self) -> bool {
        match self {
            KeyIndex::Normal(i) => i < HARDENED_KEY_START_INDEX,
            KeyIndex::Hardened(i) => i >= HARDENED_KEY_START_INDEX,
        }
    }

    /// Generate Hardened KeyIndex from normalize index value.
    pub fn hardened_from_normalize_index(i: u32) -> Result<KeyIndex, Error> {
        if i < HARDENED_KEY_START_INDEX {
            Ok(KeyIndex::Hardened(HARDENED_KEY_START_INDEX + i))
        } else {
            Ok(KeyIndex::Hardened(i))
        }
    }

    /// Generate KeyIndex from raw index value.
    pub fn from_index(i: u32) -> Result<Self, Error> {
        if i < HARDENED_KEY_START_INDEX {
            Ok(KeyIndex::Normal(i))
        } else {
            Ok(KeyIndex::Hardened(i))
        }
    }
}

impl From<u32> for KeyIndex {
    fn from(index: u32) -> Self {
        KeyIndex::from_index(index).expect("KeyIndex")
    }
}

/// ExtendedPrivKey is used for child key derivation.
/// See [secp256k1 crate documentation](https://docs.rs/secp256k1) for SecretKey signatures usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPrivKey {
    pub private_key: SecretKey,
    pub chain_code: ChainCode,
}

impl ExtendedPrivKey {
    /// Generate an ExtendedPrivKey from seed
    pub fn with_seed(seed: &[u8]) -> Result<ExtendedPrivKey, Error> {
        let signature = {
            let signing_key = Key::new(hmac::HMAC_SHA512, b"Bitcoin seed");
            let mut h = Context::with_key(&signing_key);
            h.update(&seed);
            h.sign()
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let private_key = SecretKey::from_slice(key)?;
        Ok(ExtendedPrivKey {
            private_key,
            chain_code: chain_code.to_vec(),
        })
    }

    pub fn get_ext_taddr_from_bip39seed(config: &ZingoConfig, bip39_seed: &[u8], pos: u32) -> Self {
        assert_eq!(bip39_seed.len(), 64);

        let ext_t_key = ExtendedPrivKey::with_seed(bip39_seed).unwrap();
        ext_t_key
            .derive_private_key(KeyIndex::hardened_from_normalize_index(44).unwrap())
            .unwrap()
            .derive_private_key(
                KeyIndex::hardened_from_normalize_index(config.get_coin_type()).unwrap(),
            )
            .unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(0).unwrap())
            .unwrap()
            .derive_private_key(KeyIndex::Normal(pos))
            .unwrap()
    }

    fn sign_hardended_key(&self, index: u32) -> ring::hmac::Tag {
        let signing_key = Key::new(hmac::HMAC_SHA512, &self.chain_code);
        let mut h = Context::with_key(&signing_key);
        h.update(&[0x00]);
        h.update(&self.private_key[..]);
        h.update(&index.to_be_bytes());
        h.sign()
    }

    fn sign_normal_key(&self, index: u32) -> ring::hmac::Tag {
        let signing_key = Key::new(hmac::HMAC_SHA512, &self.chain_code);
        let mut h = Context::with_key(&signing_key);
        let public_key = PublicKey::from_secret_key(&SECP256K1_SIGN_ONLY, &self.private_key);
        h.update(&public_key.serialize());
        h.update(&index.to_be_bytes());
        h.sign()
    }

    /// Derive a child key from ExtendedPrivKey.
    pub fn derive_private_key(&self, key_index: KeyIndex) -> Result<ExtendedPrivKey, Error> {
        if !key_index.is_valid() {
            return Err(Error::InvalidTweak);
        }
        let signature = match key_index {
            KeyIndex::Hardened(index) => self.sign_hardended_key(index),
            KeyIndex::Normal(index) => self.sign_normal_key(index),
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let mut private_key = SecretKey::from_slice(key)?;
        private_key.add_assign(&self.private_key[..])?;
        Ok(ExtendedPrivKey {
            private_key,
            chain_code: chain_code.to_vec(),
        })
    }
}

impl ReadableWriteable<()> for ExtendedPrivKey {
    const VERSION: u8 = 1;

    fn read<R: std::io::Read>(mut reader: R, _: ()) -> std::io::Result<Self> {
        Self::get_version(&mut reader)?;
        let mut secret_key_bytes = [0; 32];
        reader.read_exact(&mut secret_key_bytes)?;
        let private_key = SecretKey::from_slice(&secret_key_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let chain_code = Vector::read(&mut reader, |r| r.read_u8())?;
        Ok(Self {
            private_key,
            chain_code,
        })
    }

    fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_u8(Self::VERSION)?;
        writer.write(&self.private_key.serialize_secret())?;
        Vector::write(&mut writer, &self.chain_code, |w, byte| w.write_u8(*byte))?;
        Ok(())
    }
}

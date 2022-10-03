use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind, Read, Write},
};

use ::orchard::keys::{
    IncomingViewingKey as OrchardIncomingViewingKey, SpendingKey as OrchardSpendingKey,
};
use base58::{FromBase58, ToBase58};
use bip0039::Mnemonic;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::{rngs::OsRng, Rng};
use ripemd160::Digest;
use sha2::Sha256;
use sodiumoxide::crypto::secretbox;
use zcash_address::unified::{Encoding, Ufvk};
use zcash_client_backend::{
    address,
    encoding::{
        encode_extended_full_viewing_key, encode_extended_spending_key, encode_payment_address,
    },
};
use zcash_encoding::Vector;
use zcash_note_encryption::Domain;
use zcash_primitives::{
    legacy::TransparentAddress,
    sapling::PaymentAddress,
    zip32::{ChildIndex, ExtendedFullViewingKey, ExtendedSpendingKey},
};
use zingoconfig::{ZingoConfig, GAP_RULE_UNUSED_ADDRESSES};

use crate::wallet::utils;

use self::{
    orchard::{OrchardKey, WalletOKeyInner},
    sapling::{SaplingKey, WalletZKeyType},
    transparent::{TransparentKey, WalletTKeyType},
    unified::UnifiedSpendAuthority,
};

use super::traits::{DomainWalletExt, WalletKey};

pub(crate) mod extended_transparent;
pub(crate) mod orchard;
pub(crate) mod sapling;
pub(crate) mod transparent;
pub(crate) mod unified;

/// Sha256(Sha256(value))
pub fn double_sha256(payload: &[u8]) -> Vec<u8> {
    let h1 = Sha256::digest(&payload);
    let h2 = Sha256::digest(&h1);
    h2.to_vec()
}

/// A trait for converting a [u8] to base58 encoded string.
pub trait ToBase58Check {
    /// Converts a value of `self` to a base58 value, returning the owned string.
    /// The version is a coin-specific prefix that is added.
    /// The suffix is any bytes that we want to add at the end (like the "iscompressed" flag for
    /// Secret key encoding)
    fn to_base58check(&self, version: &[u8], suffix: &[u8]) -> String;
}

impl ToBase58Check for [u8] {
    fn to_base58check(&self, version: &[u8], suffix: &[u8]) -> String {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(version);
        payload.extend_from_slice(self);
        payload.extend_from_slice(suffix);

        let checksum = double_sha256(&payload);
        payload.append(&mut checksum[..4].to_vec());
        payload.to_base58()
    }
}

/// A trait for converting base58check encoded values.
pub trait FromBase58Check {
    /// Convert a value of `self`, interpreted as base58check encoded data, into the tuple with version and payload as bytes vector.
    fn from_base58check(&self) -> io::Result<(u8, Vec<u8>)>;
}

impl FromBase58Check for str {
    fn from_base58check(&self) -> io::Result<(u8, Vec<u8>)> {
        let mut payload: Vec<u8> = match self.from_base58() {
            Ok(payload) => payload,
            Err(error) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("{:?}", error),
                ))
            }
        };
        if payload.len() < 5 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("Invalid Checksum length"),
            ));
        }

        let checksum_index = payload.len() - 4;
        let provided_checksum = payload.split_off(checksum_index);
        let checksum = double_sha256(&payload)[..4].to_vec();
        if checksum != provided_checksum {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("Invalid Checksum"),
            ));
        }
        Ok((payload[0], payload[1..].to_vec()))
    }
}

// Manages all the keys in the wallet. Note that the RwLock for this is present in `lightwallet.rs`, so we'll
// assume that this is already gone through a RwLock, so we don't lock any of the individual fields.
pub struct Keys {
    // TODO: This struct is duplicated with LightWallet and LightClient
    config: ZingoConfig,

    // Is the wallet encrypted? If it is, then when writing to disk, the seed is always encrypted
    // and the individual spending keys are not written
    pub(crate) encrypted: bool,

    // In memory only (i.e, this field is not written to disk). Is the wallet unlocked and are
    // the spending keys present to allow spending from this wallet?
    pub(crate) unlocked: bool,

    enc_seed: [u8; 48], // If locked, this contains the encrypted seed
    nonce: Vec<u8>,     // Nonce used to encrypt the wallet.

    seed: [u8; 32], // Seed phrase for this wallet. If wallet is locked, this is 0

    // Unified spending keys derived from the wallet seed. This will eventually replace
    // all other HD keys.
    pub(crate) unified_keys: Vec<UnifiedSpendAuthority>,
}

impl Keys {
    pub fn serialized_version() -> u64 {
        return 22;
    }

    #[cfg(test)]
    pub fn new_empty() -> Self {
        let config = ZingoConfig::create_unconnected(zingoconfig::Network::FakeMainnet, None);
        Self {
            config,
            encrypted: false,
            unlocked: true,
            enc_seed: [0; 48],
            nonce: vec![],
            seed: [0u8; 32],
            unified_keys: vec![],
        }
    }

    pub fn new(config: &ZingoConfig, seed_phrase: Option<String>) -> Result<Self, String> {
        let mut seed_bytes = [0u8; 32];

        if seed_phrase.is_none() {
            // Create a random seed.
            let mut system_rng = OsRng;
            system_rng.fill(&mut seed_bytes);
        } else {
            let phrase = match Mnemonic::from_phrase(seed_phrase.unwrap().as_str()) {
                Ok(p) => p,
                Err(e) => {
                    let e = format!("Error parsing phrase: {}", e);
                    //error!("{}", e);
                    return Err(e);
                }
            };

            seed_bytes.copy_from_slice(&phrase.entropy());
        }

        // The seed bytes is the raw entropy. To pass it to HD wallet generation,
        // we need to get the 64 byte bip39 entropy
        let bip39_seed = Mnemonic::from_entropy(seed_bytes).unwrap().to_seed("");

        let unified_keys = vec![UnifiedSpendAuthority::new_from_seed(config, &bip39_seed, 0)];

        Ok(Self {
            config: config.clone(),
            encrypted: false,
            unlocked: true,
            enc_seed: [0; 48],
            nonce: vec![],
            seed: seed_bytes,
            unified_keys,
        })
    }

    pub fn read<R: Read>(mut reader: R, config: &ZingoConfig) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        if version > Self::serialized_version() {
            let e = format!(
                "Don't know how to read wallet version {}. Do you have the latest version?",
                version
            );
            return Err(io::Error::new(ErrorKind::InvalidData, e));
        }

        let encrypted = reader.read_u8()? > 0;

        let mut enc_seed = [0u8; 48];
        reader.read_exact(&mut enc_seed)?;

        let nonce = Vector::read(&mut reader, |r| r.read_u8())?;

        // Seed
        let mut seed_bytes = [0u8; 32];
        reader.read_exact(&mut seed_bytes)?;

        Ok(Self {
            config: config.clone(),
            encrypted,
            unlocked: !encrypted,
            enc_seed,
            nonce,
            seed: seed_bytes,
            unified_keys: vec![], // TODO: Read/write these
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Write the version
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        // Write if it is encrypted
        writer.write_u8(if self.encrypted { 1 } else { 0 })?;

        // Write the encrypted seed bytes
        writer.write_all(&self.enc_seed)?;

        // Write the nonce
        Vector::write(&mut writer, &self.nonce, |w, b| w.write_u8(*b))?;

        // Write the seed
        writer.write_all(&self.seed)?;

        // Flush after writing the seed, so in case of a disaster, we can still recover the seed.
        writer.flush()?;

        // Write the keys
        Vector::write(&mut writer, &self.unified_keys, |w, sk| sk.write(w))?;

        Ok(())
    }

    pub fn config(&self) -> ZingoConfig {
        self.config.clone()
    }

    pub fn get_seed_phrase(&self) -> String {
        if !self.unlocked {
            return "".to_string();
        }

        Mnemonic::from_entropy(self.seed)
            .unwrap()
            .phrase()
            .to_string()
    }

    pub fn get_spend_key_for_fvk<D>(&self, fvk: &D::Fvk) -> Option<<D::Key as WalletKey>::SpendKey>
    where
        D: DomainWalletExt<zingoconfig::Network>,
        <D as Domain>::Recipient: super::traits::Recipient,
        <D as Domain>::Note: PartialEq + Clone,
    {
        D::Key::get_keys(self)
            .iter()
            .find(|wallet_key| wallet_key.fvk().as_ref() == Some(fvk))
            .map(|wallet_key| wallet_key.spend_key())
            .flatten()
    }

    pub fn encrypt(&mut self, passwd: String) -> io::Result<()> {
        if self.encrypted {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                "Wallet is already encrypted",
            ));
        }

        // Get the doublesha256 of the password, which is the right length
        let key = secretbox::Key::from_slice(&double_sha256(passwd.as_bytes())).unwrap();
        let nonce = secretbox::gen_nonce();

        let cipher = secretbox::seal(&self.seed, &nonce, &key);

        self.enc_seed.copy_from_slice(&cipher);
        self.nonce = nonce.as_ref().to_vec();

        todo!("Encryption not yet implemented");

        self.encrypted = true;
        self.lock()?;

        Ok(())
    }

    pub fn lock(&mut self) -> io::Result<()> {
        if !self.encrypted {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                "Wallet is not encrypted",
            ));
        }

        if !self.unlocked {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                "Wallet is already locked",
            ));
        }

        // Empty the seed and the secret keys
        self.seed.copy_from_slice(&[0u8; 32]);

        self.unlocked = false;

        Ok(())
    }

    pub fn unlock(&mut self, passwd: String) -> io::Result<()> {
        if !self.encrypted {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "Wallet is not encrypted",
            ));
        }

        if self.encrypted && self.unlocked {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "Wallet is already unlocked",
            ));
        }

        // Get the doublesha256 of the password, which is the right length
        let key = secretbox::Key::from_slice(&double_sha256(passwd.as_bytes())).unwrap();
        let nonce = secretbox::Nonce::from_slice(&self.nonce).unwrap();

        let seed = match secretbox::open(&self.enc_seed, &nonce, &key) {
            Ok(s) => s,
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Decryption failed. Is your password correct?",
                ));
            }
        };

        self.seed.copy_from_slice(&seed);
        // Now that we have the seed, we'll generate the extsks and tkeys, and verify the fvks and addresses
        // respectively match

        // The seed bytes is the raw entropy. To pass it to HD wallet generation,
        // we need to get the 64 byte bip39 entropy
        let bip39_seed = &Mnemonic::from_entropy(seed).unwrap().to_seed("");
        let config = self.config.clone();

        self.encrypted = true;
        self.unlocked = true;

        Ok(())
    }

    // Removing encryption means unlocking it and setting the self.encrypted = false,
    // permanantly removing the encryption
    pub fn remove_encryption(&mut self, passwd: String) -> io::Result<()> {
        if !self.encrypted {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "Wallet is not encrypted",
            ));
        }

        // Unlock the wallet if it's locked
        if !self.unlocked {
            self.unlock(passwd)?;
        }

        // Permanantly remove the encryption
        self.encrypted = false;
        self.nonce = vec![];
        self.enc_seed.copy_from_slice(&[0u8; 48]);

        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        return self.encrypted;
    }

    pub fn is_unlocked_for_spending(&self) -> bool {
        return self.unlocked;
    }

    /// STATIC METHODS
    pub fn address_from_pubkeyhash(&self, ta: Option<TransparentAddress>) -> Option<String> {
        match ta {
            Some(TransparentAddress::PublicKey(hash)) => {
                Some(hash.to_base58check(&self.config.base58_pubkey_address(), &[]))
            }
            Some(TransparentAddress::Script(hash)) => {
                Some(hash.to_base58check(&self.config.base58_script_address(), &[]))
            }
            _ => None,
        }
    }

    pub fn get_zaddr_from_bip39seed(
        config: &ZingoConfig,
        bip39_seed: &[u8],
        pos: u32,
    ) -> (ExtendedSpendingKey, ExtendedFullViewingKey, PaymentAddress) {
        assert_eq!(bip39_seed.len(), 64);

        let extsk: ExtendedSpendingKey = ExtendedSpendingKey::from_path(
            &ExtendedSpendingKey::master(bip39_seed),
            &[
                ChildIndex::Hardened(32),
                ChildIndex::Hardened(config.get_coin_type()),
                ChildIndex::Hardened(pos),
            ],
        );
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let address = extfvk.default_address().1;

        (extsk, extfvk, address)
    }

    pub fn is_shielded_address(addr: &String, config: &ZingoConfig) -> bool {
        match address::RecipientAddress::decode(&config.chain, addr) {
            Some(address::RecipientAddress::Shielded(_))
            | Some(address::RecipientAddress::Unified(_)) => true,
            _ => false,
        }
    }
}

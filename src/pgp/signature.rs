use crate::parsers::{parse_cleartext_signature_parts, parse_pkcs1};
use crate::pgp::{AsciiArmor, PgpPacket};
use anyhow::anyhow;
use byteorder::{BigEndian, WriteBytesExt};
use num::BigUint;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::convert::TryInto;

use super::key::PublicKey;
use super::AsciiArmorParts;

pub type CleartextSignatureParts = (String, String, AsciiArmorParts);

#[derive(Debug)]
pub struct CleartextSignature {
    hash: String,
    cleartext: String,
    signature: SignaturePacket,
}

#[derive(Debug)]
pub struct PgpSignature {}

#[derive(Debug)]
pub struct SignaturePacket {
    pub version: u8,
    pub signature_type: u8,
    pub public_key_algorithm: u8,
    pub hash_algorithm: u8,
    pub hashed_subpacket_data: Vec<u8>,
    pub unhashed_subpacket_data: Vec<u8>,
    /// holds the left 16 bits of the signed hash value.
    pub signed_hash_value_head: u16,

    pub signature: Vec<BigUint>,
}

#[derive(Debug)]
enum SignatureType {}

#[derive(Debug)]
enum PublicKeyAlgorithm {}

#[derive(Debug)]
enum HashAlgorithm {}

#[derive(Debug)]
pub enum SignatureSubPacket {}

impl CleartextSignature {
    pub fn parse(input: &str) -> anyhow::Result<CleartextSignature> {
        let (_, (hash, cleartext, ascii_armor_parts)) = parse_cleartext_signature_parts(input)
            .map_err(|_| anyhow!("failed to parse parts of cleartext signature"))?;

        let ascii_armor = AsciiArmor::from_parts(ascii_armor_parts)?;

        if !ascii_armor.verify() {
            return Err(anyhow!(
                "ascii armor failed to verify: checksum did not match"
            ));
        }

        let mut packets = ascii_armor.into_pgp_packets()?;

        if let PgpPacket::SignaturePacket(signature) = packets.pop().unwrap() {
            Ok(CleartextSignature {
                hash,
                cleartext,
                signature,
            })
        } else {
            Err(anyhow!("did not find a signature packet"))
        }
    }

    pub fn verify(&self, key: &PublicKey) -> anyhow::Result<bool> {
        let mut hasher = Sha256::new();

        // 1. write the msg, canonicalized by replacing newlines with CRLF.
        let r = Regex::new(r"\r\n")?;
        let replaced = r.replace_all(self.cleartext.as_str(), "\n");
        let r = Regex::new(r"\n")?;
        let replaced = r.replace_all(replaced.as_ref(), "\r\n");
        hasher.update(replaced.as_ref());

        // 2. write the initial bytes of the signature packet.
        hasher.update(&[
            self.signature.version,
            self.signature.signature_type,
            self.signature.public_key_algorithm,
            self.signature.hash_algorithm,
        ]);

        let mut buf = Vec::new();
        let length = self.signature.hashed_subpacket_data.len().try_into()?;
        buf.write_u16::<BigEndian>(length)?;
        hasher.update(buf);
        hasher.update(self.signature.hashed_subpacket_data.clone());

        // 3. finally, write the v4 hash trailer.
        hasher.update(&[0x04_u8, 0xff]);
        let mut buf = Vec::new();
        let mut length = self.signature.hashed_subpacket_data.len().try_into()?;
        length += 6;
        buf.write_u32::<BigEndian>(length)?;
        hasher.update(buf);

        let hash = hasher.finalize();
        let computed = BigUint::from_bytes_be(&hash);

        let signature = self.signature.signature[0]
            .modpow(&key.e, &key.n)
            .to_bytes_be();
        let (_, decoded) = parse_pkcs1(&signature).map_err(|_| anyhow!("Failed to parse pkcs1"))?;

        Ok(decoded == computed)
    }
}

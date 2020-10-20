use crate::parsers::parse_pgp_packets;
use anyhow::anyhow;

pub mod key;
pub mod signature;

use key::KeyPacket;
use signature::SignaturePacket;

const CRC24_INIT: u32 = 0xB704CE;
const CRC24_POLY: u32 = 0x1864CFB;

#[derive(Debug)]
pub struct AsciiArmor {
    kind: AsciiArmorKind,
    data: Vec<u8>,
    checksum: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum AsciiArmorKind {
    Signature,
}

#[derive(Debug)]
#[allow(unused)]
pub enum PgpPacket {
    SignaturePacket(SignaturePacket),
    KeyPacket(KeyPacket),
}

impl AsciiArmor {
    pub fn from_parts(parts: (AsciiArmorKind, String, String)) -> anyhow::Result<AsciiArmor> {
        let (kind, data, checksum) = parts;

        let data = base64::decode(&data)?;
        let checksum = base64::decode(&checksum)?;

        Ok(AsciiArmor {
            kind,
            data,
            checksum,
        })
    }

    pub fn verify(&self) -> bool {
        let checksum_computed = crc24(self.data.as_slice());
        let checksum_stored = (self.checksum[0] as u32) << 16
            | (self.checksum[1] as u32) << 8
            | (self.checksum[2] as u32);

        checksum_computed == checksum_stored
    }

    pub fn into_pgp_packets(&self) -> anyhow::Result<Vec<PgpPacket>> {
        let (_, packets) =
            parse_pgp_packets(&self.data).map_err(|_| anyhow!("could not parse pgp packets"))?;

        Ok(packets)
    }
}

/// Implementation of CRC24 directly from the RFC.
/// https://tools.ietf.org/html/rfc4880#section-6.1
fn crc24(data: &[u8]) -> u32 {
    let mut crc = CRC24_INIT;
    for curr in data.iter() {
        crc ^= (*curr as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 {
                crc ^= CRC24_POLY;
            }
        }
    }

    crc & 0xFFFFFF
}

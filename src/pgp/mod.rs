use crate::parsers::parse_pgp_packets;
use anyhow::anyhow;
use nom::bits::bits;
use nom::bytes::complete::{tag, take, take_till, take_until, take_while, take_while_m_n};
use nom::character::complete::alphanumeric1;
use nom::character::complete::newline;
use nom::multi::fold_many0;
use nom::multi::many0;
use nom::sequence::{preceded, terminated};
use nom::IResult;
use num::BigUint;

pub mod signature;

use signature::{PgpSignature, SignaturePacket};

const CRC24_INIT: u32 = 0xB704CE;
const CRC24_POLY: u32 = 0x1864CFB;

#[derive(Debug)]
pub struct AsciiArmor {
    kind: AsciiArmorKind,
    data: Vec<u8>,
    checksum: Vec<u8>,
}

#[derive(Debug)]
pub enum AsciiArmorKind {
    Signature,
}

#[derive(Debug)]
pub enum PgpPacket {
    SignaturePacket(SignaturePacket),
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

/* XXX fix this to be an implementation block for AsciiArmoredMessage
 * should support more than just signature
impl PgpSignature {
    fn parse(input: &str) -> IResult<&str, PgpSignature> {
        let (input, _) = tag("-----BEGIN PGP SIGNATURE-----\n")(input)?;
        let (input, _) = newline(input)?;
        let (input, base64) = parse_base64(input)?;
        let (input, _) = take_while(|c| c == '\n' || c == '=')(input)?;
        let (input, checksum) = take_till(|c| c == '\n')(input)?;
        let (input, _) = newline(input)?;
        let (input, _) = tag("-----END PGP SIGNATURE-----\n")(input)?;

        let data = base64::decode(&base64).unwrap();
        let checksum = base64::decode(&checksum).unwrap();

        Ok((
            input,
            PgpSignature {
                data,
                checksum,
                valid_state: ValidState::Unchecked,
            },
        ))
    }

}
*/

/* XXX fix this to fit the new form that PgpPacket is an enum, holding a specialized struct.
impl PgpPacket {
    fn parse(input: &[u8]) -> IResult<&[u8], PgpPacket> {
}
*/

fn parse_cleartext(input: &str) -> IResult<&str, &str> {
    let (left, cleartext) = take_until("\n-----BEGIN PGP SIGNATURE-----\n")(input)?;
    let (left, _) = newline(left)?;

    Ok((left, cleartext))
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

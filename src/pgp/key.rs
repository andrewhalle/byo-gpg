use anyhow::anyhow;
use num::BigUint;

use crate::parsers::parse_ascii_armor_parts_all_consuming;
use crate::pgp::{AsciiArmor, PgpPacket};

#[derive(Debug)]
pub struct PublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

#[derive(Debug)]
pub struct PublicKeyPacket {}

impl PublicKey {
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        let (_, parts) = parse_ascii_armor_parts_all_consuming(input)
            .map_err(|_| anyhow!("could not parse ascii armor parts"))?;

        let ascii_armor = AsciiArmor::from_parts(parts)?;
        /*
        let packets = ascii_armor.into_pgp_packets()?;

        // this is a bit hacky, I know my keys will have the key used for signing as
        // the first packet, but this doesn't have to be the case.
        let public_key_packet = match &packets[0] {
            PgpPacket::PublicKeyPacket(p) => p,
            _ => {
                return Err(anyhow!(
                    "first packet from the ascii armor was not a public key packet."
                ));
            }
        };
        */

        Ok(PublicKey {
            n: BigUint::from_bytes_be(&hex::decode(include_str!("../../test-key-n.txt"))?),
            e: BigUint::from_bytes_be(&hex::decode(include_str!("../../test-key-e.txt"))?),
        })
    }
}

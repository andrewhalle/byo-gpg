use crate::parsers::parse_cleartext_signature_parts;
use crate::pgp::{AsciiArmor, PgpPacket};
use anyhow::anyhow;
use num::BigUint;

#[derive(Debug)]
pub struct CleartextSignature {
    hash: Option<String>,
    cleartext: String,
    signature: SignaturePacket,
}

#[derive(Debug)]
pub struct PgpSignature {}

// XXX try not to make all field pub
#[derive(Debug)]
pub struct SignaturePacket {
    pub version: u8,
    //signature_type: SignatureType,            XXX
    pub signature_type: u8,
    //public_key_algorithm: PublicKeyAlgorithm, XXX
    pub public_key_algorithm: u8,
    //hash_algorithm: HashAlgorithm,            XXX
    pub hash_algorithm: u8,
    pub hashed_subpackets: Vec<SignatureSubPacket>,
    pub unhashed_subpackets: Vec<SignatureSubPacket>,

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
    pub fn parse(input: &'static str) -> anyhow::Result<CleartextSignature> {
        let (_, (hash, cleartext, ascii_armor_parts)) = parse_cleartext_signature_parts(input)?;

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
}
/* XXX lots in here needs to be fixed
impl CleartextSignature {
    pub fn parse_from(data: &str) -> Result<CleartextSignature, &'static str> {
        // why is the type required on the map_err?
        let (input, _) = tag("-----BEGIN PGP SIGNED MESSAGE-----\n")(data)
            .map_err(|_: nom::Err<(_, _)>| "error 1")?;
        let (input, hash) =
            parse_hash_armor_header(input).map_err(|_: nom::Err<(_, _)>| "error 2")?;

        let (input, cleartext) = parse_cleartext(input).map_err(|_: nom::Err<(_, _)>| "error 3")?;

        let (_input, mut signature) =
            PgpSignature::parse(input).map_err(|_: nom::Err<(_, _)>| "error 4")?;

        // assert end of file here using all_consuming

        let cleartext = match cleartext.strip_prefix("- ") {
            Some(cleartext) => cleartext,
            None => cleartext,
        };
        let cleartext = cleartext.to_string().replace("\n- ", "\n");

        signature.validate();
        if signature.valid_state == ValidState::Invalid {
            Err("signature not validated")?;
        }

        let (_, packet) =
            PgpPacket::parse(&signature.data).map_err(|_: nom::Err<(_, _)>| "error 5")?;
        dbg!(packet);

        Ok(CleartextSignature {
            hash: Some(hash.to_string()),
            cleartext,
            signature,
        })
    }

    pub fn verify(&self) -> bool {
        true
    }
}
*/

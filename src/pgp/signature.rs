use crate::parsers::parse_cleartext_signature_parts;
use crate::pgp::AsciiArmor;
use anyhow::anyhow;
use num::BigUint;

#[derive(Debug)]
pub struct CleartextSignature {
    hash: Option<String>,
    cleartext: String,
    signature: PgpSignature,
}

#[derive(Debug)]
pub struct PgpSignature {}

#[derive(Debug)]
pub struct SignaturePacket {
    version: u8,
    signature_type: SignatureType,
    public_key_algorithm: PublicKeyAlgorithm,
    hash_algorithm: HashAlgorithm,
    hashed_subpackets: Vec<SignatureSubPacket>,
    unhashed_subpackets: Vec<SignatureSubPacket>,

    /// holds the left 16 bits of the signed hash value.
    signed_hash_value_head: u16,

    signature: Vec<BigUint>,
}

#[derive(Debug)]
enum SignatureType {}

#[derive(Debug)]
enum PublicKeyAlgorithm {}

#[derive(Debug)]
enum HashAlgorithm {}

#[derive(Debug)]
enum SignatureSubPacket {}

impl CleartextSignature {
    pub fn parse(input: &'static str) -> anyhow::Result<CleartextSignature> {
        let (_, (hash, cleartext, ascii_armor_parts)) = parse_cleartext_signature_parts(input)?;

        let ascii_armor = AsciiArmor::from_parts(ascii_armor_parts)?;

        if !ascii_armor.verify() {
            return Err(anyhow!(
                "ascii armor failed to verify: checksum did not match"
            ));
        }

        let signature = ascii_armor.into_pgp_signature()?;

        Ok(CleartextSignature {
            hash,
            cleartext,
            signature,
        })
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

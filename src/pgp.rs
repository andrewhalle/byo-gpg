use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take, take_till, take_until, take_while, take_while_m_n};
use nom::character::complete::alphanumeric1;
use nom::character::complete::newline;
use nom::multi::fold_many0;
use nom::multi::many0;
use nom::sequence::{preceded, terminated};
use nom::IResult;
use num::BigUint;

const BASE64_LINE_LENGTH: usize = 64_usize;
const CRC24_INIT: u32 = 0xB704CE;
const CRC24_POLY: u32 = 0x1864CFB;

#[derive(Debug)]
pub struct CleartextSignature {
    hash: Option<String>,
    cleartext: String,
    //    signature: PgpSignature,
    signature: SignaturePacket,
}

/*
#[derive(Debug)]
struct PgpSignature {
    data: Vec<u8>,
    checksum: Vec<u8>,
    valid_state: ValidState,
}
*/

/*
/// For now, only represents an old format packet.
#[derive(Debug)]
struct PgpPacket {
    packet_tag: u8,
    length_type: u8,
    length: u32,

    // the below fields are actually signature packet specific, and need to be moved
    // to a separate struct
    version: u8,
    signature_type: u8,
    public_key_algorithm: u8,
    hash_algorithm: u8,
    hashed_subpacket_length: u16,
    hashed_subpacket_data: Vec<u8>,
}
*/

#[derive(Debug)]
enum PgpPacket {
    SignaturePacket(SignaturePacket),
}

#[derive(Debug)]
struct SignaturePacket {
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

/*
#[derive(Debug, PartialEq)]
enum ValidState {
    Unchecked,
    Valid,
    Invalid,
}
*/

/*
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

    fn validate(&mut self) {
        let checksum_computed = crc24(self.data.as_slice());
        let checksum_stored = (self.checksum[0] as u32) << 16
            | (self.checksum[1] as u32) << 8
            | (self.checksum[2] as u32);
        self.valid_state = if checksum_computed == checksum_stored {
            ValidState::Valid
        } else {
            ValidState::Invalid
        }
    }
}

impl PgpPacket {
    fn parse(input: &[u8]) -> IResult<&[u8], PgpPacket> {
        let (input, (packet_tag, length_type)) = bits::<_, _, (_, _), _, _>(|input| {
            let (input, _): (_, usize) = take_bits(2_usize)(input)?;
            let (input, packet_tag) = take_bits(4_usize)(input)?;
            let (input, length_type) = take_bits(2_usize)(input)?;

            Ok((input, (packet_tag, length_type)))
        })(input)?;

        let length = match length_type {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => u32::MAX,
            _ => panic!("unrecognized length_type"),
        };

        let (input, packet_length_bytes) = take(length)(input)?;
        let mut packet_length = 0_u32;
        for (shift, elem) in packet_length_bytes
            .iter()
            .enumerate()
            .map(|(i, val)| (packet_length_bytes.len() - i - 1, val))
        {
            packet_length |= (*elem as u32) << (shift * 8);
        }

        let (input, version) = if let (input, &[version]) = take(1_usize)(input)? {
            (input, version)
        } else {
            unreachable!()
        };

        let (input, signature_type) = if let (input, &[signature_type]) = take(1_usize)(input)? {
            (input, signature_type)
        } else {
            unreachable!()
        };

        let (input, public_key_algorithm) =
            if let (input, &[public_key_algorithm]) = take(1_usize)(input)? {
                (input, public_key_algorithm)
            } else {
                unreachable!()
            };

        let (input, hash_algorithm) = if let (input, &[hash_algorithm]) = take(1_usize)(input)? {
            (input, hash_algorithm)
        } else {
            unreachable!()
        };

        let (input, hashed_subpacket_length_bytes) = take(length)(input)?;
        let mut hashed_subpacket_length = 0_u16;
        for (shift, elem) in hashed_subpacket_length_bytes
            .iter()
            .enumerate()
            .map(|(i, val)| (hashed_subpacket_length_bytes.len() - i - 1, val))
        {
            hashed_subpacket_length |= (*elem as u16) << (shift * 8);
        }

        let (input, hashed_subpacket_data) = take(hashed_subpacket_length)(input)?;

        Ok((
            input,
            PgpPacket {
                packet_tag,
                length_type,
                length: packet_length,
                version,
                signature_type,
                public_key_algorithm,
                hash_algorithm,
                hashed_subpacket_length,
                hashed_subpacket_data: hashed_subpacket_data.to_owned(),
            },
        ))
    }
}

fn parse_hash_armor_header(input: &str) -> IResult<&str, &str> {
    terminated(preceded(tag("Hash: "), alphanumeric1), many0(newline))(input)
}

fn parse_cleartext(input: &str) -> IResult<&str, &str> {
    let (left, cleartext) = take_until("\n-----BEGIN PGP SIGNATURE-----\n")(input)?;
    let (left, _) = newline(left)?;

    Ok((left, cleartext))
}

// XXX there's a bug in this, if the base64 data is exactly as long as a line, then it
// won't recognize the end.
// XXX think the bug is fixed, but better write a unit test for it
fn parse_base64(input: &str) -> IResult<&str, String> {
    let (input, mut base64) = fold_many0(parse_base64_line, String::new(), |mut s, item| {
        s.push_str(item);
        s
    })(input)?;
    let (input, remaining) = take_while(is_base_64_digit)(input)?;
    let (input, _) = newline(input)?;

    base64.push_str(remaining);

    Ok((input, base64))
}

fn parse_base64_line(input: &str) -> IResult<&str, &str> {
    let (input, res) =
        take_while_m_n(BASE64_LINE_LENGTH, BASE64_LINE_LENGTH, is_base_64_digit)(input)?;
    let (input, _) = newline(input)?;

    Ok((input, res))
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

fn is_base_64_digit(c: char) -> bool {
    (c >= '0' && c <= '9')
        || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z')
        || c == '+'
        || c == '/'
        || c == '='
}
*/

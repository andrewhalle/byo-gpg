use nom::bytes::complete::take_while_m_n;
use nom::bytes::complete::{tag, take_till, take_until, take_while};
use nom::character::complete::alphanumeric1;
use nom::character::complete::newline;
use nom::multi::fold_many0;
use nom::multi::many0;
use nom::sequence::{preceded, terminated};
use nom::IResult;

const BASE64_LINE_LENGTH: usize = 64_usize;
const CRC24_INIT: u32 = 0xB704CE;
const CRC24_POLY: u32 = 0x1864CFB;

#[derive(Debug)]
pub struct CleartextSignature {
    hash: Option<String>,
    cleartext: String,
    signature: PgpSignature,
}

#[derive(Debug)]
struct PgpSignature {
    data: Vec<u8>,
    checksum: Vec<u8>,
    valid_state: ValidState,
}

#[derive(Debug, PartialEq)]
enum ValidState {
    Unchecked,
    Valid,
    Invalid,
}

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

        Ok(CleartextSignature {
            hash: Some(hash.to_string()),
            cleartext,
            signature,
        })
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
fn parse_base64(input: &str) -> IResult<&str, String> {
    let (input, mut base64) = fold_many0(parse_base64_line, String::new(), |mut s, item| {
        s.push_str(item);
        s
    })(input)?;
    let (input, remaining) = take_till(|c| c == '\n')(input)?;
    let (input, _) = newline(input)?;

    base64.push_str(remaining);

    Ok((input, base64))
}

fn parse_base64_line(input: &str) -> IResult<&str, &str> {
    let (input, res) =
        take_while_m_n(BASE64_LINE_LENGTH, BASE64_LINE_LENGTH, |c| c != '\n')(input)?;
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

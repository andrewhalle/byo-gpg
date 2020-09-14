use nom::bytes::complete::{tag, take_till, take_until, take_while};
use nom::character::complete::alphanumeric1;
use nom::character::complete::newline;
use nom::multi::many0;
use nom::sequence::{preceded, terminated};
use nom::IResult;

#[derive(Debug)]
pub struct CleartextSignature {
    hash: Option<String>,
    cleartext: String,
    signature: String,
    end_bytes: String, // what is this field for?
}

// XXX fix me, for now just stuff the base64 bytes into this vec.
// type PgpSignature = Vec<u8>;

impl CleartextSignature {
    pub fn parse_from(data: &str) -> Result<CleartextSignature, &'static str> {
        // why is the type required on the map_err?
        let (input, _) = tag("-----BEGIN PGP SIGNED MESSAGE-----\n")(data)
            .map_err(|_: nom::Err<(_, _)>| "error 1")?;
        let (input, hash) =
            parse_hash_armor_header(input).map_err(|_: nom::Err<(_, _)>| "error 2")?;

        let (input, cleartext) = parse_cleartext(input).map_err(|_: nom::Err<(_, _)>| "error 3")?;

        let (_input, (signature, end_bytes)) =
            parse_pgp_signature(input).map_err(|_: nom::Err<(_, _)>| "error 4")?;

        // assert end of file here using all_consuming

        let cleartext = match cleartext.strip_prefix("- ") {
            Some(cleartext) => cleartext,
            None => cleartext,
        };
        let cleartext = cleartext.to_string().replace("\n- ", "\n");

        let mut signature = signature.to_string();
        signature.retain(|c| c != '\n');

        Ok(CleartextSignature {
            hash: Some(hash.to_string()),
            cleartext,
            signature,
            end_bytes: end_bytes.to_string(),
        })
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

fn parse_pgp_signature(input: &str) -> IResult<&str, (&str, &str)> {
    let (input, _) = tag("-----BEGIN PGP SIGNATURE-----\n")(input)?;
    let (input, _) = newline(input)?;
    let (input, base64) = take_until("==")(input)?;
    let (input, _) = take_while(|c| c == '\n' || c == '=')(input)?;
    let (input, end_field) = take_till(|c| c == '\n')(input)?;
    let (input, _) = newline(input)?;
    let (input, _) = tag("-----END PGP SIGNATURE-----\n")(input)?;

    Ok((input, (base64, end_field)))
}

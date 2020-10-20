use crate::pgp::AsciiArmorKind;
use byteorder::{BigEndian, ReadBytesExt};
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::bytes::complete::take;
use nom::bytes::complete::take_while;
use nom::character::complete::{alphanumeric1, char, newline};
use nom::combinator::all_consuming;
use nom::multi::many0;
use nom::sequence::tuple;
use nom::sequence::{preceded, terminated};
use nom::IResult;
use num::BigUint;

use super::base64::parse_base64;
use super::signature::parse_signature_packet;

use crate::pgp::PgpPacket;

/// Parse a multi-precision integer (MPI) as defined by the RFC in
/// section 3.2.
pub fn parse_mpi(input: &[u8]) -> IResult<&[u8], BigUint> {
    let (input, mut length) = take(2_usize)(input)?;
    let bits = length.read_u16::<BigEndian>().unwrap();
    let bytes = (bits + 7) / 8;

    let (input, num) = take(bytes)(input)?;
    let num = BigUint::from_bytes_be(num);

    Ok((input, num))
}

// XXX refactor this to support more than just signatures
// XXX probably typedef (String, String)
pub fn parse_ascii_armor_parts(input: &str) -> IResult<&str, (AsciiArmorKind, String, String)> {
    let parser = tuple((
        tag("-----BEGIN PGP SIGNATURE-----\n\n"),
        parse_base64,
        char('='),
        parse_base64,
        tag("-----END PGP SIGNATURE-----\n"),
    ));

    let (input, (_, data, _, checksum, _)) = parser(input)?;

    Ok((input, (AsciiArmorKind::Signature, data, checksum)))
}

pub fn parse_hash_armor_header(input: &str) -> IResult<&str, &str> {
    terminated(preceded(tag("Hash: "), alphanumeric1), many0(newline))(input)
}

pub fn parse_pgp_packet(input: &[u8]) -> IResult<&[u8], PgpPacket> {
    let parser = alt((parse_signature_packet, parse_signature_packet));

    let (input, packet): (&[u8], PgpPacket) = parser(input)?;

    Ok((input, packet))
}

pub fn parse_pgp_packets(input: &[u8]) -> IResult<&[u8], Vec<PgpPacket>> {
    let parser = all_consuming(many0(parse_pgp_packet));

    let (empty, packets) = parser(input)?;

    Ok((empty, packets))
}

pub fn parse_pkcs1(input: &[u8]) -> IResult<&[u8], BigUint> {
    let header = tuple((
        tag(&[0x01]),
        take_while(|b| b == 255),
        tag(&[0x00]),
        tag(&[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ]),
    ));

    let (rest, _) = header(input)?;

    let signature = BigUint::from_bytes_be(rest);

    Ok((b"", signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num::bigint::ToBigUint;

    #[test]
    fn test_parse_mpi() {
        let input: [u8; 4] = [0x00, 0x09, 0x01, 0xff];
        let expected: &[u8] = &[];
        assert_eq!(
            parse_mpi(&input),
            Ok((expected, 511_u32.to_biguint().unwrap()))
        );

        let input: [u8; 5] = [0x00, 0x01, 0x01, 0x23, 0x45];
        let expected: &[u8] = &[0x23, 0x45];
        assert_eq!(
            parse_mpi(&input),
            Ok((expected, 1_u32.to_biguint().unwrap()))
        );
    }

    #[test]
    fn test_parse_ascii_armor_parts() {
        let input = "-----BEGIN PGP SIGNATURE-----\n\n\
                     aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
                     a==\n\
                     =aaaa\n\
                     -----END PGP SIGNATURE-----\n";
        let expected = (
            AsciiArmorKind::Signature,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==".to_owned(),
            "aaaa".to_owned(),
        );

        assert_eq!(parse_ascii_armor_parts(&input), Ok(("", expected)));
    }
}

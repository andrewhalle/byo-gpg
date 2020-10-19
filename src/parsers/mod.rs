use crate::pgp::signature::SignaturePacket;
use crate::pgp::{AsciiArmorKind, PgpPacket};
use byteorder::{BigEndian, ReadBytesExt};
use nom::bits::bits;
use nom::bits::complete::{tag as tag_bits, take as take_bits};
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::bytes::complete::take;
use nom::bytes::complete::take_till;
use nom::bytes::complete::take_while;
use nom::character::complete::alphanumeric1;
use nom::character::complete::char;
use nom::character::complete::newline;
use nom::combinator::all_consuming;
use nom::combinator::map;
use nom::combinator::not;
use nom::combinator::opt;
use nom::combinator::peek;
use nom::multi::fold_many0;
use nom::multi::{many0, many1};
use nom::sequence::preceded;
use nom::sequence::terminated;
use nom::sequence::tuple;
use nom::IResult;
use num::BigUint;

mod base64;
mod pgp_utils;

use self::base64::parse_base64;
use pgp_utils::parse_mpi;

/// Parse a set of lines (that may be dash-escaped) into a String. Stops when reaching a line
/// that starts with a dash but is not dash-escaped.
fn parse_possibly_dash_escaped_chunk(input: &str) -> IResult<&str, String> {
    let (input, mut chunk) = fold_into_string(input, parse_possibly_dash_escaped_line)?;

    chunk.pop();

    Ok((input, chunk))
}

/// Parse a line of text that may be dash-escaped. If a line of text is not dash-escaped, but
/// begins with a '-', then fail.
fn parse_possibly_dash_escaped_line(input: &str) -> IResult<&str, &str> {
    alt((parse_dash_escaped_line, parse_non_dash_line))(input)
}

/// Parse a line of text that is dash-escaped. Takes a line that begins with '- ', otherwise fails.
fn parse_dash_escaped_line(input: &str) -> IResult<&str, &str> {
    let (input, _) = parse_dash(input)?;
    let (input, _) = parse_space(input)?;

    parse_line_newline_inclusive(input)
}

/// Parse a line of text that does not begin with a dash. Line may be the empty string.
fn parse_non_dash_line(input: &str) -> IResult<&str, &str> {
    peek(not(parse_dash))(input)?;

    // since peek did not error, we know the line does not begin with a dash.

    parse_line_newline_inclusive(input)
}

// XXX make this with with CRLF as well as \n.
// probably by using regex to find the next \n or \r\n and taking that many bytes,
// eliminating the unsafe.
/// Parse until a newline is encountered, but return a string slice that includes the newline.
fn parse_line_newline_inclusive(input: &str) -> IResult<&str, &str> {
    let (input, line) = take_till(is_newline)(input)?;
    let (input, _) = newline(input)?;

    // since the above did not error, we know the byte after line is a newline, so we can
    // use unsafe to extend the slice to include the newline.

    let line = unsafe { extend_str_by_one_byte(line) };
    Ok((input, line))
}

unsafe fn extend_str_by_one_byte(s: &str) -> &str {
    let ptr = s.as_ptr();
    let len = s.len();

    let bytes = std::slice::from_raw_parts(ptr, len + 1);
    std::str::from_utf8(bytes).unwrap()
}

/// Parse a single dash.
fn parse_dash(input: &str) -> IResult<&str, char> {
    char('-')(input)
}

/// Parse a single space.
fn parse_space(input: &str) -> IResult<&str, char> {
    char(' ')(input)
}

/// Runs a parser repeatedly, concatenating the results into a String.
fn fold_into_string<F: Fn(&str) -> IResult<&str, &str>>(
    input: &str,
    parser: F,
) -> IResult<&str, String> {
    fold_many0(parser, String::new(), |mut s, item| {
        s.push_str(item);
        s
    })(input)
}

fn is_newline(c: char) -> bool {
    c == '\n'
}

fn parse_hash_armor_header(input: &str) -> IResult<&str, &str> {
    terminated(preceded(tag("Hash: "), alphanumeric1), many0(newline))(input)
}

// XXX some careful typedefs will clean this up
pub fn parse_cleartext_signature_parts(
    input: &str,
) -> IResult<&str, (Option<String>, String, (AsciiArmorKind, String, String))> {
    let parser = tuple((
        tag("-----BEGIN PGP SIGNED MESSAGE-----\n"),
        map(opt(parse_hash_armor_header), |o| o.map(String::from)),
        parse_possibly_dash_escaped_chunk,
        parse_ascii_armor_parts,
    ));

    let (_, (_, hash, msg, ascii_armor_parts)) = all_consuming(parser)(input)?;

    Ok(("", (hash, msg, ascii_armor_parts)))
}

// XXX refactor this to support more than just signatures
// XXX probably typedef (String, String)
fn parse_ascii_armor_parts(input: &str) -> IResult<&str, (AsciiArmorKind, String, String)> {
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

fn take_single_byte(input: &[u8]) -> IResult<&[u8], u8> {
    let (input, slice) = take(1_usize)(input)?;

    Ok((input, slice[0]))
}

// XXX rewrite this to consider new format packets maybe?
fn parse_signature_packet(input: &[u8]) -> IResult<&[u8], PgpPacket> {
    let (input, length_type): (&[u8], u8) = bits::<_, _, (_, _), _, _>(|input| {
        let (input, _): (_, usize) = take_bits(2_usize)(input)?;
        let (input, _packet_tag) = tag_bits(2, 4_usize)(input)?;
        let (input, length_type) = take_bits(2_usize)(input)?;

        Ok((input, length_type))
    })(input)?;

    let length = match length_type {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => u32::MAX,
        _ => panic!("unrecognized length_type"),
    };

    // XXX this needs to gracefully handle lengths of different types
    let (input, mut packet_length) = take(length)(input)?;
    let _packet_length = packet_length.read_u16::<BigEndian>().unwrap();

    let (input, version) = take_single_byte(input)?;
    let (input, signature_type) = take_single_byte(input)?;
    let (input, public_key_algorithm) = take_single_byte(input)?;
    let (input, hash_algorithm) = take_single_byte(input)?;

    // XXX these can be parsers themselves
    let (input, mut hashed_subpacket_length) = take(2_usize)(input)?;
    let hashed_subpacket_length = hashed_subpacket_length.read_u16::<BigEndian>().unwrap();
    let (input, hashed_subpacket_data) = take(hashed_subpacket_length)(input)?;

    // XXX these can be parsers themselves
    let (input, mut unhashed_subpacket_length) = take(2_usize)(input)?;
    let unhashed_subpacket_length = unhashed_subpacket_length.read_u16::<BigEndian>().unwrap();
    let (input, unhashed_subpacket_data) = take(unhashed_subpacket_length)(input)?;

    // XXX these can be parsers themselves
    let (input, mut signed_hash_value_head) = take(2_usize)(input)?;
    let signed_hash_value_head = signed_hash_value_head.read_u16::<BigEndian>().unwrap();

    let (input, signature) = many1(parse_mpi)(input)?;

    Ok((
        input,
        PgpPacket::SignaturePacket(SignaturePacket {
            version,
            signature_type,
            public_key_algorithm,
            hash_algorithm,
            //hashed_subpackets: Vec::new(),   // XXX
            //unhashed_subpackets: Vec::new(), // XXX
            hashed_subpacket_data: hashed_subpacket_data.to_owned(),
            unhashed_subpacket_data: unhashed_subpacket_data.to_owned(),
            signed_hash_value_head,
            signature,
        }),
    ))
}

fn parse_pgp_packet(input: &[u8]) -> IResult<&[u8], PgpPacket> {
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

    #[test]
    fn test_parse_possibly_dash_escaped_chunk() {
        let input = "- aa\n- bb\ncc\n- dd\n-a";
        let expected = "-a";
        assert_eq!(
            parse_possibly_dash_escaped_chunk(&input),
            Ok((expected, String::from("aa\nbb\ncc\ndd")))
        );
    }

    #[test]
    fn test_parse_possibly_dash_escaped_line() {
        let input = "- aa\nbb";
        let expected = "bb";
        assert_eq!(
            parse_possibly_dash_escaped_line(&input),
            Ok((expected, "aa\n"))
        );

        let input = "aa\nbb";
        let expected = "bb";
        assert_eq!(
            parse_possibly_dash_escaped_line(&input),
            Ok((expected, "aa\n"))
        );

        let input = "-aa\nbb";
        assert_eq!(
            parse_possibly_dash_escaped_line(&input),
            Err(nom::Err::Error(("-aa\nbb", nom::error::ErrorKind::Not)))
        );
    }

    #[test]
    fn test_parse_dash_escaped_line() {
        let input = "- aa\nbb";
        let expected = "bb";
        assert_eq!(parse_dash_escaped_line(&input), Ok((expected, "aa\n")));

        let input = "aa\nbb";
        assert_eq!(
            parse_dash_escaped_line(&input),
            Err(nom::Err::Error(("aa\nbb", nom::error::ErrorKind::Char)))
        );

        let input = "-aa\nbb";
        assert_eq!(
            parse_dash_escaped_line(&input),
            Err(nom::Err::Error(("aa\nbb", nom::error::ErrorKind::Char)))
        );
    }

    #[test]
    fn test_parse_non_dash_line() {
        let input = "aa\nbb";
        let expected = "bb";
        assert_eq!(parse_non_dash_line(&input), Ok((expected, "aa\n")));

        let input = "-aa\n";
        assert_eq!(
            parse_non_dash_line(&input),
            Err(nom::Err::Error(("-aa\n", nom::error::ErrorKind::Not)))
        );
    }

    #[test]
    fn test_parse_hash_armor_header() {
        let input = "Hash: aaaa\n";
        let expected = "";
        assert_eq!(parse_hash_armor_header(&input), Ok((expected, "aaaa")));
    }

    #[test]
    fn test_parse_cleartext_signature_parts() {
        let input = include_str!("../../tests/01/msg.txt.asc");
        let (_, (_hash, _msg, _ascii_armor)) = parse_cleartext_signature_parts(input).unwrap();
    }
}

use super::utils::fold_into_string;
use byteorder::{BigEndian, ReadBytesExt};
use nom::bits::bits;
use nom::bits::complete::{tag as tag_bits, take as take_bits};
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::bytes::complete::take;
use nom::combinator::all_consuming;
use nom::combinator::{map, not, opt, peek};
use nom::multi::many1;
use nom::sequence::tuple;
use nom::IResult;

use super::pgp_utils::{parse_ascii_armor_parts, parse_hash_armor_header, parse_mpi};
use super::utils::parse_line_newline_inclusive;
use super::utils::take_single_byte;
use super::utils::{parse_dash, parse_space};

use crate::pgp::signature::SignaturePacket;
use crate::pgp::{AsciiArmorKind, PgpPacket};

/// Parse a set of lines (that may be dash-escaped) into a String. Stops when reaching a line
/// that starts with a dash but is not dash-escaped.
pub fn parse_possibly_dash_escaped_chunk(input: &str) -> IResult<&str, String> {
    let (input, mut chunk) = fold_into_string(input, parse_possibly_dash_escaped_line)?;

    chunk.pop();

    Ok((input, chunk))
}

/// Parse a line of text that may be dash-escaped. If a line of text is not dash-escaped, but
/// begins with a '-', then fail.
pub fn parse_possibly_dash_escaped_line(input: &str) -> IResult<&str, &str> {
    alt((parse_dash_escaped_line, parse_non_dash_line))(input)
}

/// Parse a line of text that is dash-escaped. Takes a line that begins with '- ', otherwise fails.
pub fn parse_dash_escaped_line(input: &str) -> IResult<&str, &str> {
    let (input, _) = parse_dash(input)?;
    let (input, _) = parse_space(input)?;

    parse_line_newline_inclusive(input)
}

/// Parse a line of text that does not begin with a dash. Line may be the empty string.
pub fn parse_non_dash_line(input: &str) -> IResult<&str, &str> {
    peek(not(parse_dash))(input)?;

    // since peek did not error, we know the line does not begin with a dash.

    parse_line_newline_inclusive(input)
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

// XXX rewrite this to consider new format packets maybe?
pub fn parse_signature_packet(input: &[u8]) -> IResult<&[u8], PgpPacket> {
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

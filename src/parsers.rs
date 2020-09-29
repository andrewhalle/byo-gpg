use byteorder::{BigEndian, ReadBytesExt};
use nom::branch::alt;
use nom::bytes::complete::take;
use nom::bytes::complete::take_till;
use nom::bytes::complete::take_while;
use nom::bytes::complete::take_while_m_n;
use nom::character::complete::char;
use nom::character::complete::newline;
use nom::combinator::not;
use nom::combinator::peek;
use nom::multi::fold_many0;
use nom::IResult;
use num::BigUint;

const BASE64_LINE_LENGTH: usize = 64_usize;

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

/// Parse a chunk of base64 encoded text.
fn parse_base64(input: &str) -> IResult<&str, String> {
    let (input, mut base64) = fold_into_string(input, parse_base64_line)?;
    let (input, remaining) = take_while(is_base_64_digit)(input)?;
    let (input, _) = newline(input)?;

    base64.push_str(remaining);

    Ok((input, base64))
}

/// Parse a single line of length BASE64_LINE_LENGTH which contains only base64 characters.
fn parse_base64_line(input: &str) -> IResult<&str, &str> {
    let (input, res) =
        take_while_m_n(BASE64_LINE_LENGTH, BASE64_LINE_LENGTH, is_base_64_digit)(input)?;
    let (input, _) = newline(input)?;

    Ok((input, res))
}

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

fn is_base_64_digit(c: char) -> bool {
    (c >= '0' && c <= '9')
        || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z')
        || c == '+'
        || c == '/'
        || c == '='
}

fn is_newline(c: char) -> bool {
    c == '\n'
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
    fn test_parse_base64() {
        let input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaa\n";
        let expected = "";
        assert_eq!(
            parse_base64(&input),
            Ok((
                expected,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
            ))
        );
    }

    #[test]
    fn test_parse_base64_line() {
        let input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nbbb";
        let expected = "bbb";
        assert_eq!(
            parse_base64_line(&input),
            Ok((
                expected,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ))
        );
    }

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
}

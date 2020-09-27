use byteorder::{BigEndian, ReadBytesExt};
use nom::bytes::complete::take;
use nom::bytes::complete::take_while;
use nom::bytes::complete::take_while_m_n;
use nom::character::complete::newline;
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
    let (input, mut base64) = fold_many0(parse_base64_line, String::new(), |mut s, item| {
        s.push_str(item);
        s
    })(input)?;
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

fn is_base_64_digit(c: char) -> bool {
    (c >= '0' && c <= '9')
        || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z')
        || c == '+'
        || c == '/'
        || c == '='
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
}

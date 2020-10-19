use super::fold_into_string;
use nom::bytes::complete::take_while;
use nom::bytes::complete::take_while_m_n;
use nom::character::complete::newline;
use nom::IResult;

const BASE64_LINE_LENGTH: usize = 64_usize;

fn is_base64_digit(c: char) -> bool {
    (c >= '0' && c <= '9')
        || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z')
        || c == '+'
        || c == '/'
        || c == '='
}

/// Parse a chunk of base64 encoded text.
pub fn parse_base64(input: &str) -> IResult<&str, String> {
    let (input, mut base64) = fold_into_string(input, parse_base64_line)?;
    let (input, remaining) = take_while(is_base64_digit)(input)?;
    let (input, _) = newline(input)?;

    base64.push_str(remaining);

    Ok((input, base64))
}

/// Parse a single line of length BASE64_LINE_LENGTH which contains only base64 characters.
fn parse_base64_line(input: &str) -> IResult<&str, &str> {
    let (input, res) =
        take_while_m_n(BASE64_LINE_LENGTH, BASE64_LINE_LENGTH, is_base64_digit)(input)?;
    let (input, _) = newline(input)?;

    Ok((input, res))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_base64() {
        let input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
                     aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
                     aaa\n";
        let expected = "";
        assert_eq!(
            parse_base64(&input),
            Ok((
                expected,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                 aaa"
                .to_owned()
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

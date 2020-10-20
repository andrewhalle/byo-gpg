mod base64;
mod pgp_utils;
mod signature;
mod utils;

pub use pgp_utils::{parse_pgp_packets, parse_pkcs1};
pub use signature::parse_cleartext_signature_parts;

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

use byteorder::{BigEndian, ReadBytesExt};
use nom::bytes::complete::take;
use nom::bytes::complete::take_till;
use nom::character::complete::char;
use nom::character::complete::newline;
use nom::multi::fold_many0;
use nom::IResult;

/// Parse a single dash.
pub fn parse_dash(input: &str) -> IResult<&str, char> {
    char('-')(input)
}

/// Parse a single space.
pub fn parse_space(input: &str) -> IResult<&str, char> {
    char(' ')(input)
}

fn is_newline(c: char) -> bool {
    c == '\n'
}

pub fn take_single_byte(input: &[u8]) -> IResult<&[u8], u8> {
    let (input, slice) = take(1_usize)(input)?;

    Ok((input, slice[0]))
}

/// Runs a parser repeatedly, concatenating the results into a String.
pub fn fold_into_string<F: Fn(&str) -> IResult<&str, &str>>(
    input: &str,
    parser: F,
) -> IResult<&str, String> {
    fold_many0(parser, String::new(), |mut s, item| {
        s.push_str(item);
        s
    })(input)
}

pub fn parse_u16(input: &[u8]) -> IResult<&[u8], u16> {
    let (input, mut num) = take(2_usize)(input)?;
    let num = num.read_u16::<BigEndian>().unwrap();

    Ok((input, num))
}

/// Parse until a newline is encountered, but return a string slice that includes the newline.
pub fn parse_line_newline_inclusive(input: &str) -> IResult<&str, &str> {
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

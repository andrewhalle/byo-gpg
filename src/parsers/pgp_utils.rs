use byteorder::{BigEndian, ReadBytesExt};
use nom::bytes::complete::take;
use nom::IResult;
use num::BigUint;

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
}

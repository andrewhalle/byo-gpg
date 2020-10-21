use nom::IResult;

use crate::pgp::key::PublicKeyPacket;
use crate::pgp::PgpPacket;

pub fn parse_public_key_packet(_input: &[u8]) -> IResult<&[u8], PgpPacket> {
    Err(nom::Err::Error(("".as_bytes(), nom::error::ErrorKind::Eof)))
}

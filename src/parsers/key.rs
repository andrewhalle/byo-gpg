use nom::bytes::complete::take;
use nom::IResult;

use super::pgp_utils::parse_mpi;
use crate::pgp::key::PublicKeyPacket;
use crate::pgp::PgpPacket;

pub fn parse_public_key_packet(input: &[u8]) -> IResult<&[u8], PgpPacket> {
    // skips the unneeded fields
    //  - version (assumed to be 4)
    //  - time key was created
    //  - public-key algorithm (assumed to be RSA)
    let (input, _) = take(6_usize)(input)?;

    // get the needed fields from the key
    let (input, n) = parse_mpi(input)?;
    let (input, e) = parse_mpi(input)?;

    // skip the rest
    let (empty, _) = take(input.len())(input)?;

    Ok((empty, PgpPacket::PublicKeyPacket(PublicKeyPacket { n, e })))
}

pub fn parse_user_id_packet(input: &[u8]) -> IResult<&[u8], PgpPacket> {
    let (empty, _) = take(input.len())(input)?;
    Ok((empty, PgpPacket::UserIdPacket))
}

pub fn parse_public_subkey_packet(input: &[u8]) -> IResult<&[u8], PgpPacket> {
    let (empty, _) = take(input.len())(input)?;
    Ok((empty, PgpPacket::PublicSubkeyPacket))
}

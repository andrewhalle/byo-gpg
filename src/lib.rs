use anyhow::anyhow;

mod output;
mod parsers;
mod pgp;
mod primes;
mod rsa;

use output::{FromFile, ToFile, read_to_string_convert_newlines};
use pgp::signature::CleartextSignature;
use rsa::{Message, PrivateKey, PublicKey};

pub fn gen_pgp_key(private_key_path: &str, public_key_path: &str) -> anyhow::Result<()> {
    let (public_key, private_key) = rsa::gen_key();

    public_key.save_to_file(public_key_path).unwrap();
    private_key.save_to_file(private_key_path).unwrap();

    Ok(())
}

pub fn encrypt_pgp_message(
    source: &str,
    target: &str,
    public_key_path: &str,
) -> anyhow::Result<()> {
    let public_key = PublicKey::from_file(public_key_path).unwrap();

    let msg = read_to_string_convert_newlines(source).unwrap();
    let mut msg = Message::from_string(msg);
    msg.encrypt(&public_key);

    msg.save_to_file(target).unwrap();

    Ok(())
}

pub fn decrypt_pgp_message(source: &str, private_key_path: &str) -> anyhow::Result<()> {
    let private_key = PrivateKey::from_file(private_key_path).unwrap();

    let mut msg = Message::from_file(source).unwrap();
    msg.decrypt(&private_key);

    if let Message::Plaintext(msg) = msg {
        let msg = String::from_utf8(msg).unwrap();
        println!("{}", msg);
    }

    Ok(())
}

pub fn verify_cleartext_message(source: &str, public_key_path: &str) -> anyhow::Result<()> {
    let data = read_to_string_convert_newlines(source)?;
    let cleartext_signature = CleartextSignature::parse(&data)?;
    println!("File read. Checksum is valid.");

    let key = read_to_string_convert_newlines(public_key_path)?;
    let key = pgp::PublicKey::parse(&key)?;

    if cleartext_signature.verify(&key)? {
        println!("Signature is valid.");
    } else {
        return Err(anyhow!("Signature is invalid."));
    }

    Ok(())
}

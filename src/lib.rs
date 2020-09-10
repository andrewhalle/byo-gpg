use std::fs;

mod output;
mod primes;
mod rsa;

use output::{FromFile, ToFile};
use rsa::{Message, PrivateKey, PublicKey};

pub fn gen_pgp_key(private_key_path: &str, public_key_path: &str) {
    let (public_key, private_key) = rsa::gen_key();

    public_key.save_to_file(public_key_path).unwrap();
    private_key.save_to_file(private_key_path).unwrap();
}

pub fn encrypt_pgp_message(source: &str, target: &str, public_key_path: &str) {
    let public_key = PublicKey::from_file(public_key_path).unwrap();

    let msg = fs::read_to_string(source).unwrap();
    let mut msg = Message::from_string(msg);
    msg.encrypt(&public_key);

    msg.save_to_file(target).unwrap();
}

pub fn decrypt_pgp_message(source: &str, private_key_path: &str) {
    let private_key = PrivateKey::from_file(private_key_path).unwrap();

    let mut msg = Message::from_file(source).unwrap();
    msg.decrypt(&private_key);

    if let Message::Plaintext(msg) = msg {
        let msg = String::from_utf8(msg).unwrap();
        println!("{}", msg);
    }
}

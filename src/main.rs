use clap::clap_app;
use pgp_rs::{decrypt, encrypt, gen_key};

fn main() {
    let matches = clap_app!(("pgp-rs") =>
        (version: "0.1")
        (author: "Andrew Halle <ahalle@berkeley.edu>")
        (about: "PGP tool written in Rust.")
        (@subcommand ("gen-key") =>
            (about: "generate a new public/private key pair")
            (@arg privateKey: --privateKey +takes_value
                "Sets the private key output file. Defaults to 'privkey.json'.")
            (@arg publicKey: --publicKey +takes_value
                "Sets the public key output file. Defaults to 'pubkey.json'.")
        )
        (@subcommand ("encrypt") =>
            (about: "encrypt a message")
            (@arg source: -s --source +takes_value
                "Sets the source file to encrypt. Defaults to 'msg.txt'.")
            (@arg target: -t --target +takes_value
                "Sets the output filename. Defaults to 'encrypted.json'.")
            (@arg publicKey: --publicKey +takes_value
                "Sets the public key output file. Defaults to 'pubkey.json'.")
        )
        (@subcommand ("decrypt") =>
            (about: "decrypt a message")
            (@arg source: -s --source +takes_value
                "Sets the source file to decrypt. Defaults to 'encrypted.json'.")
            (@arg privateKey: --privateKey +takes_value
                "Sets the private key output file. Defaults to 'privkey.json'.")
        )
    )
    .get_matches();

    if let Some(matches) = matches.subcommand_matches("gen-key") {
        let private_key_path = matches.value_of("privateKey").unwrap_or("privkey.json");
        let public_key_path = matches.value_of("publicKey").unwrap_or("pubkey.json");

        gen_key(private_key_path, public_key_path);
    } else if let Some(matches) = matches.subcommand_matches("encrypt") {
        let source = matches.value_of("source").unwrap_or("msg.txt");
        let target = matches.value_of("target").unwrap_or("encrypted.json");
        let public_key_path = matches.value_of("publicKey").unwrap_or("pubkey.json");

        encrypt(source, target, public_key_path);
    } else if let Some(matches) = matches.subcommand_matches("decrypt") {
        let source = matches.value_of("source").unwrap_or("encrypted.json");
        let private_key_path = matches.value_of("privateKey").unwrap_or("privkey.json");

        decrypt(source, private_key_path);
    }
}

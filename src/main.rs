use clap::{clap_app, ArgMatches};

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
        (@subcommand ("t") =>
            (about: "INTERNAL trigger a test")
        )
    )
    .get_matches();

    if let Some(matches) = matches.subcommand_matches("gen-key") {
        gen_key(matches);
    } else if let Some(matches) = matches.subcommand_matches("encrypt") {
        encrypt(matches);
    } else if let Some(matches) = matches.subcommand_matches("decrypt") {
        decrypt(matches);
    } else if let Some(_matches) = matches.subcommand_matches("t") {
        // XXX
        let data = std::fs::read_to_string("msg.txt.asc").unwrap();
        dbg!(pgp_rs::CleartextSignature::parse_from(&data).unwrap());
    }
}

fn gen_key(matches: &ArgMatches) {
    let private_key_path = matches.value_of("privateKey").unwrap_or("privkey.json");
    let public_key_path = matches.value_of("publicKey").unwrap_or("pubkey.json");

    pgp_rs::gen_pgp_key(private_key_path, public_key_path);
}

fn encrypt(matches: &ArgMatches) {
    let source = matches.value_of("source").unwrap_or("msg.txt");
    let target = matches.value_of("target").unwrap_or("encrypted.json");
    let public_key_path = matches.value_of("publicKey").unwrap_or("pubkey.json");

    pgp_rs::encrypt_pgp_message(source, target, public_key_path);
}

fn decrypt(matches: &ArgMatches) {
    let source = matches.value_of("source").unwrap_or("encrypted.json");
    let private_key_path = matches.value_of("privateKey").unwrap_or("privkey.json");

    pgp_rs::decrypt_pgp_message(source, private_key_path);
}

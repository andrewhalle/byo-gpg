use clap::clap_app;
use pgp_rs::{decrypt, encrypt, gen_key};

fn main() {
    let matches = clap_app!(("pgp-rs") =>
        (version: "0.1")
        (author: "Andrew Halle <ahalle@berkeley.edu>")
        (about: "PGP tool written in Rust.")
        (@subcommand ("gen-key") =>
            (about: "generate a new public/private key pair")
        )
        (@subcommand ("encrypt") =>
            (about: "encrypt a message")
        )
        (@subcommand ("decrypt") =>
            (about: "decrypt a message")
        )
    )
    .get_matches();

    if matches.subcommand_matches("gen-key").is_some() {
        gen_key();
    } else if matches.subcommand_matches("encrypt").is_some() {
        encrypt();
    } else if matches.subcommand_matches("decrypt").is_some() {
        decrypt();
    }
}

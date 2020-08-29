use clap::clap_app;
use pgp_rs::gen_key;

fn main() {
    let matches = clap_app!(("pgp-rs") =>
        (version: "0.1")
        (author: "Andrew Halle <ahalle@berkeley.edu>")
        (about: "PGP tool written in Rust.")
        (@subcommand ("gen-key") =>
            (about: "generate a new public/private key pair")
        )
    )
    .get_matches();

    if let Some(_) = matches.subcommand_matches("gen-key") {
        gen_key();
    }
}

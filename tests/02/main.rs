use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn test_02() {
    Command::cargo_bin("pgp-rs")
        .unwrap()
        .arg("verify")
        .arg("-s")
        .arg("./tests/02/shakes3.txt.asc")
        .arg("--publicKey")
        .arg("./tests/02/public.key")
        .assert()
        .success();
}

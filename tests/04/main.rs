use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn test_04() {
    Command::cargo_bin("pgp-rs")
        .unwrap()
        .arg("verify")
        .arg("-s")
        .arg("./tests/04/shakes3.txt.asc")
        .assert()
        .success();
}

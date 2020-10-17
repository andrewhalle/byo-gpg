use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn test_03() {
    Command::cargo_bin("pgp-rs")
        .unwrap()
        .arg("verify")
        .arg("-s")
        .arg("./tests/03/shakes3.txt.asc")
        .assert()
        .success();
}

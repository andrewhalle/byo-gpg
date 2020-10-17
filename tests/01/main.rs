use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn test_01() {
    Command::cargo_bin("pgp-rs")
        .unwrap()
        .arg("verify")
        .arg("-s")
        .arg("./tests/01/msg.txt.asc")
        .assert()
        .success();
}

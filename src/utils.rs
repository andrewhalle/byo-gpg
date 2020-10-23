use regex::Regex;
use std::fs;

pub fn read_to_string_convert_newlines(filename: &str) -> anyhow::Result<String> {
    let re = Regex::new(r"\r\n")?;
    let data = fs::read_to_string(filename)?;

    Ok(re.replace_all(&data, "\n").to_owned().to_string())
}

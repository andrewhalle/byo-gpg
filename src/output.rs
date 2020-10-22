use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs;
use std::io::Result as IOResult;
use std::thread;
use std::time::Duration;
use termprogress::prelude::*;
use regex::Regex;

pub fn read_to_string_convert_newlines(filename: &str) -> anyhow::Result<String> {
    let re = Regex::new(r"\r\n")?;
    let data = fs::read_to_string(filename)?;

    Ok(re.replace_all(&data, "\n").to_owned().to_string())
}

pub trait ToFile: Serialize {
    fn save_to_file(&self, filename: &str) -> IOResult<()> {
        fs::write(filename, serde_json::to_string(self).unwrap())
    }
}

pub trait FromFile: Sized + DeserializeOwned {
    fn from_file(filename: &str) -> anyhow::Result<Self> {
        let data = read_to_string_convert_newlines(filename)?;

        Ok(serde_json::from_str(data.as_ref()).unwrap())
    }
}

pub fn do_task_with_progress<T, F: FnOnce() -> T>(task: F, estimated: f64, title: &str) -> T {
    let mut elapsed = 0.0;
    let mut progress = Bar::default();
    progress.set_title(title);

    let t = thread::spawn(move || {
        while elapsed < estimated {
            elapsed += 0.2;
            progress.set_progress(f64::min(1.0, elapsed / estimated));
            thread::sleep(Duration::from_millis(200));
        }
    });

    let result = task();
    t.join().unwrap();
    println!();

    result
}

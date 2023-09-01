use std::fs::File;
use std::io::prelude::*;
use crate::commands::error::CryptoError;

pub fn output(bytes: &[u8], output_path: &Option<String>) {
    match output_path {
        Some(out_path) => {
            let mut file = File::create(out_path).unwrap();
            let _ = file.write(bytes);
            },
            None => {
                println!("{:?}", bytes);
            }
        }
    }

pub fn read_file(in_path: &String) -> Result<Vec<u8>, CryptoError> {
    let mut file = match File::open(in_path) {
        Ok(f) => f,
        Err(err) => return Err(CryptoError::Io(err)),
    };
    let mut contents = vec![];
    match file.read_to_end(&mut contents) {
        Ok(f) => f,
        Err(err) => return Err(CryptoError::Io(err)),
    };
    Ok(contents)
}
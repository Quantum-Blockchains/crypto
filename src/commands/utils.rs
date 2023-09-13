use crate::commands::arg_enums::Format;
use crate::commands::arg_enums::Format::Pem;
use crate::commands::error::CryptoError;
use std::fs::File;
use std::io::prelude::*;
use std::str::from_utf8;

pub fn output(bytes: &[u8], output_path: &Option<String>, format: Format) {
    match output_path {
        Some(out_path) => {
            let mut file = File::create(out_path).unwrap();
            let _ = file.write(bytes);
        }
        None => {
            if format == Pem {
                let str = from_utf8(bytes).unwrap();
                println!("{}", str);
            } else {
                println!("{:?}", bytes);
            }
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

use std::fs::File;
use std::io::prelude::*;
use base64;
use crate::commands::error::CryptoError;

pub fn output(key: &[u8], output_path: &Option<String>, name: String) {
        let encoded_key = base64::encode(key);
        let parts_key =
            encoded_key.chars()
            .collect::<Vec<char>>()
            .chunks(80)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<String>>();

        match output_path {
            Some(out_path) => {
                let mut file = File::create(out_path).unwrap();
                file.write_all((&encoded_key).as_ref()).unwrap();
            },
            None => {
                let mut ch = "".to_string();
                let mut start: String = "START ".to_string();
                start.push_str(&name);
                let count_start = 80 - start.len();
                let mut end: String = "END ".to_string();
                end.push_str(&name);
                let count_end = 80 - end.len();
                for _i in 0..count_start/2 {
                    ch.push('-');
                    start.push('-');
                }
                ch.push_str(&start);
                start = ch.clone();
                ch.clear();
                for _i in 0..count_end/2 {
                    ch.push('-');
                    end.push('-');
                }
                ch.push_str(&end);
                println!("{}", start);
                for i in 0..parts_key.len() {
                    println!("{}", format!("{}", parts_key[i]));
                }
                println!("{}", ch);
            }
        }
    }

pub fn read_file(in_path: &String) -> Result<Vec<u8>, CryptoError> {
     let mut file = match File::open(in_path) {
            Ok(f) => f,
            Err(err) => return Err(CryptoError::Io(err)),
        };
        let mut contents = String::new();
        match file.read_to_string(&mut contents) {
            Ok(f) => f,
            Err(err) => return Err(CryptoError::Io(err)),
        };
        Ok(base64::decode(contents).unwrap())
}
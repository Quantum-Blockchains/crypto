use std::fs::File;
use std::io::prelude::*;
use base64;

pub fn output(key: &[u8], output_path: &Option<String>) {
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
                println!("------------------------------------START--------------------------------------");
                for i in 0..parts_key.len() {
                    println!("{}", format!("{}", parts_key[i]));
                }
                println!("-----------------------------------END-----------------------------------------");
            }
        }
    }

pub fn read_file(in_path: &String) -> Vec<u8> {
     let mut file = match File::open(in_path) {
            Ok(f) => f,
            Err(err) => panic!("Error: {:?}", err),
        };
        let mut contents = String::new();
        match file.read_to_string(&mut contents) {
            Ok(f) => f,
            Err(err) => panic!("Error: {:?}", err),
        };
        base64::decode(contents).unwrap()
}
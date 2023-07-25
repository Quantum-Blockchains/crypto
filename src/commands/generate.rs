use crystals_dilithium::{dilithium2, dilithium3, dilithium5};
use rand::*;
use std::str::FromStr;
use clap::Parser;
use super::utils;


#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Algorithm {
    Dilithium2,
    Dilithium3,
    Dilithium5
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "dilithium2" => Ok(Algorithm::Dilithium2),
            "dil2" => Ok(Algorithm::Dilithium2),
            "dilithium3" => Ok(Algorithm::Dilithium3),
            "dil3" => Ok(Algorithm::Dilithium3),
            "dilithium5" => Ok(Algorithm::Dilithium5),
            "dil5" => Ok(Algorithm::Dilithium5),
            _ => panic!("ERROR ERROR"),
        }
    }
}

#[derive(Debug, Clone, Parser)]
pub struct GenerateCmd {
    #[clap(short = 'a', long="alg")]
    pub algorithm: Algorithm,
    #[clap(short = 'o', long="out")]
    pub output_path: Option<String>,
}

impl GenerateCmd {
    pub fn run(&self) {
        let mut seed = [0u8; 32];
        thread_rng().fill_bytes(&mut seed[..]);
        match self.algorithm {
            Algorithm::Dilithium2 => {
                let keypair = dilithium2::Keypair::generate(Some(&seed));
                utils::output(&keypair.to_bytes(), &self.output_path);
            }
            Algorithm::Dilithium3 => {
                let keypair = dilithium3::Keypair::generate(Some(&seed));
                utils::output(&keypair.to_bytes(), &self.output_path);
            }
            Algorithm::Dilithium5 => {
                let keypair = dilithium5::Keypair::generate(Some(&seed));
                utils::output(&keypair.to_bytes(), &self.output_path);
            }
        };
    }
}
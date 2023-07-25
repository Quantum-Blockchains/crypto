use clap::Parser;
use crystals_dilithium::{dilithium2, dilithium3, dilithium5};
use super::utils;

#[derive(Debug, Clone, Parser)]
pub struct VerifyCmd {
    #[clap(short = 'm', long)]
    message: String,
    #[clap(long="pub")]
    pub_path: String,
    #[clap(long="sig")]
    sig_path: String,
}

impl VerifyCmd {
    pub fn run(&self) {

        let pub_bytes = utils::read_file(&self.pub_path);
        let sig_bytes = utils::read_file(&self.sig_path);

        let ver = match sig_bytes.len() {
            dilithium2::SIGNBYTES => {
                if pub_bytes.len() != dilithium2::PUBLICKEYBYTES {
                    panic!("ERROR length public key.");
                }
                let public = dilithium2::PublicKey::from_bytes(&pub_bytes);
                public.verify(&self.message.as_bytes(), &sig_bytes)
            }
            dilithium3::SIGNBYTES => {
                if pub_bytes.len() != dilithium3::PUBLICKEYBYTES {
                    panic!("ERROR length public key.");
                }
                let public = dilithium3::PublicKey::from_bytes(&pub_bytes);
                public.verify(&self.message.as_bytes(), &sig_bytes)
            }
            dilithium5::SIGNBYTES => {
                if pub_bytes.len() != dilithium5::PUBLICKEYBYTES {
                    panic!("ERROR length public key.");
                }
                let public = dilithium5::PublicKey::from_bytes(&pub_bytes);
                public.verify(&self.message.as_bytes(), &sig_bytes)
            }
            _ => {
                panic!("ERROR length signature.");
            }
        };
        println!("Verification: {:?}", ver);
    }
}

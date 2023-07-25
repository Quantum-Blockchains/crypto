use super::utils;
use clap::Parser;
use crystals_dilithium::{dilithium2, dilithium3, dilithium5};

#[derive(Debug, Clone, Parser)]
pub struct PublicCmd {
    #[clap(short = 'i', long = "in")]
    pub in_path: String,
    #[clap(short = 'o', long = "out")]
    pub out_path: Option<String>,
}

impl PublicCmd {
    pub fn run(&self) {

        let bytes = utils::read_file(&self.in_path);

        match bytes.len() {
            dilithium2::KEYPAIRBYTES => {
                let keypair = dilithium2::Keypair::from_bytes(&bytes);
                utils::output(&keypair.public.bytes, &self.out_path);
            }
            dilithium3::KEYPAIRBYTES => {
                let keypair = dilithium3::Keypair::from_bytes(&bytes);
                utils::output(&keypair.public.bytes, &self.out_path);
            }
            dilithium5::KEYPAIRBYTES => {
                let keypair = dilithium5::Keypair::from_bytes(&bytes);
                utils::output(&keypair.public.bytes, &self.out_path);
            }
            _ => {
                panic!("ERROR length keypair.");
            }
        }
    }
}

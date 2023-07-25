use clap::Parser;
use crystals_dilithium::{dilithium2, dilithium3, dilithium5};
use super::utils;

#[derive(Debug, Clone, Parser)]
pub struct SignCmd {
    #[clap(short = 'm', long)]
    message: String,
    #[clap(short = 'i', long)]
    in_path: String,
    #[clap(short = 'o', long)]
    out_path: Option<String>,
}

impl SignCmd {
    pub fn run(&self) {

        let bytes = utils::read_file(&self.in_path);

        match bytes.len() {
            dilithium2::KEYPAIRBYTES => {
                let keypair = dilithium2::Keypair::from_bytes(&bytes);
                let signature = keypair.sign(&self.message.as_bytes());
                let sig_bytes = signature.as_slice();
                utils::output(&sig_bytes, &self.out_path);
            }
            dilithium3::KEYPAIRBYTES => {
                let keypair = dilithium3::Keypair::from_bytes(&bytes);
                let signature = keypair.sign(&self.message.as_bytes());
                let sig_bytes = signature.as_slice();
                utils::output(&sig_bytes, &self.out_path);
            }
            dilithium5::KEYPAIRBYTES => {
                let keypair = dilithium5::Keypair::from_bytes(&bytes);
                let signature = keypair.sign(&self.message.as_bytes());
                let sig_bytes = signature.as_slice();
                utils::output(&sig_bytes, &self.out_path);
            }
            _ => {
                panic!("ERROR length keypair.");
            }
        }
    }
}

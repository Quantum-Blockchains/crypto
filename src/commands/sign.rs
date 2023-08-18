use clap::Parser;
use crystals_dilithium::{dilithium2, dilithium3, dilithium5};
use super::{utils, error::CryptoError};

#[derive(Debug, Clone, Parser)]
#[clap(name = "sign", about = "Sign the message")]
pub struct SignCmd {
    ///A message that will be signed
    #[clap(short = 'm', long)]
    message: String,
    ///The secret key that will be used to sign the message
    #[clap(long="sec")]
    in_path: String,
    ///Path for writing the signature to the file
    #[clap(long="out")]
    out_path: Option<String>,
}

impl SignCmd {
    pub fn run(&self) -> Result<(), CryptoError>{
        let bytes = utils::read_file(&self.in_path)?;
        match bytes.len() {
            dilithium2::SECRETKEYBYTES => {
                let keypair = dilithium2::SecretKey::from_bytes(&bytes);
                let signature = keypair.sign(&self.message.as_bytes());
                let sig_bytes = signature.as_slice();
                utils::output(&sig_bytes, &self.out_path, "SIGNATURE".to_string());
            }
            dilithium3::SECRETKEYBYTES => {
                let keypair = dilithium3::SecretKey::from_bytes(&bytes);
                let signature = keypair.sign(&self.message.as_bytes());
                let sig_bytes = signature.as_slice();
                utils::output(&sig_bytes, &self.out_path, "SIGNATURE".to_string());
            }
            dilithium5::SECRETKEYBYTES => {
                let keypair = dilithium5::SecretKey::from_bytes(&bytes);
                let signature = keypair.sign(&self.message.as_bytes());
                let sig_bytes = signature.as_slice();
                utils::output(&sig_bytes, &self.out_path, "SIGNATURE".to_string());
            }
            _ => {
                return Err(CryptoError::InvalidLengthSecretKey(bytes.len()))
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::path::Path;
    use crate::commands::GenerateCmd;
    use super::*;

    #[tokio::test]
    async fn sign_message() {
        let test_sec_file = "sec_test";
        let test_pub_file = "pub_test";
        let generate = GenerateCmd::parse_from(&[
            "generate",
            "--algorithm",
            "dil5",
            "--sec",
            test_sec_file,
            "--pub",
            test_pub_file,
        ]);

        let sign = SignCmd::parse_from(&[
            "sign",
            "-m",
            "test message",
            "--sec",
            test_sec_file,
        ]);

        assert!(generate.run().await.is_ok());
        assert!(sign.run().is_ok());
        fs::remove_file(test_sec_file).unwrap();
        fs::remove_file(test_pub_file).unwrap();
    }

     #[tokio::test]
    async fn sign_message_and_write_signature_to_file() {
        let test_sec_file = "sec_test_1";
        let test_pub_file = "pub_test_1";
         let test_sig_file = "sig_test_1";
        let generate = GenerateCmd::parse_from(&[
            "generate",
            "--algorithm",
            "dil5",
            "--sec",
            test_sec_file,
            "--pub",
            test_pub_file,
        ]);

        let sign = SignCmd::parse_from(&[
            "sign",
            "-m",
            "test message",
            "--sec",
            test_sec_file,
            "--out",
            test_sig_file,
        ]);

        assert!(generate.run().await.is_ok());
        assert!(sign.run().is_ok());
         let path_sig = Path::new(test_sig_file);
         if path_sig.exists() {
            fs::remove_file(test_sig_file).unwrap();
            assert!(true);
        } else {
            assert!(false);
        }
        fs::remove_file(test_pub_file).unwrap();
        fs::remove_file(test_sec_file).unwrap();

    }
}

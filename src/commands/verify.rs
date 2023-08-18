use clap::Parser;
use crystals_dilithium::{dilithium2, dilithium3, dilithium5};
use crate::commands::error::CryptoError;
use super::utils;

#[derive(Debug, Clone, Parser)]
#[clap(name = "verify", about = "Message verification")]
pub struct VerifyCmd {
    ///A message to be verified
    #[clap(short = 'm', long)]
    message: String,
    ///The public key that will be used to verify the message
    #[clap(long="pub")]
    pub_path: String,
    ///The signature that will be used to verify the message
    #[clap(long="sig")]
    sig_path: String,
}

impl VerifyCmd {
    pub fn run(&self) -> Result<(), CryptoError> {
        let pub_bytes = utils::read_file(&self.pub_path)?;
        let sig_bytes = utils::read_file(&self.sig_path)?;
        let ver = match sig_bytes.len() {
            dilithium2::SIGNBYTES => {
                if pub_bytes.len() != dilithium2::PUBLICKEYBYTES {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        dilithium2::PUBLICKEYBYTES,
                        dilithium2::SIGNBYTES,
                    )))
                }
                let public = dilithium2::PublicKey::from_bytes(&pub_bytes);
                public.verify(&self.message.as_bytes(), &sig_bytes)
            }
            dilithium3::SIGNBYTES => {
                if pub_bytes.len() != dilithium3::PUBLICKEYBYTES {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        dilithium2::PUBLICKEYBYTES,
                        dilithium2::SIGNBYTES,
                    )))
                }
                let public = dilithium3::PublicKey::from_bytes(&pub_bytes);
                public.verify(&self.message.as_bytes(), &sig_bytes)
            }
            dilithium5::SIGNBYTES => {
                if pub_bytes.len() != dilithium5::PUBLICKEYBYTES {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        dilithium2::PUBLICKEYBYTES,
                        dilithium2::SIGNBYTES,
                    )))
                }
                let public = dilithium5::PublicKey::from_bytes(&pub_bytes);
                public.verify(&self.message.as_bytes(), &sig_bytes)
            }
            _ => {
                return Err(CryptoError::InvalidLengthSignature(sig_bytes.len()))
            }
        };
        println!("Verification: {:?}", ver);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use crystals_dilithium::sign::lvl2::verify;
    use crate::commands::{GenerateCmd, SignCmd};
    use crate::Subkey::Verify;
    use super::*;

    #[tokio::test]
    async fn verify_message() {
        let test_sec_file = "sec_test";
        let test_pub_file = "pub_test";
         let test_sig_file = "sig_test";
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

        let verify = VerifyCmd::parse_from(&[
            "verify",
            "-m",
            "test message",
            "--sig",
            test_sig_file,
            "--pub",
            test_pub_file,
        ]);

        assert!(generate.run().await.is_ok());
        assert!(sign.run().is_ok());
        assert!(verify.run().is_ok());

        fs::remove_file(test_pub_file).unwrap();
        fs::remove_file(test_sec_file).unwrap();
        fs::remove_file(test_sig_file).unwrap();
    }
}

use std::{fs::File, io::Read};

use clap::Parser;
use crystals_dilithium::{dilithium2, dilithium3, dilithium5};
use der::{asn1::OctetString, Decode, DecodePem};
use super::{utils, error::CryptoError, arg_enums::Format, asc1_dilithium::{OneAsymmetricKeyBorrowed, OneAsymmetricKeyOwned, OID_DILITHIUM2, OID_DILITHIUM3, OID_DILITHIUM5}};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Parser)]
#[clap(name = "sign", about = "Sign the message")]
pub struct SignCmd {
    // ///A message that will be signed
    // #[clap(short = 'm', long)]
    // message: String,
    ///Input format (DER or PEM)
    #[clap(long = "inform", value_name = "PEM|DER", default_value = "PEM")]
    pub inform: Format,
    ///The secret key that will be used to sign the message
    #[clap(long="sec")]
    in_path: String,
    ///Path for writing the signature to the file
    #[clap(long="out")]
    out_path: Option<String>,
    ///Path for writing the signature to the file
    #[clap(long="file")]
    file_path: String,
}

impl SignCmd {
    pub fn run(&self) -> Result<(), CryptoError>{
        let bytes = utils::read_file(&self.in_path)?;

        let key: OctetString;
        let algorithm: String;
        if self.inform == Format::DER {
            let one_asymmetric_key = OneAsymmetricKeyBorrowed::from_der(&bytes).unwrap();
            algorithm = one_asymmetric_key.private_key_algorithm.algorithm.to_string();
            key = OctetString::from_der(one_asymmetric_key.private_key).unwrap(); 
        } else {
            let one_asymmetric_key = OneAsymmetricKeyOwned::from_pem(&bytes).unwrap();
            algorithm = one_asymmetric_key.private_key_algorithm.algorithm.to_string();
            key = OctetString::from_der(one_asymmetric_key.private_key.as_bytes()).unwrap();
        }

        let bytes_keypair = key.as_bytes();

        let algorithm_str: &str = &algorithm;

        let mut file = File::open(&self.file_path)?;

        let mut hasher = Sha256::new();
        let mut buffer = [0; 4096];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let message_hash = hasher.finalize();
        // println!("SHA256: {:?}", message_hash);
        
        match algorithm_str {
            OID_DILITHIUM2 => {
                let keypair = dilithium2::Keypair::from_bytes(bytes_keypair);
                let signature = keypair.sign(&message_hash);
                let sig_bytes = signature.as_slice();
                utils::output(&sig_bytes, &self.out_path);
            }
            OID_DILITHIUM3 => {
                let keypair = dilithium3::SecretKey::from_bytes(&bytes);
                let signature = keypair.sign(&message_hash);
                let sig_bytes = signature.as_slice();
                utils::output(&sig_bytes, &self.out_path);
            }
            OID_DILITHIUM5 => {
                let keypair = dilithium5::SecretKey::from_bytes(&bytes);
                let signature = keypair.sign(&message_hash);
                let sig_bytes = signature.as_slice();
                utils::output(&sig_bytes, &self.out_path);
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

    #[test]
    fn sign_message() {
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

        assert!(generate.run().is_ok());
        assert!(sign.run().is_ok());
        fs::remove_file(test_sec_file).unwrap();
        fs::remove_file(test_pub_file).unwrap();
    }

     #[test]
    fn sign_message_and_write_signature_to_file() {
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

        assert!(generate.run().is_ok());
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

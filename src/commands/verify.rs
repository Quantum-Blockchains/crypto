use super::{arg_enums::Format, utils};
use crate::commands::{
    asc1_dilithium::{
        SubjectPublicKeyInfoBorrowed, SubjectPublicKeyInfoOwned, OID_DILITHIUM2, OID_DILITHIUM3,
        OID_DILITHIUM5,
    },
    error::CryptoError,
};
use clap::Parser;
use crystals_dilithium::{dilithium2, dilithium3, dilithium5};
use der::{asn1::BitString, Decode, DecodePem};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read};

#[derive(Debug, Clone, Parser)]
#[clap(name = "verify", about = "Signature verification")]
pub struct VerifyCmd {
    ///Input format (DER or PEM)
    #[clap(long = "inform", value_name = "PEM|DER", default_value = "PEM")]
    pub inform: Format,
    ///Input public key
    #[clap(long = "pub", value_name = "FILE")]
    pub pub_path: String,
    ///Input signature
    #[clap(long = "sig", value_name = "FILE")]
    pub sig_path: String,
    ///Input file for verification
    #[clap(long = "file", value_name = "FILE")]
    pub file_path: String,
}

impl VerifyCmd {
    pub fn run(&self) -> Result<(), CryptoError> {
        let bytes = utils::read_file(&self.pub_path)?;
        let sig_bytes = utils::read_file(&self.sig_path)?;

        let key: BitString;
        let algorithm: String;
        if self.inform == Format::Der {
            let public_key = SubjectPublicKeyInfoBorrowed::from_der(&bytes).unwrap();
            algorithm = public_key.algorithm.algorithm.to_string();
            key = BitString::from_der(public_key.subject_public_key).unwrap();
        } else {
            let public_key = SubjectPublicKeyInfoOwned::from_pem(&bytes).unwrap();
            algorithm = public_key.algorithm.algorithm.to_string();
            key = public_key.subject_public_key;
        }

        let bytes_public_key = key.as_bytes().unwrap();

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

        let ver = match algorithm_str {
            OID_DILITHIUM2 => {
                if bytes_public_key.len() != dilithium2::PUBLICKEYBYTES {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        dilithium2::PUBLICKEYBYTES,
                        dilithium2::SIGNBYTES,
                    )));
                }
                let public = dilithium2::PublicKey::from_bytes(bytes_public_key);
                public.verify(&message_hash, &sig_bytes)
            }
            OID_DILITHIUM3 => {
                if bytes_public_key.len() != dilithium3::PUBLICKEYBYTES {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        dilithium2::PUBLICKEYBYTES,
                        dilithium2::SIGNBYTES,
                    )));
                }
                let public = dilithium3::PublicKey::from_bytes(bytes_public_key);
                public.verify(&message_hash, &sig_bytes)
            }
            OID_DILITHIUM5 => {
                if bytes_public_key.len() != dilithium5::PUBLICKEYBYTES {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        dilithium2::PUBLICKEYBYTES,
                        dilithium2::SIGNBYTES,
                    )));
                }
                let public = dilithium5::PublicKey::from_bytes(bytes_public_key);
                public.verify(&message_hash, &sig_bytes)
            }
            _ => return Err(CryptoError::InvalidLengthSignature(sig_bytes.len())),
        };
        println!("Verification: {:?}", ver);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::commands::{GenerateCmd, PublicCmd, SignCmd};
    use std::fs;

    #[test]
    fn verify_message() {
        let test_sec_file = "sec_test";
        let test_pub_file = "pub_test";
        let test_sig_file = "sig_test";
        let generate =
            GenerateCmd::parse_from(&["generate", "--algorithm", "dil2", "--out", test_sec_file]);

        let public =
            PublicCmd::parse_from(&["public", "--in", test_sec_file, "--out", test_pub_file]);

        let sign = SignCmd::parse_from(&[
            "sign",
            "--sec",
            test_sec_file,
            "--out",
            test_sig_file,
            "--file",
            test_pub_file,
        ]);

        let verify = VerifyCmd::parse_from(&[
            "verify",
            "--sig",
            test_sig_file,
            "--pub",
            test_pub_file,
            "--file",
            test_pub_file,
        ]);

        assert!(generate.run().is_ok());
        assert!(public.run().is_ok());
        assert!(sign.run().is_ok());
        assert!(verify.run().is_ok());

        fs::remove_file(test_pub_file).unwrap();
        fs::remove_file(test_sec_file).unwrap();
        fs::remove_file(test_sig_file).unwrap();
    }
}

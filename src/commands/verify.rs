use super::{arg_enums::Format, utils};
use crate::commands::{
    asc1_dilithium::{
        SubjectPublicKeyInfoBorrowed, SubjectPublicKeyInfoOwned, OID_DILITHIUM2, OID_DILITHIUM3,
        OID_DILITHIUM5, OID_MLDSA44, OID_MLDSA65, OID_MLDSA87,
    },
    error::CryptoError,
};
use clap::Parser;
use crystals_dilithium::{dilithium2, dilithium3, dilithium5, ml_dsa_44, ml_dsa_65, ml_dsa_87};
use der::{asn1::BitString, Decode, DecodePem};
// use sha2::{Digest, Sha256};
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

        // let mut hasher = Sha256::new();
        // let mut buffer = [0; 4096];

        // loop {
        //     let bytes_read = file.read(&mut buffer)?;
        //     if bytes_read == 0 {
        //         break;
        //     }
        //     hasher.update(&buffer[..bytes_read]);
        // }

        // let message_hash = hasher.finalize();

        let mut message = Vec::new();
        file.read_to_end(&mut message)?;

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
                public.verify(&message, &sig_bytes)
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
                public.verify(&message, &sig_bytes)
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
                public.verify(&message, &sig_bytes)
            }
            OID_MLDSA44 => {
                if bytes_public_key.len() != ml_dsa_44::PUBLICKEYBYTES {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        ml_dsa_44::PUBLICKEYBYTES,
                        ml_dsa_44::SIGNBYTES,
                    )));
                }
                let public = ml_dsa_44::PublicKey::from_bytes(bytes_public_key);
                public.verify(&message, &sig_bytes, None)
            }
            OID_MLDSA65 => {
                if bytes_public_key.len() != ml_dsa_65::PUBLICKEYBYTES {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        ml_dsa_65::PUBLICKEYBYTES,
                        ml_dsa_65::SIGNBYTES,
                    )));
                }
                let public = ml_dsa_65::PublicKey::from_bytes(bytes_public_key);
                public.verify(&message, &sig_bytes, None)
            }
            OID_MLDSA87 => {
                if bytes_public_key.len() != ml_dsa_87::PUBLICKEYBYTES {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        ml_dsa_87::PUBLICKEYBYTES,
                        ml_dsa_87::SIGNBYTES,
                    )));
                }
                let public = ml_dsa_87::PublicKey::from_bytes(bytes_public_key);
                public.verify(&message, &sig_bytes, None)
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

    fn cleanup(files: &[String]) {
        for f in files {
            let _ = fs::remove_file(f);
        }
    }

    fn run_case(alg: &str, sec_format: &str, pub_format: &str) {
        let tag = format!("{}_{}_{}", alg, sec_format, pub_format).to_lowercase();
        let sec_file = format!("ver_sec_test_{}", tag);
        let pub_file = format!("ver_pub_test_{}", tag);
        let sig_file = format!("ver_sig_test_{}", tag);

        let generate = GenerateCmd::parse_from(&[
            "generate",
            "--algorithm",
            alg,
            "--out",
            &sec_file,
            "--outform",
            sec_format,
        ]);

        let public = PublicCmd::parse_from(&[
            "public",
            "--in",
            &sec_file,
            "--inform",
            sec_format,
            "--out",
            &pub_file,
            "--outform",
            pub_format,
        ]);

        let sign = SignCmd::parse_from(&[
            "sign",
            "--sec",
            &sec_file,
            "--inform",
            sec_format,
            "--out",
            &sig_file,
            "--file",
            &pub_file,
        ]);

        let verify = VerifyCmd::parse_from(&[
            "verify",
            "--sig",
            &sig_file,
            "--pub",
            &pub_file,
            "--inform",
            pub_format,
            "--file",
            &pub_file,
        ]);

        assert!(generate.run().is_ok());
        assert!(public.run().is_ok());
        assert!(sign.run().is_ok());
        assert!(verify.run().is_ok());

        cleanup(&vec![sec_file, pub_file, sig_file]);
    }

    #[test]
    fn verify_all_algorithms_all_formats() {
        let algorithms = ["dil2", "dil3", "dil5", "mldsa44", "mldsa65", "mldsa87"];
        let formats = ["PEM"];

        for alg in algorithms {
            for sec_format in formats {
                for pub_format in formats {
                    run_case(alg, sec_format, pub_format);
                }
            }
        }
    }
}

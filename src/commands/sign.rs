use super::{
    arg_enums::Format,
    asc1_dilithium::{
        OneAsymmetricKeyBorrowed, OneAsymmetricKeyOwned, OID_DILITHIUM2, OID_DILITHIUM3,
        OID_DILITHIUM5, OID_MLDSA44, OID_MLDSA65, OID_MLDSA87,
    },
    error::CryptoError,
    utils,
};
use crate::commands::arg_enums::Format::Der;
use clap::Parser;
use crystals_dilithium::{dilithium2, dilithium3, dilithium5, ml_dsa_44, ml_dsa_65, ml_dsa_87};
use der::{asn1::OctetString, Decode, DecodePem};
// use sha2::{Digest, Sha256};
use std::{fs::File, io::Read};

#[derive(Debug, Clone, Parser)]
#[clap(name = "sign", about = "Sign the file")]
pub struct SignCmd {
    ///Input format (DER or PEM)
    #[clap(long = "inform", value_name = "PEM|DER", default_value = "PEM")]
    pub inform: Format,
    ///Input private key
    #[clap(long = "sec", value_name = "FILE")]
    in_path: String,
    ///Output file
    #[clap(long = "out", value_name = "FILE")]
    out_path: Option<String>,
    ///Input file for signing
    #[clap(long = "file", value_name = "FILE")]
    file_path: String,
}

impl SignCmd {
    pub fn run(&self) -> Result<(), CryptoError> {
        let bytes = utils::read_file(&self.in_path)?;

        let key: OctetString;
        let algorithm: String;
        if self.inform == Format::Der {
            let one_asymmetric_key = OneAsymmetricKeyBorrowed::from_der(&bytes).unwrap();
            algorithm = one_asymmetric_key
                .private_key_algorithm
                .algorithm
                .to_string();
            key = OctetString::from_der(one_asymmetric_key.private_key).unwrap();
        } else {
            let one_asymmetric_key = OneAsymmetricKeyOwned::from_pem(&bytes).unwrap();
            algorithm = one_asymmetric_key
                .private_key_algorithm
                .algorithm
                .to_string();
            key = OctetString::from_der(one_asymmetric_key.private_key.as_bytes()).unwrap();
        }

        let bytes_keypair = key.as_bytes();

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

        match algorithm_str {
            OID_DILITHIUM2 => {
                let keypair = dilithium2::Keypair::from_bytes(bytes_keypair);
                let signature = keypair.sign(&message);
                let sig_bytes = signature.as_slice();
                utils::output(sig_bytes, &self.out_path, Der);
            }
            OID_DILITHIUM3 => {
                let keypair = dilithium3::Keypair::from_bytes(bytes_keypair);
                let signature = keypair.sign(&message);
                let sig_bytes = signature.as_slice();
                utils::output(sig_bytes, &self.out_path, Der);
            }
            OID_DILITHIUM5 => {
                let keypair = dilithium5::Keypair::from_bytes(bytes_keypair);
                let signature = keypair.sign(&message);
                let sig_bytes = signature.as_slice();
                utils::output(sig_bytes, &self.out_path, Der);
            }
            OID_MLDSA44 => {
                let keypair = ml_dsa_44::Keypair::from_bytes(bytes_keypair);
                let signature = keypair.sign(&message, None, false).unwrap();
                let sig_bytes = signature.as_slice();
                utils::output(sig_bytes, &self.out_path, Der);
            }
            OID_MLDSA65 => {
                let keypair = ml_dsa_65::Keypair::from_bytes(bytes_keypair);
                let signature = keypair.sign(&message, None, false).unwrap();
                let sig_bytes = signature.as_slice();
                utils::output(sig_bytes, &self.out_path, Der);
            }
            OID_MLDSA87 => {
                let keypair = ml_dsa_87::Keypair::from_bytes(bytes_keypair);
                let signature = keypair.sign(&message, None, false).unwrap();
                let sig_bytes = signature.as_slice();
                utils::output(sig_bytes, &self.out_path, Der);
            }
            _ => return Err(CryptoError::InvalidLengthSecretKey(bytes.len())),
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::commands::{GenerateCmd, PublicCmd};
    use std::fs;

    fn cleanup(files: &[String]) {
        for f in files {
            let _ = fs::remove_file(f);
        }
    }

    fn run_case(alg: &str, sec_format: &str, pub_format: &str) {
        let tag = format!("{}_{}_{}", alg, sec_format, pub_format).to_lowercase();
        let sec_file = format!("sign_sec_test_{}", tag);
        let pub_file = format!("sign_pub_test_{}", tag);
        let sig_file = format!("sign_sig_test_{}", tag);

        let generate = GenerateCmd::parse_from([
            "generate",
            "--algorithm",
            alg,
            "--out",
            &sec_file,
            "--outform",
            sec_format,
        ]);

        let public = PublicCmd::parse_from([
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

        let sign = SignCmd::parse_from([
            "sign", "--sec", &sec_file, "--inform", sec_format, "--out", &sig_file, "--file",
            &pub_file,
        ]);

        assert!(generate.run().is_ok());
        assert!(public.run().is_ok());
        assert!(sign.run().is_ok());
        assert!(std::path::Path::new(&sig_file).exists());

        cleanup(&[sec_file, pub_file, sig_file]);
    }

    #[test]
    fn sign_all_algorithms_all_formats() {
        let algorithms = ["dil2", "dil3", "dil5", "mldsa44", "mldsa65", "mldsa87"];
        let formats = ["PEM", "DER"];

        for alg in algorithms {
            for sec_format in formats {
                for pub_format in formats {
                    run_case(alg, sec_format, pub_format);
                }
            }
        }
    }

    #[test]
    fn sign_with_missing_secret_key_returns_io_error() {
        let sign = SignCmd::parse_from([
            "sign",
            "--sec",
            "missing_secret_key.pem",
            "--file",
            "missing_input_file.bin",
        ]);

        assert!(matches!(sign.run(), Err(CryptoError::Io(_))));
    }
}

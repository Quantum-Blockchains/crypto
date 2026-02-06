use super::{
    arg_enums::{Algorithm, Format},
    asc1_dilithium::{
        AlgorithmIdentifier, OneAsymmetricKeyBorrowed, OID_DILITHIUM2, OID_DILITHIUM3,
        OID_DILITHIUM5,
    },
    error::CryptoError,
    utils,
};
use crate::commands::{arg_enums::Format::{Der, Pem}, asc1_dilithium::{OID_MLDSA44, OID_MLDSA65, OID_MLDSA87}};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use crystals_dilithium::{dilithium2, dilithium3, dilithium5, ml_dsa_44, ml_dsa_65, ml_dsa_87};
use der::{pem::LineEnding, Encode, EncodePem};
use rand::*;

#[derive(Debug, Clone, Parser)]
#[clap(name = "generate", about = "Generate key pair")]
pub struct GenerateCmd {
    ///Algorithm for key pair generation (dilithium2 or dil2, dilithium3 or dil3, dilithium5 or dil5)
    #[clap(short = 'a', long = "algorithm")]
    pub algorithm: Algorithm,
    ///Output format (DER or PEM)
    #[clap(long = "outform", value_name = "PEM|DER", default_value = "PEM")]
    pub outform: Format,
    ///Output file
    #[clap(long = "out", value_name = "FILE")]
    pub secret_output_path: Option<String>,
    ///Entropy for key pair generation
    #[clap(long = "entropy", value_name = "ENTROPY")]
    pub entropy: Option<String>,
}

impl GenerateCmd {
    pub fn run(&self) -> Result<(), CryptoError> {
        let mut seed = [0u8; 32];
        if self.entropy.is_none() {
            thread_rng().fill_bytes(&mut seed[..]);
        } else {
            let d = &self.entropy;
            let q = d.clone().unwrap();
            let r = match general_purpose::STANDARD.decode(q) {
                Ok(b) => b,
                Err(err) => return Err(CryptoError::RequestQrngError(err.to_string())),
            };
            seed[..r.len()].copy_from_slice(&r[..]);
        }
        let mut vector_bytes_private_key: Vec<u8> = Vec::new();
        vector_bytes_private_key.push(0x04);
        vector_bytes_private_key.push(0x82);
        match self.algorithm {
            Algorithm::Dilithium2 => {
                let algorithm_identifier = AlgorithmIdentifier {
                    algorithm: OID_DILITHIUM2.parse().unwrap(),
                };
                let keypair = dilithium2::Keypair::generate(Some(&seed));
                let mut bytes_keypair = keypair.to_bytes().to_vec();

                vector_bytes_private_key.push(0x0F);
                vector_bytes_private_key.push(0x00);
                vector_bytes_private_key.append(&mut bytes_keypair);

                let der_private_key: OneAsymmetricKeyBorrowed = OneAsymmetricKeyBorrowed {
                    version: 0,
                    private_key_algorithm: algorithm_identifier,
                    private_key: &vector_bytes_private_key,
                };

                if self.outform == Format::Der {
                    let der = der_private_key.to_der().unwrap();
                    utils::output(&der, &self.secret_output_path, Der);
                } else {
                    let pem = der_private_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.secret_output_path, Pem);
                }
            }
            Algorithm::Dilithium3 => {
                let algorithm_identifier = AlgorithmIdentifier {
                    algorithm: OID_DILITHIUM3.parse().unwrap(),
                };
                let keypair = dilithium3::Keypair::generate(Some(&seed));
                let mut bytes_keypair = keypair.to_bytes().to_vec();

                vector_bytes_private_key.push(0x17);
                vector_bytes_private_key.push(0x40);
                vector_bytes_private_key.append(&mut bytes_keypair);

                let der_private_key: OneAsymmetricKeyBorrowed = OneAsymmetricKeyBorrowed {
                    version: 0,
                    private_key_algorithm: algorithm_identifier,
                    private_key: &vector_bytes_private_key,
                };

                if self.outform == Format::Der {
                    let der = der_private_key.to_der().unwrap();
                    utils::output(&der, &self.secret_output_path, Der);
                } else {
                    let pem = der_private_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.secret_output_path, Pem);
                }
            }
            Algorithm::Dilithium5 => {
                let algorithm_identifier = AlgorithmIdentifier {
                    algorithm: OID_DILITHIUM5.parse().unwrap(),
                };
                let keypair = dilithium5::Keypair::generate(Some(&seed));
                let mut bytes_keypair = keypair.to_bytes().to_vec();

                vector_bytes_private_key.push(0x1D);
                vector_bytes_private_key.push(0x20);
                vector_bytes_private_key.append(&mut bytes_keypair);

                let der_private_key: OneAsymmetricKeyBorrowed = OneAsymmetricKeyBorrowed {
                    version: 0,
                    private_key_algorithm: algorithm_identifier,
                    private_key: &vector_bytes_private_key,
                };

                if self.outform == Format::Der {
                    let der = der_private_key.to_der().unwrap();
                    utils::output(&der, &self.secret_output_path, Der);
                } else {
                    let pem = der_private_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.secret_output_path, Pem);
                }
            }
            Algorithm::Mldsa44 => {
                let algorithm_identifier = AlgorithmIdentifier {
                    algorithm: OID_MLDSA44.parse().unwrap(),
                };
                let keypair = ml_dsa_44::Keypair::generate(Some(&seed));
                let mut bytes_keypair = keypair.to_bytes().to_vec();

                vector_bytes_private_key.push(0x0F);
                vector_bytes_private_key.push(0x20);
                vector_bytes_private_key.append(&mut bytes_keypair);

                let der_private_key: OneAsymmetricKeyBorrowed = OneAsymmetricKeyBorrowed {
                    version: 0,
                    private_key_algorithm: algorithm_identifier,
                    private_key: &vector_bytes_private_key,
                };

                if self.outform == Format::Der {
                    let der = der_private_key.to_der().unwrap();
                    utils::output(&der, &self.secret_output_path, Der);
                } else {
                    let pem = der_private_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.secret_output_path, Pem);
                }
            }
            Algorithm::Mldsa65 => {
                let algorithm_identifier = AlgorithmIdentifier {
                    algorithm: OID_MLDSA65.parse().unwrap(),
                };
                let keypair = ml_dsa_65::Keypair::generate(Some(&seed));
                let mut bytes_keypair = keypair.to_bytes().to_vec();

                vector_bytes_private_key.push(0x17);
                vector_bytes_private_key.push(0x60);
                vector_bytes_private_key.append(&mut bytes_keypair);

                let der_private_key: OneAsymmetricKeyBorrowed = OneAsymmetricKeyBorrowed {
                    version: 0,
                    private_key_algorithm: algorithm_identifier,
                    private_key: &vector_bytes_private_key,
                };

                if self.outform == Format::Der {
                    let der = der_private_key.to_der().unwrap();
                    utils::output(&der, &self.secret_output_path, Der);
                } else {
                    let pem = der_private_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.secret_output_path, Pem);
                }
            }
            Algorithm::Mldsa87 => {
                let algorithm_identifier = AlgorithmIdentifier {
                    algorithm: OID_MLDSA87.parse().unwrap(),
                };
                let keypair = ml_dsa_87::Keypair::generate(Some(&seed));
                let mut bytes_keypair = keypair.to_bytes().to_vec();

                vector_bytes_private_key.push(0x1D);
                vector_bytes_private_key.push(0x40);
                vector_bytes_private_key.append(&mut bytes_keypair);

                let der_private_key: OneAsymmetricKeyBorrowed = OneAsymmetricKeyBorrowed {
                    version: 0,
                    private_key_algorithm: algorithm_identifier,
                    private_key: &vector_bytes_private_key,
                };

                if self.outform == Format::Der {
                    let der = der_private_key.to_der().unwrap();
                    utils::output(&der, &self.secret_output_path, Der);
                } else {
                    let pem = der_private_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.secret_output_path, Pem);
                }
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn cleanup(files: &[String]) {
        for f in files {
            let _ = fs::remove_file(f);
        }
    }

    fn run_case(alg: &str, out_format: &str) {
        let tag = format!("{}_{}", alg, out_format).to_lowercase();
        let out_file = format!(".out_test_{}", tag);

        let generate = GenerateCmd::parse_from(&[
            "generate",
            "--algorithm",
            alg,
            "--out",
            &out_file,
            "--outform",
            out_format,
        ]);

        assert!(generate.run().is_ok());
        assert!(std::path::Path::new(&out_file).exists());

        cleanup(&vec![out_file]);
    }

    #[test]
    fn generate_all_algorithms_all_formats() {
        let algorithms = ["dil2", "dil3", "dil5", "mldsa44", "mldsa65", "mldsa87"];
        let formats = ["PEM", "DER"];

        for alg in algorithms {
            for out_format in formats {
                run_case(alg, out_format);
            }
        }
    }
}

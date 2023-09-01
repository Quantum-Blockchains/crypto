use base64::{Engine as _, engine::general_purpose};
use crystals_dilithium::{dilithium2, dilithium3, dilithium5};
use rand::*;
use clap::Parser;
use super::{
    utils,
    error::CryptoError,
    arg_enums::{Algorithm, Format},
    asc1_dilithium::{AlgorithmIdentifier, OneAsymmetricKeyBorrowed,
        OID_DILITHIUM2, OID_DILITHIUM3, OID_DILITHIUM5}
};
use der::{ Encode, pem::LineEnding, EncodePem };

#[derive(Debug, Clone, Parser)]
#[clap(name = "generate", about = "Generate key pair")]
pub struct GenerateCmd {
    ///Algorithm for key pair generation (dilithium2 or dil2, dilithium3 or dil3, dilithium5 or dil5)
    #[clap(short = 'a', long="algorithm")]
    pub algorithm: Algorithm,
    ///Output format (DER or PEM)
    #[clap(long = "outform", value_name = "PEM|DER", default_value = "PEM")]
    pub outform: Format,
    ///Path for writing the secret key to the file
    #[clap(long="out", value_name = "FILE")]
    pub secret_output_path: Option<String>,
    // ///Path for writing the public key to the file
    // #[clap(long="pub", value_name = "FILE")]
    // pub public_output_path: Option<String>,
    ///URL to get entropy from QRNG for key pair generation
    #[clap(long="entropy", value_name = "ENTROPY")]
    pub entropy: Option<String>,
}

impl GenerateCmd {
    pub fn run(&self) -> Result<(), CryptoError> {
        let mut seed = [0u8; 32];
        if self.entropy.is_none() {
            thread_rng().fill_bytes(&mut seed[..]);
        }
        else {
            let d = &self.entropy;
            let q = d.clone().unwrap();
            let r =  match general_purpose::STANDARD.decode(q){
                Ok(b) => b,
                Err(err) => {
                    return Err(CryptoError::RequestQrngError(err.to_string()))
                }
            };
            for i in 0..r.len() {
                seed[i] = r[i];
            }
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
                

                if self.outform == Format::DER {
                    let der = der_private_key.to_der().unwrap();
                    utils::output(&der, &self.secret_output_path);
                } else {
                    let pem = der_private_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.secret_output_path);
                }
                
                // let keypair = dilithium2::Keypair::generate(Some(&seed));
                // let secret = keypair.secret.bytes;
                // let public = keypair.public.bytes;
                // utils::output(&secret, &self.secret_output_path, "SECRET KEY".to_string());
                // utils::output(&public, &self.public_output_path, "PUBLIC KEY".to_string());
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
                

                if self.outform == Format::DER {
                    let der = der_private_key.to_der().unwrap();
                    utils::output(&der, &self.secret_output_path);
                } else {
                    let pem = der_private_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.secret_output_path);
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
                

                if self.outform == Format::DER {
                    let der = der_private_key.to_der().unwrap();
                    utils::output(&der, &self.secret_output_path);
                } else {
                    let pem = der_private_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.secret_output_path);
                }
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::fs;
    use super::*;

    #[test]
    fn generate_dilithium2() {
        let generate = GenerateCmd::parse_from(&[
            "generate",
            "-a",
            "dil2"
        ]);
        assert!(generate.run().is_ok())
    }

    #[test]
    fn generate_dilithium3() {
        let generate = GenerateCmd::parse_from(&[
            "generate",
            "-a",
            "dil3"
        ]);
        assert!(generate.run().is_ok())
    }

    #[test]
    fn generate_dilithium5() {
        let generate = GenerateCmd::parse_from(&[
            "generate",
            "-a",
            "dil5"
        ]);
        assert!(generate.run().is_ok())
    }

    #[test]
    fn generate_dilithium2_and_write_keys_to_files() {
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
        assert!(generate.run().is_ok());
        let path_sec = Path::new(test_sec_file);
        let path_pub = Path::new(test_pub_file);
        if path_sec.exists() {
            fs::remove_file(test_sec_file).unwrap();
            assert!(true);
        } else {
            assert!(false);
        }
        if path_pub.exists() {
            fs::remove_file(test_pub_file).unwrap();
            assert!(true);
        } else {
            assert!(false);
        }
    }

    // #[test]
    // fn generate_keypair_with_entropy_from_qrng() {

    //     let server = MockServer::start();
    //     let url = server.base_url();

    //     let generate = GenerateCmd::parse_from(&[
    //         "generate",
    //         "-a",
    //         "dil5",
    //         "--qrng",
    //         &url,
    //     ]);

    //     let expected_response_qrng = QRNGResponseData { result :"RMbXrsa+UNk0/VPn9spdeDQhaecX4GX0HB3PIWMrIrE=".to_string()};

    //     let _qrng_mock = server.mock(|when, then| {
    //        when.method(GET)
    //            .path("/qrng/base64");
    //        then.status(200)
    //            .header("content-type", "text/json")
    //            .json_body(json!(expected_response_qrng));
    //     });
    //     assert!(generate.run().is_ok())
    // }
}
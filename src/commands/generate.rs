use crystals_dilithium::{dilithium2, dilithium3, dilithium5};
use rand::*;
use std::str::FromStr;
use clap::Parser;
use super::{utils, error::CryptoError};
use serde::{Deserialize, Serialize};


#[derive(Deserialize, Serialize)]
struct QRNGResponseData {
    result: String,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Algorithm {
    Dilithium2,
    Dilithium3,
    Dilithium5
}

impl FromStr for Algorithm {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, CryptoError> {
        match s.to_ascii_lowercase().as_str() {
            "dilithium2" => Ok(Algorithm::Dilithium2),
            "dil2" => Ok(Algorithm::Dilithium2),
            "dilithium3" => Ok(Algorithm::Dilithium3),
            "dil3" => Ok(Algorithm::Dilithium3),
            "dilithium5" => Ok(Algorithm::Dilithium5),
            "dil5" => Ok(Algorithm::Dilithium5),
            _ => return Err(CryptoError::InvalidAlgorithm(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Parser)]
#[clap(name = "generate", about = "Generate key pair")]
pub struct GenerateCmd {
    ///Algorithm for key pair generation (dilithium2 or dil2, dilithium3 or dil3, dilithium5 or dil5)
    #[clap(short = 'a', long="algorithm")]
    pub algorithm: Algorithm,
    ///Path for writing the secret key to the file
    #[clap(long="sec", value_name = "FILE")]
    pub secret_output_path: Option<String>,
    ///Path for writing the public key to the file
    #[clap(long="pub", value_name = "FILE")]
    pub public_output_path: Option<String>,
    ///URL to get entropy from QRNG for key pair generation
    #[clap(long="qrng", value_name = "URL")]
    pub url_qrng: Option<String>,
}

impl GenerateCmd {
    pub async fn run(&self) -> Result<(), CryptoError> {
        let mut seed = [0u8; 32];
        if self.url_qrng.is_none() {
            thread_rng().fill_bytes(&mut seed[..]);
        }
        else {
            let url = self.url_qrng.clone().unwrap() + "/qrng/base64?size=32";
            let body =  match reqwest::get(url).await {
                Ok(res) => res,
                Err(err) => {
                    return Err(CryptoError::RequestQrngError(err.to_string()))
                }
            };
            let text = match body.text().await {
                Ok(t) =>  t,
                Err(err) => {
                    return Err(CryptoError::RequestQrngError(err.to_string()))
                }
            };
            let qrng_response: QRNGResponseData = match serde_json::from_str(&text){
                Ok(t) => t,
                Err(err) => {
                    return Err(CryptoError::RequestQrngError(err.to_string()))
                }
            };
            let r =  match base64::decode(qrng_response.result){
                Ok(b) => b,
                Err(err) => {
                    return Err(CryptoError::RequestQrngError(err.to_string()))
                }
            };
            for i in 0..r.len() {
                seed[i] = r[i];
            }
        }
        match self.algorithm {
            Algorithm::Dilithium2 => {
                let keypair = dilithium2::Keypair::generate(Some(&seed));
                let secret = keypair.secret.bytes;
                let public = keypair.public.bytes;
                utils::output(&secret, &self.secret_output_path, "SECRET KEY".to_string());
                utils::output(&public, &self.public_output_path, "PUBLIC KEY".to_string());
            }
            Algorithm::Dilithium3 => {
                let keypair = dilithium3::Keypair::generate(Some(&seed));
                let secret = keypair.secret.bytes;
                let public = keypair.public.bytes;
                utils::output(&secret, &self.secret_output_path, "SECRET KEY".to_string());
                utils::output(&public, &self.public_output_path, "PUBLIC KEY".to_string());
            }
            Algorithm::Dilithium5 => {
                let keypair = dilithium5::Keypair::generate(Some(&seed));
                let secret = keypair.secret.bytes;
                let public = keypair.public.bytes;
                utils::output(&secret, &self.secret_output_path, "SECRET KEY".to_string());
                utils::output(&public, &self.public_output_path, "PUBLIC KEY".to_string());
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use httpmock::prelude::*;
    use serde_json::json;
    use std::fs;
    use super::*;

    #[tokio::test]
    async fn generate_dilithium2() {
        let generate = GenerateCmd::parse_from(&[
            "generate",
            "-a",
            "dil2"
        ]);
        assert!(generate.run().await.is_ok())
    }

    #[tokio::test]
    async fn generate_dilithium3() {
        let generate = GenerateCmd::parse_from(&[
            "generate",
            "-a",
            "dil3"
        ]);
        assert!(generate.run().await.is_ok())
    }

    #[tokio::test]
    async fn generate_dilithium5() {
        let generate = GenerateCmd::parse_from(&[
            "generate",
            "-a",
            "dil5"
        ]);
        assert!(generate.run().await.is_ok())
    }

    #[tokio::test]
    async fn generate_dilithium2_and_write_keys_to_files() {
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
        assert!(generate.run().await.is_ok());
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

    #[tokio::test]
    async fn generate_keypair_with_entropy_from_qrng() {

        let server = MockServer::start();
        let url = server.base_url();

        let generate = GenerateCmd::parse_from(&[
            "generate",
            "-a",
            "dil5",
            "--qrng",
            &url,
        ]);

        let expected_response_qrng = QRNGResponseData { result :"RMbXrsa+UNk0/VPn9spdeDQhaecX4GX0HB3PIWMrIrE=".to_string()};

        let _qrng_mock = server.mock(|when, then| {
           when.method(GET)
               .path("/qrng/base64");
           then.status(200)
               .header("content-type", "text/json")
               .json_body(json!(expected_response_qrng));
        });
        assert!(generate.run().await.is_ok())
    }
}
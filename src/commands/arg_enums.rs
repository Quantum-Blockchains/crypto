use std::str::FromStr;
use super::error::CryptoError;

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

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Format {
    PEM,
    DER
}

impl FromStr for Format {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, CryptoError> {
        match s {
            "PEM" => Ok(Format::PEM),
            "DER" => Ok(Format::DER),
            _ => return Err(CryptoError::InvalidFormat(s.to_string())),
        }
    }
}
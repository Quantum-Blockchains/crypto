use der::{
    asn1::{ObjectIdentifier, OctetString, BitString},
    pem::PemLabel,
    Sequence, ValueOrd
};

pub const OID_DILITHIUM2: &str = "1.3.6.1.4.1.2.267.7.4.4";
pub const OID_DILITHIUM3: &str = "1.3.6.1.4.1.2.267.7.6.5";
pub const OID_DILITHIUM5: &str = "1.3.6.1.4.1.2.267.7.8.7";

/// X.509 `AlgorithmIdentifier`
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
}

/// X.509 `SubjectPublicKeyInfo` (SPKI)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct SubjectPublicKeyInfoBorrowed<'a> {
    pub algorithm: AlgorithmIdentifier,
    #[asn1(type = "BIT STRING")]
    pub subject_public_key: &'a [u8],
}

impl PemLabel for SubjectPublicKeyInfoBorrowed<'_> {
    const PEM_LABEL: &'static str = "PUBLIC KEY";
}

/// X.509 `SubjectPublicKeyInfo` (SPKI)
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct SubjectPublicKeyInfoOwned {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
}

impl PemLabel for SubjectPublicKeyInfoOwned {
    const PEM_LABEL: &'static str = "PUBLIC KEY";
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OneAsymmetricKeyBorrowed<'a> {
    pub version: u8,
    pub private_key_algorithm: AlgorithmIdentifier,
    #[asn1(type = "OCTET STRING")]
    pub private_key: &'a [u8],
}

impl PemLabel for OneAsymmetricKeyBorrowed<'_> {
    const PEM_LABEL: &'static str = "PRIVATE KEY";
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OneAsymmetricKeyOwned {
    pub version: u8,
    pub private_key_algorithm: AlgorithmIdentifier,
    pub private_key: OctetString,
}

impl PemLabel for OneAsymmetricKeyOwned {
    const PEM_LABEL: &'static str = "PRIVATE KEY";
}

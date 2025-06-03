use rcgen::{
    CertificateParams, CertificateSigningRequestParams, PublicKey, PublicKeyData,
    SubjectPublicKeyInfo,
};

use crate::grpc::proto::sign_certificate_request::Csr;

#[derive(Debug, thiserror::Error)]
pub enum ParseCsrError {
    #[error("failed to parse X.509 CSR")]
    X509,
    #[error("invalid SubjectPublicKeyInfo")]
    Spki,
}

pub fn parse_csr(
    csr: Csr,
) -> Result<(Option<CertificateParams>, impl PublicKeyData), ParseCsrError> {
    match csr {
        Csr::Der(der) => CertificateSigningRequestParams::from_der(&der.into())
            .map_err(|_| ParseCsrError::X509)
            .map(|CertificateSigningRequestParams { params, public_key }| {
                (Some(params), CsrPublicKey::PublicKey(public_key))
            }),
        Csr::Spki(pem) => SubjectPublicKeyInfo::from_pem(&pem)
            .map_err(|_| ParseCsrError::Spki)
            .map(|spki| (None, CsrPublicKey::SubjectPublicKeyInfo(spki))),
    }
}

enum CsrPublicKey {
    PublicKey(PublicKey),
    SubjectPublicKeyInfo(SubjectPublicKeyInfo),
}

impl PublicKeyData for CsrPublicKey {
    fn der_bytes(&self) -> &[u8] {
        match self {
            CsrPublicKey::PublicKey(pk) => PublicKeyData::der_bytes(pk),
            CsrPublicKey::SubjectPublicKeyInfo(spki) => PublicKeyData::der_bytes(spki),
        }
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            CsrPublicKey::PublicKey(pk) => PublicKeyData::algorithm(pk),
            CsrPublicKey::SubjectPublicKeyInfo(spki) => PublicKeyData::algorithm(spki),
        }
    }
}

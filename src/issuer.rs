use std::{fmt, str::FromStr};

use rcgen::{CertificateParams, KeyPair, SerialNumber};
use rustls_pki_types::PrivatePkcs8KeyDer;
use secrecy::ExposeSecret;
use serde_with::DeserializeFromStr;
use sqlx::{SqliteExecutor, types::Json};
use tonic::Status;
use tracing::error;

use crate::{
    key::AeadSssContainer,
    util::{ParseHexError, parse_colon_separated_hex, write_colon_separated_hex},
};

#[derive(Debug, Clone, Copy, sqlx::Type)]
#[sqlx(transparent)]
pub struct CertSerial(i64);

impl CertSerial {
    pub fn random() -> Self {
        Self(rand::random())
    }
}

impl fmt::Display for CertSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_colon_separated_hex(&self.0.to_be_bytes(), f)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("failed to parse serial number: {0}")]
pub struct ParseSerialError(#[from] ParseHexError);

impl FromStr for CertSerial {
    type Err = ParseSerialError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut buf = [0u8; 8];
        parse_colon_separated_hex(s, &mut buf)?;
        Ok(Self(i64::from_be_bytes(buf)))
    }
}

impl From<CertSerial> for SerialNumber {
    fn from(serial: CertSerial) -> Self {
        SerialNumber::from_slice(&serial.0.to_be_bytes())
    }
}

#[derive(Debug, Clone, DeserializeFromStr, sqlx::Type)]
#[sqlx(transparent)]
pub struct IssuerIdentifier(String);

#[derive(Debug, thiserror::Error)]
pub enum IssuerIdentifierError {
    #[error("issuer identifier cannot be empty")]
    Empty,
    #[error("issuer identifier must be alphanumeric")]
    Alphanumeric,
}

impl FromStr for IssuerIdentifier {
    type Err = IssuerIdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(IssuerIdentifierError::Empty);
        }

        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(IssuerIdentifierError::Alphanumeric);
        }

        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for IssuerIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

pub async fn insert_cert(
    conn: impl SqliteExecutor<'_>,
    issuer: &IssuerIdentifier,
    serial_number: CertSerial,
    der: &[u8],
) -> sqlx::Result<()> {
    sqlx::query!(
        "INSERT INTO certificates (issuer, serial_number, der) VALUES ($1, $2, $3)",
        issuer,
        serial_number,
        der,
    )
    .execute(conn)
    .await?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum GetIssuerKeyError {
    #[error("db error")]
    Db(#[from] sqlx::Error),
    #[error("issuer not found")]
    IssuerNotFound,
    #[error("failed to parse certificate")]
    InvalidCertificate,
    #[error("invalid secret share")]
    InvalidSecretShare,
}

impl From<GetIssuerKeyError> for Status {
    fn from(err: GetIssuerKeyError) -> Self {
        match err {
            GetIssuerKeyError::Db(_) => Status::internal("database error"),
            GetIssuerKeyError::IssuerNotFound => Status::not_found("issuer not found"),
            GetIssuerKeyError::InvalidCertificate => {
                Status::invalid_argument("invalid certificate")
            }
            GetIssuerKeyError::InvalidSecretShare => {
                Status::invalid_argument("invalid secret share")
            }
        }
    }
}

pub async fn get_issuer_aead_container(
    conn: impl SqliteExecutor<'_>,
    issuer: &IssuerIdentifier,
) -> Result<Option<AeadSssContainer>, sqlx::Error> {
    let record = sqlx::query!(
        r#"
        SELECT private_key as "private_key: Json<AeadSssContainer>"
        FROM issuers
        WHERE identifier = $1
    "#,
        issuer
    )
    .fetch_optional(conn)
    .await?;

    Ok(record.map(|r| r.private_key.0))
}

pub async fn get_issuer_key(
    conn: impl SqliteExecutor<'_>,
    issuer: &IssuerIdentifier,
    final_secret_share: String,
) -> Result<(CertificateParams, KeyPair), GetIssuerKeyError> {
    let record = sqlx::query!(
        r#"SELECT cert, private_key AS "private_key: Json<AeadSssContainer>" FROM issuers WHERE identifier = $1"#,
        issuer
    )
    .fetch_optional(conn)
    .await?
    .ok_or(GetIssuerKeyError::IssuerNotFound)?;

    let params = CertificateParams::from_ca_cert_pem(&record.cert)
        .map_err(|_| GetIssuerKeyError::InvalidCertificate)?;

    let private_key = record
        .private_key
        .decrypt(final_secret_share)
        .map_err(|_| GetIssuerKeyError::InvalidSecretShare)?;
    let private_key = PrivatePkcs8KeyDer::from(private_key.expose_secret());

    let key_pair = KeyPair::try_from(&private_key).map_err(|_| {
        error!("failed to parse decrypted PKCS#8 key");
        GetIssuerKeyError::InvalidSecretShare
    })?;

    Ok((params, key_pair))
}

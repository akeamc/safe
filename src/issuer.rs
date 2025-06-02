use std::{fmt, str::FromStr};

use rcgen::{
    CertificateParams, CertificateRevocationListParams, KeyIdMethod, KeyPair, RevocationReason,
    RevokedCertParams, SerialNumber, SigningKey,
};
use rustls_pki_types::PrivatePkcs8KeyDer;
use secrecy::ExposeSecret;
use sqlx::{SqliteExecutor, SqliteTransaction, types::Json};
use time::OffsetDateTime;
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

/// Create parameters for a CRL, using the provided issued certificates and update times.
/// The `this_update` parameter will be used to derive the crl number, and must therefore
/// be monotonic.
pub fn create_crl_params(
    revoked_certs: Vec<RevokedCertParams>,
    this_update: OffsetDateTime,
    next_update: OffsetDateTime,
    crl_number: Option<SerialNumber>,
) -> CertificateRevocationListParams {
    use rcgen::CertificateRevocationListParams;

    let crl_number = crl_number.unwrap_or_else(|| {
        SerialNumber::from_slice(&(this_update.unix_timestamp_nanos() / 1_000_000).to_be_bytes())
    });

    CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number,
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    }
}

pub async fn insert_cert(
    conn: impl SqliteExecutor<'_>,
    issuer: &str,
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
    issuer: &str,
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
    issuer: &str,
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

pub async fn revoke_cert(
    conn: impl SqliteExecutor<'_>,
    serial_number: CertSerial,
    issuer: &str,
    revocation_time: OffsetDateTime,
    revocation_code: RevocationReason,
    invalidity_date: Option<OffsetDateTime>,
) -> Result<(), sqlx::Error> {
    let revocation_code = revocation_code as i32;

    sqlx::query!(
        r#"
        UPDATE certificates SET
            revocation_time = $1,
            revocation_code = $2,
            invalidity_date = $3
        WHERE issuer = $4 AND serial_number = $5
        "#,
        revocation_time,
        revocation_code,
        invalidity_date,
        issuer,
        serial_number,
    )
    .execute(conn)
    .await?;

    Ok(())
}

fn parse_revocation_code(code: Option<i64>) -> Option<RevocationReason> {
    Some(match code? {
        0 => RevocationReason::Unspecified,
        1 => RevocationReason::KeyCompromise,
        2 => RevocationReason::CaCompromise,
        3 => RevocationReason::AffiliationChanged,
        4 => RevocationReason::Superseded,
        5 => RevocationReason::CessationOfOperation,
        6 => RevocationReason::CertificateHold,
        8 => RevocationReason::RemoveFromCrl,
        9 => RevocationReason::PrivilegeWithdrawn,
        10 => RevocationReason::AaCompromise,
        _ => return None,
    })
}

async fn list_revoked_certs(
    conn: impl SqliteExecutor<'_>,
    issuer: &str,
) -> Result<Vec<RevokedCertParams>, sqlx::Error> {
    let records = sqlx::query!(
        r#"
        SELECT
            serial_number,
            revocation_time as "revocation_time: OffsetDateTime",
            revocation_code,
            invalidity_date as "invalidity_date: OffsetDateTime"
        FROM certificates
        WHERE issuer = $1 AND revocation_time IS NOT NULL
        "#,
        issuer
    )
    .fetch_all(conn)
    .await?;

    let revoked_certs = records
        .into_iter()
        .map(|record| RevokedCertParams {
            serial_number: SerialNumber::from_slice(&record.serial_number.to_be_bytes()),
            revocation_time: record.revocation_time.unwrap(),
            reason_code: parse_revocation_code(record.revocation_code),
            invalidity_date: record.invalidity_date,
        })
        .collect();

    Ok(revoked_certs)
}

#[derive(Debug, thiserror::Error)]
pub enum SignCrlError {
    #[error("db error")]
    Db(#[from] sqlx::Error),
    #[error("failed to sign CRL")]
    SignCrl,
}

pub async fn sign_crl(
    mut transaction: SqliteTransaction<'_>,
    issuer: &str,
    issuer_params: &CertificateParams,
    issuer_signing_key: &impl SigningKey,
) -> Result<(), SignCrlError> {
    let this_update = OffsetDateTime::now_utc();
    let next_update = this_update + time::Duration::days(365);

    let revoked_certs = list_revoked_certs(&mut *transaction, issuer).await?;
    let params = create_crl_params(revoked_certs, this_update, next_update, None);

    let crl = params
        .signed_by(issuer_params, issuer_signing_key)
        .map_err(|_| SignCrlError::SignCrl)?;
    let crl_der = crl.der().as_ref();

    sqlx::query!(
        "UPDATE issuers SET crl = $1 WHERE identifier = $2",
        crl_der,
        issuer
    )
    .execute(&mut *transaction)
    .await?;

    transaction.commit().await?;

    Ok(())
}

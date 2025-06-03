use rcgen::{
    CertificateParams, CertificateRevocationListParams, CrlIssuingDistributionPoint, KeyIdMethod,
    RevocationReason, RevokedCertParams, SerialNumber, SigningKey,
};
use sqlx::{SqliteExecutor, SqliteTransaction};
use time::OffsetDateTime;

use crate::issuer::{CertSerial, IssuerIdentifier};

/// Create parameters for a CRL, using the provided issued certificates and update times.
/// The `this_update` parameter will be used to derive the crl number, and must therefore
/// be monotonic.
pub fn create_crl_params(
    revoked_certs: Vec<RevokedCertParams>,
    this_update: OffsetDateTime,
    next_update: OffsetDateTime,
    issuing_distribution_point: Option<CrlIssuingDistributionPoint>,
) -> CertificateRevocationListParams {
    CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from_slice(
            &(this_update.unix_timestamp_nanos() / 1_000_000).to_be_bytes(),
        ),
        issuing_distribution_point,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    }
}

async fn list_revoked_certs(
    conn: impl SqliteExecutor<'_>,
    issuer: &IssuerIdentifier,
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
pub enum MakeCrlError {
    #[error("db error")]
    Db(#[from] sqlx::Error),
    #[error("failed to sign CRL")]
    SignCrl,
}

pub async fn make_crl(
    mut transaction: SqliteTransaction<'_>,
    issuer: &IssuerIdentifier,
    issuer_params: &CertificateParams,
    issuer_signing_key: &impl SigningKey,
    issuing_distribution_point: Option<CrlIssuingDistributionPoint>,
) -> Result<(), MakeCrlError> {
    let this_update = OffsetDateTime::now_utc();
    let next_update = this_update + time::Duration::days(365);

    let revoked_certs = list_revoked_certs(&mut *transaction, issuer).await?;
    let params = create_crl_params(
        revoked_certs,
        this_update,
        next_update,
        issuing_distribution_point,
    );

    let crl = params
        .signed_by(issuer_params, issuer_signing_key)
        .map_err(|_| MakeCrlError::SignCrl)?;
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

pub async fn set_cert_revocation(
    conn: impl SqliteExecutor<'_>,
    serial_number: CertSerial,
    issuer: &IssuerIdentifier,
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

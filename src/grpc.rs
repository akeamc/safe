use std::net::SocketAddr;

use anyhow::Context;
use proto::{
    CreateIssuerRequest, CreateIssuerResponse, IssuerInfo, IssuerList, ListCertificatesRequest,
    ListCertificatesResponse, ListIssuersRequest, RollClientSecretsRequest,
    RollClientSecretsResponse, SignCertificateRequest, SignCertificateResponse, UpdateCrlRequest,
    UpdateCrlResponse,
    safe_server::{Safe, SafeServer},
};
use rcgen::{CertificateParams, KeyPair, PublicKeyData, SerialNumber, SubjectPublicKeyInfo};
use rustls_pki_types::CertificateDer;
use sqlx::{SqlitePool, types::Json};
use tokio_util::sync::CancellationToken;
use tonic::{Code, Request, Response, Status};
use tracing::warn;
use x509_parser::pem::parse_x509_pem;

use crate::{
    issuer::{
        CertSerial, GetIssuerKeyError, SignCrlError, get_issuer_aead_container, get_issuer_key,
        insert_cert, sign_crl,
    },
    key::{self, SplitError},
};

pub mod proto {
    tonic::include_proto!("safe");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("safe_descriptor");
}

pub struct SafeService {
    pub state: crate::State,
}

#[derive(Debug, thiserror::Error)]
enum VerifyCertifiedKeyError {
    #[error("invalid certificate PEM")]
    CertificatePem,
    #[error("invalid private key PEM")]
    Key,
    #[error("certificate does not match private key")]
    Mismatch,
}

/// Decode an X.509 certificate and verify that it matches the provided private key.
/// Returns the PKCS#8 DER-encoded private key if the verification is successful.
fn decode_certified_key(
    cert: &str,
    key: &str,
) -> Result<(CertificateParams, KeyPair), VerifyCertifiedKeyError> {
    let (remaining, pem) =
        parse_x509_pem(cert.as_bytes()).map_err(|_| VerifyCertifiedKeyError::CertificatePem)?;
    if !remaining.is_empty() {
        return Err(VerifyCertifiedKeyError::CertificatePem);
    }
    let cert = pem
        .parse_x509()
        .map_err(|_| VerifyCertifiedKeyError::CertificatePem)?
        .to_owned();

    // ensure that the private key matches the certificate
    let key_pair = KeyPair::from_pem(key)
        .inspect_err(|e| println!("{e}"))
        .map_err(|_| VerifyCertifiedKeyError::Key)?;

    if cert.subject_pki.raw != key_pair.subject_public_key_info() {
        return Err(VerifyCertifiedKeyError::Mismatch);
    }

    let params = CertificateParams::from_ca_cert_der(&CertificateDer::from_slice(&pem.contents))
        .map_err(|_| VerifyCertifiedKeyError::CertificatePem)?;

    Ok((params, key_pair))
}

#[derive(Debug, thiserror::Error)]
enum SignCertError {
    #[error("invalid spki")]
    InvalidSpki,
    #[error("database error")]
    Db(#[from] sqlx::Error),
    #[error("crypto error")]
    Crypto,
    #[error(transparent)]
    GetIssuerKeyError(#[from] GetIssuerKeyError),
}

impl From<SignCertError> for Status {
    fn from(err: SignCertError) -> Self {
        let code = match err {
            SignCertError::InvalidSpki => Code::InvalidArgument,
            SignCertError::Db(_) => Code::Internal,
            SignCertError::Crypto => Code::Internal,
            SignCertError::GetIssuerKeyError(inner) => return inner.into(),
        };

        Self::new(code, err.to_string())
    }
}

async fn sign_cert(
    db: &SqlitePool,
    csr: SignCertificateRequest,
) -> Result<SignCertificateResponse, SignCertError> {
    let SignCertificateRequest {
        issuer,
        spki,
        secret,
    } = csr;

    let spki = SubjectPublicKeyInfo::from_der(&spki).map_err(|_| SignCertError::InvalidSpki)?;
    let serial_number: u64 = rand::random();
    let mut params =
        CertificateParams::new(Vec::default()).expect("empty SAN cannot produce error");
    params.serial_number = Some(SerialNumber::from_slice(&serial_number.to_be_bytes()));

    let mut conn = db.begin().await?;
    let (ca, ca_key) = get_issuer_key(&mut *conn, &issuer, secret).await?;
    let der = params
        .signed_by(&spki, &ca, &ca_key)
        .map_err(|_| SignCertError::Crypto)?
        .der()
        .to_vec();
    insert_cert(&mut *conn, &issuer, serial_number, &der).await?;
    conn.commit().await?;

    Ok(SignCertificateResponse { der })
}

#[derive(Debug, thiserror::Error)]
enum InsertIssuerError {
    #[error("db error")]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    InvalidData(#[from] VerifyCertifiedKeyError),
    #[error("issuer already exists")]
    IssuerExists,
    #[error("invalid issuer identifier")]
    InvalidIdentifier,
    #[error(transparent)]
    SplitKeyError(#[from] key::SplitError),
}

impl From<InsertIssuerError> for Status {
    fn from(err: InsertIssuerError) -> Self {
        let code = match &err {
            InsertIssuerError::Db(_) => Code::Internal,
            InsertIssuerError::InvalidData(_) => Code::InvalidArgument,
            InsertIssuerError::IssuerExists => Code::AlreadyExists,
            InsertIssuerError::InvalidIdentifier => Code::InvalidArgument,
            InsertIssuerError::SplitKeyError(e) => match e {
                SplitError::InvalidKeyCount => Code::InvalidArgument,
            },
        };

        Self::new(code, err.to_string())
    }
}

async fn create_issuer(
    db: &SqlitePool,
    req: CreateIssuerRequest,
) -> Result<CreateIssuerResponse, InsertIssuerError> {
    let CreateIssuerRequest {
        identifier,
        cert,
        private_key,
        n_client_secrets,
    } = req;

    if identifier.is_empty() {
        return Err(InsertIssuerError::InvalidIdentifier);
    }

    let (params, key_pair) = decode_certified_key(&cert, &private_key)?;
    let (ours, client_secrets) = key::split(
        &key_pair.serialize_der(),
        n_client_secrets.unwrap_or(1).try_into().unwrap(),
    )?;
    let sss_container = serde_json::to_string(&ours).unwrap();

    let res = match sqlx::query!(
        "INSERT INTO issuers (identifier, cert, private_key) VALUES ($1, $2, $3) RETURNING identifier, cert",
        identifier,
        cert,
        sss_container
    )
    .fetch_one(db)
    .await {
        Ok(new_row) => CreateIssuerResponse {
            identifier: new_row.identifier.unwrap_or_default(),
            cert: new_row.cert,
            client_secrets,
        },
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(InsertIssuerError::IssuerExists)
        }
        Err(e) => return Err(InsertIssuerError::Db(e)),
    };

    if let Err(err) = sign_crl(db.begin().await?, &res.identifier, &params, &key_pair).await {
        warn!("failed to sign CRL for new issuer: {err}");
    }

    Ok(res)
}

#[derive(Debug, thiserror::Error)]
enum RollClientSecretsError {
    #[error("db error")]
    Db(#[from] sqlx::Error),
    #[error("failed to roll client secrets: {0}")]
    Roll(#[from] key::RollError),
    #[error("issuer not found")]
    IssuerNotFound,
}

impl From<RollClientSecretsError> for Status {
    fn from(err: RollClientSecretsError) -> Self {
        let code = match &err {
            RollClientSecretsError::Db(_) => Code::Internal,
            RollClientSecretsError::Roll(_) => Code::PermissionDenied,
            RollClientSecretsError::IssuerNotFound => Code::NotFound,
        };

        Self::new(code, err.to_string())
    }
}

async fn roll_client_secrets(
    db: &SqlitePool,
    req: RollClientSecretsRequest,
) -> Result<RollClientSecretsResponse, RollClientSecretsError> {
    let RollClientSecretsRequest {
        issuer,
        secret,
        n_client_secrets,
    } = req;

    let mut conn = db.begin().await?;
    let mut container = get_issuer_aead_container(&mut *conn, &issuer)
        .await?
        .ok_or(RollClientSecretsError::IssuerNotFound)?;
    let new_secrets = container.roll_secrets(secret, n_client_secrets.unwrap_or(1) as usize)?;
    let container = Json(container);
    sqlx::query!(
        "UPDATE issuers SET private_key = $1 WHERE identifier = $2",
        container,
        issuer
    )
    .execute(&mut *conn)
    .await?;
    conn.commit().await?;

    Ok(RollClientSecretsResponse {
        client_secrets: new_secrets,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateCrlError {
    #[error("db error")]
    Db(#[from] sqlx::Error),
    #[error("failed to sign CRL")]
    SignCrl,
    #[error(transparent)]
    GetIssuerKeyError(#[from] GetIssuerKeyError),
}

impl From<SignCrlError> for UpdateCrlError {
    fn from(err: SignCrlError) -> Self {
        match err {
            SignCrlError::Db(db) => Self::Db(db),
            SignCrlError::SignCrl => Self::SignCrl,
        }
    }
}

impl From<UpdateCrlError> for Status {
    fn from(err: UpdateCrlError) -> Self {
        let code = match err {
            UpdateCrlError::Db(_) => Code::Internal,
            UpdateCrlError::SignCrl => Code::Internal,
            UpdateCrlError::GetIssuerKeyError(inner) => return inner.into(),
        };

        Self::new(code, err.to_string())
    }
}

async fn update_crl(
    db: &SqlitePool,
    req: UpdateCrlRequest,
) -> Result<UpdateCrlResponse, UpdateCrlError> {
    let UpdateCrlRequest { issuer, secret } = req;

    let mut transaction = db.begin().await?;

    let (params, key_pair) = get_issuer_key(&mut *transaction, &issuer, secret).await?;

    sign_crl(transaction, &issuer, &params, &key_pair).await?;

    Ok(UpdateCrlResponse {})
}

#[tonic::async_trait]
impl Safe for SafeService {
    async fn list_issuers(
        &self,
        _request: Request<ListIssuersRequest>,
    ) -> Result<Response<IssuerList>, Status> {
        let mut conn = self.state.db.acquire().await.map_err(|e| {
            Status::new(
                Code::Internal,
                format!("failed to acquire db connection: {e}"),
            )
        })?;

        let issuers = sqlx::query!("SELECT identifier, cert FROM issuers")
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| Status::new(Code::Internal, format!("failed to fetch issuers: {e}")))?
            .into_iter()
            .map(|row| IssuerInfo {
                identifier: row.identifier.unwrap_or_default(),
                cert: row.cert,
            })
            .collect();

        Ok(Response::new(IssuerList { issuers }))
    }

    async fn sign_certificate(
        &self,
        request: Request<SignCertificateRequest>,
    ) -> Result<Response<SignCertificateResponse>, Status> {
        let cert = sign_cert(&self.state.db, request.into_inner()).await?;

        Ok(Response::new(cert))
    }

    async fn roll_client_secrets(
        &self,
        request: Request<RollClientSecretsRequest>,
    ) -> Result<Response<RollClientSecretsResponse>, Status> {
        let res = roll_client_secrets(&self.state.db, request.into_inner()).await?;

        Ok(Response::new(res))
    }

    async fn update_crl(
        &self,
        request: Request<UpdateCrlRequest>,
    ) -> Result<Response<UpdateCrlResponse>, Status> {
        let res = update_crl(&self.state.db, request.into_inner()).await?;

        Ok(Response::new(res))
    }

    async fn create_issuer(
        &self,
        request: Request<CreateIssuerRequest>,
    ) -> Result<Response<CreateIssuerResponse>, Status> {
        let info = create_issuer(&self.state.db, request.into_inner()).await?;

        Ok(Response::new(info))
    }

    async fn list_certificates(
        &self,
        request: Request<ListCertificatesRequest>,
    ) -> Result<Response<ListCertificatesResponse>, Status> {
        let ListCertificatesRequest { issuer } = request.into_inner();

        let mut conn = self.state.db.acquire().await.map_err(|e| {
            Status::new(
                Code::Internal,
                format!("failed to acquire db connection: {e}"),
            )
        })?;

        let certificates = sqlx::query!(
            r#"SELECT serial_number AS "serial_number: CertSerial" FROM certificates WHERE issuer = $1"#,
            issuer
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| Status::new(Code::Internal, format!("failed to fetch certificates: {e}")))?
        .into_iter()
        .map(|row| row.serial_number.to_string())
        .collect();

        Ok(Response::new(ListCertificatesResponse { certificates }))
    }
}

pub async fn serve(
    svc: SafeService,
    addr: SocketAddr,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    // stop all other tasks if this function errors/panics
    let _guard = cancel_token.clone().drop_guard();

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build_v1()
        .unwrap();

    tonic::transport::Server::builder()
        .add_service(reflection)
        .add_service(SafeServer::new(svc))
        .serve_with_shutdown(addr, cancel_token.cancelled())
        .await
        .with_context(|| format!("failed to serve grpc on {addr}"))?;

    Ok(())
}

use axum::{
    Router,
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::State;

#[derive(Debug, thiserror::Error)]
enum CrlError {
    #[error("db error")]
    Db(#[from] sqlx::Error),
    #[error("issuer not found")]
    IssuerNotFound,
    #[error("no crl available")]
    NoCrl,
}

impl IntoResponse for CrlError {
    fn into_response(self) -> Response {
        let status = match &self {
            CrlError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
            CrlError::IssuerNotFound => StatusCode::NOT_FOUND,
            CrlError::NoCrl => StatusCode::NOT_FOUND,
        };

        (status, self.to_string()).into_response()
    }
}

async fn crl(state: State, Path(issuer): Path<String>) -> Result<Response, CrlError> {
    struct Row {
        crl: Option<Vec<u8>>,
    }

    let crl = sqlx::query_as!(Row, "SELECT crl FROM issuers WHERE identifier = $1", issuer)
        .fetch_optional(&state.db)
        .await?
        .ok_or(CrlError::IssuerNotFound)?
        .crl
        .ok_or(CrlError::NoCrl)?;

    Ok(([(header::CONTENT_TYPE, "application/pkix-crl")], crl).into_response())
}

async fn issuer_pem(state: State, Path(issuer): Path<String>) -> Result<Response, CrlError> {
    struct Row {
        cert: String,
    }

    let cert = sqlx::query_as!(
        Row,
        "SELECT cert FROM issuers WHERE identifier = $1",
        issuer
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(CrlError::IssuerNotFound)?
    .cert;

    Ok(([(header::CONTENT_TYPE, "application/x-pem-file")], cert).into_response())
}

pub fn router() -> Router<State> {
    Router::new()
        .route("/{issuer}/crl", axum::routing::get(crl))
        .route("/{issuer}/pem", axum::routing::get(issuer_pem))
}

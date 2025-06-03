use std::sync::Arc;

use axum::{extract::FromRequestParts, http::request::Parts};
use rcgen::{CrlDistributionPoint, CrlIssuingDistributionPoint};
use sqlx::SqlitePool;
use url::Url;

use crate::issuer::IssuerIdentifier;

pub mod csr;
pub mod grpc;
pub mod http;
pub mod issuer;
pub mod key;
pub mod revocation;
pub mod util;

#[derive(Clone)]
pub struct State {
    pub db: SqlitePool,
    pub public_http_url: Arc<Url>,
}

impl State {
    pub fn crl_distribution_point(&self, issuer: &IssuerIdentifier) -> CrlDistributionPoint {
        CrlDistributionPoint {
            uris: vec![
                self.public_http_url
                    .join(&format!("issuer/{issuer}/crl"))
                    .unwrap()
                    .to_string(),
            ],
        }
    }

    pub fn issuing_distribution_point(
        &self,
        issuer: &IssuerIdentifier,
    ) -> CrlIssuingDistributionPoint {
        CrlIssuingDistributionPoint {
            distribution_point: self.crl_distribution_point(issuer),
            scope: None,
        }
    }
}

impl FromRequestParts<State> for State {
    type Rejection = ();

    async fn from_request_parts(
        _parts: &mut Parts,
        state: &State,
    ) -> Result<Self, Self::Rejection> {
        Ok(state.clone())
    }
}

use axum::{extract::FromRequestParts, http::request::Parts};
use sqlx::SqlitePool;

pub mod grpc;
pub mod http;
pub mod issuer;
pub mod key;
pub mod util;

#[derive(Clone)]
pub struct State {
    pub db: SqlitePool,
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

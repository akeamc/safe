use std::net::SocketAddr;

use anyhow::Context;
use axum::Router;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::State;

pub mod issuer;

pub async fn serve(
    state: State,
    addr: SocketAddr,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    // stop all other tasks if this function errors/panics
    let _guard = cancel_token.clone().drop_guard();

    let app = Router::new()
        .nest("/issuer", issuer::router())
        .with_state(state)
        .into_make_service();

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind http listener to {addr}"))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(cancel_token.cancelled_owned())
        .await?;

    Ok(())
}

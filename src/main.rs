use std::net::SocketAddr;

use clap::Parser;
use safe::{State, grpc::SafeService};
use sqlx::SqlitePool;
use tokio::{signal, task::JoinSet};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
struct Args {
    /// The address to bind the HTTP server to.
    #[clap(long, env, default_value = "[::]:8000")]
    http_addr: SocketAddr,
    /// The address to bind the gRPC server to.
    #[clap(long, env, default_value = "[::]:8001")]
    grpc_addr: SocketAddr,

    #[clap(long, env)]
    database_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let Args {
        http_addr,
        grpc_addr,
        database_url,
    } = Args::parse();

    let db = SqlitePool::connect(&database_url).await?;

    sqlx::migrate!().run(&db).await?;

    let state = State { db };
    let cancel_token = CancellationToken::new();

    let svc = SafeService {
        state: state.clone(),
    };

    let mut join_set = JoinSet::new();

    join_set.spawn(safe::grpc::serve(svc, grpc_addr, cancel_token.clone()));
    join_set.spawn(safe::http::serve(state, http_addr, cancel_token.clone()));
    join_set.spawn(async move {
        cancel_token
            .run_until_cancelled(signal::ctrl_c())
            .await
            .transpose()?;
        cancel_token.cancel();
        anyhow::Ok(())
    });

    // return the first error, but not before all tasks have exited cleanly
    let mut err = None;

    while let Some(task_result) = join_set.join_next().await {
        err = err.or(task_result?.err());
    }

    err.map_or(Ok(()), Err)
}

use std::{net::SocketAddr, sync::Arc};

use clap::Parser;
use safe::{State, grpc::SafeService};
use sqlx::{Sqlite, SqlitePool, migrate::MigrateDatabase};
use tokio::{signal, task::JoinSet};
use tokio_util::sync::CancellationToken;
use url::Url;

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

    /// URL that the public HTTP server will be accessible at,
    /// used to specify the CRL URl in the certificates and
    /// CRLs.
    #[clap(long, env)]
    public_http_url: Url,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let Args {
        http_addr,
        grpc_addr,
        database_url,
        public_http_url,
    } = Args::parse();

    if !Sqlite::database_exists(&database_url).await? {
        eprintln!("Creating database {}", &database_url);
        Sqlite::create_database(&database_url).await?;
        eprintln!("Database created successfully");
    }

    let db = SqlitePool::connect(&database_url).await?;

    sqlx::migrate!().run(&db).await?;

    let state = State {
        db,
        public_http_url: Arc::new(public_http_url),
    };
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

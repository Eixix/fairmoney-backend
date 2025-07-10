use crate::auth::handlers::auth_routes;
use crate::transactions::handlers::transaction_routes;
use axum::{Extension, Router};
use sqlx::SqlitePool;

pub fn routes(pool: SqlitePool) -> Router {
    Router::new()
        .nest("/auth", auth_routes())
        .nest("/transactions", transaction_routes())
        .layer(Extension(pool))
}

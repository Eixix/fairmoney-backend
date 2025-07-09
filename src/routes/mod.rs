use crate::auth::handlers::auth_routes;
use axum::{Extension, Router};
use sqlx::SqlitePool;

pub fn routes(pool: SqlitePool) -> Router {
    Router::new()
        .nest("/auth", auth_routes())
        .layer(Extension(pool))
}

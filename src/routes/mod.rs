use axum::Router;
use crate::auth::handlers::auth_routes;

pub fn routes() -> Router {
    Router::new().nest("/auth", auth_routes())
}

use crate::auth::jwt::AuthBearer;
use axum::routing::get;
use axum::Router;

pub fn transaction_routes() -> Router {
    Router::new().route("/test", get(protected))
}

async fn protected(AuthBearer(claims): AuthBearer) -> String {
    format!("Hello, {}!", claims.uid)
}

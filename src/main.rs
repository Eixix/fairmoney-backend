use axum::Router;
use axum::routing::get;
use dotenvy::dotenv;
use crate::routes::routes;

mod auth;
mod config;
mod db;
mod errors;
mod routes;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let app = routes();
    let addr: String = "127.0.0.1:3000".parse().unwrap();
    println!("FairMoney API running at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

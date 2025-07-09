use crate::db::connect_db;
use crate::routes::routes;
use dotenvy::dotenv;
use std::env;

mod auth;
mod config;
mod db;
mod errors;
mod routes;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pool = connect_db(&db_url).await;

    let app = routes(pool.clone());
    let addr: String = "127.0.0.1:3000".parse().unwrap();
    println!("FairMoney API running at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

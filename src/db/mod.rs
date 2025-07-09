use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;

pub mod models;

pub async fn connect_db(database_url: &str) -> SqlitePool {
    SqlitePoolOptions::new()
        .connect(database_url)
        .await
        .expect("Failed to connect to the database")
}

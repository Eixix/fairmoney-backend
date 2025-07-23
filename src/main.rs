mod api_doc;
mod db;
mod errors;
mod handlers;
mod models;
mod schema;

use crate::api_doc::ApiDoc;
use crate::handlers::{
    create_group, create_group_membership, create_transaction, create_transaction_share,
    delete_group_handler, delete_transaction_handler, delete_transaction_share_handler,
    get_groups_for_user, get_transaction_shares_for_transaction, get_transactions_for_group, login,
    register, update_group, update_transaction, update_transaction_share,
};
use actix_web::{web, App, HttpServer};
use diesel::{r2d2, SqliteConnection};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

type DbPool = r2d2::Pool<r2d2::ConnectionManager<SqliteConnection>>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Check out environment
    dotenvy::dotenv().expect("Failed to load .env file");
    // connect to SQLite DB
    let manager = r2d2::ConnectionManager::<SqliteConnection>::new("fairmoney.db");
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("database URL should be valid path to SQLite DB file");
    println!("Running server on http://localhost:8080");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(register)
            .service(login)
            .service(get_groups_for_user)
            .service(create_group)
            .service(update_group)
            .service(delete_group_handler)
            .service(get_transactions_for_group)
            .service(create_transaction)
            .service(update_transaction)
            .service(delete_transaction_handler)
            .service(create_group_membership)
            .service(get_transaction_shares_for_transaction)
            .service(create_transaction_share)
            .service(update_transaction_share)
            .service(delete_transaction_share_handler)
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-doc/openapi.json", ApiDoc::openapi()),
            )
    })
    .bind(("localhost", 8080))?
    .run()
    .await
}

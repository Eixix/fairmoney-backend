use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use dotenvy::dotenv;
use std::env;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use utoipa::openapi::{OpenApi as OpenApiDoc, security::{SecurityScheme, HttpAuthScheme, HttpBuilder}};
use utoipa::Modify;

mod auth;
mod config;
mod db;
mod errors;
mod groups;
mod routes;
mod transactions;

pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut OpenApiDoc) {
        openapi.components = openapi.components.take().map(|mut components| {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).bearer_format("JWT").build())
            );
            components
        });
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        auth::handlers::login,
        auth::handlers::register,
        auth::handlers::me,
        groups::handlers::create_group,
        groups::handlers::get_groups,
        groups::handlers::get_group,
        groups::handlers::add_group_member,
        groups::handlers::remove_group_member,
        groups::handlers::delete_group,
        transactions::handlers::create_transaction,
        transactions::handlers::get_group_transactions,
        transactions::handlers::get_transaction,
        transactions::handlers::delete_transaction
    ),
    components(
        schemas(
            db::models::User,
            db::models::Group,
            db::models::GroupMember,
            db::models::Transaction,
            db::models::TransactionShare,
            db::models::CreateUserRequest,
            db::models::LoginRequest,
            db::models::LoginResponse,
            db::models::CreateGroupRequest,
            db::models::AddGroupMemberByEmailRequest,
            db::models::CreateTransactionRequest,
            db::models::TransactionShareRequest,
            db::models::GroupWithMembers,
            db::models::TransactionWithShares
        )
    ),
    tags(
        (name = "Authentication", description = "User authentication endpoints"),
        (name = "Groups", description = "Group management endpoints"),
        (name = "Transactions", description = "Transaction management endpoints")
    ),
    info(
        title = "FairMoney API",
        description = "A complete expense tracking API similar to Tricount or Splitwise",
        version = "1.0.0",
        contact(
            name = "FairMoney",
            email = "support@fairmoney.com"
        )
    ),
    servers(
        (url = "http://127.0.0.1:3000", description = "Development server")
    ),
    security(
        ("bearer_auth" = [])
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pool = db::connect_db(&db_url).await;

    println!("FairMoney API running at http://127.0.0.1:3000");
    println!("Swagger UI available at http://127.0.0.1:3000/swagger-ui/");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .configure(routes::config)
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", ApiDoc::openapi())
            )
    })
    .bind("127.0.0.1:3000")?
    .run()
    .await
}

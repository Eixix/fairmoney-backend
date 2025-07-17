mod db;
mod errors;
mod models;
mod schema;

use crate::db::{check_if_user_exists, get_user_by_username, insert_new_user};
use crate::errors::AppError;
use crate::models::{Claims, LoginAnswer, RequestRegisterUser, User};
use actix_web::{error, get, post, web, App, HttpResponse, HttpServer, Responder};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::Duration;
use diesel::{r2d2, SqliteConnection};
use jsonwebtoken::{encode, EncodingKey, Header};
use uuid::Uuid;

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
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(hello)
            .service(register)
            .service(login)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[post("/register")]
async fn register(
    pool: web::Data<DbPool>,
    request_user: web::Json<RequestRegisterUser>,
) -> actix_web::Result<impl Responder> {
    // Check if user already exists
    let pool_insert = pool.clone();
    let user_insert = request_user.clone();
    let user_already_exists = web::block(move || {
        let mut conn = pool.get().expect("Failed to get db connection from pool");
        check_if_user_exists(&mut conn, &*request_user.username)
    })
    .await?
    .map_err(error::ErrorInternalServerError)?;

    if !user_already_exists {
        // Create user if it does not exist
        let user = web::block(move || {
            let mut conn = pool_insert
                .get()
                .expect("Failed to get db connection from pool");

            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let hashed_pw = argon2
                .hash_password(user_insert.password.as_bytes(), &salt)
                .unwrap()
                .to_string();

            let user_to_register: User = User {
                uid: Uuid::new_v4().to_string(),
                username: user_insert.username.to_string(),
                hashed_password: hashed_pw,
            };
            insert_new_user(&mut conn, user_to_register.clone())
        })
        .await?
        .map_err(error::ErrorInternalServerError)?;

        Ok(HttpResponse::Ok().json(user))
    } else {
        Err(error::ErrorBadRequest("User already exists"))
    }
}

#[post("/login")]
async fn login(
    pool: web::Data<DbPool>,
    request_user: web::Json<RequestRegisterUser>,
) -> Result<HttpResponse, AppError> {
    let username = request_user.username.clone();
    let password = request_user.password.clone();

    let user = web::block(move || -> Result<LoginAnswer, AppError> {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        let user =
            get_user_by_username(&mut conn, &username).map_err(|_| AppError::UserNotFound)?;

        let parsed_hash =
            PasswordHash::new(&user.hashed_password).map_err(|_| AppError::InternalError)?;

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AppError::WrongPassword)?;

        let claims = Claims {
            sub: user.username,
            exp: (chrono::Utc::now() + Duration::days(7)).timestamp() as usize,
        };
        let jwt_secret = dotenvy::var("JWT_SECRET").map_err(|_| AppError::InternalError)?;
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_ref()),
        )
        .map_err(|_| AppError::InternalError)?;

        Ok(LoginAnswer { token })
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().json(user))
}

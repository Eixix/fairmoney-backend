mod db;
mod errors;
mod models;
mod schema;

use crate::db::{
    check_if_user_exists, delete_group, delete_transaction, delete_transaction_share,
    get_shares_by_transaction, get_transactions_by_group, get_user_by_username, get_user_groups,
    insert_new_group, insert_new_group_membership, insert_new_transaction,
    insert_new_transaction_share, insert_new_user, update_group_by_id, update_transaction_by_id,
    update_transaction_share_by_id,
};
use crate::errors::AppError;
use crate::models::models::{Group, GroupMembership, Transaction, TransactionShare, User};
use crate::models::request_models::{
    Claims, LoginAnswer, NewGroup, NewGroupMembership, NewTransaction, NewTransactionShare, NewUser,
};
use actix_web::{delete, error, get, post, put, web, App, HttpResponse, HttpServer, Responder};
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
    request_user: web::Json<NewUser>,
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
        let result = web::block(move || {
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

        Ok(HttpResponse::Ok().json(result))
    } else {
        Err(error::ErrorBadRequest("User already exists"))
    }
}

#[post("/login")]
async fn login(
    pool: web::Data<DbPool>,
    request_user: web::Json<NewUser>,
) -> Result<HttpResponse, AppError> {
    let username = request_user.username.clone();
    let password = request_user.password.clone();

    let result = web::block(move || -> Result<LoginAnswer, AppError> {
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

    Ok(HttpResponse::Ok().json(result))
}

#[get("/user/{user_id}/groups")]
async fn get_groups_for_user(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let user_uid = path.into_inner();
    let pool = pool.clone();

    let result = web::block(move || {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        get_user_groups(&mut conn, &user_uid).map_err(|_| AppError::InternalError)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().json(result))
}

#[put("/group")]
async fn create_group(
    pool: web::Data<DbPool>,
    new_group: web::Json<NewGroup>,
) -> Result<HttpResponse, AppError> {
    let name = new_group.group_name.clone();
    let pool = pool.clone();
    let result = web::block(move || -> Result<Group, AppError> {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        let group = insert_new_group(&mut conn, name).map_err(|_| AppError::InternalError)?;
        Ok(group)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().json(result))
}

#[post("/group")]
async fn update_group(
    pool: web::Data<DbPool>,
    data: web::Json<Group>,
) -> Result<HttpResponse, AppError> {
    let group = data.into_inner();
    let pool = pool.clone();

    let updated = web::block(move || {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        update_group_by_id(&mut conn, &group).map_err(|_| AppError::InternalError)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().json(updated))
}

#[delete("/group/{group_id}")]
async fn delete_group_handler(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let group_uid = path.into_inner();
    let pool = pool.clone();

    web::block(move || {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        delete_group(&mut conn, &group_uid).map_err(|_| AppError::InternalError)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().finish())
}

#[get("/group/{group_uid}/transactions")]
async fn get_transactions_for_group(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let group_uid = path.into_inner();
    let pool = pool.clone();

    let result = web::block(move || {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        get_transactions_by_group(&mut conn, &group_uid).map_err(|_| AppError::InternalError)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().json(result))
}

#[put("/transaction")]
async fn create_transaction(
    pool: web::Data<DbPool>,
    data: web::Json<NewTransaction>,
) -> Result<HttpResponse, AppError> {
    let txn_data = data.into_inner();
    let pool = pool.clone();
    let result = web::block(move || -> Result<Transaction, AppError> {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        let txn =
            insert_new_transaction(&mut conn, txn_data).map_err(|_| AppError::InternalError)?;
        Ok(txn)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().json(result))
}

#[post("/transaction")]
async fn update_transaction(
    pool: web::Data<DbPool>,
    data: web::Json<Transaction>,
) -> Result<HttpResponse, AppError> {
    let txn = data.into_inner();
    let pool = pool.clone();

    let updated = web::block(move || {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        update_transaction_by_id(&mut conn, &txn).map_err(|_| AppError::InternalError)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().json(updated))
}

#[delete("/transaction/{transaction_id}")]
async fn delete_transaction_handler(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let transaction_uid = path.into_inner();
    let pool = pool.clone();

    web::block(move || {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        delete_transaction(&mut conn, &transaction_uid).map_err(|_| AppError::InternalError)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().finish())
}

#[put("/group_membership")]
async fn create_group_membership(
    pool: web::Data<DbPool>,
    data: web::Json<NewGroupMembership>,
) -> Result<HttpResponse, AppError> {
    let data = data.into_inner();
    let pool = pool.clone();
    let result = web::block(move || -> Result<GroupMembership, AppError> {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        insert_new_group_membership(&mut conn, data.user_id, data.group_id)
            .map_err(|_| AppError::InternalError)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().json(result))
}

#[get("/group/{group_uid}/transaction/{transaction_uid}/transaction_shares")]
async fn get_transaction_shares_for_transaction(
    pool: web::Data<DbPool>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, AppError> {
    let (_group_uid, transaction_uid) = path.into_inner(); // group_uid unused but part of the route
    let pool = pool.clone();

    let result = web::block(move || {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        get_shares_by_transaction(&mut conn, &transaction_uid).map_err(|_| AppError::InternalError)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().json(result))
}

#[put("/transaction_share")]
async fn create_transaction_share(
    pool: web::Data<DbPool>,
    data: web::Json<NewTransactionShare>,
) -> Result<HttpResponse, AppError> {
    let data = data.into_inner();
    let pool = pool.clone();
    let result = web::block(move || -> Result<TransactionShare, AppError> {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        insert_new_transaction_share(&mut conn, data).map_err(|_| AppError::InternalError)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().json(result))
}

#[post("/transaction_share")]
async fn update_transaction_share(
    pool: web::Data<DbPool>,
    data: web::Json<TransactionShare>,
) -> Result<HttpResponse, AppError> {
    let share = data.into_inner();
    let pool = pool.clone();

    let updated = web::block(move || {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        update_transaction_share_by_id(&mut conn, &share).map_err(|_| AppError::InternalError)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().json(updated))
}

#[delete("/transaction_share/{share_id}")]
async fn delete_transaction_share_handler(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let share_uid = path.into_inner();
    let pool = pool.clone();

    web::block(move || {
        let mut conn = pool.get().map_err(|_| AppError::InternalError)?;
        delete_transaction_share(&mut conn, &share_uid).map_err(|_| AppError::InternalError)
    })
    .await
    .map_err(|_| AppError::InternalError)??;

    Ok(HttpResponse::Ok().finish())
}

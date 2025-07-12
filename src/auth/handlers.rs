use actix_web::{web, HttpResponse, HttpRequest};
use crate::auth::jwt::{create_jwt, Claims};
use crate::db::models::{User, CreateUserRequest, LoginRequest, LoginResponse};
use crate::errors::AppError;
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use sqlx::SqlitePool;

/// Login with email and password
#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Invalid credentials")
    ),
    tag = "Authentication"
)]
pub async fn login(
    pool: web::Data<SqlitePool>,
    login_data: web::Json<LoginRequest>,
) -> Result<HttpResponse, AppError> {
    let user = sqlx::query_as_unchecked!(
        User,
        "SELECT id, username, email, password_hash, created_at FROM users WHERE email = ?",
        login_data.email
    )
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| AppError::Unauthorized("Invalid email or password".to_string()))?;

    if verify_password(&login_data.password, &user.password_hash)? {
        let token = create_jwt(&user.id)?;
        let response = LoginResponse { token, user };
        Ok(HttpResponse::Ok().json(response))
    } else {
        Err(AppError::Unauthorized("Invalid email or password".to_string()))
    }
}

/// Register a new user
#[utoipa::path(
    post,
    path = "/api/auth/register",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created successfully", body = LoginResponse),
        (status = 400, description = "User already exists")
    ),
    tag = "Authentication"
)]
pub async fn register(
    pool: web::Data<SqlitePool>,
    user_data: web::Json<CreateUserRequest>,
) -> Result<HttpResponse, AppError> {
    // Check if user already exists
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users WHERE email = ? OR username = ?",
    )
    .bind(&user_data.email)
    .bind(&user_data.username)
    .fetch_one(pool.get_ref())
    .await?;

    if count.0 > 0 {
        return Err(AppError::BadRequest("User with this email or username already exists".to_string()));
    }

    let hash = hash_password(&user_data.password)?;
    let user = User::new(&user_data.username, &user_data.email, &hash);

    sqlx::query!(
        "INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
        user.id,
        user.username,
        user.email,
        user.password_hash,
        user.created_at
    )
    .execute(pool.get_ref())
    .await?;

    let token = create_jwt(&user.id)?;
    let response = LoginResponse { token, user };
    Ok(HttpResponse::Created().json(response))
}

/// Get current user information
#[utoipa::path(
    get,
    path = "/api/auth/me",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "User information", body = User),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found")
    ),
    tag = "Authentication"
)]
pub async fn me(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let claims = Claims::from_request(&req)?;
    
    let user = sqlx::query_as_unchecked!(
        User,
        "SELECT id, username, email, password_hash, created_at FROM users WHERE id = ?",
        claims.user_id
    )
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(HttpResponse::Ok().json(user))
}

fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::ArgonError(e.to_string()))?;
    Ok(password_hash.to_string())
}

fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
    let parsed_hash = PasswordHash::new(&hash).map_err(|e| AppError::ArgonError(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

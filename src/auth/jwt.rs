use crate::errors::AppError;
use actix_web::http::header::AUTHORIZATION;
use actix_web::HttpRequest;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::env;
use chrono::{Duration, Utc};

#[derive(Serialize, Deserialize, Clone)]
pub struct Claims {
    pub user_id: String,
    pub exp: i64,
}

impl Claims {
    pub fn from_request(req: &HttpRequest) -> Result<Self, AppError> {
        let auth_header = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header format".to_string()))?;

        validate_jwt(token)
            .map_err(|_| AppError::Unauthorized("Invalid or expired token".to_string()))
    }
}

pub fn create_jwt(user_id: &str) -> Result<String, AppError> {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let expiration = Utc::now() + Duration::hours(24);
    
    let claims = Claims {
        user_id: user_id.to_string(),
        exp: expiration.timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| AppError::JwtError(e.to_string()))
}

pub fn validate_jwt(jwt: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token_data = decode::<Claims>(
        jwt,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

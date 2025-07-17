use crate::errors::AppError;
use actix_web::{FromRequest, HttpRequest};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use std::future::{ready, Ready};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct Claims {
    pub sub: String, // Username
    pub user_id: String,
    pub exp: usize,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct LoginAnswer {
    pub token: String,
}

pub struct JwtAuth(pub Claims);

impl FromRequest for JwtAuth {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        // Extract header
        let header = req.headers().get("Authorization");

        if header.is_none() {
            return ready(Err(AppError::NoAuthToken));
        }

        let auth_header = header.unwrap().to_str().unwrap_or("");

        // Expect format: "Bearer <token>"
        if !auth_header.starts_with("Bearer ") {
            return ready(Err(AppError::NoAuthToken));
        }

        let token = &auth_header[7..]; // Skip "Bearer "

        let jwt_secret = match env::var("JWT_SECRET") {
            Ok(secret) => secret,
            Err(_) => {
                return ready(Err(AppError::InternalError));
            }
        };

        let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());

        let token_data = decode::<Claims>(token, &decoding_key, &Validation::default());

        match token_data {
            Ok(data) => ready(Ok(JwtAuth(data.claims))),
            Err(_) => ready(Err(AppError::NoAuthToken)),
        }
    }
}

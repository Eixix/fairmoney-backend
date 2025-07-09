use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use std::env;

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub fn create_jwt(user_id: String) -> Result<String, jsonwebtoken::errors::Error> {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let claims = Claims {
        sub: user_id,
        exp: 86400,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
}

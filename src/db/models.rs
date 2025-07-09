use serde::Serialize;
use uuid::Uuid;

#[derive(sqlx::FromRow, Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
}

impl User {
    pub fn new(username: String, password_hash: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            username,
            password_hash,
        }
    }
}

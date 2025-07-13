use diesel::Queryable;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone)]
pub struct RequestRegisterUser {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Clone, Debug, Queryable)]
pub struct User {
    pub uid: String,
    pub username: String,
    pub hashed_password: String,
}

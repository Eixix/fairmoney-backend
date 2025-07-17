use serde::{Deserialize, Serialize};

#[derive(Deserialize, Clone)]
pub struct NewUser {
    pub username: String,
    pub password: String,
}
#[derive(Deserialize)]
pub struct NewGroup {
    pub group_name: String,
}

#[derive(Deserialize)]
pub struct NewTransaction {
    pub transaction_name: String,
    pub amount: i32,
    pub group_id: String,
    pub created_by: String,
    pub created_at: Option<String>,
}

#[derive(Deserialize)]
pub struct NewGroupMembership {
    pub user_id: String,
    pub group_id: String,
}

#[derive(Deserialize)]
pub struct NewTransactionShare {
    pub transaction_id: String,
    pub user_id: String,
    pub paid_cents: i32,
    pub owed_cents: i32,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Serialize, Deserialize)]
pub struct LoginAnswer {
    pub token: String,
}

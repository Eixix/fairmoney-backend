use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema, Clone)]
pub struct NewUser {
    pub username: String,
    pub password: String,
}
#[derive(Deserialize, ToSchema)]
pub struct NewGroup {
    pub group_name: String,
}

#[derive(Deserialize, ToSchema)]
pub struct NewTransaction {
    pub transaction_name: String,
    pub amount: i32,
    pub group_id: String,
    pub created_by: String,
}

#[derive(Deserialize, ToSchema)]
pub struct NewGroupMembership {
    pub user_id: String,
    pub group_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct NewTransactionShare {
    pub transaction_id: String,
    pub user_id: String,
    pub paid_cents: i32,
    pub owed_cents: i32,
}

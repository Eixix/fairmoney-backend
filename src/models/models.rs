use crate::schema::{group_memberships, groups, transaction_shares, transactions, users};
use diesel::{Associations, Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, ToSchema, Clone, Debug, Queryable, Identifiable, Selectable, Insertable)]
#[diesel(primary_key(uid))]
pub struct User {
    pub uid: String,
    pub username: String,
    pub hashed_password: String,
}

#[derive(
    Serialize, ToSchema, Deserialize, Queryable, Identifiable, Selectable, Insertable, Clone,
)]
#[diesel(primary_key(uid))]
pub struct Group {
    pub uid: String,
    pub group_name: String,
    pub created_by: String,
}

#[derive(Insertable, ToSchema, Serialize, Deserialize, Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Group))]
#[diesel(belongs_to(User))]
#[diesel(primary_key(uid))]
pub struct GroupMembership {
    pub uid: String,
    pub user_id: String,
    pub group_id: String,
}

#[derive(
    Insertable,
    ToSchema,
    Deserialize,
    Clone,
    Queryable,
    Selectable,
    Identifiable,
    Serialize,
    Associations,
    Debug,
    PartialEq,
)]
#[diesel(belongs_to(Group))]
#[diesel(primary_key(uid))]
pub struct Transaction {
    pub uid: String,
    pub transaction_name: String,
    pub amount: i32,
    pub group_id: String,
    pub created_by: String,
    pub created_at: Option<String>,
}

#[derive(
    Insertable, ToSchema, Clone, Serialize, Deserialize, Queryable, Identifiable, Associations,
)]
#[diesel(belongs_to(User))]
#[diesel(belongs_to(Transaction))]
#[diesel(primary_key(uid))]
pub struct TransactionShare {
    pub uid: String,
    pub transaction_id: String,
    pub user_id: String,
    pub paid_cents: i32,
    pub owed_cents: i32,
}

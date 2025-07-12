use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use utoipa::ToSchema;

#[derive(sqlx::FromRow, Serialize, Deserialize, Clone, ToSchema)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn new(username: &str, email: &str, password_hash: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            email: email.to_string(),
            password_hash: password_hash.to_string(),
            created_at: Utc::now(),
        }
    }
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Clone, ToSchema)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub created_by: String, // user ID
    pub created_at: DateTime<Utc>,
}

impl Group {
    pub fn new(name: &str, created_by: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            created_by: created_by.to_string(),
            created_at: Utc::now(),
        }
    }
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Clone, ToSchema)]
pub struct GroupMember {
    pub group_id: String,
    pub user_id: String,
    pub joined_at: DateTime<Utc>,
}

impl GroupMember {
    pub fn new(group_id: &str, user_id: &str) -> Self {
        Self {
            group_id: group_id.to_string(),
            user_id: user_id.to_string(),
            joined_at: Utc::now(),
        }
    }
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Clone, ToSchema)]
pub struct Transaction {
    pub id: String,
    pub group_id: String,
    pub paid_by: String,
    pub amount: i64, // amount in cents
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Transaction {
    pub fn new(group_id: &str, paid_by: &str, amount: i64, description: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            group_id: group_id.to_string(),
            paid_by: paid_by.to_string(),
            amount,
            description,
            created_at: Utc::now(),
        }
    }
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Clone, ToSchema)]
pub struct TransactionShare {
    pub transaction_id: String,
    pub user_id: String,
    pub amount: i64,
}

impl TransactionShare {
    pub fn new(transaction_id: &str, user_id: &str, amount: i64) -> Self {
        Self {
            transaction_id: transaction_id.to_string(),
            user_id: user_id.to_string(),
            amount,
        }
    }
}

// Request/Response DTOs
#[derive(Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub user: User,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateGroupRequest {
    pub name: String,
}

#[derive(Deserialize, ToSchema)]
pub struct AddGroupMemberByEmailRequest {
    pub email: String,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateTransactionRequest {
    pub group_id: String,
    pub amount: i64,
    pub description: Option<String>,
    pub shares: Vec<TransactionShareRequest>,
}

#[derive(Deserialize, ToSchema)]
pub struct TransactionShareRequest {
    pub user_id: String,
    pub amount: i64,
}

#[derive(Serialize, ToSchema)]
pub struct GroupWithMembers {
    pub group: Group,
    pub members: Vec<User>,
}

#[derive(Serialize, ToSchema)]
pub struct TransactionWithShares {
    pub transaction: Transaction,
    pub shares: Vec<TransactionShare>,
    pub paid_by_user: User,
}
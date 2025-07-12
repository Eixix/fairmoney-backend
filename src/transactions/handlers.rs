use actix_web::{web, HttpResponse, HttpRequest};
use sqlx::SqlitePool;
use crate::db::models::{Transaction, TransactionShare, User, CreateTransactionRequest, TransactionWithShares};
use crate::auth::jwt::Claims;
use crate::errors::AppError;

/// Create a new transaction
#[utoipa::path(
    post,
    path = "/api/transactions",
    security(
        ("bearer_auth" = [])
    ),
    request_body = CreateTransactionRequest,
    responses(
        (status = 201, description = "Transaction created successfully", body = Transaction),
        (status = 400, description = "Invalid request data"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not a member of this group")
    ),
    tag = "Transactions"
)]
pub async fn create_transaction(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    transaction_data: web::Json<CreateTransactionRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = Claims::from_request(&req)?;
    
    // Check if user is member of the group
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id = ?",
    )
    .bind(&transaction_data.group_id)
    .bind(&claims.user_id)
    .fetch_one(pool.get_ref())
    .await?;
    let is_member = count.0 > 0;

    if !is_member {
        return Err(AppError::Forbidden("Not a member of this group".to_string()));
    }

    // Validate that the total shares equal the transaction amount
    let total_shares: i64 = transaction_data.shares.iter().map(|s| s.amount).sum();
    if total_shares != transaction_data.amount {
        return Err(AppError::BadRequest("Total shares must equal transaction amount".to_string()));
    }

    // Validate that all share users are members of the group
    for share in &transaction_data.shares {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id = ?",
        )
        .bind(&transaction_data.group_id)
        .bind(&share.user_id)
        .fetch_one(pool.get_ref())
        .await?;
        let is_share_user_member = count.0 > 0;

        if !is_share_user_member {
            return Err(AppError::BadRequest(format!("User {} is not a member of this group", share.user_id)));
        }
    }

    let transaction = Transaction::new(
        &transaction_data.group_id,
        &claims.user_id,
        transaction_data.amount,
        transaction_data.description.clone(),
    );

    // Insert transaction
    sqlx::query!(
        "INSERT INTO transactions (id, group_id, paid_by, amount, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        transaction.id,
        transaction.group_id,
        transaction.paid_by,
        transaction.amount,
        transaction.description,
        transaction.created_at
    )
    .execute(pool.get_ref())
    .await?;

    // Insert transaction shares
    for share_request in &transaction_data.shares {
        let share = TransactionShare::new(&transaction.id, &share_request.user_id, share_request.amount);
        sqlx::query!(
            "INSERT INTO transaction_shares (transaction_id, user_id, amount) VALUES (?, ?, ?)",
            share.transaction_id,
            share.user_id,
            share.amount
        )
        .execute(pool.get_ref())
        .await?;
    }

    Ok(HttpResponse::Created().json(transaction))
}

/// Get all transactions for a group
#[utoipa::path(
    get,
    path = "/api/transactions/group/{group_id}",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("group_id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 200, description = "List of transactions with shares", body = Vec<TransactionWithShares>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not a member of this group")
    ),
    tag = "Transactions"
)]
pub async fn get_group_transactions(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let claims = Claims::from_request(&req)?;
    let group_id = path.into_inner();
    
    // Check if user is member of the group
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id = ?",
    )
    .bind(&group_id)
    .bind(&claims.user_id)
    .fetch_one(pool.get_ref())
    .await?;
    let is_member = count.0 > 0;

    if !is_member {
        return Err(AppError::Forbidden("Not a member of this group".to_string()));
    }

    let transactions = sqlx::query_as_unchecked!(
        Transaction,
        r#"
        SELECT id, group_id, paid_by, amount, description, created_at
        FROM transactions
        WHERE group_id = ?
        ORDER BY created_at DESC
        "#,
        group_id
    )
    .fetch_all(pool.get_ref())
    .await?;

    let mut transactions_with_shares = Vec::new();

    for transaction in transactions {
        let shares = sqlx::query_as!(
            TransactionShare,
            "SELECT transaction_id, user_id, amount FROM transaction_shares WHERE transaction_id = ?",
            transaction.id
        )
        .fetch_all(pool.get_ref())
        .await?;

        let paid_by_user = sqlx::query_as_unchecked!(
            User,
            "SELECT id, username, email, password_hash, created_at FROM users WHERE id = ?",
            transaction.paid_by
        )
        .fetch_optional(pool.get_ref())
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        transactions_with_shares.push(TransactionWithShares {
            transaction,
            shares,
            paid_by_user,
        });
    }

    Ok(HttpResponse::Ok().json(transactions_with_shares))
}

/// Get transaction details
#[utoipa::path(
    get,
    path = "/api/transactions/{transaction_id}",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("transaction_id" = String, Path, description = "Transaction ID")
    ),
    responses(
        (status = 200, description = "Transaction details with shares", body = TransactionWithShares),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not a member of this group"),
        (status = 404, description = "Transaction not found")
    ),
    tag = "Transactions"
)]
pub async fn get_transaction(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let claims = Claims::from_request(&req)?;
    let transaction_id = path.into_inner();
    
    let transaction = sqlx::query_as_unchecked!(
        Transaction,
        "SELECT id, group_id, paid_by, amount, description, created_at FROM transactions WHERE id = ?",
        transaction_id
    )
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| AppError::NotFound("Transaction not found".to_string()))?;

    // Check if user is member of the group
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id = ?",
    )
    .bind(&transaction.group_id)
    .bind(&claims.user_id)
    .fetch_one(pool.get_ref())
    .await?;
    let is_member = count.0 > 0;

    if !is_member {
        return Err(AppError::Forbidden("Not a member of this group".to_string()));
    }

    let shares = sqlx::query_as!(
        TransactionShare,
        "SELECT transaction_id, user_id, amount FROM transaction_shares WHERE transaction_id = ?",
        transaction_id
    )
    .fetch_all(pool.get_ref())
    .await?;

    let paid_by_user = sqlx::query_as_unchecked!(
        User,
        "SELECT id, username, email, password_hash, created_at FROM users WHERE id = ?",
        transaction.paid_by
    )
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let transaction_with_shares = TransactionWithShares {
        transaction,
        shares,
        paid_by_user,
    };

    Ok(HttpResponse::Ok().json(transaction_with_shares))
}

/// Delete a transaction
#[utoipa::path(
    delete,
    path = "/api/transactions/{transaction_id}",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("transaction_id" = String, Path, description = "Transaction ID")
    ),
    responses(
        (status = 204, description = "Transaction deleted successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only the person who paid can delete this transaction"),
        (status = 404, description = "Transaction not found")
    ),
    tag = "Transactions"
)]
pub async fn delete_transaction(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let claims = Claims::from_request(&req)?;
    let transaction_id = path.into_inner();
    
    let transaction = sqlx::query_as_unchecked!(
        Transaction,
        "SELECT id, group_id, paid_by, amount, description, created_at FROM transactions WHERE id = ?",
        transaction_id
    )
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| AppError::NotFound("Transaction not found".to_string()))?;

    // Only the person who paid can delete the transaction
    if transaction.paid_by != claims.user_id {
        return Err(AppError::Forbidden("Only the person who paid can delete this transaction".to_string()));
    }

    // Delete transaction shares first (due to foreign key constraint)
    sqlx::query!(
        "DELETE FROM transaction_shares WHERE transaction_id = ?",
        transaction_id
    )
    .execute(pool.get_ref())
    .await?;

    // Delete transaction
    sqlx::query!(
        "DELETE FROM transactions WHERE id = ?",
        transaction_id
    )
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::NoContent().finish())
}

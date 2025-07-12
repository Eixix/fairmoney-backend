use actix_web::{web, HttpResponse, HttpRequest};
use sqlx::SqlitePool;
use crate::db::models::{Group, GroupMember, User, CreateGroupRequest, AddGroupMemberByEmailRequest, GroupWithMembers};
use crate::auth::jwt::Claims;
use crate::errors::AppError;

/// Create a new group
#[utoipa::path(
    post,
    path = "/api/groups",
    security(
        ("bearer_auth" = [])
    ),
    request_body = CreateGroupRequest,
    responses(
        (status = 201, description = "Group created successfully", body = Group),
        (status = 401, description = "Unauthorized")
    ),
    tag = "Groups"
)]
pub async fn create_group(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    group_data: web::Json<CreateGroupRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = Claims::from_request(&req)?;
    
    let group = Group::new(&group_data.name, &claims.user_id);
    
    sqlx::query!(
        "INSERT INTO groups (id, name, created_by, created_at) VALUES (?, ?, ?, ?)",
        group.id,
        group.name,
        group.created_by,
        group.created_at
    )
    .execute(pool.get_ref())
    .await?;

    // Add creator as member
    let member = GroupMember::new(&group.id, &claims.user_id);
    sqlx::query!(
        "INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)",
        member.group_id,
        member.user_id,
        member.joined_at
    )
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Created().json(group))
}

/// Get all groups for the current user
#[utoipa::path(
    get,
    path = "/api/groups",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List of user's groups", body = Vec<Group>),
        (status = 401, description = "Unauthorized")
    ),
    tag = "Groups"
)]
pub async fn get_groups(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let claims = Claims::from_request(&req)?;
    
    let groups = sqlx::query_as_unchecked!(
        Group,
        r#"
        SELECT g.id, g.name, g.created_by, g.created_at
        FROM groups g
        INNER JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.user_id = ?
        ORDER BY g.created_at DESC
        "#,
        claims.user_id
    )
    .fetch_all(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(groups))
}

/// Get group details with members
#[utoipa::path(
    get,
    path = "/api/groups/{group_id}",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("group_id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 200, description = "Group details with members", body = GroupWithMembers),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not a member of this group"),
        (status = 404, description = "Group not found")
    ),
    tag = "Groups"
)]
pub async fn get_group(
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

    let group = sqlx::query_as_unchecked!(
        Group,
        "SELECT id, name, created_by, created_at FROM groups WHERE id = ?",
        group_id
    )
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;

    let members = sqlx::query_as_unchecked!(
        User,
        r#"
        SELECT u.id, u.username, u.email, u.password_hash, u.created_at
        FROM users u
        INNER JOIN group_members gm ON u.id = gm.user_id
        WHERE gm.group_id = ?
        ORDER BY u.username
        "#,
        group_id
    )
    .fetch_all(pool.get_ref())
    .await?;

    let group_with_members = GroupWithMembers {
        group,
        members,
    };

    Ok(HttpResponse::Ok().json(group_with_members))
}

/// Add a member to a group by email
#[utoipa::path(
    post,
    path = "/api/groups/{group_id}/members",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("group_id" = String, Path, description = "Group ID")
    ),
    request_body = AddGroupMemberByEmailRequest,
    responses(
        (status = 201, description = "Member added successfully", body = GroupMember),
        (status = 400, description = "User already a member or not found"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only group creator can add members")
    ),
    tag = "Groups"
)]
pub async fn add_group_member(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
    member_data: web::Json<AddGroupMemberByEmailRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = Claims::from_request(&req)?;
    let group_id = path.into_inner();
    
    // Check if user is creator of the group
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM groups WHERE id = ? AND created_by = ?",
    )
    .bind(&group_id)
    .bind(&claims.user_id)
    .fetch_one(pool.get_ref())
    .await?;
    let is_creator = count.0 > 0;

    if !is_creator {
        return Err(AppError::Forbidden("Only group creator can add members".to_string()));
    }

    // Find user by email
    let user = sqlx::query_as_unchecked!(
        User,
        "SELECT id, username, email, password_hash, created_at FROM users WHERE email = ?",
        member_data.email
    )
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| AppError::NotFound("User with this email not found".to_string()))?;

    // Check if already a member
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id = ?",
    )
    .bind(&group_id)
    .bind(&user.id)
    .fetch_one(pool.get_ref())
    .await?;
    let already_member = count.0 > 0;

    if already_member {
        return Err(AppError::BadRequest("User is already a member".to_string()));
    }

    let member = GroupMember::new(&group_id, &user.id);
    sqlx::query!(
        "INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)",
        member.group_id,
        member.user_id,
        member.joined_at
    )
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Created().json(member))
}

/// Remove a member from a group
#[utoipa::path(
    delete,
    path = "/api/groups/{group_id}/members/{user_id}",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("group_id" = String, Path, description = "Group ID"),
        ("user_id" = String, Path, description = "User ID to remove")
    ),
    responses(
        (status = 204, description = "Member removed successfully"),
        (status = 400, description = "Cannot remove group creator"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only group creator can remove members")
    ),
    tag = "Groups"
)]
pub async fn remove_group_member(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, AppError> {
    let claims = Claims::from_request(&req)?;
    let (group_id, user_id) = path.into_inner();
    
    // Check if user is creator of the group
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM groups WHERE id = ? AND created_by = ?",
    )
    .bind(&group_id)
    .bind(&claims.user_id)
    .fetch_one(pool.get_ref())
    .await?;
    let is_creator = count.0 > 0;

    if !is_creator {
        return Err(AppError::Forbidden("Only group creator can remove members".to_string()));
    }

    // Don't allow removing the creator
    if user_id == claims.user_id {
        return Err(AppError::BadRequest("Cannot remove group creator".to_string()));
    }

    sqlx::query!(
        "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
        group_id,
        user_id
    )
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::NoContent().finish())
}

/// Delete a group (only group creator can delete)
#[utoipa::path(
    delete,
    path = "/api/groups/{group_id}",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("group_id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 204, description = "Group deleted successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only group creator can delete the group"),
        (status = 404, description = "Group not found")
    ),
    tag = "Groups"
)]
pub async fn delete_group(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let claims = Claims::from_request(&req)?;
    let group_id = path.into_inner();
    
    // Check if group exists and user is the creator
    let group = sqlx::query_as_unchecked!(
        Group,
        "SELECT id, name, created_by, created_at FROM groups WHERE id = ?",
        group_id
    )
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;

    if group.created_by != claims.user_id {
        return Err(AppError::Forbidden("Only group creator can delete the group".to_string()));
    }

    // Delete the group (cascade will handle related records)
    sqlx::query!(
        "DELETE FROM groups WHERE id = ?",
        group_id
    )
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::NoContent().finish())
} 
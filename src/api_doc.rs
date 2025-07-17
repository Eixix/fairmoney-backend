use crate::handlers::*;
use crate::models::auth::Claims;
use crate::models::auth::LoginAnswer;
use crate::models::models::{Group, GroupMembership, Transaction, TransactionShare, User};
use crate::models::request_models::{
    NewGroup, NewGroupMembership, NewTransaction, NewTransactionShare, NewUser,
};
use utoipa::openapi::{
    security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    OpenApi as OpenApiDoc,
};
use utoipa::{Modify, OpenApi};

pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut OpenApiDoc) {
        openapi.components = openapi.components.take().map(|mut components| {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
            components
        });
    }
}
#[derive(OpenApi)]
#[openapi(
    paths(
        register,
        login,
        get_groups_for_user,
        create_group,
        update_group,
        delete_group_handler,
        get_transactions_for_group,
        create_transaction,
        update_transaction,
        delete_transaction_handler,
        create_group_membership,
        get_transaction_shares_for_transaction,
        create_transaction_share,
        update_transaction_share,
        delete_transaction_share_handler,
    ),
    components(
        schemas(
            User,
            NewUser,
            Group,
            NewGroup,
            Transaction,
            NewTransaction,
            TransactionShare,
            NewTransactionShare,
            GroupMembership,
            NewGroupMembership,
            LoginAnswer,
            Claims,
        ),
    ),
    tags(
        (name = "Auth", description = "Authentication endpoints"),
        (name = "Users", description = "User related endpoints"),
        (name = "Groups", description = "Group management endpoints"),
        (name = "Transactions", description = "Transaction management endpoints"),
        (name = "Group Memberships", description = "Group membership endpoints"),
        (name = "Transaction Shares", description = "Transaction share endpoints"),
    ),
    info(
        title = "FairMoney API",
        description = "A complete expense tracking API similar to Tricount or Splitwise",
        version = "1.0.0",
        contact(
            name = "FairMoney",
            email = "fairmoney@betz.coffee"
        )
    ),
    servers(
        (url = "http://localhost:8080", description = "Development server")
    ),
    security(
        ("bearer_auth" = [])
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

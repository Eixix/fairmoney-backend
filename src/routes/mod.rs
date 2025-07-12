use actix_web::web;
use crate::auth::handlers::{login, register, me};
use crate::groups::handlers::{create_group, get_groups, get_group, add_group_member, remove_group_member, delete_group};
use crate::transactions::handlers::{create_transaction, get_group_transactions, get_transaction, delete_transaction};

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .service(
                web::scope("/auth")
                    .route("/login", web::post().to(login))
                    .route("/register", web::post().to(register))
                    .route("/me", web::get().to(me))
            )
            .service(
                web::scope("/groups")
                    .route("", web::post().to(create_group))
                    .route("", web::get().to(get_groups))
                    .route("/{group_id}", web::get().to(get_group))
                    .route("/{group_id}/members", web::post().to(add_group_member))
                    .route("/{group_id}/members/{user_id}", web::delete().to(remove_group_member))
                    .route("/{group_id}", web::delete().to(delete_group))
            )
            .service(
                web::scope("/transactions")
                    .route("", web::post().to(create_transaction))
                    .route("/group/{group_id}", web::get().to(get_group_transactions))
                    .route("/{transaction_id}", web::get().to(get_transaction))
                    .route("/{transaction_id}", web::delete().to(delete_transaction))
            )
    );
}

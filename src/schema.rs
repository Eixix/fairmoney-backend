// @generated automatically by Diesel CLI.

diesel::table! {
    group_memberships (uid) {
        uid -> Text,
        user_id -> Text,
        group_id -> Text,
    }
}

diesel::table! {
    groups (uid) {
        uid -> Text,
        group_name -> Text,
        created_by -> Text,
    }
}

diesel::table! {
    transaction_shares (uid) {
        uid -> Text,
        transaction_id -> Text,
        user_id -> Text,
        paid_cents -> Integer,
        owed_cents -> Integer,
    }
}

diesel::table! {
    transactions (uid) {
        uid -> Text,
        transaction_name -> Text,
        amount -> Integer,
        group_id -> Text,
        created_by -> Text,
        created_at -> Nullable<Text>,
    }
}

diesel::table! {
    users (uid) {
        uid -> Text,
        username -> Text,
        hashed_password -> Text,
    }
}

diesel::joinable!(group_memberships -> groups (group_id));
diesel::joinable!(group_memberships -> users (user_id));
diesel::joinable!(groups -> users (created_by));
diesel::joinable!(transaction_shares -> transactions (transaction_id));
diesel::joinable!(transaction_shares -> users (user_id));
diesel::joinable!(transactions -> groups (group_id));
diesel::joinable!(transactions -> users (created_by));

diesel::allow_tables_to_appear_in_same_query!(
    group_memberships,
    groups,
    transaction_shares,
    transactions,
    users,
);

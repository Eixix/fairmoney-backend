use crate::models::models::{Group, GroupMembership, Transaction, TransactionShare, User};
use crate::models::request_models::{NewTransaction, NewTransactionShare};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::RunQueryDsl;

pub fn insert_new_user(connection: &mut SqliteConnection, user: User) -> QueryResult<User> {
    use crate::schema::users::dsl::users;

    let new_user = User {
        uid: user.uid,
        username: user.username,
        hashed_password: user.hashed_password,
    };

    diesel::insert_into(users)
        .values(&new_user)
        .execute(connection)
        .expect("Error inserting user");

    Ok(new_user)
}

pub fn check_if_user_exists(
    connection: &mut SqliteConnection,
    user_name: &str,
) -> QueryResult<bool> {
    use crate::schema::users::dsl::{username, users};

    diesel::select(diesel::dsl::exists(users.filter(username.eq(user_name)))).get_result(connection)
}

pub fn get_user_by_username(
    connection: &mut SqliteConnection,
    user_name: &str,
) -> QueryResult<User> {
    use crate::schema::users::dsl::{username, users};

    users
        .filter(username.eq(user_name))
        .first::<User>(connection)
}

pub fn get_user_groups(
    conn: &mut SqliteConnection,
    user_uid: &str,
) -> Result<Vec<Group>, diesel::result::Error> {
    use crate::schema::group_memberships::dsl::*;
    use crate::schema::groups::dsl::{groups, uid as group_uid};

    let group_ids: Vec<String> = group_memberships
        .filter(user_id.eq(user_uid))
        .select(group_id)
        .load::<String>(conn)?;

    groups
        .filter(group_uid.eq_any(group_ids))
        .load::<Group>(conn)
}

pub fn insert_new_group(conn: &mut SqliteConnection, name: String) -> QueryResult<Group> {
    use crate::schema::groups::dsl::groups;
    let group = Group {
        uid: uuid::Uuid::new_v4().to_string(),
        group_name: name,
    };

    diesel::insert_into(groups).values(&group).execute(conn)?;

    Ok(group)
}

pub fn update_group_by_id(
    conn: &mut SqliteConnection,
    group: &Group,
) -> Result<Group, diesel::result::Error> {
    use crate::schema::groups::dsl::*;

    diesel::update(groups.filter(uid.eq(&group.uid)))
        .set(group_name.eq(&group.group_name))
        .execute(conn)?;

    Ok(group.clone())
}

pub fn delete_group(
    conn: &mut SqliteConnection,
    group_uid_val: &str,
) -> Result<(), diesel::result::Error> {
    use crate::schema::groups::dsl::*;
    diesel::delete(groups.filter(uid.eq(group_uid_val))).execute(conn)?;
    Ok(())
}

pub fn get_transactions_by_group(
    conn: &mut SqliteConnection,
    group_id_val: &str,
) -> Result<Vec<Transaction>, diesel::result::Error> {
    use crate::schema::transactions::dsl::*;
    transactions
        .filter(group_id.eq(group_id_val))
        .load::<Transaction>(conn)
}

pub fn insert_new_transaction(
    conn: &mut SqliteConnection,
    new_txn: NewTransaction,
) -> QueryResult<Transaction> {
    use crate::schema::transactions::dsl::transactions;
    let txn = Transaction {
        uid: uuid::Uuid::new_v4().to_string(),
        transaction_name: new_txn.transaction_name,
        amount: new_txn.amount,
        group_id: new_txn.group_id,
        created_by: new_txn.created_by,
        created_at: new_txn.created_at,
    };

    diesel::insert_into(transactions)
        .values(&txn)
        .execute(conn)?;

    Ok(txn)
}

pub fn update_transaction_by_id(
    conn: &mut SqliteConnection,
    txn: &Transaction,
) -> Result<Transaction, diesel::result::Error> {
    use crate::schema::transactions::dsl::*;

    diesel::update(transactions.filter(uid.eq(&txn.uid)))
        .set((
            group_id.eq(&txn.group_id),
            transaction_name.eq(&txn.transaction_name),
            amount.eq(&txn.amount),
            created_by.eq(&txn.created_by),
        ))
        .execute(conn)?;

    Ok(txn.clone())
}

pub fn delete_transaction(
    conn: &mut SqliteConnection,
    transaction_uid_val: &str,
) -> Result<(), diesel::result::Error> {
    use crate::schema::transactions::dsl::*;
    diesel::delete(transactions.filter(uid.eq(transaction_uid_val))).execute(conn)?;
    Ok(())
}

pub fn insert_new_group_membership(
    conn: &mut SqliteConnection,
    user_id: String,
    group_id: String,
) -> QueryResult<GroupMembership> {
    use crate::schema::group_memberships::dsl::group_memberships;
    let membership = GroupMembership {
        uid: uuid::Uuid::new_v4().to_string(),
        user_id,
        group_id,
    };

    diesel::insert_into(group_memberships)
        .values(&membership)
        .execute(conn)?;

    Ok(membership)
}

pub fn get_shares_by_transaction(
    conn: &mut SqliteConnection,
    transaction_id_val: &str,
) -> Result<Vec<TransactionShare>, diesel::result::Error> {
    use crate::schema::transaction_shares::dsl::*;
    transaction_shares
        .filter(transaction_id.eq(transaction_id_val))
        .load::<TransactionShare>(conn)
}

pub fn insert_new_transaction_share(
    conn: &mut SqliteConnection,
    new_share: NewTransactionShare,
) -> QueryResult<TransactionShare> {
    use crate::schema::transaction_shares::dsl::transaction_shares;
    let share = TransactionShare {
        uid: uuid::Uuid::new_v4().to_string(),
        transaction_id: new_share.transaction_id,
        user_id: new_share.user_id,
        paid_cents: new_share.paid_cents,
        owed_cents: new_share.owed_cents,
    };

    diesel::insert_into(transaction_shares)
        .values(&share)
        .execute(conn)?;

    Ok(share)
}

pub fn update_transaction_share_by_id(
    conn: &mut SqliteConnection,
    share: &TransactionShare,
) -> Result<TransactionShare, diesel::result::Error> {
    use crate::schema::transaction_shares::dsl::*;

    diesel::update(transaction_shares.filter(uid.eq(&share.uid)))
        .set((
            transaction_id.eq(&share.transaction_id),
            user_id.eq(&share.user_id),
            paid_cents.eq(&share.paid_cents),
            owed_cents.eq(&share.owed_cents),
        ))
        .execute(conn)?;

    Ok(share.clone())
}

pub fn delete_transaction_share(
    conn: &mut SqliteConnection,
    share_uid_val: &str,
) -> Result<(), diesel::result::Error> {
    use crate::schema::transaction_shares::dsl::*;
    diesel::delete(transaction_shares.filter(uid.eq(share_uid_val))).execute(conn)?;
    Ok(())
}

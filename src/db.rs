use crate::models::User;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::RunQueryDsl;

pub fn insert_new_user(connection: &mut SqliteConnection, user: User) -> QueryResult<User> {
    use crate::schema::users::dsl::*;

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
    use crate::schema::users::dsl::*;

    diesel::select(diesel::dsl::exists(users.filter(username.eq(user_name)))).get_result(connection)
}

pub fn get_user_by_username(
    connection: &mut SqliteConnection,
    user_name: &str,
) -> QueryResult<User> {
    use crate::schema::users::dsl::*;

    users
        .filter(username.eq(user_name))
        .first::<User>(connection)
}

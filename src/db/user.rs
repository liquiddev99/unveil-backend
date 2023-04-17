use crate::db::schema::users;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Insertable, Debug, Serialize, Deserialize, Queryable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Queryable, Serialize, Deserialize, PartialEq, Insertable)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserClaim {
    pub exp: i64,
    pub id: String,
    pub name: String,
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserForm {
    pub name: String,
    pub email: String,
}

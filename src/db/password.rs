use crate::db::schema::passwords;
use crate::db::user::User;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordForm {
    pub name: String,
    pub username: String,
    pub value: String,
    pub website: Option<String>,
    pub note: Option<String>,
}

#[derive(Insertable, Queryable, Serialize, Deserialize, Debug)]
#[diesel(table_name = passwords)]
pub struct NewPassword {
    pub name: String,
    pub username: String,
    pub value: Option<Vec<u8>>,
    pub website: Option<String>,
    pub note: Option<String>,
    pub key: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub user_id: String,
}

#[derive(Serialize, Deserialize, Queryable, Associations)]
#[diesel(belongs_to(User))]
#[diesel(table_name = passwords)]
pub struct Password {
    pub id: String,
    pub name: String,
    pub username: String,
    pub value: Vec<u8>,
    pub website: Option<String>,
    pub note: Option<String>,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub user_id: String,
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum ErrorCode {
    NotFound,
    BadRequest,
    Forbidden,
    InternalServer,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub code: ErrorCode,
    pub msg: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordResponse {
    pub id: String,
    pub name: String,
    pub value: String,
    pub website: Option<String>,
    pub note: Option<String>,
}

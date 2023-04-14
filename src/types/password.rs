use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ReturnPassword {
    pub id: String,
    pub name: String,
    pub username: String,
    pub website: Option<String>,
    pub note: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

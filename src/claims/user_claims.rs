#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UserClaims {
    pub name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub picture: Option<String>,
}

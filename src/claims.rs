mod authorization_claims;
mod user_claims;

use std::time::{Duration, SystemTime};

pub use authorization_claims::AuthorizationClaims;
pub use user_claims::UserClaims;

use crate::scope::Scope;

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Claims<Extension> {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub iat: u64,
    pub exp: u64,
    #[serde(flatten)]
    pub extension: Extension,
}

type Resource = String;
type Action = String;
type ActionList = Vec<Action>;

impl<Extension> Claims<Extension> {
    pub fn new(
        iss: &str,
        sub: &str,
        aud: &Vec<String>,
        lifetime: Duration,
        extension: Extension,
    ) -> Self {
        let iat = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Expected system time since epoch");
        let exp = iat + lifetime;
        Self {
            iss: iss.to_string(),
            sub: sub.to_string(),
            aud: aud.clone(),
            iat: iat.as_secs(),
            exp: exp.as_secs(),
            extension,
        }
    }
}

mod authorization_claims;
mod user_claims;

use std::{
    time::{Duration, SystemTime},
    vec,
};

pub use authorization_claims::AuthorizationClaims;
pub use user_claims::UserClaims;

use crate::scope::Scope;

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl From<Vec<String>> for Audience {
    fn from(value: Vec<String>) -> Self {
        Audience::Multiple(value)
    }
}

impl IntoIterator for Audience {
    type Item = String;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Audience::Single(single) => vec![single],
            Audience::Multiple(multiple) => multiple,
        }
        .into_iter()
    }
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Claims<Extension> {
    pub iss: String,
    pub sub: String,
    pub aud: Audience,
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
            aud: aud.clone().into(),
            iat: iat.as_secs(),
            exp: exp.as_secs(),
            extension,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct TestExtension {}

    #[test]
    fn claims_can_be_constructed_with_single_audience() {
        let string = r#"
        {
            "iss": "issuer",
            "sub": "subject",
            "aud": "audience",
            "scope": "create:users read:users",
            "iat": 1000,
            "exp": 1000
        }"#;
        let claims: Claims<TestExtension> =
            serde_json::from_str(string).expect("Expected deserialize");
        let aud = claims.aud.into_iter().collect::<Vec<_>>();
        let expected_aud = vec!["audience".to_string()];
        assert_eq!(aud, expected_aud);
    }

    #[test]
    fn claims_can_be_constructed_with_multiple_audiences() {
        let string = r#"
        {
            "iss": "issuer",
            "sub": "subject",
            "aud": ["audience_a", "audience_b", "audience_c"],
            "scope" :"create:users read:users",
            "iat": 1000,
            "exp": 1000
        }"#;
        let claims: Claims<TestExtension> =
            serde_json::from_str(string).expect("Expected deserialize");
        let aud = claims.aud.into_iter().collect::<Vec<_>>();
        let expected_aud = vec![
            "audience_a".to_string(),
            "audience_b".to_string(),
            "audience_c".to_string(),
        ];
        assert_eq!(aud, expected_aud);
    }
}

use std::time::{Duration, SystemTime};

use crate::{scope::Scope, space_separated_deserialize, space_separated_serialize};

#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Claims {
    iss: String,
    sub: String,
    aud: String,
    #[serde(
        deserialize_with = "space_separated_deserialize",
        serialize_with = "space_separated_serialize",
        alias = "scope",
        rename(serialize = "scope")
    )]
    pub scopes: Vec<Scope>,
    iat: u64,
    exp: u64,
}

impl Claims {
    pub fn new(iss: &str, sub: &str, aud: &str, scopes: Vec<Scope>) -> Self {
        let iat = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Expected system time since epoch");
        let exp = iat + Duration::new(86400, 0);
        Self {
            iss: iss.to_string(),
            sub: sub.to_string(),
            aud: aud.to_string(),
            scopes,
            iat: iat.as_secs(),
            exp: exp.as_secs(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{claims::Claims, scope::Scope};

    #[test]
    fn can_be_deserialized_from_string() {
        let string = r#"{"iss":"issuer","sub":"subject","aud":"audience","scope":"create:users read:users","iat":1000,"exp":1000}"#;
        let claims: Claims = serde_json::from_str(string).expect("Expected deserialize");
        let scope_create_users = Scope {
            action: "create".to_string(),
            resource: "users".to_string(),
        };
        let scope_read_users = Scope {
            action: "read".to_string(),
            resource: "users".to_string(),
        };
        let expected_claims = Claims {
            iss: "issuer".to_string(),
            sub: "subject".to_string(),
            aud: "audience".to_string(),
            scopes: vec![scope_create_users, scope_read_users],
            iat: 1000,
            exp: 1000,
        };
        assert_eq!(claims, expected_claims)
    }

    #[test]
    fn can_be_serialized_to_string() {
        let scope_create_users = Scope {
            action: "create".to_string(),
            resource: "users".to_string(),
        };
        let scope_read_users = Scope {
            action: "read".to_string(),
            resource: "users".to_string(),
        };
        let claims = Claims {
            iss: "issuer".to_string(),
            sub: "subject".to_string(),
            aud: "audience".to_string(),
            scopes: vec![scope_create_users, scope_read_users],
            iat: 1000,
            exp: 1000,
        };
        let string = serde_json::to_string(&claims).expect("Expected serialize");
        let expected_string = r#"{"iss":"issuer","sub":"subject","aud":"audience","scope":"create:users read:users","iat":1000,"exp":1000}"#;
        assert_eq!(string, expected_string);
    }
}

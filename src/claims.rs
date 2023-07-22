use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

use crate::{scope::Scope, space_separated_deserialize, space_separated_serialize};

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct AuthorizationClaims {
    #[serde(
        deserialize_with = "space_separated_deserialize",
        serialize_with = "space_separated_serialize",
        alias = "scope",
        rename(serialize = "scope")
    )]
    pub scopes: Vec<Scope>,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Claims<Extension> {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(flatten)]
    pub extension: Extension,
}

type Resource = String;
type Action = String;
type ActionList = Vec<Action>;

impl<Extension> Claims<Extension> {
    pub fn new(iss: &str, sub: &str, aud: &str, lifetime: Duration, extension: Extension) -> Self {
        let iat = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Expected system time since epoch");
        let exp = iat + lifetime;
        Self {
            iss: iss.to_string(),
            sub: sub.to_string(),
            aud: aud.to_string(),
            iat: iat.as_secs(),
            exp: exp.as_secs(),
            extension,
        }
    }
}

impl Claims<AuthorizationClaims> {
    pub fn scopes(&self) -> &Vec<Scope> {
        &self.extension.scopes
    }

    pub fn resources(&self) -> HashMap<Resource, ActionList> {
        let mut resources = HashMap::<Resource, ActionList>::new();
        for scope in self.scopes().iter() {
            let resource = scope.resource.clone();
            let action = scope.action.clone();
            resources
                .entry(resource)
                .and_modify(|vec| vec.push(action.clone()))
                .or_insert(vec![action]);
        }
        resources
    }
}

#[cfg(test)]
mod test {
    use crate::{
        claims::{AuthorizationClaims, Claims},
        scope::Scope,
    };

    #[test]
    fn can_be_deserialized_from_string() {
        let string = r#"{"iss":"issuer","sub":"subject","aud":"audience","scope":"create:users read:users","iat":1000,"exp":1000}"#;
        let claims: Claims<AuthorizationClaims> =
            serde_json::from_str(string).expect("Expected deserialize");
        let scope_create_users = Scope {
            action: "create".to_string(),
            resource: "users".to_string(),
        };
        let scope_read_users = Scope {
            action: "read".to_string(),
            resource: "users".to_string(),
        };
        let extension = AuthorizationClaims {
            scopes: vec![scope_create_users, scope_read_users],
        };
        let expected_claims = Claims::<AuthorizationClaims> {
            iss: "issuer".to_string(),
            sub: "subject".to_string(),
            aud: "audience".to_string(),
            extension,
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
        let claims = Claims::<AuthorizationClaims> {
            iss: "issuer".to_string(),
            sub: "subject".to_string(),
            aud: "audience".to_string(),
            extension: AuthorizationClaims {
                scopes: vec![scope_create_users, scope_read_users],
            },
            iat: 1000,
            exp: 1000,
        };
        let string = serde_json::to_string(&claims).expect("Expected serialize");
        let expected_string = r#"{"iss":"issuer","sub":"subject","aud":"audience","scope":"create:users read:users","iat":1000,"exp":1000}"#;
        assert_eq!(string, expected_string);
    }
}

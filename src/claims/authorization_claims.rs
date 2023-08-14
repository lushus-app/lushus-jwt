use std::collections::HashMap;

use super::{ActionList, Claims, Resource, Scope};

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct AuthorizationClaims {
    #[serde(
        deserialize_with = "crate::space_separated_deserialize",
        serialize_with = "crate::space_separated_serialize",
        alias = "scope",
        rename(serialize = "scope")
    )]
    pub scopes: Vec<Scope>,
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
    use super::*;

    #[test]
    fn can_be_deserialized_from_string() {
        let string = r#"
        {
            "iss":"issuer",
            "sub":"subject",
            "aud":["audience"],
            "scope":"create:users read:users",
            "iat":1000,
            "exp":1000
        }"#;
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
            aud: vec!["audience".to_string()],
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
            aud: vec!["audience".to_string()],
            extension: AuthorizationClaims {
                scopes: vec![scope_create_users, scope_read_users],
            },
            iat: 1000,
            exp: 1000,
        };
        let string = serde_json::to_string(&claims).expect("Expected serialize");
        let expected_string = r#"{"iss":"issuer","sub":"subject","aud":["audience"],"iat":1000,"exp":1000,"scope":"create:users read:users"}"#;
        assert_eq!(string, expected_string);
    }
}

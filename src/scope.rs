use std::{
    fmt,
    fmt::{Display, Formatter},
    str::FromStr,
};

use serde::{de, de::Visitor, Deserializer, Serialize, Serializer};

use crate::{scope_deserializer::ScopeDeserializerError, serde_scope};

#[derive(Debug, Clone, PartialEq)]
pub struct Scope {
    pub action: String,
    pub resource: String,
}

impl Scope {
    pub fn new(action: &str, resource: &str) -> Self {
        Self {
            action: action.to_string(),
            resource: resource.to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    #[error("scope \"{0}\" has invalid format; expected format action:resource")]
    InvalidScopeFormat(String),
    #[error(transparent)]
    DeserializeError(#[from] ScopeDeserializerError),
}

impl FromStr for Scope {
    type Err = ScopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_scope::from_str(s).map_err(ScopeError::DeserializeError)
    }
}

impl Display for Scope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let string = serde_scope::to_string(self).map_err(|_| fmt::Error)?;
        write!(f, "{}", string)
    }
}

impl<'de> de::Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScopeVisitor;

        impl<'de> Visitor<'de> for ScopeVisitor {
            type Value = Scope;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("Scope")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let parts = v
                    .split(":")
                    .map(FromStr::from_str)
                    .collect::<Result<Vec<String>, _>>()
                    .map_err(de::Error::custom)?;
                if parts.len() < 2 || parts[0].len() < 1 || parts[1].len() < 1 {
                    return Err(ScopeError::InvalidScopeFormat(v.to_string()))
                        .map_err(de::Error::custom);
                }
                let action = &parts[0];
                let resource = &parts[1];
                let scope = Scope::new(action, resource);
                Ok(scope)
            }
        }

        let visitor = ScopeVisitor {};
        deserializer.deserialize_str(visitor)
    }
}

impl Serialize for Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let str = format!("{}:{}", self.action, self.resource);
        serializer.serialize_str(&str)
    }
}

#[cfg(test)]
mod test {
    use crate::{scope::Scope, ScopeError};

    #[test]
    fn scope_can_be_parsed_from_string() {
        let scope: Scope = "create:users".parse().expect("expected to parse");
        let expected_scope = Scope {
            action: "create".to_string(),
            resource: "users".to_string(),
        };
        assert_eq!(scope, expected_scope);
    }

    #[test]
    fn scope_cannot_be_parsed_from_invalid_string() {
        let scope = "create"
            .parse::<Scope>()
            .expect_err("expected to fail to parse");
        println!("{}", scope.to_string());
        assert!(matches!(scope, ScopeError::DeserializeError(_)))
    }

    #[test]
    fn scope_can_be_serialized_to_string() {
        let scope = Scope {
            action: "create".to_string(),
            resource: "users".to_string(),
        };
        let string = scope.to_string();
        let expected_string = "create:users";
        assert_eq!(string, expected_string);
    }
}

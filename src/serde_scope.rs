use serde::{Deserialize, Serialize};

use crate::{
    scope_deserializer::{ScopeDeserializer, ScopeDeserializerError},
    scope_serializer::{ScopeSerializer, ScopeSerializerError},
};

pub fn from_str<'a, T>(s: &'a str) -> Result<T, ScopeDeserializerError>
where
    T: Deserialize<'a>,
{
    let mut deserializer = ScopeDeserializer::from_str(s);
    let t = T::deserialize(&mut deserializer)?;
    if deserializer.input.is_empty() {
        Ok(t)
    } else {
        Err(ScopeDeserializerError::Error(
            "Failed to deserialize".to_string(),
        ))
    }
}

pub fn to_string<T>(value: &T) -> Result<String, ScopeSerializerError>
where
    T: Serialize,
{
    let mut serializer = ScopeSerializer {
        output: String::new(),
    };
    value.serialize(&mut serializer)?;
    Ok(serializer.output)
}

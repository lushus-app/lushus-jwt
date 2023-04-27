use std::{fmt, fmt::Display, marker::PhantomData, str::FromStr};

use serde::{de, de::Visitor, Deserializer, Serializer};

mod claims;
mod jwk_set_middleware;
mod jwt_middleware;
mod scope;
mod scope_deserializer;
mod scope_serializer;
mod serde_scope;
pub mod token;

pub use jwk_set_middleware::JwkSetFactory;
pub use jwt_middleware::{AuthorizationFactory, AuthorizationMiddleware};
pub use token::Token;

fn space_separated_deserialize<'de, V, T, D>(deserializer: D) -> Result<V, D::Error>
where
    V: FromIterator<T>,
    T: FromStr,
    T::Err: Display,
    D: Deserializer<'de>,
{
    struct SpaceSeparated<V, T>(PhantomData<V>, PhantomData<T>);

    impl<'de, V, T> Visitor<'de> for SpaceSeparated<V, T>
    where
        V: FromIterator<T>,
        T: FromStr,
        T::Err: Display,
    {
        type Value = V;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string containing space-separated elements")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let iter = s.split(" ").map(FromStr::from_str);
            Result::from_iter(iter).map_err(de::Error::custom)
        }
    }

    let visitor = SpaceSeparated(PhantomData, PhantomData);
    deserializer.deserialize_str(visitor)
}

fn space_separated_serialize<V, T, S>(x: &V, s: S) -> Result<S::Ok, S::Error>
where
    V: Clone + IntoIterator<Item = T>,
    T: ToString,
    S: Serializer,
{
    let iter = x
        .clone()
        .into_iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>();
    let res = iter.join(" ");
    s.serialize_str(&res)
}

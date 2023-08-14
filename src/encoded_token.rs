use std::{
    fmt::{Display, Formatter},
    marker::PhantomData,
};

use jsonwebtoken::{
    decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};

use crate::{token::Token, Claims};

#[derive(Debug, thiserror::Error)]
pub enum EncodedTokenError {
    #[error(transparent)]
    TokenError(#[from] jsonwebtoken::errors::Error),
    #[error("no matching JWK found in the JWK set")]
    NoJWKError,
    #[error("JWT does not provide a valid key id")]
    NoKID,
}

#[derive(Debug, Clone)]
pub struct EncodedToken<Extension> {
    encoded: String,
    phantom_data: PhantomData<Extension>,
}

impl<Extension> From<&str> for EncodedToken<Extension> {
    fn from(encoded: &str) -> Self {
        let split = encoded.split("Bearer ").collect::<Vec<_>>();
        let token = split[1];
        Self {
            encoded: token.to_string(),
            phantom_data: Default::default(),
        }
    }
}

impl<Extension> From<String> for EncodedToken<Extension> {
    fn from(encoded: String) -> Self {
        Self {
            encoded,
            phantom_data: Default::default(),
        }
    }
}

impl<Extension> Display for EncodedToken<Extension> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

impl<Extension> EncodedToken<Extension>
where
    Extension: serde::Serialize,
{
    pub fn new(
        header: Header,
        claims: Claims<Extension>,
        key: EncodingKey,
    ) -> Result<Self, EncodedTokenError> {
        let encoded_token = jsonwebtoken::encode(&header, &claims, &key)?.into();
        Ok(encoded_token)
    }
}

impl<Extension> EncodedToken<Extension>
where
    for<'a> Extension: serde::Deserialize<'a>,
{
    fn encoded(&self) -> &str {
        &self.encoded
    }

    fn header(&self) -> Result<Header, EncodedTokenError> {
        let header = decode_header(self.encoded())?;
        Ok(header)
    }

    fn kid(&self) -> Result<String, EncodedTokenError> {
        let kid = self.header()?.kid.ok_or(EncodedTokenError::NoKID)?;
        Ok(kid)
    }

    pub fn decode(self, jwk_set: &JwkSet) -> Result<Token<Extension>, EncodedTokenError> {
        let kid = self.kid()?;
        let jwk = jwk_set.find(&kid).ok_or(EncodedTokenError::NoJWKError)?;
        let decoding_key = DecodingKey::from_jwk(jwk)?;
        let validation = Validation::new(Algorithm::RS256);
        let decoded_token =
            decode::<Claims<Extension>>(self.encoded(), &decoding_key, &validation)?;
        let token = Token::new(decoded_token.header, decoded_token.claims);
        Ok(token)
    }
}

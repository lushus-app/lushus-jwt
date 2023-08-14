use crate::{token::Token, EncodedToken, UserClaims};

pub type EncodedIdToken = EncodedToken<UserClaims>;
pub type IdToken = Token<UserClaims>;

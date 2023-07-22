use std::{
    convert::Infallible,
    future::{ready, Ready},
};

use actix_web::{FromRequest, HttpMessage};

use crate::{AccessToken, AuthorizationClaims, Claims};

#[derive(Debug)]
pub struct Authorized(Option<AccessToken>);

impl Authorized {
    pub fn claims(&self) -> Option<Claims<AuthorizationClaims>> {
        self.0.as_ref().map(|token| token.claims().clone())
    }
}

impl FromRequest for Authorized {
    type Error = Infallible;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let token = req.extensions().get::<AccessToken>().cloned();
        let result = Ok(Authorized(token));
        ready(result)
    }
}

impl std::ops::Deref for Authorized {
    type Target = Option<AccessToken>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

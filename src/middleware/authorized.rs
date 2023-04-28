use std::{
    convert::Infallible,
    future::{ready, Ready},
};

use actix_web::{FromRequest, HttpMessage};

use crate::Token;

#[derive(Debug)]
pub struct Authorized(Option<Token>);

impl FromRequest for Authorized {
    type Error = Infallible;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let token = req.extensions().get::<Token>().cloned();
        let result = Ok(Authorized(token));
        ready(result)
    }
}

impl std::ops::Deref for Authorized {
    type Target = Option<Token>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

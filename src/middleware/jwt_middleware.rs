use std::{
    future::{ready, Ready},
    rc::Rc,
};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::StatusCode,
    Error, HttpMessage, ResponseError,
};
use futures::future::LocalBoxFuture;
use jsonwebtoken::jwk::JwkSet;

use crate::token::EncodedToken;

pub struct JWTFactory {}

impl JWTFactory {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for JWTFactory {
    fn default() -> Self {
        Self {}
    }
}

impl<S, B> Transform<S, ServiceRequest> for JWTFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JWTMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let middleware = JWTMiddleware {
            service: Rc::new(service),
        };
        ready(Ok(middleware))
    }
}

pub struct JWTMiddleware<S> {
    service: Rc<S>,
}

#[derive(Debug, thiserror::Error)]
pub enum JWTMiddlewareError {
    #[error("no authorization header present")]
    NoAuthorizationHeader,
    #[error("authorization header is invalid")]
    InvalidAuthorizationHeader,
    #[error("no JWK set available")]
    NoJWKSet,
    #[error("encoded token is not valid")]
    InvalidEncodedToken,
}

impl ResponseError for JWTMiddlewareError {
    fn status_code(&self) -> StatusCode {
        StatusCode::FORBIDDEN
    }
}

impl<S, B> Service<ServiceRequest> for JWTMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        Box::pin(async move {
            let headers = req.headers();
            let auth = headers
                .get("Authorization")
                .ok_or(JWTMiddlewareError::NoAuthorizationHeader)?
                .to_str()
                .map_err(|_| JWTMiddlewareError::InvalidAuthorizationHeader)?;
            let jwk_set = req
                .extensions()
                .get::<JwkSet>()
                .ok_or(JWTMiddlewareError::NoJWKSet)?
                .clone();
            let encoded_token: EncodedToken = auth.into();
            let token = encoded_token
                .decode(&jwk_set)
                .map_err(|_| JWTMiddlewareError::InvalidEncodedToken)?;
            req.extensions_mut().insert(token);
            let res = service.call(req).await?;
            Ok(res)
        })
    }

    forward_ready!(service);
}

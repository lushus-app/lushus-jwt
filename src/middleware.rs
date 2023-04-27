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

pub struct AuthorizationFactory {}

impl AuthorizationFactory {
    pub fn new() -> Self {
        Self {}
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthorizationFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthorizationMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let middleware = AuthorizationMiddleware {
            service: Rc::new(service),
        };
        ready(Ok(middleware))
    }
}

pub struct AuthorizationMiddleware<S> {
    service: Rc<S>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationMiddlewareError {
    #[error("no authorization header present")]
    NoAuthorizationHeader,
    #[error("authorization header is invalid")]
    InvalidAuthorizationHeader,
    #[error("encoded token {0} is not valid")]
    InvalidEncodedToken(String),
}

impl ResponseError for AuthorizationMiddlewareError {
    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl<S, B> Service<ServiceRequest> for AuthorizationMiddleware<S>
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
                .ok_or(AuthorizationMiddlewareError::NoAuthorizationHeader)?
                .to_str()
                .map_err(|_| AuthorizationMiddlewareError::InvalidAuthorizationHeader)?;
            let jwk_set = req.extensions().get::<JwkSet>().unwrap().clone();
            let encoded_token: EncodedToken = auth.into();
            let token = encoded_token.clone().decode(&jwk_set).map_err(|_| {
                AuthorizationMiddlewareError::InvalidEncodedToken(encoded_token.to_string())
            })?;
            req.extensions_mut().insert(token);
            let res = service.call(req).await?;
            Ok(res)
        })
    }

    forward_ready!(service);
}

use std::{
    future::{ready, Ready},
    rc::Rc,
};

use actix_web::{
    body::BoxBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::StatusCode,
    Error, HttpMessage, HttpResponse, HttpResponseBuilder, ResponseError,
};
use futures::future::LocalBoxFuture;
use jsonwebtoken::jwk::JwkSet;

use crate::{
    middleware::error_response::{forbidden_error_body, internal_server_error_body},
    token::EncodedToken,
};

pub struct JWTFactory {
    enabled: bool,
}

impl JWTFactory {
    pub fn new() -> Self {
        Self { enabled: true }
    }

    pub fn enabled(mut self, value: bool) -> Self {
        self.enabled = value;
        self
    }
}

impl Default for JWTFactory {
    fn default() -> Self {
        Self::new()
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
            enabled: Rc::new(self.enabled),
        };
        ready(Ok(middleware))
    }
}

pub struct JWTMiddleware<S> {
    service: Rc<S>,
    enabled: Rc<bool>,
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
        match self {
            JWTMiddlewareError::NoJWKSet => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let error_body = match self {
            JWTMiddlewareError::NoJWKSet => internal_server_error_body("NO_JWK_SET", self),
            JWTMiddlewareError::NoAuthorizationHeader => {
                forbidden_error_body("NO_AUTHORIZATION_HEADER", self)
            }
            JWTMiddlewareError::InvalidAuthorizationHeader => {
                forbidden_error_body("INVALID_AUTHORIZATION_HEADER", self)
            }
            JWTMiddlewareError::InvalidEncodedToken => {
                forbidden_error_body("INVALID_ENCODED_TOKEN", self)
            }
        };
        HttpResponseBuilder::new(self.status_code()).json(error_body)
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
        let enabled = self.enabled.clone();
        Box::pin(async move {
            if !*enabled {
                let res = service.call(req).await?;
                return Ok(res);
            }

            let headers = req.headers();
            let auth = headers
                .get("Authorization")
                .ok_or(JWTMiddlewareError::NoAuthorizationHeader)
                .map_err(|e| {
                    log::info!("{}", e);
                    e
                })?
                .to_str()
                .map_err(|_| JWTMiddlewareError::InvalidAuthorizationHeader)
                .map_err(|e| {
                    log::info!("{}", e);
                    e
                })?;
            let jwk_set = req
                .extensions()
                .get::<JwkSet>()
                .ok_or(JWTMiddlewareError::NoJWKSet)
                .map_err(|e| {
                    log::info!("{}", e);
                    e
                })?
                .clone();
            let encoded_token: EncodedToken = auth.into();
            let token = encoded_token
                .decode(&jwk_set)
                .map_err(|_| JWTMiddlewareError::InvalidEncodedToken)
                .map_err(|e| {
                    log::info!("{}", e);
                    e
                })?;
            req.extensions_mut().insert(token);
            let res = service.call(req).await?;
            Ok(res)
        })
    }

    forward_ready!(service);
}

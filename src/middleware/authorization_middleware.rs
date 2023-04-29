use std::{
    future::{ready, Ready},
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use actix_web::{
    body::BoxBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::StatusCode,
    Error, HttpMessage, HttpResponse, HttpResponseBuilder, ResponseError,
};
use futures::future::LocalBoxFuture;

use crate::{
    middleware::error_response::{forbidden_error_body, internal_server_error_body},
    Token,
};

#[derive(Clone, Debug)]
struct ExpectedClaims {
    pub expected_issuer: String,
    pub expected_audience: String,
}

pub struct AuthorizationFactory {
    expected_claims: ExpectedClaims,
}

impl AuthorizationFactory {
    pub fn new(expected_issuer: String, expected_audience: String) -> Self {
        let expected_claims = ExpectedClaims {
            expected_issuer,
            expected_audience,
        };
        Self { expected_claims }
    }
}

impl Default for AuthorizationFactory {
    fn default() -> Self {
        let authority = std::env::var("LUSHUS_AUTHORITY")
            .expect("expected environment var LUSHUS_AUTHORITY to be set");
        let audience = std::env::var("LUSHUS_AUDIENCE")
            .expect("expected environment var LUSHUS_AUDIENCE to be set");
        Self::new(authority, audience)
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
            expected_claims: Rc::new(self.expected_claims.clone()),
        };
        ready(Ok(middleware))
    }
}

pub struct AuthorizationMiddleware<S> {
    service: Rc<S>,
    expected_claims: Rc<ExpectedClaims>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationMiddlewareError {
    #[error("no token")]
    NoToken,
    #[error("invalid claims: {0}")]
    InvalidClaims(String),
}

impl ResponseError for AuthorizationMiddlewareError {
    fn status_code(&self) -> StatusCode {
        StatusCode::FORBIDDEN
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let error_body = match self {
            AuthorizationMiddlewareError::NoToken => internal_server_error_body("NO_TOKEN", self),
            AuthorizationMiddlewareError::InvalidClaims(_) => {
                forbidden_error_body("INVALID_CLAIMS", self)
            }
        };
        HttpResponseBuilder::new(self.status_code()).json(error_body)
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
        let expected_claims = self.expected_claims.clone();
        Box::pin(async move {
            let token = req
                .extensions()
                .get::<Token>()
                .ok_or(AuthorizationMiddlewareError::NoToken)?
                .clone();
            let claims = token.claims();
            let now = SystemTime::now();
            let timestamp = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

            (claims.iss == expected_claims.expected_issuer)
                .then_some(true)
                .ok_or(AuthorizationMiddlewareError::InvalidClaims(
                    "Issuer does not match".to_string(),
                ))
                .map_err(|e| {
                    log::info!("{}", e);
                    e
                })?;
            (claims.aud == expected_claims.expected_audience)
                .then_some(true)
                .ok_or(AuthorizationMiddlewareError::InvalidClaims(
                    "Audience does not match".to_string(),
                ))
                .map_err(|e| {
                    log::info!("{}", e);
                    e
                })?;
            (timestamp <= claims.exp)
                .then_some(true)
                .ok_or(AuthorizationMiddlewareError::InvalidClaims(
                    "Token is expired".to_string(),
                ))
                .map_err(|e| {
                    log::info!("{}", e);
                    e
                })?;

            let res = service.call(req).await?;
            Ok(res)
        })
    }

    forward_ready!(service);
}

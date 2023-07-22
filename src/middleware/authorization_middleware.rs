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
use chrono::Utc;
use futures::future::LocalBoxFuture;

use crate::{
    middleware::error_response::{forbidden_error_body, internal_server_error_body},
    AccessToken,
};

#[derive(Clone, Debug)]
struct ExpectedClaims {
    pub expected_issuer: String,
    pub expected_audience: String,
}

pub struct AuthorizationFactory {
    enabled: bool,
    expected_claims: ExpectedClaims,
}

impl AuthorizationFactory {
    pub fn new(expected_issuer: String, expected_audience: String) -> Self {
        let enabled = true;
        let expected_claims = ExpectedClaims {
            expected_issuer,
            expected_audience,
        };
        Self {
            expected_claims,
            enabled,
        }
    }

    pub fn enabled(mut self, value: bool) -> Self {
        self.enabled = value;
        self
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
            enabled: Rc::new(self.enabled),
            expected_claims: Rc::new(self.expected_claims.clone()),
        };
        ready(Ok(middleware))
    }
}

pub struct AuthorizationMiddleware<S> {
    service: Rc<S>,
    enabled: Rc<bool>,
    expected_claims: Rc<ExpectedClaims>,
}

fn require(condition: bool, message: &str) -> Result<(), AuthorizationMiddlewareError> {
    condition
        .then_some(true)
        .ok_or(AuthorizationMiddlewareError::InvalidClaims(
            message.to_string(),
        ))
        .map_err(|e| {
            log::info!("{}", e);
            e
        })?;
    Ok(())
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
        match self {
            AuthorizationMiddlewareError::InvalidClaims(_) => StatusCode::FORBIDDEN,
            AuthorizationMiddlewareError::NoToken => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let error_body = match self {
            AuthorizationMiddlewareError::InvalidClaims(_) => {
                forbidden_error_body("INVALID_CLAIMS", self)
            }
            AuthorizationMiddlewareError::NoToken => internal_server_error_body("NO_TOKEN", self),
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
        let enabled = self.enabled.clone();
        let expected_claims = self.expected_claims.clone();
        Box::pin(async move {
            if !*enabled {
                let res = service.call(req).await?;
                return Ok(res);
            }

            let token = req
                .extensions()
                .get::<AccessToken>()
                .ok_or(AuthorizationMiddlewareError::NoToken)?
                .clone();
            let claims = token.claims();
            let timestamp = Utc::now().timestamp() as u64;

            require(
                claims.iss == expected_claims.expected_issuer,
                "Issuer does not match",
            )?;
            require(
                claims.aud == expected_claims.expected_audience,
                "Audience does not match",
            )?;
            require(timestamp >= claims.iat, "Token issued for invalid time")?;
            require(timestamp <= claims.exp, "Token is expired")?;
            let res = service.call(req).await?;
            Ok(res)
        })
    }

    forward_ready!(service);
}

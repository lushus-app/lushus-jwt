use std::{
    future::{ready, Ready},
    marker::PhantomData,
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
    AccessToken, Claims, Issuer,
};

#[derive(Clone, Debug)]
struct ExpectedClaims {
    pub expected_audience: String,
}

pub struct AuthorizationFactory<I: Issuer> {
    enabled: bool,
    expected_claims: ExpectedClaims,
    phantom: PhantomData<I>,
}

impl<I: Issuer> AuthorizationFactory<I> {
    pub fn new(expected_audience: String) -> Self {
        let enabled = true;
        let expected_claims = ExpectedClaims { expected_audience };
        Self {
            expected_claims,
            enabled,
            phantom: Default::default(),
        }
    }

    pub fn enabled(mut self, value: bool) -> Self {
        self.enabled = value;
        self
    }
}

impl<I: Issuer> Default for AuthorizationFactory<I> {
    fn default() -> Self {
        let audience = std::env::var("LUSHUS_AUDIENCE")
            .expect("expected environment var LUSHUS_AUDIENCE to be set");
        Self::new(audience)
    }
}

impl<I, S, B> Transform<S, ServiceRequest> for AuthorizationFactory<I>
where
    I: Issuer + Clone + 'static,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthorizationMiddleware<I, S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let middleware = AuthorizationMiddleware {
            service: Rc::new(service),
            enabled: Rc::new(self.enabled),
            expected_claims: Rc::new(self.expected_claims.clone()),
            phantom: Default::default(),
        };
        ready(Ok(middleware))
    }
}

pub struct AuthorizationMiddleware<I, S> {
    service: Rc<S>,
    enabled: Rc<bool>,
    expected_claims: Rc<ExpectedClaims>,
    phantom: PhantomData<I>,
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
    #[error("no issuer")]
    NoIssuer,
    #[error("invalid claims: {0}")]
    InvalidClaims(String),
}

impl ResponseError for AuthorizationMiddlewareError {
    fn status_code(&self) -> StatusCode {
        match self {
            AuthorizationMiddlewareError::InvalidClaims(_) => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let error_body = match self {
            AuthorizationMiddlewareError::InvalidClaims(_) => {
                forbidden_error_body("INVALID_CLAIMS", self)
            }
            _ => internal_server_error_body("INVALID", self),
        };
        HttpResponseBuilder::new(self.status_code()).json(error_body)
    }
}

impl<I, S, B> Service<ServiceRequest> for AuthorizationMiddleware<I, S>
where
    I: Issuer + Clone + 'static,
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

            let extensions = req.extensions();
            let issuer = extensions
                .get::<I>()
                .ok_or(AuthorizationMiddlewareError::NoIssuer)?
                .url();
            let token = extensions
                .get::<AccessToken>()
                .ok_or(AuthorizationMiddlewareError::NoToken)?
                .clone();
            drop(extensions);

            let claims = token.claims().clone();
            let Claims { iss, aud, .. } = claims;
            let timestamp = Utc::now().timestamp() as u64;

            require(iss == issuer, "Issuer does not match")?;
            require(
                aud.into_iter()
                    .any(|aud| aud == expected_claims.expected_audience),
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

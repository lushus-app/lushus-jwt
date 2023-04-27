use std::{
    future::{ready, Ready},
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::StatusCode,
    Error, HttpMessage, ResponseError,
};
use futures::future::LocalBoxFuture;

use crate::Token;

#[derive(Clone, Debug)]
struct ExpectedClaims {
    pub expected_issuer: String,
    pub expected_audience: String,
}

pub struct AuthorizationFactory {
    expected_claims: ExpectedClaims,
    expected_resource: String,
}

impl AuthorizationFactory {
    pub fn new(
        expected_issuer: String,
        expected_audience: String,
        expected_resource: String,
    ) -> Self {
        let expected_claims = ExpectedClaims {
            expected_issuer,
            expected_audience,
        };
        Self {
            expected_claims,
            expected_resource,
        }
    }

    pub fn for_resource(resource: &str) -> Self {
        let authority = std::env::var("LUSHUS_AUTHORITY")
            .expect("expected environment var LUSHUS_AUTHORITY to be set");
        let audience = std::env::var("LUSHUS_AUDIENCE")
            .expect("expected environment var LUSHUS_AUDIENCE to be set");
        let resource = resource.to_string();
        Self::new(authority, audience, resource)
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
            expected_resource: self.expected_resource.clone(),
        };
        ready(Ok(middleware))
    }
}

pub struct AuthorizationMiddleware<S> {
    service: Rc<S>,
    expected_claims: Rc<ExpectedClaims>,
    expected_resource: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationMiddlewareError {
    #[error("no token")]
    NoToken,
    #[error("invalid claims")]
    InvalidClaims,
}

impl ResponseError for AuthorizationMiddlewareError {
    fn status_code(&self) -> StatusCode {
        StatusCode::FORBIDDEN
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
        let expected_resource = self.expected_resource.clone();
        Box::pin(async move {
            let token = req
                .extensions()
                .get::<Token>()
                .ok_or(AuthorizationMiddlewareError::NoToken)?
                .clone();

            let claims = token.claims();

            token
                .actions(&expected_resource)
                .ok_or(AuthorizationMiddlewareError::InvalidClaims)?;

            let now = SystemTime::now();
            let timestamp = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

            (claims.iss == expected_claims.expected_issuer)
                .then_some(true)
                .ok_or(AuthorizationMiddlewareError::InvalidClaims)?;
            (claims.aud == expected_claims.expected_audience)
                .then_some(true)
                .ok_or(AuthorizationMiddlewareError::InvalidClaims)?;
            (claims.iat < timestamp)
                .then_some(true)
                .ok_or(AuthorizationMiddlewareError::InvalidClaims)?;
            (claims.exp >= timestamp)
                .then_some(true)
                .ok_or(AuthorizationMiddlewareError::InvalidClaims)?;

            let res = service.call(req).await?;
            Ok(res)
        })
    }

    forward_ready!(service);
}
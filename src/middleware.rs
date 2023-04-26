use std::future::{ready, Ready};

use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures::future::LocalBoxFuture;
use jsonwebtoken::jwk::JwkSet;

use crate::token::EncodedToken;

pub struct AuthorizationFactory {
    jwk_set: JwkSet,
}

impl AuthorizationFactory {
    pub fn new(jwk_set: JwkSet) -> Self {
        Self { jwk_set }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthorizationFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AuthorizationMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let jwk_set = self.jwk_set.clone();
        let middleware = AuthorizationMiddleware { service, jwk_set };
        ready(Ok(middleware))
    }
}

pub struct AuthorizationMiddleware<S> {
    jwk_set: JwkSet,
    service: S,
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

#[derive(serde::Serialize)]
struct ErrorBody {
    code: String,
    message: String,
}

fn internal_server_error_body(code: &str, e: impl std::error::Error) -> ErrorBody {
    ErrorBody {
        code: code.to_string(),
        message: format!("An internal error occurred: {e}"),
    }
}

impl<S, B> Service<ServiceRequest> for AuthorizationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, req: ServiceRequest) -> Self::Future {
        println!("Hi from start. You requested: {}", req.path());

        let headers = req.headers();
        let auth = headers
            .get("Authorization")
            .ok_or(AuthorizationMiddlewareError::NoAuthorizationHeader);

        if let Err(e) = auth {
            let error = internal_server_error_body("NO AUTH HEADER", e);
            let response = HttpResponse::InternalServerError()
                .json(error)
                .map_into_right_body();
            let request = req.request().clone();
            return Box::pin(async move { Ok(Self::Response::new(request, response)) });
        }

        let auth = auth.unwrap().to_str();
        if let Err(e) = auth {
            let error = internal_server_error_body("AUTH HEADER INVALID", e);
            let response = HttpResponse::InternalServerError()
                .json(error)
                .map_into_right_body();
            let request = req.request().clone();
            return Box::pin(async move { Ok(Self::Response::new(request, response)) });
        }

        let encoded = auth.unwrap();
        let encoded_token: EncodedToken = encoded.into();
        println!("{:?}", encoded_token);
        let token = encoded_token.decode(&self.jwk_set);

        if let Err(e) = token {
            let error = internal_server_error_body("AUTH TOKEN INVALID", e);
            let response = HttpResponse::InternalServerError()
                .json(error)
                .map_into_right_body();
            let request = req.request().clone();
            return Box::pin(async move { Ok(Self::Response::new(request, response)) });
        }

        req.extensions_mut().insert(token.unwrap());

        let fut = self.service.call(req);
        Box::pin(async move {
            println!("Hi from response");
            fut.await.map(ServiceResponse::map_into_left_body)
        })
    }

    forward_ready!(service);
}

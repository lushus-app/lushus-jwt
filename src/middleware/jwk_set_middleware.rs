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
use futures::future::LocalBoxFuture;
use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions};
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};

use crate::{middleware::error_response::internal_server_error_body, Issuer};

pub struct JwkSetFactory<I: Issuer> {
    client: Rc<ClientWithMiddleware>,
    phantom: PhantomData<I>,
}

impl<I: Issuer> JwkSetFactory<I> {
    pub fn new() -> Self {
        let client = ClientBuilder::new(Client::new())
            .with(Cache(HttpCache {
                mode: CacheMode::Default,
                manager: CACacheManager::default(),
                options: HttpCacheOptions::default(),
            }))
            .build();
        let client = Rc::new(client);
        Self {
            client,
            phantom: Default::default(),
        }
    }
}

impl<I: Issuer> Default for JwkSetFactory<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I, S, B> Transform<S, ServiceRequest> for JwkSetFactory<I>
where
    I: Issuer + 'static,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JwkSetMiddleware<I, S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let middleware = JwkSetMiddleware {
            phantom: Default::default(),
            service: Rc::new(service),
            client: self.client.clone(),
        };
        ready(Ok(middleware))
    }
}

pub struct JwkSetMiddleware<I: Issuer, S> {
    phantom: PhantomData<I>,
    service: Rc<S>,
    // well_known_url: Rc<String>,
    client: Rc<ClientWithMiddleware>,
}

#[derive(thiserror::Error, Debug)]
pub enum JwkSetError {
    #[error("No issuer")]
    NoIssuer,
    #[error("unable to get JWK set: {0}")]
    FetchError(String),
    #[error("unable to deserialize JWK set")]
    DeserializeError,
}

impl ResponseError for JwkSetError {
    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let error_body = internal_server_error_body("NO_JWK_SET", self);
        HttpResponseBuilder::new(self.status_code()).json(error_body)
    }
}

impl<I, S, B> Service<ServiceRequest> for JwkSetMiddleware<I, S>
where
    I: Issuer + 'static,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let client = self.client.clone();
        Box::pin(async move {
            let extensions = req.extensions();
            let issuer = extensions.get::<I>().ok_or(JwkSetError::NoIssuer)?;
            let url = issuer.url();
            let jwk_set_url = format!("{url}/.well-known/jwks.json");
            let jwk_set = client
                .get(jwk_set_url)
                .send()
                .await
                .map_err(|e| JwkSetError::FetchError(e.to_string()))
                .map_err(|e| {
                    log::info!("{}", e);
                    e
                })?
                .json::<JwkSet>()
                .await
                .map_err(|_| JwkSetError::DeserializeError)
                .map_err(|e| {
                    log::info!("{}", e);
                    e
                })?;
            drop(extensions);
            req.extensions_mut().insert(jwk_set);
            let res = service.call(req).await?;
            Ok(res)
        })
    }

    forward_ready!(service);
}

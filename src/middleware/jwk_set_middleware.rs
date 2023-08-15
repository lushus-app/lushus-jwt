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
use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions};
use jsonwebtoken::jwk::JwkSet;
use reqwest::{Client, Url};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};

use crate::middleware::error_response::internal_server_error_body;

pub struct JwkSetFactory {
    well_known_url: Rc<String>,
    client: Rc<ClientWithMiddleware>,
}

impl JwkSetFactory {
    pub fn new(well_known_url: String) -> Self {
        let well_known_url = Rc::new(well_known_url);
        let client = ClientBuilder::new(Client::new())
            .with(Cache(HttpCache {
                mode: CacheMode::Default,
                manager: CACacheManager::default(),
                options: HttpCacheOptions::default(),
            }))
            .build();
        let client = Rc::new(client);
        Self {
            well_known_url,
            client,
        }
    }
}

impl Default for JwkSetFactory {
    fn default() -> Self {
        let authority = std::env::var("LUSHUS_AUTHORITY")
            .expect("expected environment var LUSHUS_AUTHORITY to be set");
        let well_known_url = Url::parse(&authority)
            .expect("expected authority to be a valid URL")
            .join(".well-known/jwks.json")
            .expect("expected well-known url to be valid")
            .to_string();
        Self::new(well_known_url)
    }
}

impl<S, B> Transform<S, ServiceRequest> for JwkSetFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JwkSetMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let middleware = JwkSetMiddleware {
            service: Rc::new(service),
            well_known_url: self.well_known_url.clone(),
            client: self.client.clone(),
        };
        ready(Ok(middleware))
    }
}

pub struct JwkSetMiddleware<S> {
    service: Rc<S>,
    well_known_url: Rc<String>,
    client: Rc<ClientWithMiddleware>,
}

#[derive(thiserror::Error, Debug)]
pub enum JwkSetError {
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

impl<S, B> Service<ServiceRequest> for JwkSetMiddleware<S>
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
        let client = self.client.clone();
        let url = self.well_known_url.clone();
        Box::pin(async move {
            let jwk_set = client
                .get(url.to_string())
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
            req.extensions_mut().insert(jwk_set);
            let res = service.call(req).await?;
            Ok(res)
        })
    }

    forward_ready!(service);
}

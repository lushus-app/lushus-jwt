use std::{
    future::{ready, Ready},
    rc::Rc,
};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, ResponseError,
};
use futures::future::LocalBoxFuture;
use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache};
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};

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
                options: None,
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
        let well_known_url = std::env::var("LUSHUS_WELL_KNOWN_URL")
            .expect("expected environment var LUSHUS_WELL_KNOWN_URL to be set");
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

impl ResponseError for JwkSetError {}

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
                .map_err(|e| JwkSetError::FetchError(e.to_string()))?
                .json::<JwkSet>()
                .await
                .map_err(|_| JwkSetError::DeserializeError)?;
            req.extensions_mut().insert(jwk_set);
            let res = service.call(req).await?;
            Ok(res)
        })
    }

    forward_ready!(service);
}

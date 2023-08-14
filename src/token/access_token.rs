use std::collections::HashMap;

use crate::{
    token::{ActionList, Resource, Token},
    AuthorizationClaims, EncodedToken, Scope,
};

pub type EncodedAccessToken = EncodedToken<AuthorizationClaims>;
pub type AccessToken = Token<AuthorizationClaims>;

impl AccessToken {
    pub fn scopes(&self) -> &Vec<Scope> {
        &self.claims.scopes()
    }

    pub fn resources(&self) -> HashMap<Resource, ActionList> {
        self.claims.resources()
    }

    pub fn actions(&self, resource: &str) -> Option<ActionList> {
        self.resources().get(resource).map(Clone::clone)
    }
}

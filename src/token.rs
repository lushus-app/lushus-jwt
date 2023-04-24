use std::collections::HashMap;

use jsonwebtoken::{
    decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Header, Validation,
};

use crate::claims::Claims;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("decode error")]
    DecodeError(#[from] jsonwebtoken::errors::Error),
    #[error("no jwk")]
    NoJWKError,
}

pub struct EncodedToken {
    encoded: String,
}

impl From<&str> for EncodedToken {
    fn from(encoded: &str) -> Self {
        Self {
            encoded: encoded.to_string(),
        }
    }
}

impl From<String> for EncodedToken {
    fn from(encoded: String) -> Self {
        Self { encoded }
    }
}

impl EncodedToken {
    fn encoded(&self) -> &str {
        &self.encoded
    }

    fn header(&self) -> Header {
        decode_header(self.encoded()).expect("Expected to have a header")
    }

    fn kid(&self) -> String {
        self.header().kid.expect("Expected to have a key id")
    }

    pub fn decode(self, jwk_set: JwkSet) -> Result<Token, Error> {
        let kid = self.kid();
        let jwk = jwk_set.find(&kid).ok_or(Error::NoJWKError)?;
        let decoding_key = DecodingKey::from_jwk(jwk)?;
        let validation = Validation::new(Algorithm::RS256);
        let decoded_token = decode::<Claims>(self.encoded(), &decoding_key, &validation)?;
        let token = Token::new(decoded_token.header, decoded_token.claims);
        Ok(token)
    }
}

type Resource = String;
type Action = String;
type ActionList = Vec<Action>;

pub struct Token {
    header: Header,
    claims: Claims,
    resources: HashMap<Resource, ActionList>,
}

impl Token {
    pub fn new(header: Header, claims: Claims) -> Self {
        let mut resources = HashMap::<Resource, ActionList>::new();
        for scope in claims.scopes.iter() {
            let resource = scope.resource.clone();
            let action = scope.action.clone();
            resources
                .entry(resource)
                .and_modify(|vec| vec.push(action.clone()))
                .or_insert(vec![action]);
        }
        Self {
            header,
            claims,
            resources,
        }
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    pub fn actions(&self, resource: &str) -> Option<&ActionList> {
        self.resources.get(resource)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use jsonwebtoken::{jwk::JwkSet, Algorithm, EncodingKey, Header};

    use crate::{claims::Claims, scope::Scope, token::EncodedToken};

    const PEM: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQBHSqoiB5cHHxlOwed23xAuOC2c/8YE/gQm8KeT/NtLpAqwP6BA
C7D9ZLIygtmdaVRc6/q9i1s/MaKF2RUNDVj3IAWBno7pM4ypiEr0HcMwbNbVZS27
Lswrbb5d9dECIqk/NyWuZD0tU470f4jgdkNyvl3wSNxGEsQdLUAa8dePyVELB7wf
8K0LV2o+HG+6HfMWa1nlHl9X/PpsinpiXXnXeSYyAtd06er2NwBm+T8Fx3ACaSVr
RxjbDMAGELI6s1GC8ODFd0xsQ2pdTV3sbQHsSzleCKqP4Za3YBd5yCmulM4Bwo2p
ue25OIjWVJH/BwyGVG2sRBm8IQQ5FFDK2iALAgMBAAECggEAELaMVBX7bgv4XuJO
ZSu+G1fIObosrhbu2kIoxyTMNFtstgz0gI89Gup0bCsI4UJEKNSZn73/0jzMoRxX
NwweAzFamRyW3EzdeREeoUQo8j1R0A08P1mlO7kqm9R4/0so6kz/ZHbTcMDaDq+n
YxfWkBvY4e/y0+qqVzy4fpibtHV6QPKeNATxwe68tauFmGO5JJSFvQhaY2fwo6NZ
qWsRzuhiNGHvv8ZakSBZQbqPNU2NfAIwqTbFKALdpRpZQRkd2rl2kZAG1941hFuL
M8ePiyDYllnLX3ep9L7SLkmWeKhmZKAy7IVv9WBoZ8PnoZx2w2+3uD45s5+PwUOK
UxEAwQKBgQCOSNJ1VLrLKBAD4LzmCFhFf4r/L0aeT+Wj8VnWdGBsnmWMX3JiVTuu
GkpBcN2v4qHZmA8vdV0bgsAdnWM+lO9JANyMBY8B+/O7jDV0dLs+1J7kKZlbrQaN
MoxcAAPBEFGmNDFBCL7buMq8AgCe44K8DBTQqyg+coxio+UNeOxAwwKBgQCARNOE
IkTIPx0IlRaRsZ3t97CpVKIcaW1QjnOq+05gb1v2pvkpUKIAe8SVVmtBj05Um0cF
buRaAfz1/NbNO8D8HS8JL4Bxw3jZXOfui09VE4jQQLmo+ZldKCvtYKTwAx8dMEx1
Rd14VABD/thTQdavyaczTJcPCwrgnob69kwvGQKBgEwh5RLI+oYX8rHQf+LqFilh
vIMczcGJ6MtXKgXZEXstKhL5Q2AgUSWwhYkMlmI1dvrSJVX0i5Rb2uY9v8vNr1e1
sUzu8H1UTi9NL5EXoNVWuYpGQ/vM0lOc94OGsnuMetPe23f78PvqnfgJbkGWZO6v
3DdnTcpUSo/BOJ+D0443AoGANq0f/JMe/rzog2AJ3tD3oRiUFZoeAD5weoY+iAPX
xQOzD9DdJN9aLxqTEZVk4u1TVn1aKNa8QCHY0oKUjaeK++z0v9Wfyt6oBP+1XdnE
V1+cUilE+uJqnWsiTm2D4UtzV93euZ6uaTxlYJahX9wQx54Nx7A+NAtg956bqx6S
GwECgYBTFAcjNU9Y8nHqOBe2/j1ioeoA00rgVe4Mi2WeTEMTWAhMTbP9IondbQoO
SlWrHE/Kr+NP9jL0egrUpYLquCIq71wY2bLykCX+vu6de3lduklQb5v9YoUM64a/
gBHwk7Elh43LZsvSyGpOLGLpuugTyMLEu9EAtZUAzx8PSXNlnA==
-----END RSA PRIVATE KEY-----
"#;

    const JWKS_JSON: &str = r#"
    {
        "keys": [
            {
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "n": "R0qqIgeXBx8ZTsHndt8QLjgtnP_GBP4EJvCnk_zbS6QKsD-gQAuw_WSyMoLZnWlUXOv6vYtbPzGihdkVDQ1Y9yAFgZ6O6TOMqYhK9B3DMGzW1WUtuy7MK22-XfXRAiKpPzclrmQ9LVOO9H-I4HZDcr5d8EjcRhLEHS1AGvHXj8lRCwe8H_CtC1dqPhxvuh3zFmtZ5R5fV_z6bIp6Yl1513kmMgLXdOnq9jcAZvk_BcdwAmkla0cY2wzABhCyOrNRgvDgxXdMbENqXU1d7G0B7Es5Xgiqj-GWt2AXecgprpTOAcKNqbntuTiI1lSR_wcMhlRtrEQZvCEEORRQytogCw",
                "e": "AQAB",
                "kid": "QeiAb2kNPCohaTF8f51Tm"
            },
            {
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "n": "yQiDNcAx5t6g99Aj2yGE5lO6QKZsF5cjzzBel0tUd7biSDGU-LbubbYfRxUsXuDzNvnEHgw8iRqWbS7Zs1JJWvQp8RlcMlxaCTAGJPjjww3O6WFgpLvt_YMMxq-OhZ3ZTAj7u8MDwmYyiWFjEhX7_3-3FKx3qVhCg6D3udZ5f2R5Zw73Bi153qBJHCC2rjyQErEApT6Z1br8JCkThfc2AxTeIzsmJJKzMRmqfwBZuEyreITuMRh5dyaIj9yVGIoaEmCszOB8cMauLcapOOSevf7P9LtTOEJfGUZWP4arRWwANrJ3Kwc4ykczPkx2doIUf9ZFZVUAnam0ymXva6IHRw",
                "e": "AQAB",
                "kid": "nMFbG4UtjkituDYs1DHv-",
                "x5t": "pIpcivx4HxzNRO95lUDPDEhOLac"
            }
        ]
    }
    "#;

    fn generate_token(scopes: Vec<Scope>) -> Result<EncodedToken> {
        let header = Header {
            alg: Algorithm::RS256,
            kid: Some("QeiAb2kNPCohaTF8f51Tm".to_string()),
            ..Default::default()
        };
        let claims = Claims::new("issuer", "subject", "audience", scopes);
        let key = EncodingKey::from_rsa_pem(PEM.as_ref()).expect("expected encoding key from PEM");
        let token: EncodedToken = jsonwebtoken::encode(&header, &claims, &key)?.into();
        Ok(token)
    }

    #[test]
    fn test_decode() {
        let jwk_set: JwkSet = serde_json::from_str(JWKS_JSON).expect("expected JWK set");
        let scopes = vec![
            Scope::new("create", "user"),
            Scope::new("read", "user"),
            Scope::new("delete", "user"),
        ];
        let token = generate_token(scopes)
            .expect("expected token")
            .decode(jwk_set)
            .expect("expected decoded token");
        let user_actions = token
            .actions("user")
            .expect("expected to have user actions");
        assert_eq!(
            *user_actions,
            vec!(
                "create".to_string(),
                "read".to_string(),
                "delete".to_string()
            )
        );
    }
}

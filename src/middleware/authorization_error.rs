#[derive(thiserror::Error, Debug)]
pub enum AuthorizationError {
    #[error("not authorized")]
    Unauthorized,
    #[error("Resource '{0}' not authorized")]
    UnauthorizedResource(String),
    #[error("Action '{0}' not authorized")]
    UnauthorizedAction(String),
}

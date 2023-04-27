#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("not authorized")]
    Bad,
    #[error("Resource '{0}' not authorized")]
    UnauthorizedResource(String),
    #[error("Action '{0}' not authorized")]
    UnauthorizedAction(String),
}
use crate::middleware::{auth_error::AuthError, authorized::Authorized};

pub fn authorize(auth: Authorized, resource: &str, required_action: &str) -> Result<(), AuthError> {
    let token = auth.clone().ok_or(AuthError::Unauthorized)?;
    let actions = token
        .actions(resource)
        .ok_or(AuthError::UnauthorizedResource(resource.to_string()))?;
    actions
        .iter()
        .find(|v| *v == required_action)
        .ok_or(AuthError::UnauthorizedAction(required_action.to_string()))?;
    Ok(())
}

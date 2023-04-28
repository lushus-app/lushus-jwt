use crate::middleware::{authorization_error::AuthorizationError, authorized::Authorized};

pub fn authorize(
    auth: Authorized,
    resource: &str,
    required_action: &str,
) -> Result<(), AuthorizationError> {
    let token = auth.clone().ok_or(AuthorizationError::Unauthorized)?;
    let actions = token
        .actions(resource)
        .ok_or(AuthorizationError::UnauthorizedResource(
            resource.to_string(),
        ))?;
    actions.iter().find(|v| *v == required_action).ok_or(
        AuthorizationError::UnauthorizedAction(required_action.to_string()),
    )?;
    Ok(())
}

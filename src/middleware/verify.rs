use crate::middleware::{authorization::Authorization, authorization_error::AuthorizationError};

pub fn verify(
    auth: &Authorization,
    resource: &str,
    required_action: &str,
) -> Result<(), AuthorizationError> {
    let token = auth.as_ref().ok_or(AuthorizationError::Unauthorized)?;
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

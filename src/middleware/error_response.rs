use std::fmt::Display;

#[derive(Serialize)]
pub struct ErrorBody {
    code: String,
    message: String,
}

// 403
pub fn forbidden_error_body(code: &str, e: impl std::error::Error) -> ErrorBody {
    ErrorBody {
        code: code.to_string(),
        message: format!("Forbidden: {e}"),
    }
}

// 500
pub fn internal_server_error_body(code: &str, e: impl std::error::Error) -> ErrorBody {
    ErrorBody {
        code: code.to_string(),
        message: format!("An internal error occurred: {e}"),
    }
}

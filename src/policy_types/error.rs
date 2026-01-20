use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttributeError {
    #[error("Invalid attribute domain: {0}")]
    InvalidDomain(String),

    #[error("Invalid attribute: {0}")]
    ParseError(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}

#[derive(Debug, Error)]
pub enum PolicyTypeError {
    #[error("attribute error: {0}")]
    AttributeError(#[from] AttributeError),

    #[error("Deserialization error: {0:?}")]
    DeserializationError(&'static str),

    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("Cap'n Proto schema error: {0}")]
    NotInSchema(#[from] capnp::NotInSchema),

    #[error("Cap'n Proto utf8 error: {0}")]
    Utf8Error(#[from] core::str::Utf8Error),
}

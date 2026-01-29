use crate::vsapi::v1;
use std::net::AddrParseError;
use thiserror::Error;

/// Error type
#[derive(Debug, Error)]
pub enum VsapiTypeError {
    #[error("Serialization error {0}")]
    SerializationError(&'static str),
    #[error("Deserialization error: {0:?}")]
    DeserializationError(&'static str),
    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),
    #[error("Cap'n Proto error: {0}")]
    NotInSchema(#[from] capnp::NotInSchema),
    #[error("Cap'n Proto error: {0}")]
    Utf8Error(#[from] core::str::Utf8Error),
    #[error("Error code: {0:?}")]
    CodedError(crate::vsapi_types::ErrorCode),
    #[error("IP address conversion error: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("Addr Parse Error")]
    AddrParseError(#[from] AddrParseError),
}

/// Error information.
/// Mirrors the "Error" struct in the vsapi.
#[derive(Debug)]
pub struct ApiResponseError {
    pub code: ErrorCode,
    pub message: String,
    pub retry_in: u32,
}

/// Denial code, match the codes in vs.capnp, except for Fail and UnknownStatusCode
#[derive(Clone, Debug)]
pub enum ErrorCode {
    Internal,
    AuthRequired,
    InvalidOperation,
    OutOfSync,
    NotFound,
    InvalidSignature,
    QuotaExceeded,
    TemporarilyUnavailable,
    AuthError,
    ParamError,
    UnknownStatusCode,
    Fail,
}

impl ApiResponseError {
    pub fn new<S: Into<String>>(code: ErrorCode, message: S, retry_in: u32) -> Self {
        Self {
            code,
            message: message.into(),
            retry_in,
        }
    }

    /// Sets retry value to 0.
    pub fn new_code_msg<S: Into<String>>(code: ErrorCode, message: S) -> Self {
        Self {
            code,
            message: message.into(),
            retry_in: 0,
        }
    }
}

impl TryFrom<v1::error::Reader<'_>> for ApiResponseError {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::error::Reader<'_>) -> Result<Self, Self::Error> {
        let code = match reader.get_code()? {
            v1::ErrorCode::Internal => ErrorCode::Internal,
            v1::ErrorCode::AuthRequired => ErrorCode::AuthRequired,
            v1::ErrorCode::InvalidOperation => ErrorCode::InvalidOperation,
            v1::ErrorCode::OutOfSync => ErrorCode::OutOfSync,
            v1::ErrorCode::NotFound => ErrorCode::NotFound,
            v1::ErrorCode::InvalidSignature => ErrorCode::InvalidSignature,
            v1::ErrorCode::QuotaExceeded => ErrorCode::QuotaExceeded,
            v1::ErrorCode::TemporarilyUnavailable => ErrorCode::TemporarilyUnavailable,
            v1::ErrorCode::AuthError => ErrorCode::AuthError,
            v1::ErrorCode::ParamError => ErrorCode::ParamError,
        };
        let message = reader.get_message()?.to_string()?;
        let retry_in = reader.get_retry_in();
        Ok(ApiResponseError {
            code,
            message,
            retry_in,
        })
    }
}

impl Into<v1::ErrorCode> for ErrorCode {
    fn into(self) -> v1::ErrorCode {
        match self {
            ErrorCode::Internal => v1::ErrorCode::Internal,
            ErrorCode::AuthRequired => v1::ErrorCode::AuthRequired,
            ErrorCode::InvalidOperation => v1::ErrorCode::InvalidOperation,
            ErrorCode::OutOfSync => v1::ErrorCode::OutOfSync,
            ErrorCode::NotFound => v1::ErrorCode::NotFound,
            ErrorCode::InvalidSignature => v1::ErrorCode::InvalidSignature,
            ErrorCode::QuotaExceeded => v1::ErrorCode::QuotaExceeded,
            ErrorCode::TemporarilyUnavailable => v1::ErrorCode::TemporarilyUnavailable,
            ErrorCode::AuthError => v1::ErrorCode::AuthError,
            ErrorCode::ParamError => v1::ErrorCode::ParamError,

            // These are not 1:1 mapped to IDL.
            ErrorCode::UnknownStatusCode => v1::ErrorCode::Internal,
            ErrorCode::Fail => v1::ErrorCode::Internal,
        }
    }
}

use crate::vsapi::v1;
use std::net::AddrParseError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VsapiTypeError {
    #[error("capn proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("capn proto not in schema: {0}")]
    CapnpNotInSchema(#[from] capnp::NotInSchema),

    #[error("string conversion error: {0}")]
    StringConversion(#[from] std::str::Utf8Error),

    #[error("Serialization error {0}")]
    SerializationError(&'static str),

    #[error("Deserialization error: {0:?}")]
    DeserializationError(&'static str),

    #[error("IP address conversion error: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),

    #[error("Addr Parse Error")]
    AddrParseError(#[from] AddrParseError),
}

/// Error information.
/// Mirrors the "Error" struct in the vsapi.
#[derive(Debug, Error)]
pub struct ApiResponseError {
    pub code: ErrorCode,
    pub message: String,
    pub retry_in: u32,
}

impl std::fmt::Display for ApiResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Customize so only `x` and `y` are denoted.
        write!(
            f,
            " {:?}: {} (retry in {} seconds)",
            self.code, self.message, self.retry_in
        )
    }
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

    // Altered to match functionality of former libnode2::vsconn::new_coded_error
    fn try_from(reader: v1::error::Reader<'_>) -> Result<Self, Self::Error> {
        let code: ErrorCode = match reader.get_code() {
            Ok(c) => c.into(),
            Err(_) => ErrorCode::Internal,
        };

        let message = match reader.get_message() {
            Ok(m) => m.to_string().unwrap(),
            Err(_) => String::from("(no message)"),
        };

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

// /// Create a VSApiError::CodedError from a capn proto vsapi2::error::Reader.
// /// TODO remove this, we are trying to move away from importing capnp types in this file
// fn new_coded_error(rdr: vsapi2::error::Reader) -> VsapiTypeError {
//     let err_code: ErrorCode = match rdr.get_code() {
//         Ok(c) => c.into(),
//         Err(_) => ErrorCode::Internal,
//     };
//     let err_msg = match rdr.get_message() {
//         Ok(m) => m.to_string().unwrap(),
//         Err(_) => String::from("(no message)"),
//     };
//     let retry = rdr.get_retry_in();
//     VSApiError::CodedError(ApiResponseError::new(err_code, err_msg, retry))
// }

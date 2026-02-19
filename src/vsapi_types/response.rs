use std::fmt;
use std::net::IpAddr;
use std::time::SystemTime;

use crate::vsapi::v1;
use crate::vsapi_types::error::{ApiResponseError, ErrorCode};
use crate::vsapi_types::{Visa, VsapiTypeError};

/// Info recieved from VS in response to ConnectRequest
#[derive(Debug)]
pub struct Connection {
    pub zpr_addr: IpAddr,
    pub auth_expires: u64,
}

/// Response to a visa request
#[derive(Debug)]
pub enum VisaResponse {
    Allow(Visa),
    Deny(Denied),
    VSApiError(ApiResponseError),
}

/// Denial information
#[derive(Debug)]
pub struct Denied {
    pub code: DenyCode,
    pub reason: Option<String>,
}

/// Disconnect reason, mirrors DisconnectReason in vs.capnp
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DisconnectReason {
    RemoteDisconnect,
    Timeout,
    LinkError,
    NodeShutdown,
    Admin,
}

/// Denial code, match the codes in vs.capnp, except for Fail
#[derive(Debug, Eq, PartialEq)]
pub enum DenyCode {
    Fail,
    NoReason,
    NoMatch,
    Denied,
    SourceNotFound,
    DestNotFound,
    SourceAuthError,
    DestAuthError,
    QuotaExceeded,
}

impl Connection {
    pub fn new(zpr_addr: IpAddr, auth_expires: SystemTime) -> Self {
        Self {
            zpr_addr,
            auth_expires: auth_expires
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

impl Denied {
    pub fn new(code: DenyCode, reason: Option<String>) -> Self {
        Self { code, reason }
    }
}

impl fmt::Display for DenyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<v1::connection::Reader<'_>> for Connection {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::connection::Reader<'_>) -> Result<Self, Self::Error> {
        let zpr_addr = IpAddr::try_from(reader.get_zpr_addr()?)?;
        let auth_expires = reader.get_auth_expires();
        Ok(Connection {
            zpr_addr,
            auth_expires,
        })
    }
}

impl TryFrom<v1::visa_response::Reader<'_>> for VisaResponse {
    type Error = VsapiTypeError;

    /// Returns err if visa_response is Error, if Visa is poorly format, if DenyCode or ErrorCode are unrecognized
    fn try_from(capnp_visa_response: v1::visa_response::Reader) -> Result<Self, Self::Error> {
        match capnp_visa_response.which()? {
            v1::visa_response::Which::Allow(v) => {
                let visa = v?;
                Ok(Self::Allow(visa.try_into()?))
            }
            v1::visa_response::Which::Deny(c) => {
                let deny_code = DenyCode::from(c?);
                Ok(Self::Deny(Denied::new(deny_code, None)))
            }
            v1::visa_response::Which::Error(e) => {
                let code = ErrorCode::from(e?.get_code()?);
                Err(VsapiTypeError::CodedError(code))
            }
        }
    }
}

impl From<v1::VisaDenyCode> for DenyCode {
    fn from(code: v1::VisaDenyCode) -> Self {
        match code {
            v1::VisaDenyCode::NoReason => DenyCode::NoReason,
            v1::VisaDenyCode::NoMatch => DenyCode::NoMatch,
            v1::VisaDenyCode::Denied => DenyCode::Denied,
            v1::VisaDenyCode::SourceNotFound => DenyCode::SourceNotFound,
            v1::VisaDenyCode::DestNotFound => DenyCode::DestNotFound,
            v1::VisaDenyCode::SourceAuthError => DenyCode::SourceAuthError,
            v1::VisaDenyCode::DestAuthError => DenyCode::DestAuthError,
            v1::VisaDenyCode::QuotaExceeded => DenyCode::QuotaExceeded,
        }
    }
}

impl From<DenyCode> for v1::VisaDenyCode {
    fn from(code: DenyCode) -> Self {
        match code {
            DenyCode::NoReason => v1::VisaDenyCode::NoReason,
            DenyCode::NoMatch => v1::VisaDenyCode::NoMatch,
            DenyCode::Denied => v1::VisaDenyCode::Denied,
            DenyCode::SourceNotFound => v1::VisaDenyCode::SourceNotFound,
            DenyCode::DestNotFound => v1::VisaDenyCode::DestNotFound,
            DenyCode::SourceAuthError => v1::VisaDenyCode::SourceAuthError,
            DenyCode::DestAuthError => v1::VisaDenyCode::DestAuthError,
            DenyCode::QuotaExceeded => v1::VisaDenyCode::QuotaExceeded,
            DenyCode::Fail => v1::VisaDenyCode::NoReason, // No direct mapping (TODO: remove Fail)
        }
    }
}

impl From<v1::DisconnectReason> for DisconnectReason {
    fn from(reason: v1::DisconnectReason) -> Self {
        match reason {
            v1::DisconnectReason::RemoteDisconnect => DisconnectReason::RemoteDisconnect,
            v1::DisconnectReason::Timeout => DisconnectReason::Timeout,
            v1::DisconnectReason::LinkError => DisconnectReason::LinkError,
            v1::DisconnectReason::NodeShutdown => DisconnectReason::NodeShutdown,
            v1::DisconnectReason::Admin => DisconnectReason::Admin,
        }
    }
}

impl From<DisconnectReason> for v1::DisconnectReason {
    fn from(reason: DisconnectReason) -> Self {
        match reason {
            DisconnectReason::RemoteDisconnect => v1::DisconnectReason::RemoteDisconnect,
            DisconnectReason::Timeout => v1::DisconnectReason::Timeout,
            DisconnectReason::LinkError => v1::DisconnectReason::LinkError,
            DisconnectReason::NodeShutdown => v1::DisconnectReason::NodeShutdown,
            DisconnectReason::Admin => v1::DisconnectReason::Admin,
        }
    }
}

impl From<v1::ErrorCode> for ErrorCode {
    fn from(code: v1::ErrorCode) -> Self {
        match code {
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
        }
    }
}

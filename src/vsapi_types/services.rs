use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

use crate::vsapi_types::VsapiTypeError;
use crate::vsapi_types::util::ip::ip_addr_from_vec;

use crate::vsapi::v1;

/// Capnp does not have a separate AuthServicesList structure, instead just uses List(ServiceDescriptor)
#[derive(Debug, Clone)]
pub struct AuthServicesList {
    pub expiration: Option<SystemTime>, // 0 value means "no expiration"
    pub services: Vec<ServiceDescriptor>,
}

/// A parsed [vsapi::ServiceDescriptor] that we use to keep ASA records.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ServiceDescriptor {
    // TYPE is omitted -- only supported type currently is 'actorAuthentication'
    pub service_id: String,
    pub service_uri: String,
    pub zpr_addr: IpAddr,
}

impl Default for AuthServicesList {
    fn default() -> Self {
        AuthServicesList {
            expiration: Some(SystemTime::UNIX_EPOCH),
            services: Vec::new(),
        }
    }
}

impl AuthServicesList {
    pub fn update(&mut self, expiration: Option<SystemTime>, services: Vec<ServiceDescriptor>) {
        self.expiration = expiration;
        self.services = services;
    }

    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expiration {
            SystemTime::now() >= exp
        } else {
            false
        }
    }

    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// The list is "valid" it is non-empty and not expired.
    pub fn is_valid(&self) -> bool {
        !self.is_empty() && !self.is_expired()
    }
}

impl ServiceDescriptor {
    /// Gently try to extract a SocketAddr from this ServiceDescriptor.
    /// If there are any problems, None is returned.
    pub fn get_socket_addr(&self) -> Option<std::net::SocketAddr> {
        // To create a socket addr we need a port, which is on the URI.
        let uri = match Url::parse(&self.service_uri) {
            Ok(u) => u,
            Err(_) => return None, // Invalid URI
        };
        let port = match uri.port() {
            Some(p) => p,
            None => return None, // No port in URI, so no SocketAddr for you
        };
        Some(std::net::SocketAddr::new(self.zpr_addr.into(), port))
    }
}

impl TryFrom<vsapi::ServicesList> for AuthServicesList {
    type Error = VsapiTypeError;

    /// Returns err if a ServiceDescriptor is badly formatted
    fn try_from(services_list: vsapi::ServicesList) -> Result<Self, Self::Error> {
        let mut expiration = None;
        if let Some(exp) = services_list.expiration {
            expiration = Some(UNIX_EPOCH + Duration::from_secs(exp as u64));
        }
        let mut services = Vec::new();
        if let Some(svc_list) = services_list.services {
            for svc in svc_list {
                services.push(ServiceDescriptor::try_from(svc)?);
            }
        }
        Ok(Self {
            expiration,
            services,
        })
    }
}

impl TryFrom<vsapi::ServiceDescriptor> for ServiceDescriptor {
    type Error = VsapiTypeError;

    /// Returns err if required values are not set
    fn try_from(value: vsapi::ServiceDescriptor) -> Result<Self, Self::Error> {
        if value.type_ != vsapi::ServiceType::ACTOR_AUTHENTICATION {
            return Err(VsapiTypeError::DeserializationError(
                "vsapi::ServiceDescriptor is not of type ACTOR_AUTHENTICATION",
            ));
        }
        let zpr_addr = match value.address {
            Some(address) => ip_addr_from_vec(address)?,
            None => {
                return Err(VsapiTypeError::DeserializationError(
                    "vsapi::ServiceDescriptor addr is empty",
                ));
            }
        };

        Ok(ServiceDescriptor {
            service_id: value.service_id.unwrap_or_default(),
            service_uri: value.uri.unwrap_or_default(),
            zpr_addr,
        })
    }
}

impl TryFrom<v1::service_descriptor::Reader<'_>> for ServiceDescriptor {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::service_descriptor::Reader<'_>) -> Result<Self, Self::Error> {
        let svc_id = reader.get_service_id()?.to_string()?;
        let svc_uri = reader.get_service_uri()?.to_string()?;
        let zpr_addr = IpAddr::try_from(reader.get_zpr_addr()?)?;

        match reader.get_stype()? {
            v1::ServiceT::ActorAuthentication => {}
        }

        Ok(ServiceDescriptor {
            service_id: svc_id,
            service_uri: svc_uri,
            zpr_addr,
        })
    }
}

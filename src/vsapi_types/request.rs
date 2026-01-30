use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::vsapi_types::AuthBlobs;
use crate::vsapi_types::VsapiTypeError;
use crate::vsapi_types::auth::AuthBlobV1;
use crate::vsapi_types::util::ip::ip_addr_from_vec;

/// Request to connect to VS
#[derive(Debug)]
pub struct ConnectRequest {
    pub blobs: AuthBlobs,
    pub claims: Vec<Claim>,
    pub substrate_addr: IpAddr,
    pub dock_interface: u8,
}

#[derive(Debug)]
pub struct Claim {
    pub key: String,
    pub value: String,
}

impl Claim {
    pub fn new(key: String, value: String) -> Self {
        Self { key, value }
    }
}

impl TryFrom<vsapi::ConnectRequest> for ConnectRequest {
    type Error = VsapiTypeError;

    /// Returns error if all fields are not set
    fn try_from(thrift_req: vsapi::ConnectRequest) -> Result<Self, Self::Error> {
        let substrate_addr = match thrift_req.dock_addr {
            Some(val) => ip_addr_from_vec(val)?,
            None => return Err(VsapiTypeError::DeserializationError("No dock addr")),
        };
        let claims = match thrift_req.claims {
            Some(claims) => {
                let mut v = Vec::new();
                for (key, val) in claims.iter() {
                    v.push(Claim::new(key.clone(), val.clone()));
                }
                v
            }
            None => return Err(VsapiTypeError::DeserializationError("No claims")),
        };
        let blobs = match thrift_req.challenge_responses {
            Some(cr) => AuthBlobs::V1(AuthBlobV1::new(cr)),
            None => {
                return Err(VsapiTypeError::DeserializationError(
                    "No challenge responses",
                ));
            }
        };
        Ok(Self {
            blobs,
            claims,
            substrate_addr,
            dock_interface: 0,
        })
    }
}

impl TryFrom<ConnectRequest> for vsapi::ConnectRequest {
    type Error = VsapiTypeError;

    /// Returns an error if blob type is incorrect
    fn try_from(req: ConnectRequest) -> Result<Self, Self::Error> {
        let mut claims = BTreeMap::new();
        for claim in req.claims {
            claims.insert(claim.key, claim.value);
        }

        let challenge_responses = match req.blobs {
            AuthBlobs::V1(v1_blobs) => v1_blobs.challenge_responses,
            AuthBlobs::V2(_) => {
                return Err(VsapiTypeError::DeserializationError(
                    "Incorrect blob type, expected V1",
                ));
            }
        };

        let dock_addr = match req.substrate_addr {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        Ok(Self {
            connection_id: Some(0),
            dock_addr: Some(dock_addr),
            claims: Some(claims),
            challenge: None,
            challenge_responses: Some(challenge_responses),
        })
    }
}

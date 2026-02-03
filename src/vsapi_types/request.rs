use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::vsapi_types::AuthBlob;
use crate::vsapi_types::VsapiTypeError;
use crate::vsapi_types::util::ip::ip_addr_from_vec;

use crate::vsapi::v1;

/// Request to connect to VS
#[derive(Debug)]
pub struct ConnectRequest {
    pub blobs: Vec<AuthBlob>,
    pub claims: Vec<Claim>,
    pub substrate_addr: IpAddr,
    pub dock_interface: u8,
}

#[derive(Debug)]
pub struct ConnectRequestV1 {
    pub challenge_responses: Vec<Vec<u8>>,
    pub claims: Vec<Claim>,
    pub dock_addr: IpAddr,
    pub connection_id: i32,
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

impl TryFrom<vsapi::ConnectRequest> for ConnectRequestV1 {
    type Error = VsapiTypeError;

    /// Returns error if all fields are not set
    fn try_from(thrift_req: vsapi::ConnectRequest) -> Result<Self, Self::Error> {
        let dock_addr = match thrift_req.dock_addr {
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
        let challenge_responses = match thrift_req.challenge_responses {
            Some(cr) => cr,
            None => {
                return Err(VsapiTypeError::DeserializationError(
                    "No challenge responses",
                ));
            }
        };

        let connection_id = match thrift_req.connection_id {
            Some(id) => id,
            None => return Err(VsapiTypeError::DeserializationError("No connection_id")),
        };

        Ok(Self {
            challenge_responses,
            claims,
            dock_addr,
            connection_id,
        })
    }
}

impl TryFrom<ConnectRequestV1> for vsapi::ConnectRequest {
    type Error = VsapiTypeError;

    /// Returns an error if blob type is incorrect
    fn try_from(req: ConnectRequestV1) -> Result<Self, Self::Error> {
        let mut claims = BTreeMap::new();
        for claim in req.claims {
            claims.insert(claim.key, claim.value);
        }

        let challenge_responses = req.challenge_responses;

        let dock_addr = match req.dock_addr {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };

        let connection_id = req.connection_id;

        Ok(Self {
            connection_id: Some(connection_id),
            dock_addr: Some(dock_addr),
            claims: Some(claims),
            challenge: None,
            challenge_responses: Some(challenge_responses),
        })
    }
}

impl TryFrom<v1::connect_request::Reader<'_>> for ConnectRequest {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::connect_request::Reader<'_>) -> Result<Self, Self::Error> {
        let dock_interface = reader.get_dock_interface();
        let substrate_addr = IpAddr::try_from(reader.get_substrate_addr()?)?;

        let mut blobs = Vec::new();
        let blob_readers = reader.get_blobs()?;
        for blob_reader in blob_readers.iter() {
            let blob = AuthBlob::try_from(blob_reader)?;
            blobs.push(blob);
        }

        let mut claims = Vec::new();
        let claim_readers = reader.get_claims()?;
        for claim_reader in claim_readers.iter() {
            let claim = Claim::try_from(claim_reader)?;
            claims.push(claim);
        }

        Ok(ConnectRequest {
            blobs,
            claims,
            substrate_addr,
            dock_interface,
        })
    }
}

impl TryFrom<v1::claim::Reader<'_>> for Claim {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::claim::Reader<'_>) -> Result<Self, Self::Error> {
        let key = reader.get_key()?.to_string()?;
        let value = reader.get_value()?.to_string()?;
        Ok(Claim { key, value })
    }
}

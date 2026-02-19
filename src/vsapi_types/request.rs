use std::net::IpAddr;

use crate::vsapi::v1;
use crate::vsapi_types::AuthBlob;
use crate::vsapi_types::VsapiTypeError;

/// Request to connect to VS
#[derive(Debug)]
pub struct ConnectRequest {
    pub blobs: Vec<AuthBlob>,
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

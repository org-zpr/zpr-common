use std::net::IpAddr;

use crate::vsapi::v1;

/// Blob passed with a ConnectRequest
#[derive(Debug)]
pub enum AuthBlob {
    SS(SelfSignedBlob),
    AC(AuthCodeBlob),
}

#[derive(Debug, Default)]
pub struct SelfSignedBlob {
    pub alg: ChallengeAlg,
    pub challenge: Vec<u8>,
    pub cn: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub struct AuthCodeBlob {
    pub asa_addr: IpAddr,
    pub code: String,
    pub pkce: String,
    pub client_id: String,
}

#[derive(Debug, Default)]
pub enum ChallengeAlg {
    #[default]
    RsaSha256Pkcs1v15,
}

impl TryFrom<v1::auth_blob::Reader<'_>> for AuthBlob {
    type Error = crate::vsapi_types::VsapiTypeError;

    fn try_from(reader: v1::auth_blob::Reader<'_>) -> Result<Self, Self::Error> {
        match reader.which()? {
            v1::auth_blob::Which::Ss(ss_blob_reader) => {
                let ss_blob_reader = ss_blob_reader?;
                let ss_blob = SelfSignedBlob::try_from(ss_blob_reader)?;
                Ok(AuthBlob::SS(ss_blob))
            }
            v1::auth_blob::Which::Ac(ac_blob_reader) => {
                let ac_blob_reader = ac_blob_reader?;
                let ac_blob = AuthCodeBlob::try_from(ac_blob_reader)?;
                Ok(AuthBlob::AC(ac_blob))
            }
        }
    }
}

impl TryFrom<v1::self_signed_blob::Reader<'_>> for SelfSignedBlob {
    type Error = crate::vsapi_types::VsapiTypeError;

    fn try_from(reader: v1::self_signed_blob::Reader<'_>) -> Result<Self, Self::Error> {
        let alg = match reader.get_alg()? {
            v1::ChallengeAlg::RsaSha256Pkcs1v15 => ChallengeAlg::RsaSha256Pkcs1v15,
        };
        Ok(SelfSignedBlob {
            alg,
            challenge: reader.get_challenge()?.to_vec(),
            cn: reader.get_cn()?.to_string()?,
            timestamp: reader.get_timestamp(),
            signature: reader.get_signature()?.to_vec(),
        })
    }
}

impl TryFrom<v1::auth_code_blob::Reader<'_>> for AuthCodeBlob {
    type Error = crate::vsapi_types::VsapiTypeError;

    fn try_from(reader: v1::auth_code_blob::Reader<'_>) -> Result<Self, Self::Error> {
        let asa_addr = IpAddr::try_from(reader.get_asa_addr()?)?;
        Ok(AuthCodeBlob {
            asa_addr,
            code: reader.get_code()?.to_string()?,
            pkce: reader.get_pkce()?.to_string()?,
            client_id: reader.get_client_id()?.to_string()?,
        })
    }
}

use std::net::IpAddr;

#[derive(Debug)]
pub enum AuthBlobs {
    V1(AuthBlobV1),
    V2(Vec<AuthBlobV2>),
}

/// Blob passed with a ConnectRequest
#[derive(Debug)]
pub enum AuthBlobV2 {
    SS(SelfSignedBlob),
    AC(AuthCodeBlob),
}

#[derive(Debug)]
pub struct AuthBlobV1 {
    pub challenge_responses: Vec<Vec<u8>>,
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

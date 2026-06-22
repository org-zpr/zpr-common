use std::net::IpAddr;

use crate::vsapi::v1;
use crate::vsapi_types::AuthBlob;
use crate::vsapi_types::PacketDesc;
use crate::vsapi_types::Param;
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
pub struct NodeConnect {
    /// Connect will fail if this does not match policy.
    pub zpr_addr: IpAddr,
    pub state: StateFlag,
}

#[derive(Debug)]
pub struct NodeOpen {
    pub state: StateFlag,
}

/// Wraps the Cap'n Proto `VSConnT` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectType {
    Reset,
    Reconnect,
}

#[derive(Debug)]
pub struct VSConnectRequest {
    pub cn: String,
    pub ctype: ConnectType,
    pub params: Vec<Param>,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateFlag {
    /// Visa service / node has no state for this connection.
    #[default]
    NoState,

    /// Visa service / node has existing state for this connection.
    HasState,
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

#[derive(Debug)]
pub struct VisaRequest {
    pub pdesc: PacketDesc,
    pub previous_id: Option<u64>,
}

impl StateFlag {
    /// Derive the state flag value from the connection type.
    pub fn new_from_connect_type(ctype: ConnectType) -> Self {
        match ctype {
            ConnectType::Reset => StateFlag::NoState,
            ConnectType::Reconnect => StateFlag::HasState,
        }
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

impl TryFrom<v1::v_s_connect_request::Reader<'_>> for VSConnectRequest {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::v_s_connect_request::Reader<'_>) -> Result<Self, Self::Error> {
        let cn = reader.get_cn()?.to_string()?;
        let ctype = ConnectType::from(reader.get_ctype()?);
        let params = {
            let mut params = Vec::new();
            let param_readers = reader.get_params()?;
            for param_reader in param_readers.iter() {
                let param = Param::try_from(param_reader)?;
                params.push(param);
            }
            params
        };

        Ok(VSConnectRequest { cn, ctype, params })
    }
}

impl From<v1::VSConnT> for ConnectType {
    fn from(value: v1::VSConnT) -> Self {
        match value {
            v1::VSConnT::Reset => ConnectType::Reset,
            v1::VSConnT::Reconnect => ConnectType::Reconnect,
        }
    }
}

impl From<ConnectType> for v1::VSConnT {
    fn from(value: ConnectType) -> Self {
        match value {
            ConnectType::Reset => v1::VSConnT::Reset,
            ConnectType::Reconnect => v1::VSConnT::Reconnect,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vsapi_types::ParamValue;
    use crate::write_to::WriteTo;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_vs_connect_request_msg(
        cn: &str,
        ctype: v1::VSConnT,
        params: &[Param],
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::v_s_connect_request::Builder<'_> = msg.init_root();
            root.set_cn(cn);
            root.set_ctype(ctype);
            let mut params_bldr = root.reborrow().init_params(params.len() as u32);
            for (i, param) in params.iter().enumerate() {
                let mut param_bldr = params_bldr.reborrow().get(i as u32);
                param.write_to(&mut param_bldr);
            }
        }
        msg
    }

    fn read_vs_connect_request(
        msg: &capnp::message::Builder<capnp::message::HeapAllocator>,
    ) -> VSConnectRequest {
        let reader: v1::v_s_connect_request::Reader<'_> = msg.get_root_as_reader().unwrap();
        VSConnectRequest::try_from(reader).unwrap()
    }

    fn roundtrip_vs_connect_request(req: &VSConnectRequest) -> VSConnectRequest {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::v_s_connect_request::Builder<'_> = msg.init_root();
            req.write_to(&mut root);
        }
        read_vs_connect_request(&msg)
    }

    #[test]
    fn vs_connect_request_tryfrom_reset_without_params() {
        let msg = make_vs_connect_request_msg("actor.example", v1::VSConnT::Reset, &[]);
        let req = read_vs_connect_request(&msg);

        assert_eq!(req.cn, "actor.example");
        assert_eq!(req.ctype, ConnectType::Reset);
        assert!(req.params.is_empty());
    }

    #[test]
    fn vs_connect_request_tryfrom_reconnect_with_params() {
        let params = vec![
            Param::new_str("mode".to_string(), "bootstrap".to_string()),
            Param::new_u64("generation".to_string(), 42),
            Param::new_ip(
                "zpr_addr".to_string(),
                IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
            ),
        ];
        let msg = make_vs_connect_request_msg("actor.example", v1::VSConnT::Reconnect, &params);
        let req = read_vs_connect_request(&msg);

        assert_eq!(req.cn, "actor.example");
        assert_eq!(req.ctype, ConnectType::Reconnect);
        assert_eq!(req.params.len(), 3);
        assert!(matches!(
            req.params[0].value,
            ParamValue::StrParam(ref value) if value == "bootstrap"
        ));
        assert!(matches!(req.params[1].value, ParamValue::U64Param(42)));
        assert!(matches!(
            req.params[2].value,
            ParamValue::IpParam(IpAddr::V4(addr)) if addr == Ipv4Addr::new(10, 20, 30, 40)
        ));
    }

    #[test]
    fn vs_connect_request_roundtrip_reset_without_params() {
        let original = VSConnectRequest {
            cn: "actor.example".to_string(),
            ctype: ConnectType::Reset,
            params: Vec::new(),
        };
        let result = roundtrip_vs_connect_request(&original);

        assert_eq!(result.cn, original.cn);
        assert_eq!(result.ctype, original.ctype);
        assert!(result.params.is_empty());
    }

    #[test]
    fn vs_connect_request_roundtrip_reconnect_with_params() {
        let original = VSConnectRequest {
            cn: "actor.example".to_string(),
            ctype: ConnectType::Reconnect,
            params: vec![
                Param::new_str("mode".to_string(), "resume".to_string()),
                Param::new_u64("generation".to_string(), u64::MAX),
            ],
        };
        let result = roundtrip_vs_connect_request(&original);

        assert_eq!(result.cn, original.cn);
        assert_eq!(result.ctype, original.ctype);
        assert_eq!(result.params.len(), 2);
        assert!(matches!(
            result.params[0].value,
            ParamValue::StrParam(ref value) if value == "resume"
        ));
        assert!(matches!(
            result.params[1].value,
            ParamValue::U64Param(u64::MAX)
        ));
    }
}

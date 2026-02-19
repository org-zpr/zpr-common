use std::io::Cursor;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::packet_info::L3Type;
use crate::vsapi::v1;
use crate::vsapi_types::VsapiFiveTuple;
use crate::vsapi_types::VsapiTypeError;
use crate::vsapi_types::util::time::visa_expiration_timestamp_to_system_time;
use crate::vsapi_types::vsapi_ip_number;

/// Structure representing the Visa
// TODO figure out which of these need to stay once we switch to capnp
#[derive(Debug, Clone)]
pub struct Visa {
    pub issuer_id: u64,
    pub config: i64,
    pub expires: SystemTime,
    pub source_addr: IpAddr,
    pub dest_addr: IpAddr,
    pub dock_pep: DockPep,
    pub session_key: KeySet,
    pub cons: Option<Constraints>,
}

#[derive(Debug, Clone)]
pub enum DockPep {
    TCP(TcpUdpPep),
    UDP(TcpUdpPep),
    ICMP(IcmpPep),
}

#[derive(Debug, Clone)]
pub struct TcpUdpPep {
    pub source_port: u16,
    pub dest_port: u16,
    pub endpoint: EndpointT,
}

#[derive(Debug, Clone)]
pub enum EndpointT {
    Any,
    Server,
    Client,
}

#[derive(Debug, Clone)]
pub struct IcmpPep {
    /// the allowed ICMP type and code (in lower 16 bits)
    pub icmp_type: u8,
    pub icmp_code: u8,
}

#[derive(Default, Debug, Clone)]
pub struct KeySet {
    pub format: KeyFormat,
    /// session key encrypted for ingress node to read
    pub ingress_key: Vec<u8>,
    /// session key encrypted for egress node to read
    pub egress_key: Vec<u8>,
}

#[derive(Default, Debug, Clone)]
pub enum KeyFormat {
    #[default]
    ZprKF01,
}

#[derive(Debug)]
pub enum VisaOp {
    Grant(Visa),
    RevokeVisaId(u64),
}

#[derive(Debug, Clone)]
pub struct Constraints {
    /// not set or none means no bandwidth constraint
    pub bw: bool,
    pub bw_limit_bps: i64,
    /// empty/None means no data cap
    pub data_cap_id: String,
    pub data_cap_bytes: i64,
    /// tether addr of service actor
    pub data_cap_affinity_addr: Vec<u8>,
}

impl KeySet {
    pub fn new(ingress: &[u8], egress: &[u8]) -> Self {
        KeySet {
            ingress_key: ingress.to_vec(),
            egress_key: egress.to_vec(),
            format: KeyFormat::default(),
        }
    }
}

impl Visa {
    /// Create a new Visa, given values
    pub fn new(
        issuer_id: u64,
        config: i64,
        expires: SystemTime,
        source_addr: IpAddr,
        dest_addr: IpAddr,
        dock_pep: DockPep,
        session_key: KeySet,
        cons: Option<Constraints>,
    ) -> Self {
        Self {
            issuer_id,
            config,
            expires,
            source_addr,
            dest_addr,
            dock_pep,
            session_key,
            cons,
        }
    }

    pub fn from_capnp_bytes(bytes: &[u8]) -> Result<Self, VsapiTypeError> {
        let mut cur = Cursor::new(bytes);
        let reader =
            capnp::serialize::read_message(&mut cur, capnp::message::ReaderOptions::new())?;
        let visa_reader = reader.get_root::<v1::visa::Reader>()?;
        Visa::try_from(visa_reader)
    }

    /// Get the FiveTuple from a Visa
    pub fn get_five_tuple(&self) -> VsapiFiveTuple {
        let source_addr = self.source_addr;
        let dest_addr = self.dest_addr;

        let l3_protocol = if source_addr.is_ipv4() {
            L3Type::Ipv4
        } else {
            L3Type::Ipv6
        };

        let (l4_protocol, source_port, dest_port) = match &self.dock_pep {
            DockPep::ICMP(icmp_pep) => {
                if l3_protocol == L3Type::Ipv6 {
                    (
                        vsapi_ip_number::IPV6_ICMP,
                        icmp_pep.icmp_type as u16,
                        icmp_pep.icmp_code as u16,
                    )
                } else {
                    (
                        vsapi_ip_number::ICMP,
                        icmp_pep.icmp_type as u16,
                        icmp_pep.icmp_code as u16,
                    )
                }
            }
            DockPep::UDP(tcp_udp_pep) => (
                vsapi_ip_number::UDP,
                tcp_udp_pep.source_port,
                tcp_udp_pep.dest_port,
            ),
            DockPep::TCP(tcp_udp_pep) => (
                vsapi_ip_number::TCP,
                tcp_udp_pep.source_port,
                tcp_udp_pep.dest_port,
            ),
        };

        return VsapiFiveTuple {
            source_addr,
            dest_addr,
            l3_type: l3_protocol,
            l4_protocol,
            source_port,
            dest_port,
        };
    }

    /// Get the expiration in milliseconds since UNIX epoch (which is how visa service formats it).
    pub fn get_expiration_timestamp(&self) -> u64 {
        match self.expires.duration_since(UNIX_EPOCH) {
            Ok(dur) => dur.as_millis() as u64,
            Err(_) => 0,
        }
    }
}

impl TcpUdpPep {
    pub fn new(source_port: u16, dest_port: u16, endpoint: EndpointT) -> Self {
        Self {
            source_port,
            dest_port,
            endpoint,
        }
    }
}

impl IcmpPep {
    pub fn new(icmp_type: u8, icmp_code: u8) -> Self {
        Self {
            icmp_type,
            icmp_code,
        }
    }
}

impl TryFrom<v1::visa::Reader<'_>> for Visa {
    type Error = VsapiTypeError;

    /// Returns err if required values are not set or if values are badly formatted
    fn try_from(reader: v1::visa::Reader) -> Result<Self, Self::Error> {
        let issuer_id = reader.get_issuer_id();
        let config = 0i64;
        let expires = visa_expiration_timestamp_to_system_time(reader.get_expiration());

        let source_addr = IpAddr::try_from(reader.get_source_addr()?)?;
        let dest_addr = IpAddr::try_from(reader.get_dest_addr()?)?;

        let dock_pep = DockPep::try_from(reader.get_dock_pep()?)?;
        let session_key = KeySet::try_from(reader.get_session_key()?)?;

        // TODO: constraints not yet implemented.
        let cons = None;

        Ok(Self {
            issuer_id,
            config,
            expires,
            source_addr,
            dest_addr,
            dock_pep,
            session_key,
            cons,
        })
    }
}

impl TryFrom<v1::visa_op::Reader<'_>> for VisaOp {
    type Error = VsapiTypeError;

    /// Returns err if required values are not set or if values are badly formatted
    fn try_from(reader: v1::visa_op::Reader) -> Result<Self, Self::Error> {
        match reader.which()? {
            v1::visa_op::Which::Grant(visa_result) => {
                let visa_reader = visa_result?;
                let visa = Visa::try_from(visa_reader)?;
                Ok(VisaOp::Grant(visa))
            }
            v1::visa_op::Which::RevokeVisaId(issuer_id) => Ok(VisaOp::RevokeVisaId(issuer_id)),
        }
    }
}

impl TryFrom<v1::dock_pep::Reader<'_>> for DockPep {
    type Error = VsapiTypeError;

    /// Returns err if required values are not set
    fn try_from(reader: v1::dock_pep::Reader) -> Result<Self, Self::Error> {
        match reader.which()? {
            v1::dock_pep::Which::Tcp(tcp_udp_pep_result) => {
                let tcp_udp_pep_reader = tcp_udp_pep_result?;
                let source_port = tcp_udp_pep_reader.get_source_port();
                let dest_port = tcp_udp_pep_reader.get_dest_port();
                let endpoint = match tcp_udp_pep_reader.get_endpoint()? {
                    v1::EndpointT::Any => EndpointT::Any,
                    v1::EndpointT::Server => EndpointT::Server,
                    v1::EndpointT::Client => EndpointT::Client,
                };
                let tcp_udp_pep = TcpUdpPep::new(source_port, dest_port, endpoint);
                Ok(DockPep::TCP(tcp_udp_pep))
            }
            v1::dock_pep::Which::Udp(tcp_udp_pep_result) => {
                let tcp_udp_pep_reader = tcp_udp_pep_result?;
                let source_port = tcp_udp_pep_reader.get_source_port();
                let dest_port = tcp_udp_pep_reader.get_dest_port();
                let endpoint = match tcp_udp_pep_reader.get_endpoint()? {
                    v1::EndpointT::Any => EndpointT::Any,
                    v1::EndpointT::Server => EndpointT::Server,
                    v1::EndpointT::Client => EndpointT::Client,
                };
                let tcp_udp_pep = TcpUdpPep::new(source_port, dest_port, endpoint);
                Ok(DockPep::UDP(tcp_udp_pep))
            }
            v1::dock_pep::Which::Icmp(icmp_pep_result) => {
                let icmp_pep_reader = icmp_pep_result?;
                let type_code = icmp_pep_reader.get_icmp_type_code();
                let icmp_pep = IcmpPep::new(type_code as u8, 0);
                Ok(DockPep::ICMP(icmp_pep))
            }
        }
    }
}

impl TryFrom<v1::key_set::Reader<'_>> for KeySet {
    type Error = VsapiTypeError;

    /// Returns err if required values are not set
    fn try_from(reader: v1::key_set::Reader) -> Result<Self, Self::Error> {
        let format = match reader.get_format()? {
            v1::KeyFormat::ZprKF01 => KeyFormat::ZprKF01,
        };
        let ingress_key = reader.get_ingress_key()?.to_vec();
        let egress_key = reader.get_egress_key()?.to_vec();

        Ok(Self {
            format,
            ingress_key,
            egress_key,
        })
    }
}

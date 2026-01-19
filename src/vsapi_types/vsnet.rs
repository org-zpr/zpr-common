use crate::vsapi::v1;
use crate::vsapi_types::VsapiTypeError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug)]
pub struct SockAddr {
    pub addr: IpAddr,
    pub port: u16,
}

impl From<SockAddr> for SocketAddr {
    fn from(sock_addr: SockAddr) -> Self {
        SocketAddr::new(sock_addr.addr, sock_addr.port)
    }
}

impl TryFrom<v1::sock_addr::Reader<'_>> for SockAddr {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::sock_addr::Reader<'_>) -> Result<Self, Self::Error> {
        let addr_rdr = reader.get_addr()?;
        let addr = match addr_rdr.which()? {
            v1::ip_addr::V4(ipv4) => {
                let octets: [u8; 4] = ipv4?.try_into()?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            v1::ip_addr::V6(ipv6) => {
                let octets: [u8; 16] = ipv6?.try_into()?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        let port = reader.get_port();

        Ok(SockAddr { addr, port })
    }
}

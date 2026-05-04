use crate::vsapi::v1;
use crate::vsapi_types::{SockAddr, VsapiTypeError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRole {
    Active,
    Backup,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    pub link_id: String,
    pub peer: SockAddr,
    pub role: LinkRole,
}

impl TryFrom<v1::LinkRole> for LinkRole {
    type Error = VsapiTypeError;

    fn try_from(r: v1::LinkRole) -> Result<Self, Self::Error> {
        match r {
            v1::LinkRole::Active => Ok(LinkRole::Active),
            v1::LinkRole::Backup => Ok(LinkRole::Backup),
        }
    }
}

impl TryFrom<v1::link::Reader<'_>> for Link {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::link::Reader<'_>) -> Result<Self, Self::Error> {
        let link_id = reader.get_link_id()?.to_string()?;
        let peer = SockAddr::try_from(reader.get_peer()?)?;
        let role = LinkRole::try_from(reader.get_role()?)?;
        Ok(Link {
            link_id,
            peer,
            role,
        })
    }
}

impl Link {
    pub fn is_active(&self) -> bool {
        matches!(self.role, LinkRole::Active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vsapi::v1;
    use crate::vsapi_types::SockAddr;
    use crate::write_to::WriteTo;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn make_link_msg(
        link_id: &str,
        peer_ip: IpAddr,
        peer_port: u16,
        role: v1::LinkRole,
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::link::Builder<'_> = msg.init_root();
            root.set_link_id(link_id);
            root.set_role(role);
            let mut peer = root.reborrow().init_peer();
            peer.set_port(peer_port);
            let mut addr_bldr = peer.reborrow().init_addr();
            match peer_ip {
                IpAddr::V4(ipv4) => {
                    let buf = addr_bldr.reborrow().init_v4(4);
                    buf.copy_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    let buf = addr_bldr.reborrow().init_v6(16);
                    buf.copy_from_slice(&ipv6.octets());
                }
            }
        }
        msg
    }

    fn roundtrip_link(link: &Link) -> Link {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::link::Builder<'_> = msg.init_root();
            link.write_to(&mut root);
        }
        let reader: v1::link::Reader<'_> = msg.get_root_as_reader().unwrap();
        Link::try_from(reader).unwrap()
    }

    fn roundtrip_sock_addr(sa: &SockAddr) -> SockAddr {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::sock_addr::Builder<'_> = msg.init_root();
            sa.write_to(&mut root);
        }
        let reader: v1::sock_addr::Reader<'_> = msg.get_root_as_reader().unwrap();
        SockAddr::try_from(reader).unwrap()
    }

    #[test]
    fn test_link_role_active() {
        let role = LinkRole::try_from(v1::LinkRole::Active).unwrap();
        assert_eq!(role, LinkRole::Active);
    }

    #[test]
    fn test_link_role_backup() {
        let role = LinkRole::try_from(v1::LinkRole::Backup).unwrap();
        assert_eq!(role, LinkRole::Backup);
    }

    #[test]
    fn test_link_tryfrom_active_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let msg = make_link_msg("link-v4-active", ip, 4500, v1::LinkRole::Active);
        let reader: v1::link::Reader<'_> = msg.get_root_as_reader().unwrap();
        let link = Link::try_from(reader).unwrap();
        assert_eq!(link.link_id, "link-v4-active");
        assert_eq!(link.peer.addr, ip);
        assert_eq!(link.peer.port, 4500);
        assert_eq!(link.role, LinkRole::Active);
    }

    #[test]
    fn test_link_tryfrom_backup_ipv6() {
        let ip = IpAddr::V6("2001:db8::1".parse().unwrap());
        let msg = make_link_msg("link-v6-backup", ip, 6000, v1::LinkRole::Backup);
        let reader: v1::link::Reader<'_> = msg.get_root_as_reader().unwrap();
        let link = Link::try_from(reader).unwrap();
        assert_eq!(link.link_id, "link-v6-backup");
        assert_eq!(link.peer.addr, ip);
        assert_eq!(link.peer.port, 6000);
        assert_eq!(link.role, LinkRole::Backup);
    }

    #[test]
    fn test_link_roundtrip_active_ipv4() {
        let original = Link {
            link_id: "rt-v4-active".to_string(),
            peer: SockAddr {
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                port: 8080,
            },
            role: LinkRole::Active,
        };
        let result = roundtrip_link(&original);
        assert_eq!(result, original);
    }

    #[test]
    fn test_link_roundtrip_backup_ipv6() {
        let original = Link {
            link_id: "rt-v6-backup".to_string(),
            peer: SockAddr {
                addr: IpAddr::V6(Ipv6Addr::from([
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ])),
                port: 9000,
            },
            role: LinkRole::Backup,
        };
        let result = roundtrip_link(&original);
        assert_eq!(result, original);
    }

    #[test]
    fn test_sock_addr_roundtrip_ipv4() {
        let original = SockAddr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
            port: 1234,
        };
        let result = roundtrip_sock_addr(&original);
        assert_eq!(result.addr, original.addr);
        assert_eq!(result.port, original.port);
    }

    #[test]
    fn test_sock_addr_roundtrip_ipv6() {
        let original = SockAddr {
            addr: IpAddr::V6(Ipv6Addr::from([0u8; 16])),
            port: 5678,
        };
        let result = roundtrip_sock_addr(&original);
        assert_eq!(result.addr, original.addr);
        assert_eq!(result.port, original.port);
    }
}

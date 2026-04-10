use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::policy::v1;
use crate::policy_types::attr_exp::AttrExp;
use crate::policy_types::error::PolicyTypeError;
use crate::write_to::WriteTo;

/// Shadows the cap'n proto `Peering` struct.
pub struct Peering {
    pub link_id: String,
    pub node_a: IpAddr, // by convention we are useing ZPR address
    pub substrate_a: SubstrateAddr,
    pub node_b: IpAddr, // by convention we are useing ZPR address
    pub substrate_b: SubstrateAddr,
    pub attributes: Vec<AttrExp>,
}

/// Either a host name or an IP address.
#[derive(Debug)]
pub enum NetworkHost {
    Ip(IpAddr),
    Hostname(String),
}

/// Maps to a Cap'n Proto `NetAddr`
#[derive(Debug)]
pub struct SubstrateAddr {
    pub host: NetworkHost,
    pub port: u16,
}

impl TryFrom<v1::net_addr::Reader<'_>> for SubstrateAddr {
    type Error = PolicyTypeError;

    fn try_from(reader: v1::net_addr::Reader<'_>) -> Result<Self, Self::Error> {
        let port = reader.get_port();
        match reader.which()? {
            v1::net_addr::IpAddr(ip) => {
                let ip = ip?;
                if ip.len() == 4 {
                    let octets: [u8; 4] = ip.try_into().map_err(|_| {
                        PolicyTypeError::DeserializationError("Invalid IPv4 length")
                    })?;
                    let ipv4_addr = Ipv4Addr::from(octets);
                    return Ok(SubstrateAddr {
                        host: NetworkHost::Ip(IpAddr::V4(ipv4_addr)),
                        port,
                    });
                } else if ip.len() == 16 {
                    let octets: [u8; 16] = ip.try_into().map_err(|_| {
                        PolicyTypeError::DeserializationError("Invalid IPv6 length")
                    })?;
                    let ipv6_addr = Ipv6Addr::from(octets);
                    return Ok(SubstrateAddr {
                        host: NetworkHost::Ip(IpAddr::V6(ipv6_addr)),
                        port,
                    });
                } else {
                    return Err(PolicyTypeError::DeserializationError("Invalid IP length"));
                }
            }
            v1::net_addr::Hostname(hostname) => {
                let hostname_str = hostname?.to_string()?;
                Ok(SubstrateAddr {
                    host: NetworkHost::Hostname(hostname_str),
                    port,
                })
            }
        }
    }
}

impl TryFrom<v1::peering::Reader<'_>> for Peering {
    type Error = PolicyTypeError;

    fn try_from(reader: v1::peering::Reader<'_>) -> Result<Self, Self::Error> {
        let link_id = reader.get_link_id()?.to_string()?;
        let node_a: IpAddr = reader.get_node_a()?.to_string()?.parse()?;
        let substrate_a: SubstrateAddr = reader.get_node_a_substrate()?.try_into()?;

        let node_b: IpAddr = reader.get_node_b()?.to_string()?.parse()?;
        let substrate_b: SubstrateAddr = reader.get_node_b_substrate()?.try_into()?;

        let mut attributes = Vec::new();
        for attr in reader.get_attrs()?.iter() {
            attributes.push(attr.try_into()?);
        }

        Ok(Self {
            link_id,
            node_a,
            substrate_a,
            node_b,
            substrate_b,
            attributes,
        })
    }
}

impl WriteTo<v1::peering::Builder<'_>> for Peering {
    fn write_to(&self, bldr: &mut v1::peering::Builder) {
        bldr.set_link_id(&self.link_id);
        bldr.set_node_a(&self.node_a.to_string());
        self.substrate_a
            .write_to(&mut bldr.reborrow().init_node_a_substrate());
        bldr.set_node_b(&self.node_b.to_string());
        self.substrate_b
            .write_to(&mut bldr.reborrow().init_node_b_substrate());

        let mut attr_list = bldr.reborrow().init_attrs(self.attributes.len() as u32);
        for (i, attr) in self.attributes.iter().enumerate() {
            attr.write_to(&mut attr_list.reborrow().get(i as u32));
        }
    }
}

impl WriteTo<v1::net_addr::Builder<'_>> for SubstrateAddr {
    fn write_to(&self, bldr: &mut v1::net_addr::Builder) {
        bldr.set_port(self.port);
        match &self.host {
            NetworkHost::Ip(ip) => {
                let ip_bytes = match ip {
                    IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
                    IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
                };
                bldr.set_ip_addr(&ip_bytes);
            }
            NetworkHost::Hostname(hostname) => {
                bldr.set_hostname(hostname);
            }
        }
    }
}

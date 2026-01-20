use std::net::IpAddr;

use crate::vsapi::v1;
use crate::vsapi_types::{
    CommFlag, DockPep, EndpointT, IcmpPep, KeySet, PacketDesc, ServiceDescriptor, TcpUdpPep, Visa,
    VisaOp,
};
use crate::write_to::WriteTo;

impl WriteTo<v1::ip_addr::Builder<'_>> for IpAddr {
    fn write_to(&self, bldr: &mut v1::ip_addr::Builder<'_>) {
        match self {
            IpAddr::V4(ipv4) => {
                let v4_buf = bldr.reborrow().init_v4(4);
                v4_buf.copy_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                let v6_buf = bldr.reborrow().init_v6(16);
                v6_buf.copy_from_slice(&ipv6.octets());
            }
        }
    }
}

// Write out a visa to a Cap'n Proto builder.
impl WriteTo<v1::visa::Builder<'_>> for Visa {
    fn write_to(&self, bldr: &mut v1::visa::Builder<'_>) {
        bldr.set_issuer_id(self.issuer_id);
        bldr.set_expiration(self.get_expiration_timestamp());
        let mut ip_bldr = bldr.reborrow().init_dest_addr();
        self.dest_addr.write_to(&mut ip_bldr);
        let mut ip_bldr = bldr.reborrow().init_source_addr();
        self.source_addr.write_to(&mut ip_bldr);
        match &self.dock_pep {
            DockPep::TCP(pep) => {
                let pep_bldr = bldr.reborrow().init_dock_pep();
                let mut tcp_bldr = pep_bldr.init_tcp();
                pep.write_to(&mut tcp_bldr);
            }
            DockPep::UDP(pep) => {
                let pep_bldr = bldr.reborrow().init_dock_pep();
                let mut udp_bldr = pep_bldr.init_udp();
                pep.write_to(&mut udp_bldr);
            }
            DockPep::ICMP(pep) => {
                let pep_bldr = bldr.reborrow().init_dock_pep();
                let mut icmp_bldr = pep_bldr.init_icmp();
                pep.write_to(&mut icmp_bldr);
            }
        }
        if self.cons.is_some() {
            unimplemented!("visa constraints serialization not implemented yet");
        }
        let mut keyset_bldr = bldr.reborrow().init_session_key();
        self.session_key.write_to(&mut keyset_bldr);
    }
}

impl WriteTo<v1::dock_pep_tcp_udp::Builder<'_>> for TcpUdpPep {
    fn write_to(&self, bldr: &mut v1::dock_pep_tcp_udp::Builder<'_>) {
        bldr.set_source_port(self.source_port);
        bldr.set_dest_port(self.dest_port);
        match self.endpoint {
            EndpointT::Any => bldr.set_endpoint(v1::EndpointT::Any),
            EndpointT::Server => bldr.set_endpoint(v1::EndpointT::Server),
            EndpointT::Client => bldr.set_endpoint(v1::EndpointT::Client),
        }
    }
}

impl WriteTo<v1::dock_pep_icmp::Builder<'_>> for IcmpPep {
    fn write_to(&self, bldr: &mut v1::dock_pep_icmp::Builder<'_>) {
        let typecode: u16 = ((self.icmp_type as u16) << 8) | (self.icmp_code as u16);
        bldr.set_icmp_type_code(typecode);
    }
}

impl WriteTo<v1::key_set::Builder<'_>> for KeySet {
    fn write_to(&self, bldr: &mut v1::key_set::Builder<'_>) {
        bldr.set_format(v1::KeyFormat::ZprKF01);
        bldr.set_ingress_key(&self.ingress_key);
        bldr.set_egress_key(&self.egress_key);
    }
}

impl WriteTo<v1::packet_desc::Builder<'_>> for PacketDesc {
    fn write_to(&self, bldr: &mut v1::packet_desc::Builder<'_>) {
        let mut ip_bldr = bldr.reborrow().init_source_addr();
        self.source_addr().write_to(&mut ip_bldr);
        let mut ip_bldr = bldr.reborrow().init_dest_addr();
        self.dest_addr().write_to(&mut ip_bldr);
        bldr.set_protocol(self.protocol());
        bldr.set_source_port(self.source_port());
        bldr.set_dest_port(self.dest_port());
        match self.comm_flags {
            CommFlag::BiDirectional => bldr.set_comm_type(v1::CommType::Bidirectional),
            CommFlag::UniDirectional => bldr.set_comm_type(v1::CommType::Unidirectional),
            CommFlag::ReRequest(_) => bldr.set_comm_type(v1::CommType::Rerequest),
        }
    }
}

impl WriteTo<v1::visa_op::Builder<'_>> for VisaOp {
    fn write_to(&self, bldr: &mut v1::visa_op::Builder<'_>) {
        match self {
            VisaOp::Grant(v) => {
                let mut grant_bldr = bldr.reborrow().init_grant();
                v.write_to(&mut grant_bldr);
            }
            VisaOp::RevokeVisaId(id) => {
                bldr.set_revoke_visa_id(*id);
            }
        }
    }
}

impl WriteTo<v1::service_descriptor::Builder<'_>> for ServiceDescriptor {
    fn write_to(&self, bldr: &mut v1::service_descriptor::Builder<'_>) {
        bldr.set_stype(v1::ServiceT::ActorAuthentication);
        bldr.set_service_id(self.service_id.clone());
        bldr.set_service_uri(self.service_uri.clone());
        let mut ip_bldr = bldr.reborrow().init_zpr_addr();
        self.zpr_addr.write_to(&mut ip_bldr);
    }
}

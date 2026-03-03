//! Model the Param type in the Cap'n Proto.

use crate::vsapi::v1;
use crate::vsapi_types::VsapiTypeError;

const IPV4_LEN: usize = 4;
const IPV6_LEN: usize = 16;

/// Shared, well known parameter names.
pub mod pname {
    /// Used to pass a ZPR address
    pub const ZPR_ADDR: &str = "zpr_addr";

    /// Used to pass a network prefix string in CIDR format.
    pub const AAA_PREFIX: &str = "aaa_prefix";
}

#[derive(Debug)]
pub enum ParamValue {
    StrParam(String),
    U64Param(u64),
    IpParam(std::net::IpAddr),
}

#[derive(Debug)]
pub struct Param {
    pub name: String,
    pub value: ParamValue,
}

impl TryFrom<v1::param::Reader<'_>> for Param {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::param::Reader<'_>) -> Result<Self, Self::Error> {
        let pname = reader.get_name()?.to_string()?;
        let ptype = reader.get_ptype()?;
        match ptype {
            v1::ParamT::String => match reader.which()? {
                v1::param::ValueText(txt) => {
                    let srdr = txt?;
                    let sval = std::str::from_utf8(srdr.as_bytes())?.to_string();
                    return Ok(Param {
                        name: pname,
                        value: ParamValue::StrParam(sval),
                    });
                }
                _ => {
                    return Err(VsapiTypeError::DeserializationError(
                        "string param must be valueText",
                    ));
                }
            },

            v1::ParamT::U64 => match reader.which()? {
                v1::param::ValueU64(uval) => {
                    return Ok(Param {
                        name: pname,
                        value: ParamValue::U64Param(uval),
                    });
                }
                _ => {
                    return Err(VsapiTypeError::DeserializationError(
                        "u64 param must be valueU64",
                    ));
                }
            },

            v1::ParamT::Ipv4 => match reader.which()? {
                v1::param::ValueData(data) => {
                    let bytes = data?;
                    if bytes.len() != IPV4_LEN {
                        return Err(VsapiTypeError::DeserializationError(
                            "IPv4 param must be 4 bytes",
                        ));
                    }
                    let addr = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                    return Ok(Param {
                        name: pname,
                        value: ParamValue::IpParam(std::net::IpAddr::V4(addr)),
                    });
                }
                _ => {
                    return Err(VsapiTypeError::DeserializationError(
                        "IPv4 param must be valueData",
                    ));
                }
            },

            v1::ParamT::Ipv6 => match reader.which()? {
                v1::param::ValueData(data) => {
                    let bytes = data?;
                    if bytes.len() != IPV6_LEN {
                        return Err(VsapiTypeError::DeserializationError(
                            "IPv6 param must be 16 bytes",
                        ));
                    }
                    let addr = std::net::Ipv6Addr::from(
                        <[u8; IPV6_LEN]>::try_from(bytes.as_ref()).map_err(|_| {
                            VsapiTypeError::DeserializationError(
                                "Failed to convert to [u8; 16] for IPv6",
                            )
                        })?,
                    );
                    return Ok(Param {
                        name: pname,
                        value: ParamValue::IpParam(std::net::IpAddr::V6(addr)),
                    });
                }
                _ => {
                    return Err(VsapiTypeError::DeserializationError(
                        "IPv6 param must be valueData",
                    ));
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vsapi::v1;

    // --- helpers ---

    fn text_param_msg(
        name: &str,
        ptype: v1::ParamT,
        text_value: &str,
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::param::Builder<'_> = msg.init_root();
            root.set_name(name);
            root.set_ptype(ptype);
            root.set_value_text(text_value);
        }
        msg
    }

    fn u64_param_msg(
        name: &str,
        ptype: v1::ParamT,
        u64_value: u64,
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::param::Builder<'_> = msg.init_root();
            root.set_name(name);
            root.set_ptype(ptype);
            root.set_value_u64(u64_value);
        }
        msg
    }

    fn data_param_msg(
        name: &str,
        ptype: v1::ParamT,
        data_value: &[u8],
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::param::Builder<'_> = msg.init_root();
            root.set_name(name);
            root.set_ptype(ptype);
            root.set_value_data(data_value);
        }
        msg
    }

    fn read_param(
        msg: &capnp::message::Builder<capnp::message::HeapAllocator>,
    ) -> Result<Param, VsapiTypeError> {
        let reader: v1::param::Reader<'_> = msg.get_root_as_reader().unwrap();
        Param::try_from(reader)
    }

    // --- happy path ---

    #[test]
    fn string_param_roundtrip() {
        let msg = text_param_msg("zpr_addr", v1::ParamT::String, "10.0.0.1");
        let param = read_param(&msg).unwrap();
        assert_eq!(param.name, "zpr_addr");
        assert!(matches!(param.value, ParamValue::StrParam(ref s) if s == "10.0.0.1"));
    }

    #[test]
    fn string_param_empty_value() {
        let msg = text_param_msg("key", v1::ParamT::String, "");
        let param = read_param(&msg).unwrap();
        assert!(matches!(param.value, ParamValue::StrParam(ref s) if s.is_empty()));
    }

    #[test]
    fn u64_param_roundtrip() {
        let msg = u64_param_msg("counter", v1::ParamT::U64, 42);
        let param = read_param(&msg).unwrap();
        assert_eq!(param.name, "counter");
        assert!(matches!(param.value, ParamValue::U64Param(42)));
    }

    #[test]
    fn u64_param_zero() {
        let msg = u64_param_msg("counter", v1::ParamT::U64, 0);
        let param = read_param(&msg).unwrap();
        assert!(matches!(param.value, ParamValue::U64Param(0)));
    }

    #[test]
    fn u64_param_max() {
        let msg = u64_param_msg("counter", v1::ParamT::U64, u64::MAX);
        let param = read_param(&msg).unwrap();
        assert!(matches!(param.value, ParamValue::U64Param(u64::MAX)));
    }

    #[test]
    fn ipv4_param_roundtrip() {
        let msg = data_param_msg("addr", v1::ParamT::Ipv4, &[192, 168, 1, 1]);
        let param = read_param(&msg).unwrap();
        assert_eq!(param.name, "addr");
        match param.value {
            ParamValue::IpParam(std::net::IpAddr::V4(a)) => {
                assert_eq!(a, std::net::Ipv4Addr::new(192, 168, 1, 1));
            }
            _ => panic!("expected IpParam(V4)"),
        }
    }

    #[test]
    fn ipv4_broadcast() {
        let msg = data_param_msg("bc", v1::ParamT::Ipv4, &[255, 255, 255, 255]);
        let param = read_param(&msg).unwrap();
        assert!(matches!(
            param.value,
            ParamValue::IpParam(std::net::IpAddr::V4(a)) if a == std::net::Ipv4Addr::BROADCAST
        ));
    }

    #[test]
    fn ipv6_param_roundtrip() {
        let bytes: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let msg = data_param_msg("addr6", v1::ParamT::Ipv6, &bytes);
        let param = read_param(&msg).unwrap();
        match param.value {
            ParamValue::IpParam(std::net::IpAddr::V6(a)) => {
                assert_eq!(a, std::net::Ipv6Addr::from(bytes));
            }
            _ => panic!("expected IpParam(V6)"),
        }
    }

    #[test]
    fn ipv6_loopback() {
        let mut bytes = [0u8; 16];
        bytes[15] = 1; // ::1
        let msg = data_param_msg("lo6", v1::ParamT::Ipv6, &bytes);
        let param = read_param(&msg).unwrap();
        assert!(matches!(
            param.value,
            ParamValue::IpParam(std::net::IpAddr::V6(a)) if a == std::net::Ipv6Addr::LOCALHOST
        ));
    }

    // --- type/union mismatches ---

    #[test]
    fn string_ptype_u64_union_errors() {
        let msg = u64_param_msg("x", v1::ParamT::String, 99);
        assert!(matches!(
            read_param(&msg),
            Err(VsapiTypeError::DeserializationError(_))
        ));
    }

    #[test]
    fn string_ptype_data_union_errors() {
        let msg = data_param_msg("x", v1::ParamT::String, &[1, 2, 3]);
        assert!(matches!(
            read_param(&msg),
            Err(VsapiTypeError::DeserializationError(_))
        ));
    }

    #[test]
    fn u64_ptype_text_union_errors() {
        let msg = text_param_msg("x", v1::ParamT::U64, "oops");
        assert!(matches!(
            read_param(&msg),
            Err(VsapiTypeError::DeserializationError(_))
        ));
    }

    #[test]
    fn u64_ptype_data_union_errors() {
        let msg = data_param_msg("x", v1::ParamT::U64, &[1, 2, 3, 4]);
        assert!(matches!(
            read_param(&msg),
            Err(VsapiTypeError::DeserializationError(_))
        ));
    }

    #[test]
    fn ipv4_ptype_text_union_errors() {
        let msg = text_param_msg("x", v1::ParamT::Ipv4, "not-bytes");
        assert!(matches!(
            read_param(&msg),
            Err(VsapiTypeError::DeserializationError(_))
        ));
    }

    #[test]
    fn ipv6_ptype_text_union_errors() {
        let msg = text_param_msg("x", v1::ParamT::Ipv6, "not-bytes");
        assert!(matches!(
            read_param(&msg),
            Err(VsapiTypeError::DeserializationError(_))
        ));
    }

    // --- wrong byte lengths for IP types ---

    #[test]
    fn ipv4_too_few_bytes_errors() {
        let msg = data_param_msg("x", v1::ParamT::Ipv4, &[1, 2, 3]);
        assert!(matches!(
            read_param(&msg),
            Err(VsapiTypeError::DeserializationError(_))
        ));
    }

    #[test]
    fn ipv4_too_many_bytes_errors() {
        let msg = data_param_msg("x", v1::ParamT::Ipv4, &[1, 2, 3, 4, 5]);
        assert!(matches!(
            read_param(&msg),
            Err(VsapiTypeError::DeserializationError(_))
        ));
    }

    #[test]
    fn ipv4_zero_bytes_errors() {
        let msg = data_param_msg("x", v1::ParamT::Ipv4, &[]);
        assert!(matches!(
            read_param(&msg),
            Err(VsapiTypeError::DeserializationError(_))
        ));
    }

    #[test]
    fn ipv6_too_few_bytes_errors() {
        let msg = data_param_msg("x", v1::ParamT::Ipv6, &[0u8; 15]);
        assert!(matches!(
            read_param(&msg),
            Err(VsapiTypeError::DeserializationError(_))
        ));
    }

    #[test]
    fn ipv6_too_many_bytes_errors() {
        let msg = data_param_msg("x", v1::ParamT::Ipv6, &[0u8; 17]);
        assert!(matches!(
            read_param(&msg),
            Err(VsapiTypeError::DeserializationError(_))
        ));
    }
}

//! Model the Param type in the Cap'n Proto.

use crate::vsapi::v1;
use crate::vsapi_types::VsapiTypeError;

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
                    if bytes.len() != 4 {
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
                    if bytes.len() != 16 {
                        return Err(VsapiTypeError::DeserializationError(
                            "IPv6 param must be 16 bytes",
                        ));
                    }
                    let addr = std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(bytes.as_ref()).map_err(|_| {
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

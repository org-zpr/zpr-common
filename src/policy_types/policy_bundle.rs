use bytes::{Buf, Bytes};
use std::fmt;
use std::io::prelude::*;

use crate::policy::v1;
use crate::policy_types::PolicyTypeError;

use base64::prelude::*;
use colored::Colorize;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct PolicyBundle {
    pub config_id: u64,  // ignored when installing
    pub version: String, // use empty string if you don't care
    pub format: String,
    pub container: String,
}

impl fmt::Display for PolicyBundle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}  ", "id:".dimmed(), self.config_id)?;
        write!(f, "{} {}  ", "version:".dimmed(), self.version)?;
        write!(f, "{} {}  ", "format:".dimmed(), self.format)?;
        write!(f, "{} {}\n", "container:".dimmed(), self.container)
    }
}

impl PolicyBundle {
    /// Create the [PolicyBundle] from the PolicyContainerBytes.
    ///
    /// ### Errors
    /// - Cap'n Proto errors related to deserialization.
    /// - GZIP errors related to compression. (unlikely)
    pub fn new_from_policy_container(
        config_id: u64,
        container_bytes: PolicyContainerBytes,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let compiler_version = container_bytes.get_compiler_info()?.to_string();

        // compress policy data with gzip
        let mut gz_w = GzEncoder::new(Vec::new(), Compression::default());
        gz_w.write_all(container_bytes.as_bytes())?;
        let gz_bytes = gz_w.finish()?;

        // encode the compressed data as base64
        let container_b64 = BASE64_STANDARD.encode(&gz_bytes);

        Ok(PolicyBundle {
            config_id,
            version: String::new(),
            format: format!("base64;zip;{}", compiler_version),
            container: container_b64,
        })
    }

    /// Decode the `container` field of the [PolicyBundle] back into the original Cap'n Proto encoded
    /// bytes of a `PolicyContainer` struct.
    pub fn decode(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // check format:
        let mut format_parts = self.format.split(';');
        let encoding = format_parts
            .next()
            .ok_or("invalid format: missing encoding")?;
        if encoding != "base64" {
            return Err(format!("unsupported encoding: {encoding}").into());
        }
        let compression = format_parts
            .next()
            .ok_or("invalid format: missing compression")?;
        if compression != "zip" {
            return Err(format!("unsupported compression: {compression}").into());
        }

        // Don't care about compiler version (TODO: remove?) It is already in the container.

        // decode base64
        let gz_bytes = BASE64_STANDARD.decode(&self.container)?;

        // decompress gzip
        let mut gz_d = flate2::read::GzDecoder::new(&gz_bytes[..]);
        let mut container_bytes = Vec::new();
        gz_d.read_to_end(&mut container_bytes)?;

        Ok(container_bytes)
    }
}

/// Encoded Cap'n Proto `PolicyContainer` bytes.
///
/// A cheap-to-clone newtype over [bytes::Bytes] that documents, at the type
/// level, that the wrapped bytes are a policy *container* (compiler version
/// metadata, signature, and the inner policy) rather than raw policy bytes or
/// unrelated binary data.
#[derive(Clone, Debug)]
pub struct PolicyContainerBytes(Bytes);

impl PolicyContainerBytes {
    /// Borrow the raw container bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn get_compiler_info(&self) -> Result<CompilerInfo, PolicyTypeError> {
        let bytes: &[u8] = &self.0;
        let container_reader =
            capnp::serialize::read_message(bytes.reader(), capnp::message::ReaderOptions::new())?;

        let container = container_reader.get_root::<v1::policy_container::Reader>()?;
        let zplc_maj = container.get_zplc_ver_major();
        let zplc_min = container.get_zplc_ver_minor();
        let zplc_patch = container.get_zplc_ver_patch();

        Ok(CompilerInfo {
            zplc_maj,
            zplc_min,
            zplc_patch,
        })
    }
}

impl From<Vec<u8>> for PolicyContainerBytes {
    /// Take ownership of `Vec<u8>` container bytes (zero-copy via `Bytes::from`).
    fn from(v: Vec<u8>) -> Self {
        PolicyContainerBytes(Bytes::from(v))
    }
}

impl From<Bytes> for PolicyContainerBytes {
    /// Wrap already-shared `Bytes` container bytes.
    fn from(b: Bytes) -> Self {
        PolicyContainerBytes(b)
    }
}

impl Eq for PolicyContainerBytes {}

impl PartialEq for PolicyContainerBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

pub struct CompilerInfo {
    pub zplc_maj: u32,
    pub zplc_min: u32,
    pub zplc_patch: u32,
}

impl fmt::Display for CompilerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.zplc_maj, self.zplc_min, self.zplc_patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::v1;
    use bytes::Bytes;

    /// Build the Cap'n Proto encoded bytes of a `PolicyContainer` with the given
    /// compiler version and (arbitrary) policy payload, for use as test input.
    fn make_container_bytes(maj: u32, min: u32, patch: u32, policy: &[u8]) -> PolicyContainerBytes {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut container = msg.init_root::<v1::policy_container::Builder>();
            container.set_zplc_ver_major(maj);
            container.set_zplc_ver_minor(min);
            container.set_zplc_ver_patch(patch);
            container.set_policy(policy);
            container.set_signature(&[]);
        }
        let mut buf = Vec::new();
        capnp::serialize::write_message(&mut buf, &msg).unwrap();
        PolicyContainerBytes::from(buf)
    }

    /// new_from_policy_container should record the config id, an empty version,
    /// and a format string carrying the compiler version parsed from the container.
    #[test]
    fn new_from_policy_container_sets_fields() {
        let container = make_container_bytes(1, 2, 3, b"some-policy");
        let bundle = PolicyBundle::new_from_policy_container(42, container).unwrap();

        assert_eq!(bundle.config_id, 42);
        assert_eq!(bundle.version, "");
        assert_eq!(bundle.format, "base64;zip;1.2.3");
        assert!(!bundle.container.is_empty());
    }

    /// Encoding a container and decoding it back should reproduce the original bytes.
    #[test]
    fn encode_decode_round_trips() {
        let container = make_container_bytes(0, 9, 17, b"round-trip-policy");
        let bundle = PolicyBundle::new_from_policy_container(7, container.clone()).unwrap();
        let decoded = PolicyContainerBytes::from(bundle.decode().unwrap());

        assert_eq!(decoded, container);
    }

    /// new_from_policy_container should error on bytes that aren't a valid Cap'n Proto message.
    #[test]
    fn new_from_policy_container_rejects_garbage() {
        let result = PolicyBundle::new_from_policy_container(
            0,
            PolicyContainerBytes::from(Bytes::copy_from_slice(b"not capnp")),
        );
        assert!(result.is_err());
    }

    /// decode should reject a format whose encoding segment isn't "base64".
    #[test]
    fn decode_rejects_unsupported_encoding() {
        let bundle = PolicyBundle {
            config_id: 0,
            version: String::new(),
            format: "hex;zip;1.0.0".to_string(),
            container: String::new(),
        };
        let err = bundle.decode().unwrap_err();
        assert!(err.to_string().contains("unsupported encoding"));
    }

    /// decode should reject a format whose compression segment isn't "zip".
    #[test]
    fn decode_rejects_unsupported_compression() {
        let bundle = PolicyBundle {
            config_id: 0,
            version: String::new(),
            format: "base64;lz4;1.0.0".to_string(),
            container: String::new(),
        };
        let err = bundle.decode().unwrap_err();
        assert!(err.to_string().contains("unsupported compression"));
    }

    /// decode should fail when the container field isn't valid base64.
    #[test]
    fn decode_rejects_invalid_base64() {
        let bundle = PolicyBundle {
            config_id: 0,
            version: String::new(),
            format: "base64;zip;1.0.0".to_string(),
            container: "!!!not base64!!!".to_string(),
        };
        assert!(bundle.decode().is_err());
    }

    #[test]
    fn get_compiler_info_returns_correct_version() {
        let container = make_container_bytes(3, 7, 11, b"policy");
        let info = container.get_compiler_info().unwrap();
        assert_eq!(info.zplc_maj, 3);
        assert_eq!(info.zplc_min, 7);
        assert_eq!(info.zplc_patch, 11);
    }

    #[test]
    fn get_compiler_info_version_zero() {
        let container = make_container_bytes(0, 0, 0, b"");
        let info = container.get_compiler_info().unwrap();
        assert_eq!(info.zplc_maj, 0);
        assert_eq!(info.zplc_min, 0);
        assert_eq!(info.zplc_patch, 0);
    }

    #[test]
    fn get_compiler_info_rejects_garbage() {
        let bad = PolicyContainerBytes::from(Bytes::copy_from_slice(b"not capnp"));
        assert!(bad.get_compiler_info().is_err());
    }

    #[test]
    fn get_compiler_info_display_format() {
        let container = make_container_bytes(2, 4, 8, b"policy");
        let info = container.get_compiler_info().unwrap();
        assert_eq!(info.to_string(), "2.4.8");
    }

    #[test]
    fn partial_eq_same_bytes_are_equal() {
        let a = make_container_bytes(1, 0, 0, b"data");
        let b = make_container_bytes(1, 0, 0, b"data");
        assert_eq!(a, b);
    }

    #[test]
    fn partial_eq_clone_is_equal() {
        let a = make_container_bytes(1, 2, 3, b"data");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn partial_eq_different_version_not_equal() {
        let a = make_container_bytes(1, 0, 0, b"data");
        let b = make_container_bytes(2, 0, 0, b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn partial_eq_different_policy_not_equal() {
        let a = make_container_bytes(1, 0, 0, b"policy-a");
        let b = make_container_bytes(1, 0, 0, b"policy-b");
        assert_ne!(a, b);
    }

    #[test]
    fn partial_eq_from_vec_and_bytes_equal_for_same_content() {
        let container = make_container_bytes(0, 1, 0, b"x");
        let raw: Vec<u8> = container.as_bytes().to_vec();
        let from_vec = PolicyContainerBytes::from(raw.clone());
        let from_bytes = PolicyContainerBytes::from(Bytes::from(raw));
        assert_eq!(from_vec, from_bytes);
    }

    /// Display should render all four fields with their labels.
    #[test]
    fn display_includes_all_fields() {
        let bundle = PolicyBundle {
            config_id: 99,
            version: "v1".to_string(),
            format: "base64;zip;1.2.3".to_string(),
            container: "abc".to_string(),
        };
        let rendered = format!("{bundle}");
        assert!(rendered.contains("99"));
        assert!(rendered.contains("v1"));
        assert!(rendered.contains("base64;zip;1.2.3"));
        assert!(rendered.contains("abc"));
    }
}

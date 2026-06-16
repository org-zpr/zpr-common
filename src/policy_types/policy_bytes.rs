use bytes::{Buf, Bytes};
use std::fmt;

use crate::policy::v1;
use crate::policy_types::PolicyTypeError;

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

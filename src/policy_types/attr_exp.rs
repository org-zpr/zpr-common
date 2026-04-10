//! For working with the `AttrExp` policy type.

use crate::policy::v1;
use crate::policy_types::error::PolicyTypeError;
use crate::write_to::WriteTo;

/// Maps to the Cap'n Proto `AttrExp` struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrExp {
    pub key: String,
    pub op: AttrOp,
    pub value: Vec<String>, // could be empty
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttrOp {
    Eq,
    Ne,
    Has,
    Excludes,
}

impl TryFrom<v1::attr_expr::Reader<'_>> for AttrExp {
    type Error = PolicyTypeError;

    fn try_from(attr_rdr: v1::attr_expr::Reader<'_>) -> Result<Self, Self::Error> {
        let key = attr_rdr.get_key()?.to_string()?;
        let op = match attr_rdr.get_op()? {
            v1::AttrOp::Eq => AttrOp::Eq,
            v1::AttrOp::Ne => AttrOp::Ne,
            v1::AttrOp::Has => AttrOp::Has,
            v1::AttrOp::Excludes => AttrOp::Excludes,
        };
        let mut values: Vec<String> = Vec::new();
        for val in attr_rdr.get_value()?.iter() {
            values.push(val?.to_string()?);
        }
        Ok(AttrExp {
            key,
            op,
            value: values,
        })
    }
}

impl WriteTo<v1::attr_expr::Builder<'_>> for AttrExp {
    fn write_to(&self, bldr: &mut v1::attr_expr::Builder) {
        bldr.set_key(&self.key);
        let op = match self.op {
            AttrOp::Eq => v1::AttrOp::Eq,
            AttrOp::Ne => v1::AttrOp::Ne,
            AttrOp::Has => v1::AttrOp::Has,
            AttrOp::Excludes => v1::AttrOp::Excludes,
        };
        bldr.set_op(op);
        let mut val_list = bldr.reborrow().init_value(self.value.len() as u32);
        for (i, val) in self.value.iter().enumerate() {
            val_list.set(i as u32, val);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::v1;

    fn make_msg(
        key: &str,
        op: v1::AttrOp,
        values: &[&str],
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::attr_expr::Builder<'_> = msg.init_root();
            root.set_key(key);
            root.set_op(op);
            let mut val_list = root.reborrow().init_value(values.len() as u32);
            for (i, v) in values.iter().enumerate() {
                val_list.set(i as u32, v);
            }
        }
        msg
    }

    fn read(
        msg: &capnp::message::Builder<capnp::message::HeapAllocator>,
    ) -> Result<AttrExp, PolicyTypeError> {
        let reader: v1::attr_expr::Reader<'_> = msg.get_root_as_reader().unwrap();
        AttrExp::try_from(reader)
    }

    #[test]
    fn test_op_eq() {
        // AttrOp::Eq is deserialized correctly
        let msg = make_msg("role", v1::AttrOp::Eq, &["admin"]);
        let attr = read(&msg).unwrap();
        assert_eq!(attr.key, "role");
        assert_eq!(attr.op, AttrOp::Eq);
        assert_eq!(attr.value, vec!["admin"]);
    }

    #[test]
    fn test_op_ne() {
        // AttrOp::Ne is deserialized correctly
        let msg = make_msg("role", v1::AttrOp::Ne, &["guest"]);
        let attr = read(&msg).unwrap();
        assert_eq!(attr.op, AttrOp::Ne);
    }

    #[test]
    fn test_op_has() {
        // AttrOp::Has is deserialized correctly
        let msg = make_msg("tags", v1::AttrOp::Has, &["red"]);
        let attr = read(&msg).unwrap();
        assert_eq!(attr.op, AttrOp::Has);
    }

    #[test]
    fn test_op_excludes() {
        // AttrOp::Excludes is deserialized correctly
        let msg = make_msg("tags", v1::AttrOp::Excludes, &["blue"]);
        let attr = read(&msg).unwrap();
        assert_eq!(attr.op, AttrOp::Excludes);
    }

    #[test]
    fn test_multiple_values() {
        // All entries in the value list are deserialized
        let msg = make_msg("group", v1::AttrOp::Has, &["a", "b", "c"]);
        let attr = read(&msg).unwrap();
        assert_eq!(attr.value, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_empty_values() {
        // An empty value list is valid
        let msg = make_msg("tag", v1::AttrOp::Has, &[]);
        let attr = read(&msg).unwrap();
        assert!(attr.value.is_empty());
    }

    #[test]
    fn test_roundtrip_with_values() {
        // write_to then TryFrom preserves key, op, and multiple values
        let original = AttrExp {
            key: "user.role".to_string(),
            op: AttrOp::Eq,
            value: vec!["admin".to_string(), "superuser".to_string()],
        };
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::attr_expr::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::attr_expr::Reader<'_> = msg.get_root_as_reader().unwrap();
        let result = AttrExp::try_from(reader).unwrap();
        assert_eq!(result.key, original.key);
        assert_eq!(result.op, original.op);
        assert_eq!(result.value, original.value);
    }

    #[test]
    fn test_roundtrip_excludes_empty_values() {
        // write_to then TryFrom preserves Excludes op with empty value list
        let original = AttrExp {
            key: "service.type".to_string(),
            op: AttrOp::Excludes,
            value: vec![],
        };
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::attr_expr::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::attr_expr::Reader<'_> = msg.get_root_as_reader().unwrap();
        let result = AttrExp::try_from(reader).unwrap();
        assert_eq!(result.key, original.key);
        assert_eq!(result.op, original.op);
        assert!(result.value.is_empty());
    }
}

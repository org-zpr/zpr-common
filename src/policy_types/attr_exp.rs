//! For working with the `AttrExp` policy type.

use crate::policy::v1;
use crate::policy_types::error::PolicyTypeError;
use crate::write_to::WriteTo;

/// Maps to the Cap'n Proto `AttrExp` struct.
#[derive(Debug)]
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

/// A trait for writing to a builder type. This is the pattern used to write Cap'n Proto messages.
pub trait WriteTo<Bldr> {
    fn write_to(&self, bldr: &mut Bldr);
}

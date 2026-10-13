//! Stable names for exchange formats.

/// Identifier of an import or export format.
///
/// Adapters compare this value exactly. It is not a file extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FormatId(&'static str);

impl FormatId {
    /// KeePass 2 `.kdbx` database.
    pub const KDBX: Self = Self::new("kdbx");

    /// Build an identifier from a stable name such as `"csv"`.
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    /// The name passed to [`FormatId::new`].
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for FormatId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

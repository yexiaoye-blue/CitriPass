//! Resource ceilings. They are part of the domain, not of a transport.

/// Maximum encrypted item records held in one vault session.
pub const MAX_ITEMS: usize = 10_000;
/// Maximum plaintext body inside one item, in bytes.
pub const MAX_PLAINTEXT: usize = 64 * 1024;
/// Maximum entries in one item metadata list.
pub const MAX_METADATA: usize = 128;
/// Maximum master-password length accepted by key derivation, in bytes.
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// Maximum encoded backup or other bulk input, in bytes.
pub const MAX_COLLECTION_BYTES: usize = 16 * 1024 * 1024;
/// Maximum attachment plaintext, in bytes.
pub const MAX_ATTACHMENT_SIZE: u64 = 1024 * 1024 * 1024 * 1024;
/// STREAM chunk size, in bytes.
pub const ATTACHMENT_CHUNK_SIZE: usize = 64 * 1024;

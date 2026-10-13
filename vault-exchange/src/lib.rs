//! Import and export adapters around [`vault_core`].
//!
//! Vault records stay in `vault-core`. This crate turns other password-database
//! formats into [`vault_core::ItemDraft`] values, and can later write those
//! drafts back out. A new format implements [`Importer`] or [`Exporter`] and is
//! registered on a [`Catalog`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod apply;
mod catalog;
mod error;
mod export;
mod format;
mod import;
mod kdbx;

pub use apply::{apply_plan, ApplyError, ApplyReport, ItemWriter, WrittenRecord};
pub use catalog::Catalog;
pub use error::{Error, Result};
pub use export::{ExportRequest, Exporter};
pub use format::FormatId;
pub use import::{
    ImportPlan, ImportSource, Importer, PlannedFolder, PlannedItem, SkipReason, SkippedRecord,
};
pub use kdbx::KdbxImporter;

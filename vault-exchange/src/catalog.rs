//! Registry of import and export adapters.

use crate::export::{ExportRequest, Exporter};
use crate::format::FormatId;
use crate::import::{ImportPlan, ImportSource, Importer};
use crate::kdbx::KdbxImporter;
use crate::{Error, Result};

/// Adapters the host can select by [`FormatId`].
///
/// Importers and exporters are separate. A format may support only one direction.
pub struct Catalog {
    importers: Vec<Box<dyn Importer>>,
    exporters: Vec<Box<dyn Exporter>>,
}

impl Catalog {
    /// Empty registry.
    pub fn new() -> Self {
        Self {
            importers: Vec::new(),
            exporters: Vec::new(),
        }
    }

    /// Registry containing the built-in adapters.
    ///
    /// KDBX import is included. KDBX export is not, until an [`Exporter`] is registered.
    pub fn with_builtins() -> Self {
        Self {
            importers: vec![Box::new(KdbxImporter)],
            exporters: Vec::new(),
        }
    }

    /// Add an importer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FormatAlreadyRegistered`] when this format already imports.
    pub fn register_importer(&mut self, importer: Box<dyn Importer>) -> Result<()> {
        let format_id = importer.format_id();
        if self
            .importers
            .iter()
            .any(|item| item.format_id() == format_id)
        {
            return Err(Error::FormatAlreadyRegistered(format_id));
        }
        self.importers.push(importer);
        Ok(())
    }

    /// Add an exporter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FormatAlreadyRegistered`] when this format already exports.
    pub fn register_exporter(&mut self, exporter: Box<dyn Exporter>) -> Result<()> {
        let format_id = exporter.format_id();
        if self
            .exporters
            .iter()
            .any(|item| item.format_id() == format_id)
        {
            return Err(Error::FormatAlreadyRegistered(format_id));
        }
        self.exporters.push(exporter);
        Ok(())
    }

    /// Formats that can be imported.
    pub fn import_formats(&self) -> Vec<FormatId> {
        self.importers.iter().map(|item| item.format_id()).collect()
    }

    /// Formats that can be exported.
    pub fn export_formats(&self) -> Vec<FormatId> {
        self.exporters.iter().map(|item| item.format_id()).collect()
    }

    /// Read one source.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FormatNotRegistered`] when no importer handles `format`.
    ///
    /// # Examples
    ///
    /// ```
    /// use keepass::db::fields;
    /// use keepass::{config::KdfConfig, Database, DatabaseKey};
    /// use vault_exchange::{Catalog, FormatId, ImportSource};
    ///
    /// let mut database = Database::new();
    /// database.config.kdf_config = KdfConfig::Aes { rounds: 1 };
    /// database
    ///     .root_mut()
    ///     .add_entry()
    ///     .set_unprotected(fields::TITLE, "Mail");
    /// let mut bytes = Vec::new();
    /// database
    ///     .save(&mut bytes, DatabaseKey::new().with_password("secret"))
    ///     .expect("test database saves");
    /// let plan = Catalog::with_builtins()
    ///     .import(FormatId::KDBX, &ImportSource::new(&bytes, "secret"))
    ///     .expect("kdbx imports");
    /// assert_eq!(plan.items[0].draft.title, "Mail");
    /// ```
    pub fn import(&self, format: FormatId, source: &ImportSource<'_>) -> Result<ImportPlan> {
        self.importer(format)?.import(source)
    }

    /// Write one destination.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FormatNotRegistered`] when no exporter handles `format`.
    pub fn export(&self, format: FormatId, request: &ExportRequest<'_>) -> Result<Vec<u8>> {
        self.exporter(format)?.export(request)
    }

    fn importer(&self, format: FormatId) -> Result<&dyn Importer> {
        self.importers
            .iter()
            .find(|item| item.format_id() == format)
            .map(|item| item.as_ref())
            .ok_or(Error::FormatNotRegistered(format))
    }

    fn exporter(&self, format: FormatId) -> Result<&dyn Exporter> {
        self.exporters
            .iter()
            .find(|item| item.format_id() == format)
            .map(|item| item.as_ref())
            .ok_or(Error::FormatNotRegistered(format))
    }
}

impl Default for Catalog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::ExportRequest;
    use crate::import::ImportPlan;

    struct ExampleExporter;

    impl Exporter for ExampleExporter {
        fn format_id(&self) -> FormatId {
            FormatId::new("example")
        }

        fn export(&self, request: &ExportRequest<'_>) -> Result<Vec<u8>> {
            Ok(request.items.len().to_string().into_bytes())
        }
    }

    struct RepeatedKdbx;

    impl Importer for RepeatedKdbx {
        fn format_id(&self) -> FormatId {
            FormatId::KDBX
        }

        fn import(&self, _source: &ImportSource<'_>) -> Result<ImportPlan> {
            Ok(ImportPlan::default())
        }
    }

    #[test]
    fn builtins_import_kdbx_and_do_not_export_it() {
        let catalog = Catalog::with_builtins();
        assert_eq!(catalog.import_formats(), vec![FormatId::KDBX]);
        assert!(catalog.export_formats().is_empty());
        let error = catalog
            .export(FormatId::KDBX, &ExportRequest::new("secret", &[]))
            .unwrap_err();
        assert!(matches!(error, Error::FormatNotRegistered(FormatId::KDBX)));
    }

    #[test]
    fn unknown_format_is_rejected() {
        let error = Catalog::new()
            .import(FormatId::new("csv"), &ImportSource::new(&[], "secret"))
            .unwrap_err();
        assert!(matches!(error, Error::FormatNotRegistered(id) if id.as_str() == "csv"));
    }

    #[test]
    fn duplicate_importer_is_rejected_and_exporter_can_share_the_name() {
        let mut catalog = Catalog::with_builtins();
        let error = catalog
            .register_importer(Box::new(RepeatedKdbx))
            .unwrap_err();
        assert!(matches!(
            error,
            Error::FormatAlreadyRegistered(FormatId::KDBX)
        ));
        catalog
            .register_exporter(Box::new(ExampleExporter))
            .unwrap();
        let bytes = catalog
            .export(FormatId::new("example"), &ExportRequest::new("secret", &[]))
            .unwrap();
        assert_eq!(bytes, b"0");
    }
}

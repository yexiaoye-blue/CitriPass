//! A local file made only of existing vault records.
//!
//! The first record is a CPV1 header from [`SealedVault::to_bytes`]. Each
//! following record is a CPI1 item from [`SealedItem::to_bytes`]. A big-endian
//! length sits in front of each record so the file can hold more than one of
//! them. That length is not encrypted and is not a new vault format.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use vault_core::{SealedItem, SealedVault};

use crate::error::Error;

const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 256 * 1024;
const HEADER_MAGIC: &[u8; 4] = b"CPV1";
const ITEM_MAGIC: &[u8; 4] = b"CPI1";

/// Header plus the item records stored beside it.
pub struct VaultFile {
    /// CPV1 header. Its own item list is empty until the records are imported.
    pub header: SealedVault,
    /// CPI1 records in file order.
    pub items: Vec<SealedItem>,
}

/// Write the header and every item currently sealed in `vault`.
pub fn save(path: &Path, vault: &SealedVault) -> Result<(), Error> {
    let mut records = Vec::with_capacity(1 + vault.items().len());
    records.push(vault.to_bytes()?);
    for item in vault.items() {
        records.push(item.to_bytes()?);
    }
    let bytes = encode(&records)?;
    write_private(path, &bytes)
}

/// Read a file produced by [`save`].
pub fn load(path: &Path) -> Result<VaultFile, Error> {
    let bytes = fs::read(path).map_err(Error::Read)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Error::TooLarge);
    }
    let records = decode(&bytes)?;
    let header_bytes = records.first().ok_or(Error::UnexpectedRecord)?;
    if !header_bytes.starts_with(HEADER_MAGIC) {
        return Err(Error::UnexpectedRecord);
    }
    let header = SealedVault::from_bytes(header_bytes)?;
    let mut items = Vec::with_capacity(records.len().saturating_sub(1));
    for record in records.iter().skip(1) {
        if !record.starts_with(ITEM_MAGIC) {
            return Err(Error::UnexpectedRecord);
        }
        items.push(SealedItem::from_bytes(record)?);
    }
    Ok(VaultFile { header, items })
}

fn encode(records: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for record in records {
        let len = u32::try_from(record.len()).map_err(|_| Error::TooLarge)?;
        if record.len() > MAX_RECORD_BYTES {
            return Err(Error::TooLarge);
        }
        out.extend(len.to_be_bytes());
        out.extend(record);
        if out.len() > MAX_FILE_BYTES {
            return Err(Error::TooLarge);
        }
    }
    Ok(out)
}

fn decode(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let rest = bytes.len() - offset;
        if rest < 4 {
            return Err(Error::Truncated);
        }
        let len_bytes: [u8; 4] = bytes[offset..offset + 4]
            .try_into()
            .map_err(|_| Error::Truncated)?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len == 0 || len > MAX_RECORD_BYTES {
            return Err(Error::TooLarge);
        }
        offset += 4;
        if bytes.len() - offset < len {
            return Err(Error::Truncated);
        }
        records.push(bytes[offset..offset + len].to_vec());
        offset += len;
    }
    if records.is_empty() {
        return Err(Error::UnexpectedRecord);
    }
    Ok(records)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let tmp = temp_path(path);
    {
        let mut file = open_private(&tmp)?;
        file.write_all(bytes).map_err(Error::Write)?;
        file.sync_all().map_err(Error::Write)?;
    }
    fs::rename(&tmp, path).map_err(Error::Write)?;
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

fn open_private(path: &Path) -> Result<fs::File, Error> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(Error::Write)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_keeps_record_bytes_and_order() {
        let records = vec![b"CPV1-header".to_vec(), b"CPI1-item".to_vec()];
        let decoded = decode(&encode(&records).unwrap()).unwrap();
        assert_eq!(decoded, records);
    }

    #[test]
    fn truncated_length_is_rejected() {
        let mut bytes = encode(&[b"CPV1".to_vec()]).unwrap();
        bytes.pop();
        assert!(matches!(decode(&bytes), Err(Error::Truncated)));
    }
}

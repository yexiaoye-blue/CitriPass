//! Big-endian cursor. Callers set the byte ceiling before writing.

use crate::{Error, InputError, Result};

pub(crate) struct Buf {
    data: Vec<u8>,
    limit: usize,
}

impl Buf {
    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            data: Vec::new(),
            limit,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<()> {
        if self.data.len().saturating_add(bytes.len()) > self.limit {
            return Err(Error::LimitExceeded);
        }
        self.data.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn u8(&mut self, value: u8) -> Result<()> {
        self.push(&[value])
    }

    pub(crate) fn u16(&mut self, value: u16) -> Result<()> {
        self.push(&value.to_be_bytes())
    }

    pub(crate) fn u32(&mut self, value: u32) -> Result<()> {
        self.push(&value.to_be_bytes())
    }

    pub(crate) fn u64(&mut self, value: u64) -> Result<()> {
        self.push(&value.to_be_bytes())
    }

    pub(crate) fn str(&mut self, value: &str) -> Result<()> {
        let len = u32::try_from(value.len()).map_err(|_| Error::LimitExceeded)?;
        self.u32(len)?;
        self.push(value.as_bytes())
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.data
    }
}

pub(crate) struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.rest.len() < len {
            return Err(malformed());
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| Error::Internal)?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Internal)
    }

    pub(crate) fn str(&mut self) -> Result<String> {
        let len = self.u32()? as usize;
        if len > self.rest.len() {
            return Err(malformed());
        }
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| malformed())
    }

    pub(crate) fn finish(self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(malformed())
        }
    }
}

fn malformed() -> Error {
    Error::InvalidInput(InputError::MalformedEncoding)
}

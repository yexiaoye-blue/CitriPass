//! Plaintext items and the versioned body layout.
//!
//! Schema 1 is a sequence of big-endian fields, not a self-describing document.
//! Unknown schema numbers are rejected.

use crate::codec::{Buf, Cursor};
use crate::limits::{MAX_METADATA, MAX_PLAINTEXT};
use crate::totp::{Hotp, Otp, Totp, TotpAlgorithm};
use crate::{Error, InputError, Result};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SCHEMA: u16 = 1;
const KIND_LOGIN: u16 = 1;
const KIND_NOTE: u16 = 2;
const KIND_FOLDER: u16 = 3;
const KIND_TOTP: u16 = 4;
const KIND_CARD: u16 = 5;
const KIND_IDENTITY: u16 = 6;
const KIND_HOTP: u16 = 7;

/// Login fields copied into an item. The strings are wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LoginDraft {
    /// Display title.
    pub title: String,
    /// Login username.
    pub username: String,
    /// Login password.
    pub password: String,
    /// Freeform notes.
    pub notes: String,
}

/// Secret payload stored inside one item.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum ItemData {
    /// Username, password, URLs, and an optional one-time password.
    Login {
        /// Login username.
        username: String,
        /// Login password.
        password: String,
        /// Associated URLs.
        urls: Vec<String>,
        /// Optional TOTP or HOTP stored with the login.
        otp: Option<Otp>,
    },
    /// Notes live on the common item fields.
    SecureNote,
    /// Folder. The parent is absent for a root folder.
    Folder {
        /// Parent folder id.
        #[zeroize(skip)]
        parent_id: Option<Uuid>,
    },
    /// Standalone TOTP.
    Totp {
        /// TOTP parameters.
        totp: Totp,
    },
    /// Standalone HOTP.
    Hotp {
        /// HOTP parameters. The counter advances when a code is issued.
        hotp: Hotp,
    },
    /// Payment card.
    Card {
        /// Cardholder name.
        cardholder: String,
        /// Card number.
        number: String,
        /// Expiry text as entered by the caller.
        expiry: String,
        /// Card security code.
        security_code: String,
    },
    /// Identity contact fields.
    Identity {
        /// Full name.
        full_name: String,
        /// Email address.
        email: String,
        /// Phone number.
        phone: String,
        /// Postal address.
        address: String,
    },
}

/// Extra named field inside the item body.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CustomField {
    /// Field name.
    pub name: String,
    /// Field value.
    pub value: String,
    /// Whether a host should conceal the value.
    #[zeroize(skip)]
    pub concealed: bool,
}

/// Attachment selected by an item. The file bytes live outside the item.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AttachmentRef {
    /// Attachment id.
    #[zeroize(skip)]
    pub attachment_id: Uuid,
    /// Attachment revision, starting at one.
    #[zeroize(skip)]
    pub revision: u64,
    /// File name. It is stored only inside the encrypted item.
    pub file_name: String,
    /// Media type.
    pub media_type: String,
}

/// Complete item content, validated before encryption.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ItemDraft {
    /// Display title.
    pub title: String,
    /// Freeform notes.
    pub notes: String,
    /// Kind-specific secret.
    pub data: ItemData,
    /// Containing folder. None is the vault root.
    #[zeroize(skip)]
    pub folder_id: Option<Uuid>,
    /// Favorite flag.
    #[zeroize(skip)]
    pub favorite: bool,
    /// Tags.
    pub tags: Vec<String>,
    /// Custom fields.
    pub custom_fields: Vec<CustomField>,
    /// Attachment references.
    pub attachments: Vec<AttachmentRef>,
}

impl ItemDraft {
    /// Build a draft. Validation runs when the draft is encrypted.
    pub fn new(title: impl Into<String>, data: ItemData) -> Self {
        Self {
            title: title.into(),
            notes: String::new(),
            data,
            folder_id: None,
            favorite: false,
            tags: Vec::new(),
            custom_fields: Vec::new(),
            attachments: Vec::new(),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.title.trim().is_empty() {
            return Err(Error::InvalidInput(InputError::EmptyTitle));
        }
        if self.folder_id.is_some_and(|id| id.is_nil()) {
            return Err(Error::InvalidInput(InputError::InvalidFolderId));
        }
        if self.tags.len() > MAX_METADATA
            || self.custom_fields.len() > MAX_METADATA
            || self.attachments.len() > MAX_METADATA
        {
            return Err(Error::InvalidInput(InputError::TooManyMetadataEntries {
                max_entries: MAX_METADATA,
            }));
        }
        if self.attachments.iter().any(|attachment| {
            attachment.attachment_id.is_nil()
                || attachment.revision == 0
                || attachment.file_name.is_empty()
        }) {
            return Err(Error::InvalidInput(InputError::InvalidAttachmentReference));
        }
        match &self.data {
            ItemData::Folder {
                parent_id: Some(id),
            } if id.is_nil() => {
                return Err(Error::InvalidInput(InputError::InvalidFolderId));
            }
            ItemData::Login { otp: Some(otp), .. } => otp.validate()?,
            ItemData::Totp { totp } => totp.validate()?,
            ItemData::Hotp { hotp } => hotp.validate()?,
            _ => {}
        }
        Ok(())
    }

    /// Login password, if this draft is a login.
    pub fn login_password(&self) -> Option<&str> {
        match &self.data {
            ItemData::Login { password, .. } => Some(password),
            _ => None,
        }
    }

    /// Login username, if this draft is a login.
    pub fn login_username(&self) -> Option<&str> {
        match &self.data {
            ItemData::Login { username, .. } => Some(username),
            _ => None,
        }
    }
}

impl From<LoginDraft> for ItemDraft {
    fn from(mut draft: LoginDraft) -> Self {
        let mut item = Self::new(
            std::mem::take(&mut draft.title),
            ItemData::Login {
                username: std::mem::take(&mut draft.username),
                password: std::mem::take(&mut draft.password),
                urls: Vec::new(),
                otp: None,
            },
        );
        item.notes = std::mem::take(&mut draft.notes);
        item
    }
}

/// Decrypted item. The content is wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Item {
    /// Item id.
    pub item_id: Uuid,
    /// Record revision, starting at one.
    pub revision: u64,
    /// Tombstone flag. It is authenticated with the ciphertext.
    pub deleted: bool,
    /// Plaintext content.
    pub content: ItemDraft,
}

impl std::ops::Deref for Item {
    type Target = ItemDraft;
    fn deref(&self) -> &ItemDraft {
        &self.content
    }
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("item_id", &self.item_id)
            .field("revision", &self.revision)
            .field("deleted", &self.deleted)
            .field("content", &"***")
            .finish()
    }
}

macro_rules! redacted {
    ($($name:ty),*) => {$(
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(***)"))
            }
        }
    )*};
}
redacted!(LoginDraft, ItemDraft, ItemData, CustomField, AttachmentRef);

pub(crate) fn encode_body(draft: &ItemDraft) -> Result<Zeroizing<Vec<u8>>> {
    draft.validate()?;
    let mut buf = Buf::with_limit(MAX_PLAINTEXT);
    buf.u16(SCHEMA)?;
    write_common(&mut buf, draft)?;
    write_payload(&mut buf, &draft.data)?;
    Ok(Zeroizing::new(buf.finish()))
}

pub(crate) fn decode_body(
    bytes: &[u8],
    item_id: Uuid,
    revision: u64,
    deleted: bool,
) -> Result<Item> {
    if bytes.len() > MAX_PLAINTEXT {
        return Err(Error::Integrity);
    }
    let mut cursor = Cursor::new(bytes);
    let schema = cursor.u16().map_err(|_| Error::Integrity)?;
    if schema != SCHEMA {
        return Err(Error::UnsupportedFormat);
    }
    let draft = read_draft(&mut cursor).map_err(stored)?;
    cursor.finish().map_err(|_| Error::Integrity)?;
    draft.validate().map_err(|_| Error::Integrity)?;
    Ok(Item {
        item_id,
        revision,
        deleted,
        content: draft,
    })
}

fn stored(error: Error) -> Error {
    match error {
        Error::UnsupportedFormat => Error::UnsupportedFormat,
        Error::LimitExceeded => Error::LimitExceeded,
        _ => Error::Integrity,
    }
}

fn write_common(buf: &mut Buf, draft: &ItemDraft) -> Result<()> {
    let kind = match draft.data {
        ItemData::Login { .. } => KIND_LOGIN,
        ItemData::SecureNote => KIND_NOTE,
        ItemData::Folder { .. } => KIND_FOLDER,
        ItemData::Totp { .. } => KIND_TOTP,
        ItemData::Hotp { .. } => KIND_HOTP,
        ItemData::Card { .. } => KIND_CARD,
        ItemData::Identity { .. } => KIND_IDENTITY,
    };
    buf.u16(kind)?;
    buf.str(&draft.title)?;
    buf.str(&draft.notes)?;
    buf.u8(u8::from(draft.favorite))?;
    write_uuid(buf, draft.folder_id)?;
    buf.u16(u16::try_from(draft.tags.len()).map_err(|_| Error::LimitExceeded)?)?;
    for tag in &draft.tags {
        buf.str(tag)?;
    }
    buf.u16(u16::try_from(draft.custom_fields.len()).map_err(|_| Error::LimitExceeded)?)?;
    for field in &draft.custom_fields {
        buf.str(&field.name)?;
        buf.str(&field.value)?;
        buf.u8(u8::from(field.concealed))?;
    }
    buf.u16(u16::try_from(draft.attachments.len()).map_err(|_| Error::LimitExceeded)?)?;
    for attachment in &draft.attachments {
        buf.push(attachment.attachment_id.as_bytes())?;
        buf.u64(attachment.revision)?;
        buf.str(&attachment.file_name)?;
        buf.str(&attachment.media_type)?;
    }
    Ok(())
}

fn write_payload(buf: &mut Buf, data: &ItemData) -> Result<()> {
    match data {
        ItemData::Login {
            username,
            password,
            urls,
            otp,
        } => {
            buf.str(username)?;
            buf.str(password)?;
            buf.u16(u16::try_from(urls.len()).map_err(|_| Error::LimitExceeded)?)?;
            for url in urls {
                buf.str(url)?;
            }
            // 0 is absent, 1 is TOTP, 2 is HOTP. Older records only used 0 and 1.
            match otp {
                None => buf.u8(0)?,
                Some(Otp::Totp(totp)) => {
                    buf.u8(1)?;
                    write_totp(buf, totp)?;
                }
                Some(Otp::Hotp(hotp)) => {
                    buf.u8(2)?;
                    write_hotp(buf, hotp)?;
                }
            }
        }
        ItemData::SecureNote => {}
        ItemData::Folder { parent_id } => write_uuid(buf, *parent_id)?,
        ItemData::Totp { totp } => write_totp(buf, totp)?,
        ItemData::Hotp { hotp } => write_hotp(buf, hotp)?,
        ItemData::Card {
            cardholder,
            number,
            expiry,
            security_code,
        } => {
            buf.str(cardholder)?;
            buf.str(number)?;
            buf.str(expiry)?;
            buf.str(security_code)?;
        }
        ItemData::Identity {
            full_name,
            email,
            phone,
            address,
        } => {
            buf.str(full_name)?;
            buf.str(email)?;
            buf.str(phone)?;
            buf.str(address)?;
        }
    }
    Ok(())
}

fn write_totp(buf: &mut Buf, totp: &Totp) -> Result<()> {
    buf.str(&totp.secret)?;
    write_algorithm(buf, totp.algorithm)?;
    buf.u8(u8::try_from(totp.digits).map_err(|_| Error::Internal)?)?;
    buf.u32(totp.period)
}

fn write_hotp(buf: &mut Buf, hotp: &Hotp) -> Result<()> {
    buf.str(&hotp.secret)?;
    write_algorithm(buf, hotp.algorithm)?;
    buf.u8(u8::try_from(hotp.digits).map_err(|_| Error::Internal)?)?;
    buf.u64(hotp.counter)
}

fn write_algorithm(buf: &mut Buf, algorithm: TotpAlgorithm) -> Result<()> {
    buf.u16(match algorithm {
        TotpAlgorithm::Sha1 => 1,
        TotpAlgorithm::Sha256 => 2,
        TotpAlgorithm::Sha512 => 3,
    })
}

fn write_uuid(buf: &mut Buf, id: Option<Uuid>) -> Result<()> {
    match id {
        None => buf.u8(0),
        Some(id) => {
            buf.u8(1)?;
            buf.push(id.as_bytes())
        }
    }
}

fn read_draft(cursor: &mut Cursor<'_>) -> Result<ItemDraft> {
    let kind = cursor.u16()?;
    let title = cursor.str()?;
    let notes = cursor.str()?;
    let favorite = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(Error::InvalidInput(InputError::MalformedEncoding)),
    };
    let folder_id = read_uuid(cursor)?;
    let tag_count = cursor.u16()? as usize;
    if tag_count > MAX_METADATA {
        return Err(Error::LimitExceeded);
    }
    let mut tags = Vec::with_capacity(tag_count);
    for _ in 0..tag_count {
        tags.push(cursor.str()?);
    }
    let field_count = cursor.u16()? as usize;
    if field_count > MAX_METADATA {
        return Err(Error::LimitExceeded);
    }
    let mut custom_fields = Vec::with_capacity(field_count);
    for _ in 0..field_count {
        custom_fields.push(CustomField {
            name: cursor.str()?,
            value: cursor.str()?,
            concealed: match cursor.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Error::InvalidInput(InputError::MalformedEncoding)),
            },
        });
    }
    let attachment_count = cursor.u16()? as usize;
    if attachment_count > MAX_METADATA {
        return Err(Error::LimitExceeded);
    }
    let mut attachments = Vec::with_capacity(attachment_count);
    for _ in 0..attachment_count {
        attachments.push(AttachmentRef {
            attachment_id: Uuid::from_bytes(cursor.array()?),
            revision: cursor.u64()?,
            file_name: cursor.str()?,
            media_type: cursor.str()?,
        });
    }
    let data = read_payload(cursor, kind)?;
    Ok(ItemDraft {
        title,
        notes,
        data,
        folder_id,
        favorite,
        tags,
        custom_fields,
        attachments,
    })
}

fn read_payload(cursor: &mut Cursor<'_>, kind: u16) -> Result<ItemData> {
    match kind {
        KIND_LOGIN => {
            let username = cursor.str()?;
            let password = cursor.str()?;
            let url_count = cursor.u16()? as usize;
            if url_count > MAX_METADATA {
                return Err(Error::LimitExceeded);
            }
            let mut urls = Vec::with_capacity(url_count);
            for _ in 0..url_count {
                urls.push(cursor.str()?);
            }
            let otp = match cursor.u8()? {
                0 => None,
                1 => Some(Otp::Totp(read_totp(cursor)?)),
                2 => Some(Otp::Hotp(read_hotp(cursor)?)),
                _ => return Err(Error::InvalidInput(InputError::MalformedEncoding)),
            };
            Ok(ItemData::Login {
                username,
                password,
                urls,
                otp,
            })
        }
        KIND_NOTE => Ok(ItemData::SecureNote),
        KIND_FOLDER => Ok(ItemData::Folder {
            parent_id: read_uuid(cursor)?,
        }),
        KIND_TOTP => Ok(ItemData::Totp {
            totp: read_totp(cursor)?,
        }),
        KIND_HOTP => Ok(ItemData::Hotp {
            hotp: read_hotp(cursor)?,
        }),
        KIND_CARD => Ok(ItemData::Card {
            cardholder: cursor.str()?,
            number: cursor.str()?,
            expiry: cursor.str()?,
            security_code: cursor.str()?,
        }),
        KIND_IDENTITY => Ok(ItemData::Identity {
            full_name: cursor.str()?,
            email: cursor.str()?,
            phone: cursor.str()?,
            address: cursor.str()?,
        }),
        _ => Err(Error::UnsupportedFormat),
    }
}

fn read_totp(cursor: &mut Cursor<'_>) -> Result<Totp> {
    Ok(Totp {
        secret: cursor.str()?,
        algorithm: read_algorithm(cursor)?,
        digits: u32::from(cursor.u8()?),
        period: cursor.u32()?,
    })
}

fn read_hotp(cursor: &mut Cursor<'_>) -> Result<Hotp> {
    Ok(Hotp {
        secret: cursor.str()?,
        algorithm: read_algorithm(cursor)?,
        digits: u32::from(cursor.u8()?),
        counter: cursor.u64()?,
    })
}

fn read_algorithm(cursor: &mut Cursor<'_>) -> Result<TotpAlgorithm> {
    match cursor.u16()? {
        1 => Ok(TotpAlgorithm::Sha1),
        2 => Ok(TotpAlgorithm::Sha256),
        3 => Ok(TotpAlgorithm::Sha512),
        _ => Err(Error::UnsupportedFormat),
    }
}

/// Issue the current HOTP and advance its counter inside `data`.
pub(crate) fn advance_hotp(data: &mut ItemData) -> Result<Zeroizing<String>> {
    match data {
        ItemData::Hotp { hotp } => hotp.next_code(),
        ItemData::Login {
            otp: Some(Otp::Hotp(hotp)),
            ..
        } => hotp.next_code(),
        _ => Err(Error::InvalidInput(InputError::NotHotp)),
    }
}

fn read_uuid(cursor: &mut Cursor<'_>) -> Result<Option<Uuid>> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(Uuid::from_bytes(cursor.array()?))),
        _ => Err(Error::InvalidInput(InputError::MalformedEncoding)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn roundtrip(data: ItemData) -> ItemDraft {
        let mut draft = ItemDraft::new("Title", data);
        draft.notes = "notes".into();
        draft.folder_id = Some(Uuid::from_u128(9));
        draft.favorite = true;
        draft.tags = vec!["one".into(), "two".into()];
        draft.custom_fields = vec![CustomField {
            name: "custom".into(),
            value: "value".into(),
            concealed: true,
        }];
        draft.attachments = vec![AttachmentRef {
            attachment_id: Uuid::from_u128(10),
            revision: 2,
            file_name: "file.txt".into(),
            media_type: "text/plain".into(),
        }];
        let bytes = encode_body(&draft).unwrap();
        let item = decode_body(&bytes, Uuid::from_u128(1), 1, false).unwrap();
        assert_eq!(item.content, draft);
        item.content
    }

    #[test]
    fn schema_roundtrip_covers_every_item_data_variant() {
        let login_password = format!("login-test-{}", std::process::id());
        let login = roundtrip(ItemData::Login {
            username: "user".into(),
            password: login_password,
            urls: vec!["https://example.test".into()],
            otp: Some(Otp::Totp(Totp::new(SECRET))),
        });
        assert!(matches!(
            login.data,
            ItemData::Login {
                otp: Some(Otp::Totp(_)),
                ..
            }
        ));

        assert!(matches!(
            roundtrip(ItemData::SecureNote).data,
            ItemData::SecureNote
        ));
        assert_eq!(
            roundtrip(ItemData::Folder {
                parent_id: Some(Uuid::from_u128(11)),
            })
            .data,
            ItemData::Folder {
                parent_id: Some(Uuid::from_u128(11)),
            }
        );

        let mut totp = Totp::new(SECRET);
        totp.algorithm = TotpAlgorithm::Sha256;
        totp.digits = 8;
        totp.period = 45;
        assert_eq!(
            roundtrip(ItemData::Totp { totp: totp.clone() }).data,
            ItemData::Totp { totp }
        );

        let mut hotp = Hotp::new(SECRET, 7);
        hotp.algorithm = TotpAlgorithm::Sha512;
        hotp.digits = 7;
        assert_eq!(
            roundtrip(ItemData::Hotp { hotp: hotp.clone() }).data,
            ItemData::Hotp { hotp }
        );
        assert_eq!(
            roundtrip(ItemData::Card {
                cardholder: "Ada".into(),
                number: "4111111111111111".into(),
                expiry: "2030-01".into(),
                security_code: "123".into(),
            })
            .data,
            ItemData::Card {
                cardholder: "Ada".into(),
                number: "4111111111111111".into(),
                expiry: "2030-01".into(),
                security_code: "123".into(),
            }
        );
        assert_eq!(
            roundtrip(ItemData::Identity {
                full_name: "Ada Lovelace".into(),
                email: "ada@example.test".into(),
                phone: "+1 555 0100".into(),
                address: "1 Example Street".into(),
            })
            .data,
            ItemData::Identity {
                full_name: "Ada Lovelace".into(),
                email: "ada@example.test".into(),
                phone: "+1 555 0100".into(),
                address: "1 Example Street".into(),
            }
        );
    }

    #[test]
    fn schema_roundtrip_keeps_login_fields() {
        let mut draft = ItemDraft::new(
            "Title",
            ItemData::Login {
                username: "user".into(),
                password: "secret".into(),
                urls: vec!["https://example.test".into()],
                otp: None,
            },
        );
        draft.tags = vec!["home".into()];
        let bytes = encode_body(&draft).unwrap();
        let item = decode_body(&bytes, Uuid::from_u128(1), 1, false).unwrap();
        assert_eq!(item.content, draft);
        assert_eq!(item.login_password(), Some("secret"));
    }

    #[test]
    fn unknown_schema_is_rejected() {
        let mut bytes = encode_body(&ItemDraft::new("Title", ItemData::SecureNote)).unwrap();
        bytes[0] = 0;
        bytes[1] = 2;
        assert_eq!(
            decode_body(&bytes, Uuid::from_u128(1), 1, false).unwrap_err(),
            Error::UnsupportedFormat
        );
    }

    #[test]
    fn hotp_roundtrip_and_advance() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let mut draft = ItemDraft::new(
            "Token",
            ItemData::Login {
                username: String::new(),
                password: String::new(),
                urls: Vec::new(),
                otp: Some(Otp::Hotp(Hotp::new(secret, 0))),
            },
        );
        let bytes = encode_body(&draft).unwrap();
        let item = decode_body(&bytes, Uuid::from_u128(2), 1, false).unwrap();
        assert_eq!(item.content, draft);

        let code = advance_hotp(&mut draft.data).unwrap();
        assert_eq!(code.as_str(), "755224");
        match &draft.data {
            ItemData::Login {
                otp: Some(Otp::Hotp(hotp)),
                ..
            } => assert_eq!(hotp.counter, 1),
            _ => panic!("hotp login"),
        }

        let mut standalone = ItemData::Hotp {
            hotp: Hotp::new(secret, 1),
        };
        assert_eq!(advance_hotp(&mut standalone).unwrap().as_str(), "287082");
        let mut note = ItemData::SecureNote;
        assert!(matches!(
            advance_hotp(&mut note),
            Err(Error::InvalidInput(InputError::NotHotp))
        ));
    }
}

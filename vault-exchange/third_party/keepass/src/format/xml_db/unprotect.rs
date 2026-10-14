//! Decrypt protected XML values in document order.
//!
//! KeePass applies one inner stream to protected values as they appear in the file.
//! History can sit between `<String>` elements, so decrypting every current string
//! before history uses the wrong part of that stream.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use std::io::Cursor;

use crate::crypt::ciphers::Cipher;
use crate::format::xml_db::entry::UnprotectError;
use crate::format::xml_db::ParseXmlError;

struct ProtectedElement {
    start: BytesStart<'static>,
    binary: bool,
    text: String,
}

pub(super) fn decrypt_protected_values(
    xml: &[u8],
    cipher: &mut dyn Cipher,
) -> Result<Vec<u8>, ParseXmlError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();
    let mut pending: Option<ProtectedElement> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(start)) => {
                if pending.is_some() {
                    return Err(ParseXmlError::NestedProtectedValue);
                }
                if protected_payload(&start) {
                    pending = Some(ProtectedElement {
                        binary: is_binary(&start),
                        start: owned_start(&start)?,
                        text: String::new(),
                    });
                } else {
                    write_event(&mut writer, Event::Start(start))?;
                }
            }
            Ok(Event::Empty(start)) => {
                if pending.is_some() {
                    return Err(ParseXmlError::NestedProtectedValue);
                }
                if protected_payload(&start) {
                    let binary = is_binary(&start);
                    let start = owned_start(&start)?;
                    let body = decrypt_text(cipher, binary, "")?;
                    if !body.is_empty() {
                        return Err(ParseXmlError::NestedProtectedValue);
                    }
                    write_event(&mut writer, Event::Empty(start))?;
                } else {
                    write_event(&mut writer, Event::Empty(start))?;
                }
            }
            Ok(Event::Text(text)) => {
                append_or_copy(&mut writer, &mut pending, text.as_ref())?;
            }
            Ok(Event::CData(text)) => {
                let text = text.into_inner();
                append_or_copy(&mut writer, &mut pending, text.as_ref())?;
            }
            Ok(Event::End(end)) => {
                if let Some(element) = pending.take() {
                    let body = decrypt_text(cipher, element.binary, &element.text)?;
                    write_event(&mut writer, Event::Start(element.start))?;
                    if !body.is_empty() {
                        write_event(&mut writer, Event::Text(BytesText::new(&body)))?;
                    }
                    write_event(&mut writer, Event::End(end))?;
                } else {
                    write_event(&mut writer, Event::End(end))?;
                }
            }
            Ok(Event::Eof) => break,
            Ok(other) => write_event(&mut writer, other)?,
            Err(err) => return Err(ParseXmlError::Read(err)),
        }
        buf.clear();
    }

    if pending.is_some() {
        return Err(ParseXmlError::NestedProtectedValue);
    }
    Ok(writer.into_inner().into_inner())
}

fn append_or_copy(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    pending: &mut Option<ProtectedElement>,
    text: &str,
) -> Result<(), ParseXmlError> {
    if let Some(element) = pending {
        element.text.push_str(text);
        Ok(())
    } else {
        write_event(writer, Event::Text(BytesText::from_escaped(text)))
    }
}

fn decrypt_text(
    cipher: &mut dyn Cipher,
    binary: bool,
    text: &str,
) -> Result<String, ParseXmlError> {
    let ciphertext = STANDARD
        .decode(text.trim().as_bytes())
        .map_err(|err| ParseXmlError::Unprotect(UnprotectError::Base64(err)))?;
    let plaintext = cipher
        .decrypt(&ciphertext)
        .map_err(|err| ParseXmlError::Unprotect(UnprotectError::Decrypt(err)))?;
    if binary {
        Ok(STANDARD.encode(plaintext))
    } else {
        Ok(String::from_utf8_lossy(&plaintext).into_owned())
    }
}

fn write_event<'a, E>(writer: &mut Writer<Cursor<Vec<u8>>>, event: E) -> Result<(), ParseXmlError>
where
    E: Into<Event<'a>>,
{
    writer
        .write_event(event.into())
        .map_err(ParseXmlError::Rewrite)
}

fn protected_payload(start: &BytesStart<'_>) -> bool {
    let name = element_name(start);
    if name != "Value" && name != "Binary" {
        return false;
    }
    let mut protected = false;
    let mut reference = false;
    for attr in start.attributes().flatten() {
        let key = attr.key.as_ref();
        if key == "Protected" {
            protected = attribute_value(&attr)
                .map(|value| value.eq_ignore_ascii_case("True"))
                .unwrap_or(false);
        } else if key == "Ref" {
            reference = true;
        }
    }
    protected && !reference
}

fn is_binary(start: &BytesStart<'_>) -> bool {
    element_name(start) == "Binary"
}

fn element_name(start: &BytesStart<'_>) -> String {
    let raw = start.name();
    let name = raw.as_ref();
    match name.rsplit(':').next() {
        Some(local) => local.to_string(),
        None => name.to_string(),
    }
}

fn owned_start(start: &BytesStart<'_>) -> Result<BytesStart<'static>, ParseXmlError> {
    let mut owned = BytesStart::new(start.name().as_ref().to_string());
    for attr in start.attributes().flatten() {
        if attr.key.as_ref() == "Protected" {
            continue;
        }
        let key = attr.key.as_ref().to_string();
        let value = attribute_value(&attr)?.to_string();
        owned.push_attribute((key.as_str(), value.as_str()));
    }
    Ok(owned)
}

fn attribute_value<'a>(
    attr: &'a quick_xml::events::attributes::Attribute<'a>,
) -> Result<std::borrow::Cow<'a, str>, ParseXmlError> {
    attr.normalized_value(quick_xml::XmlVersion::Implicit1_0)
        .map_err(ParseXmlError::Read)
}

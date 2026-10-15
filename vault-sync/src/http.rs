//! HTTP client for the CitriPass item sync service.
//!
//! The transport sends CPI1 records produced by [`SealedItem::to_bytes`] and
//! reads them back with [`SealedItem::from_bytes`]. It does not decrypt items
//! and does not decide conflicts.

use std::io::Read;
use std::time::Duration;

use base64::Engine;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;
use vault_core::SealedItem;
use vault_storage::{OperationKind, SyncCursor};

use crate::{
    OperationOutcome, OperationResult, PullRequest, PullResponse, PushRequest, PushResponse,
    SyncTransport,
};

const MAX_BODY: usize = 8 * 1024 * 1024;

/// Failures from the HTTP sync transport.
#[derive(Debug, Error)]
pub enum HttpSyncError {
    /// The configured base URL is not an HTTP(S) origin without user info.
    #[error("sync URL is not usable")]
    Url,
    /// A record could not be encoded or decoded as CPI1.
    #[error("sync record could not be encoded")]
    Record,
    /// The service returned an error payload or a response the client cannot use.
    #[error("sync service rejected the request: {0}")]
    Service(String),
    /// The HTTP client could not finish the call.
    #[error("sync transport failed: {0}")]
    Transport(String),
}

/// Blocking HTTP implementation of [`SyncTransport`].
pub struct HttpSyncTransport {
    base_url: String,
    agent: ureq::Agent,
}

impl HttpSyncTransport {
    /// Connect to a sync service such as `http://127.0.0.1:18081`.
    ///
    /// The string must be `http` or `https`, without a username, password,
    /// query, or fragment. A trailing slash is ignored.
    ///
    /// # Errors
    ///
    /// Returns [`HttpSyncError::Url`] when the address is not usable.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, HttpSyncError> {
        let base_url = normalize_base_url(base_url.as_ref())?;
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(30))
            .timeout_write(Duration::from_secs(30))
            .redirects(0)
            .build();
        Ok(Self { base_url, agent })
    }
}

impl SyncTransport for HttpSyncTransport {
    type Error = HttpSyncError;

    fn push(&mut self, request: PushRequest) -> Result<PushResponse, Self::Error> {
        let body = encode_push(&request)?;
        let url = format!("{}/v1/vaults/{}/sync/push", self.base_url, request.vault_id);
        let payload = send_json(&self.agent, &url, Some(body))?;
        decode_push(&payload)
    }

    fn pull(&mut self, request: PullRequest) -> Result<PullResponse, Self::Error> {
        let mut url = format!(
            "{}/v1/vaults/{}/sync/pull?device_id={}",
            self.base_url, request.vault_id, request.device_id
        );
        if let Some(cursor) = &request.cursor {
            url.push_str("&cursor=");
            url.push_str(&query_escape(cursor.as_str()));
        }
        let payload = send_json(&self.agent, &url, None)?;
        decode_pull(&payload)
    }
}

fn normalize_base_url(value: &str) -> Result<String, HttpSyncError> {
    let trimmed = value.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or(HttpSyncError::Url)?;
    if rest.is_empty()
        || rest.contains('@')
        || rest.contains(' ')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains('\\')
    {
        return Err(HttpSyncError::Url);
    }
    Ok(trimmed.to_string())
}

fn encode_push(request: &PushRequest) -> Result<String, HttpSyncError> {
    let operations = request
        .operations
        .iter()
        .map(|operation| {
            let record = operation
                .item
                .to_bytes()
                .map_err(|_| HttpSyncError::Record)?;
            Ok(PushOperationBody {
                operation_id: operation.operation_id.to_string(),
                device_id: operation.device_id.to_string(),
                kind: kind_name(operation.kind),
                base_revision: operation.base_revision,
                record: base64::engine::general_purpose::STANDARD.encode(record),
            })
        })
        .collect::<Result<Vec<_>, HttpSyncError>>()?;
    let body = PushBody {
        device_id: request.device_id.to_string(),
        operations,
    };
    serde_json::to_string(&body).map_err(|_| HttpSyncError::Record)
}

fn decode_push(payload: &str) -> Result<PushResponse, HttpSyncError> {
    let body: PushResponseBody = serde_json::from_str(payload)
        .map_err(|_| HttpSyncError::Service("malformed_record".into()))?;
    let mut results = Vec::with_capacity(body.results.len());
    for result in body.results {
        let operation_id = parse_id(&result.operation_id)?;
        let outcome = match result.outcome.as_str() {
            "accepted" => OperationOutcome::Accepted,
            "conflict" => {
                let encoded = result
                    .record
                    .ok_or_else(|| HttpSyncError::Service("malformed_record".into()))?;
                OperationOutcome::Conflict {
                    server_item: decode_record(&encoded)?,
                }
            }
            _ => return Err(HttpSyncError::Service("malformed_record".into())),
        };
        results.push(OperationResult {
            operation_id,
            outcome,
        });
    }
    Ok(PushResponse {
        results,
        cursor: SyncCursor::new(body.cursor),
    })
}

fn decode_pull(payload: &str) -> Result<PullResponse, HttpSyncError> {
    let body: PullResponseBody = serde_json::from_str(payload)
        .map_err(|_| HttpSyncError::Service("malformed_record".into()))?;
    let mut items = Vec::with_capacity(body.records.len());
    for record in body.records {
        items.push(decode_record(&record)?);
    }
    Ok(PullResponse {
        items,
        cursor: SyncCursor::new(body.cursor),
    })
}

fn decode_record(encoded: &str) -> Result<SealedItem, HttpSyncError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| HttpSyncError::Service("malformed_record".into()))?;
    SealedItem::from_bytes(&bytes).map_err(|_| HttpSyncError::Service("malformed_record".into()))
}

fn parse_id(value: &str) -> Result<Uuid, HttpSyncError> {
    Uuid::parse_str(value).map_err(|_| HttpSyncError::Service("operation_mismatch".into()))
}

fn kind_name(kind: OperationKind) -> &'static str {
    match kind {
        OperationKind::UpsertItem => "upsert_item",
        OperationKind::DeleteItem => "delete_item",
    }
}

fn send_json(
    agent: &ureq::Agent,
    url: &str,
    body: Option<String>,
) -> Result<String, HttpSyncError> {
    let request = if body.is_some() {
        agent.post(url)
    } else {
        agent.get(url)
    };
    let result = if let Some(body) = body {
        request
            .set("Content-Type", "application/json")
            .set("Accept", "application/json")
            .send_string(&body)
    } else {
        request.set("Accept", "application/json").call()
    };
    match result {
        Ok(response) => read_body(response.into_reader()),
        Err(ureq::Error::Status(status, response)) => {
            let payload = read_body(response.into_reader()).unwrap_or_default();
            Err(service_error(status, &payload))
        }
        Err(error) => Err(HttpSyncError::Transport(error.to_string())),
    }
}

fn service_error(status: u16, payload: &str) -> HttpSyncError {
    let code = serde_json::from_str::<ErrorBody>(payload)
        .map(|body| body.error)
        .unwrap_or_else(|_| "store".to_string());
    HttpSyncError::Service(format!("{code} ({status})"))
}

fn read_body(mut reader: impl Read) -> Result<String, HttpSyncError> {
    let mut buffer = Vec::new();
    reader
        .by_ref()
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut buffer)
        .map_err(|error| HttpSyncError::Transport(error.to_string()))?;
    if buffer.len() > MAX_BODY {
        return Err(HttpSyncError::Service("store".into()));
    }
    String::from_utf8(buffer).map_err(|_| HttpSyncError::Service("malformed_record".into()))
}

/// sync-service encodes an empty list as JSON null.
fn empty_if_null<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

fn query_escape(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                escaped.push(char::from(byte));
            }
            _ => escaped.push_str(&format!("%{byte:02X}")),
        }
    }
    escaped
}

#[derive(Serialize)]
struct PushBody {
    device_id: String,
    operations: Vec<PushOperationBody>,
}

#[derive(Serialize)]
struct PushOperationBody {
    operation_id: String,
    device_id: String,
    kind: &'static str,
    base_revision: Option<u64>,
    record: String,
}

#[derive(Deserialize)]
struct PushResponseBody {
    cursor: String,
    #[serde(default, deserialize_with = "empty_if_null")]
    results: Vec<PushResultBody>,
}

#[derive(Deserialize)]
struct PushResultBody {
    operation_id: String,
    outcome: String,
    record: Option<String>,
}

#[derive(Deserialize)]
struct PullResponseBody {
    cursor: String,
    #[serde(default, deserialize_with = "empty_if_null")]
    records: Vec<String>,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

#[cfg(test)]
mod tests {
    use super::normalize_base_url;

    #[test]
    fn rejects_urls_that_could_carry_a_secret_or_leave_http() {
        assert!(normalize_base_url("http://127.0.0.1:18081").is_ok());
        assert!(normalize_base_url("https://sync.example/citri/").is_ok());
        assert!(normalize_base_url("http://user:secret@127.0.0.1:18081").is_err());
        assert!(normalize_base_url("ftp://127.0.0.1").is_err());
        assert!(normalize_base_url("http://127.0.0.1:18081?cursor=1").is_err());
    }

    #[test]
    fn empty_push_results_may_be_json_null() {
        let decoded = super::decode_push(r#"{"cursor":"0","results":null}"#).unwrap();
        assert!(decoded.results.is_empty());
    }
}

use std::collections::VecDeque;

use async_trait::async_trait;
use base64::Engine as _;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::generated::*;

const LEGACY_REJECTED_CONTROL_MESSAGE_TYPES: &[&str] = &[
    "session.send",
    "control.debug_subscribe",
    "control.debug_unsubscribe",
    "control.node_service_watch",
    "control.node_service_unwatch",
    "control.node_service_event",
    "control.venom_watch",
    "control.venom_unwatch",
    "control.venom_event",
];

const LEGACY_REJECTED_ACHERON_MESSAGE_TYPES: &[&str] = &[
    "acheron.t_hello",
    "acheron.fs_t_*",
    "acheron.fs_r_*",
    "acheron.fs_evt_*",
    "acheron.fs_error",
];

#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct SpiderProtocolError {
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
}

impl SpiderProtocolError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

#[async_trait]
pub trait TextTransport: Send {
    async fn send_text(&mut self, text: String) -> Result<(), SpiderProtocolError>;
    async fn receive_text(&mut self) -> Result<String, SpiderProtocolError>;
    async fn close(&mut self) -> Result<(), SpiderProtocolError>;
}

pub fn encode_data_b64(data: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn decode_data_b64(data_b64: &str) -> Result<Vec<u8>, SpiderProtocolError> {
    base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .map_err(|error| SpiderProtocolError::new("invalid_base64", "base64 decode failed").with_details(Value::String(error.to_string())))
}

pub fn stringify_control_request(envelope: &ControlRequestEnvelope) -> Result<String, SpiderProtocolError> {
    stringify_value(envelope.to_value())
}

pub fn stringify_control_response(envelope: &ControlResponseEnvelope) -> Result<String, SpiderProtocolError> {
    stringify_value(envelope.to_value())
}

pub fn stringify_control_error(envelope: &ControlErrorEnvelope) -> Result<String, SpiderProtocolError> {
    stringify_value(serde_json::to_value(envelope))
}

pub fn stringify_acheron_request(envelope: &AcheronRequestEnvelope) -> Result<String, SpiderProtocolError> {
    stringify_value(envelope.to_value())
}

pub fn stringify_acheron_response(envelope: &AcheronResponseEnvelope) -> Result<String, SpiderProtocolError> {
    stringify_value(envelope.to_value())
}

pub fn stringify_acheron_event(envelope: &AcheronEventEnvelopeEnum) -> Result<String, SpiderProtocolError> {
    stringify_value(envelope.to_value())
}

pub fn stringify_acheron_error(envelope: &AcheronErrorEnvelopeEnum) -> Result<String, SpiderProtocolError> {
    stringify_value(envelope.to_value())
}

pub fn parse_control_request(raw: &str) -> Result<ControlRequestEnvelope, SpiderProtocolError> {
    let value = parse_raw_object(raw)?;
    validate_control_value(&value)?;
    ControlRequestEnvelope::from_value(value).map_err(json_error)
}

pub fn parse_control_response(raw: &str) -> Result<ControlResponseEnvelope, SpiderProtocolError> {
    let value = parse_raw_object(raw)?;
    validate_control_value(&value)?;
    if value.get("type").and_then(Value::as_str) == Some("control.error") {
        return Err(protocol_error_from_control_value(&value));
    }
    ControlResponseEnvelope::from_value(value).map_err(json_error)
}

pub fn parse_control_error(raw: &str) -> Result<ControlErrorEnvelope, SpiderProtocolError> {
    let value = parse_raw_object(raw)?;
    validate_control_value(&value)?;
    serde_json::from_value(value).map_err(json_error)
}

pub fn parse_acheron_request(raw: &str) -> Result<AcheronRequestEnvelope, SpiderProtocolError> {
    let value = parse_raw_object(raw)?;
    validate_acheron_value(&value)?;
    AcheronRequestEnvelope::from_value(value).map_err(json_error)
}

pub fn parse_acheron_response(raw: &str) -> Result<AcheronResponseEnvelope, SpiderProtocolError> {
    let value = parse_raw_object(raw)?;
    validate_acheron_value(&value)?;
    let message_type = value.get("type").and_then(Value::as_str).unwrap_or_default();
    if message_type == "acheron.error" || message_type == "acheron.err_fs" {
        return Err(protocol_error_from_acheron_value(&value));
    }
    AcheronResponseEnvelope::from_value(value).map_err(json_error)
}

pub fn parse_acheron_event(raw: &str) -> Result<AcheronEventEnvelopeEnum, SpiderProtocolError> {
    let value = parse_raw_object(raw)?;
    validate_acheron_value(&value)?;
    AcheronEventEnvelopeEnum::from_value(value).map_err(json_error)
}

pub fn parse_acheron_error(raw: &str) -> Result<AcheronErrorEnvelopeEnum, SpiderProtocolError> {
    let value = parse_raw_object(raw)?;
    validate_acheron_value(&value)?;
    AcheronErrorEnvelopeEnum::from_value(value).map_err(json_error)
}

pub struct ControlClient<T: TextTransport> {
    transport: T,
}

impl<T: TextTransport> ControlClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    pub async fn negotiate_version(&mut self, request_id: impl Into<String>) -> Result<ControlResponseEnvelope, SpiderProtocolError> {
        let request_id = request_id.into();
        self.request(ControlRequestEnvelope::Version(ControlEnvelope {
            channel: Channel::Control,
            message_type: ControlMessageType::Version,
            id: Some(request_id),
            ok: None,
            payload: Some(ControlVersionRequestPayload {
                protocol: CONTROL_PROTOCOL.to_string(),
            }),
        }))
        .await
    }

    pub async fn connect(&mut self, request_id: impl Into<String>) -> Result<ControlResponseEnvelope, SpiderProtocolError> {
        self.request(ControlRequestEnvelope::Connect(ControlEnvelope {
            channel: Channel::Control,
            message_type: ControlMessageType::Connect,
            id: Some(request_id.into()),
            ok: None,
            payload: Some(EmptyObject::default()),
        }))
        .await
    }

    pub async fn request(&mut self, request: ControlRequestEnvelope) -> Result<ControlResponseEnvelope, SpiderProtocolError> {
        let request_id = control_request_id(&request)?;
        self.transport.send_text(stringify_control_request(&request)?).await?;
        loop {
            let raw = self.transport.receive_text().await?;
            let value = parse_raw_object(&raw)?;
            if value.get("channel").and_then(Value::as_str) != Some("control") {
                continue;
            }
            if value.get("id").and_then(Value::as_str) != Some(request_id.as_str()) {
                continue;
            }
            if value.get("type").and_then(Value::as_str) == Some("control.error") {
                return Err(protocol_error_from_control_value(&value));
            }
            validate_control_value(&value)?;
            return ControlResponseEnvelope::from_value(value).map_err(json_error);
        }
    }
}

pub struct AcheronClient<T: TextTransport> {
    transport: T,
}

impl<T: TextTransport> AcheronClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    pub async fn negotiate_version(&mut self, tag: u32, msize: u32) -> Result<AcheronResponseEnvelope, SpiderProtocolError> {
        self.request(AcheronRequestEnvelope::TVersion(AcheronVersionEnvelope {
            channel: Channel::Acheron,
            message_type: AcheronMessageType::TVersion,
            tag: Some(tag),
            ok: None,
            msize,
            version: ACHERON_RUNTIME_VERSION.to_string(),
        }))
        .await
    }

    pub async fn attach(&mut self, tag: u32, fid: u32) -> Result<AcheronResponseEnvelope, SpiderProtocolError> {
        self.request(AcheronRequestEnvelope::TAttach(AcheronAttachEnvelope {
            channel: Channel::Acheron,
            message_type: AcheronMessageType::TAttach,
            tag: Some(tag),
            ok: None,
            fid,
        }))
        .await
    }

    pub async fn request(&mut self, request: AcheronRequestEnvelope) -> Result<AcheronResponseEnvelope, SpiderProtocolError> {
        self.request_with_events(request, |_| Ok(())).await
    }

    pub async fn request_with_events<F>(&mut self, request: AcheronRequestEnvelope, mut on_event: F) -> Result<AcheronResponseEnvelope, SpiderProtocolError>
    where
        F: FnMut(AcheronEventEnvelopeEnum) -> Result<(), SpiderProtocolError>,
    {
        let request_tag = acheron_request_tag(&request)?;
        self.transport.send_text(stringify_acheron_request(&request)?).await?;
        loop {
            let raw = self.transport.receive_text().await?;
            let value = parse_raw_object(&raw)?;
            if value.get("channel").and_then(Value::as_str) != Some("acheron") {
                continue;
            }
            validate_acheron_value(&value)?;
            let message_type = value.get("type").and_then(Value::as_str).unwrap_or_default();
            if message_type == "acheron.e_fs_inval" || message_type == "acheron.e_fs_inval_dir" {
                on_event(AcheronEventEnvelopeEnum::from_value(value).map_err(json_error)?)?;
                continue;
            }
            if value.get("tag").and_then(Value::as_u64) != Some(u64::from(request_tag)) {
                continue;
            }
            if message_type == "acheron.error" || message_type == "acheron.err_fs" {
                return Err(protocol_error_from_acheron_value(&value));
            }
            return AcheronResponseEnvelope::from_value(value).map_err(json_error);
        }
    }
}

pub struct FsClient<T: TextTransport> {
    acheron: AcheronClient<T>,
}

impl<T: TextTransport> FsClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            acheron: AcheronClient::new(transport),
        }
    }

    pub fn into_inner(self) -> T {
        self.acheron.into_inner()
    }

    pub async fn hello(&mut self, tag: u32) -> Result<AcheronResponseEnvelope, SpiderProtocolError> {
        self.acheron
            .request(AcheronRequestEnvelope::FsTHello(AcheronPayloadEnvelope {
                channel: Channel::Acheron,
                message_type: AcheronMessageType::FsTHello,
                tag: Some(tag),
                ok: None,
                payload: Some(FsHelloRequest {
                    protocol: NODE_FS_PROTOCOL.to_string(),
                    proto: NODE_FS_PROTO,
                    auth_token: None,
                    node_id: None,
                    node_secret: None,
                }),
            }))
            .await
    }

    pub async fn lookup(&mut self, tag: u32, node: u64, name: impl Into<String>) -> Result<AcheronResponseEnvelope, SpiderProtocolError> {
        self.acheron
            .request(AcheronRequestEnvelope::FsTLookup(AcheronNodeEnvelope {
                channel: Channel::Acheron,
                message_type: AcheronMessageType::FsTLookup,
                tag: Some(tag),
                ok: None,
                node,
                payload: Some(FsLookupRequest { name: name.into() }),
            }))
            .await
    }

    pub async fn getattr(&mut self, tag: u32, node: u64) -> Result<AcheronResponseEnvelope, SpiderProtocolError> {
        self.acheron
            .request(AcheronRequestEnvelope::FsTGetattr(AcheronNodeEnvelope {
                channel: Channel::Acheron,
                message_type: AcheronMessageType::FsTGetattr,
                tag: Some(tag),
                ok: None,
                node,
                payload: Some(EmptyObject::default()),
            }))
            .await
    }

    pub async fn readdirp(&mut self, tag: u32, node: u64, cookie: u64, count: u32) -> Result<AcheronResponseEnvelope, SpiderProtocolError> {
        self.acheron
            .request(AcheronRequestEnvelope::FsTReaddirp(AcheronNodeEnvelope {
                channel: Channel::Acheron,
                message_type: AcheronMessageType::FsTReaddirp,
                tag: Some(tag),
                ok: None,
                node,
                payload: Some(FsReaddirpRequest {
                    cookie: Some(cookie),
                    count: Some(count),
                    max: None,
                }),
            }))
            .await
    }

    pub async fn open(&mut self, tag: u32, node: u64, mode: impl Into<String>) -> Result<AcheronResponseEnvelope, SpiderProtocolError> {
        self.acheron
            .request(AcheronRequestEnvelope::FsTOpen(AcheronNodeEnvelope {
                channel: Channel::Acheron,
                message_type: AcheronMessageType::FsTOpen,
                tag: Some(tag),
                ok: None,
                node,
                payload: Some(FsOpenRequest {
                    mode: Some(mode.into()),
                    flags: None,
                }),
            }))
            .await
    }

    pub async fn read(&mut self, tag: u32, handle: u64, offset: u64, count: u32) -> Result<AcheronResponseEnvelope, SpiderProtocolError> {
        self.acheron
            .request(AcheronRequestEnvelope::FsTRead(AcheronHandleEnvelope {
                channel: Channel::Acheron,
                message_type: AcheronMessageType::FsTRead,
                tag: Some(tag),
                ok: None,
                handle,
                payload: Some(FsReadRequest {
                    offset,
                    count,
                }),
            }))
            .await
    }

    pub async fn write(&mut self, tag: u32, handle: u64, offset: u64, data: impl AsRef<[u8]>) -> Result<AcheronResponseEnvelope, SpiderProtocolError> {
        self.acheron
            .request(AcheronRequestEnvelope::FsTWrite(AcheronHandleEnvelope {
                channel: Channel::Acheron,
                message_type: AcheronMessageType::FsTWrite,
                tag: Some(tag),
                ok: None,
                handle,
                payload: Some(FsWriteRequest {
                    offset,
                    data_b64: encode_data_b64(data),
                }),
            }))
            .await
    }

    pub async fn close(&mut self, tag: u32, handle: u64) -> Result<AcheronResponseEnvelope, SpiderProtocolError> {
        self.acheron
            .request(AcheronRequestEnvelope::FsTClose(AcheronHandleEnvelope {
                channel: Channel::Acheron,
                message_type: AcheronMessageType::FsTClose,
                tag: Some(tag),
                ok: None,
                handle,
                payload: Some(EmptyObject::default()),
            }))
            .await
    }
}

fn parse_raw_object(raw: &str) -> Result<Value, SpiderProtocolError> {
    let value: Value = serde_json::from_str(raw).map_err(json_error)?;
    if !value.is_object() {
        return Err(SpiderProtocolError::new("invalid_envelope", "message must decode to an object"));
    }
    Ok(value)
}

fn validate_control_value(value: &Value) -> Result<(), SpiderProtocolError> {
    let channel = expect_string(value, "channel")?;
    if channel != "control" {
        return Err(SpiderProtocolError::new("invalid_channel", "unsupported control channel").with_details(value.clone()));
    }
    let message_type = expect_string(value, "type")?;
    if !message_type.starts_with("control.") {
        return Err(SpiderProtocolError::new("namespace_mismatch", "control channel requires a control.* type").with_details(value.clone()));
    }
    if LEGACY_REJECTED_CONTROL_MESSAGE_TYPES.contains(&message_type) {
        return Err(SpiderProtocolError::new("unsupported_legacy_type", "legacy control type is rejected").with_details(value.clone()));
    }
    if let Some(id) = value.get("id") {
        if !id.is_string() {
            return Err(SpiderProtocolError::new("invalid_id", "control id must be a string").with_details(value.clone()));
        }
    }
    Ok(())
}

fn validate_acheron_value(value: &Value) -> Result<(), SpiderProtocolError> {
    let channel = expect_string(value, "channel")?;
    if channel != "acheron" {
        return Err(SpiderProtocolError::new("invalid_channel", "unsupported acheron channel").with_details(value.clone()));
    }
    let message_type = expect_string(value, "type")?;
    if !message_type.starts_with("acheron.") {
        return Err(SpiderProtocolError::new("namespace_mismatch", "acheron channel requires an acheron.* type").with_details(value.clone()));
    }
    if LEGACY_REJECTED_ACHERON_MESSAGE_TYPES.contains(&message_type) {
        return Err(SpiderProtocolError::new("unsupported_legacy_type", "legacy acheron type is rejected").with_details(value.clone()));
    }
    if let Some(tag) = value.get("tag") {
        if tag.as_u64().is_none() {
            return Err(SpiderProtocolError::new("invalid_tag", "acheron tag must be an integer").with_details(value.clone()));
        }
    }
    Ok(())
}

fn expect_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, SpiderProtocolError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| SpiderProtocolError::new("missing_field", format!("{key} must be a string")).with_details(value.clone()))
}

fn stringify_value(value: serde_json::Result<Value>) -> Result<String, SpiderProtocolError> {
    let value = value.map_err(json_error)?;
    serde_json::to_string(&value).map_err(json_error)
}

fn json_error(error: serde_json::Error) -> SpiderProtocolError {
    SpiderProtocolError::new("invalid_json", "json serialization or parse failed").with_details(Value::String(error.to_string()))
}

fn control_request_id(request: &ControlRequestEnvelope) -> Result<String, SpiderProtocolError> {
    request
        .to_value()
        .map_err(json_error)?
        .get("id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| SpiderProtocolError::new("missing_id", "control request id is required"))
}

fn acheron_request_tag(request: &AcheronRequestEnvelope) -> Result<u32, SpiderProtocolError> {
    request
        .to_value()
        .map_err(json_error)?
        .get("tag")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| SpiderProtocolError::new("missing_tag", "acheron request tag is required"))
}

fn protocol_error_from_control_value(value: &Value) -> SpiderProtocolError {
    let error = value.get("error").and_then(Value::as_object);
    let code = error
        .and_then(|inner| inner.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("control_error");
    let message = error
        .and_then(|inner| inner.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("control request failed");
    SpiderProtocolError::new(code, message).with_details(value.clone())
}

fn protocol_error_from_acheron_value(value: &Value) -> SpiderProtocolError {
    let error = value.get("error").and_then(Value::as_object);
    if let Some(errno) = error.and_then(|inner| inner.get("errno")).and_then(Value::as_u64) {
        return SpiderProtocolError::new(
            "acheron_fs_error",
            error
                .and_then(|inner| inner.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("acheron fs request failed"),
        )
        .with_details(Value::Object(Map::from_iter([
            ("envelope".to_string(), value.clone()),
            ("errno".to_string(), Value::from(errno)),
        ])));
    }
    SpiderProtocolError::new(
        error
            .and_then(|inner| inner.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("acheron_error"),
        error
            .and_then(|inner| inner.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("acheron request failed"),
    )
    .with_details(value.clone())
}

pub struct MockTextTransport {
    sent: Vec<String>,
    incoming: VecDeque<String>,
}

impl MockTextTransport {
    pub fn new(incoming: impl IntoIterator<Item = String>) -> Self {
        Self {
            sent: Vec::new(),
            incoming: incoming.into_iter().collect(),
        }
    }

    pub fn sent(&self) -> &[String] {
        &self.sent
    }
}

#[async_trait]
impl TextTransport for MockTextTransport {
    async fn send_text(&mut self, text: String) -> Result<(), SpiderProtocolError> {
        self.sent.push(text);
        Ok(())
    }

    async fn receive_text(&mut self) -> Result<String, SpiderProtocolError> {
        self.incoming
            .pop_front()
            .ok_or_else(|| SpiderProtocolError::new("transport_eof", "mock transport is out of messages"))
    }

    async fn close(&mut self) -> Result<(), SpiderProtocolError> {
        Ok(())
    }
}

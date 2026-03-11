from __future__ import annotations

import asyncio
import base64
import json
from typing import Any, Protocol, TypedDict, cast

from .generated import (
    ACHERON_MESSAGE_TYPES,
    ACHERON_RUNTIME_VERSION,
    CONTROL_MESSAGE_TYPES,
    CONTROL_PROTOCOL,
    LEGACY_REJECTED_ACHERON_MESSAGE_TYPES,
    LEGACY_REJECTED_CONTROL_MESSAGE_TYPES,
    NODE_FS_PROTO,
    NODE_FS_PROTOCOL,
)


class SpiderProtocolError(RuntimeError):
    def __init__(self, code: str, message: str, details: Any | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details


class ControlErrorPayload(TypedDict):
    code: str
    message: str


class AcheronErrorPayload(TypedDict, total=False):
    code: str
    errno: int
    message: str


class TextTransport(Protocol):
    async def send_text(self, text: str) -> None: ...
    async def receive_text(self) -> str: ...
    async def close(self) -> None: ...


class WebSocketTextTransport:
    def __init__(self, websocket: Any) -> None:
        self._websocket = websocket

    @classmethod
    async def connect(cls, url: str, **connect_kwargs: Any) -> "WebSocketTextTransport":
        try:
            import websockets
        except ImportError as exc:
            raise SpiderProtocolError(
                "missing_websocket_dependency",
                "install spiderweb-protocol[websocket] to use WebSocketTextTransport",
                exc,
            ) from exc

        websocket = await websockets.connect(url, **connect_kwargs)
        return cls(websocket)

    async def send_text(self, text: str) -> None:
        await self._websocket.send(text)

    async def receive_text(self) -> str:
        message = await self._websocket.recv()
        if not isinstance(message, str):
            raise SpiderProtocolError(
                "invalid_frame_type",
                "websocket transport expected a text frame",
                type(message).__name__,
            )
        return message

    async def close(self) -> None:
        await self._websocket.close()


def encode_data_b64(data: bytes | str) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return base64.b64encode(raw).decode("ascii")


def decode_data_b64(data_b64: str) -> bytes:
    return base64.b64decode(data_b64, validate=True)


def parse_envelope(raw: str | dict[str, Any]) -> dict[str, Any]:
    payload = _parse_json_object(raw) if isinstance(raw, str) else raw
    channel = _expect_string(payload, "channel")
    msg_type = _expect_string(payload, "type")

    if channel == "control":
        if not msg_type.startswith("control."):
            raise SpiderProtocolError(
                "namespace_mismatch",
                "control channel requires a control.* type",
                payload,
            )
        if msg_type in LEGACY_REJECTED_CONTROL_MESSAGE_TYPES:
            raise SpiderProtocolError(
                "unsupported_legacy_type",
                f"legacy control type {msg_type} is rejected",
                payload,
            )
        if msg_type not in CONTROL_MESSAGE_TYPES:
            raise SpiderProtocolError(
                "unsupported_type",
                f"unsupported control type {msg_type}",
                payload,
            )
        if "id" in payload and not isinstance(payload["id"], str):
            raise SpiderProtocolError("invalid_id", "control id must be a string", payload)
        return payload

    if channel == "acheron":
        if not msg_type.startswith("acheron."):
            raise SpiderProtocolError(
                "namespace_mismatch",
                "acheron channel requires an acheron.* type",
                payload,
            )
        if msg_type in LEGACY_REJECTED_ACHERON_MESSAGE_TYPES:
            raise SpiderProtocolError(
                "unsupported_legacy_type",
                f"legacy acheron type {msg_type} is rejected",
                payload,
            )
        if msg_type not in ACHERON_MESSAGE_TYPES:
            raise SpiderProtocolError(
                "unsupported_type",
                f"unsupported acheron type {msg_type}",
                payload,
            )
        if "tag" in payload and (not isinstance(payload["tag"], int) or isinstance(payload["tag"], bool)):
            raise SpiderProtocolError("invalid_tag", "acheron tag must be an integer", payload)
        return payload

    raise SpiderProtocolError("invalid_channel", f"unsupported channel {channel}", payload)


def stringify_envelope(envelope: dict[str, Any]) -> str:
    return json.dumps(envelope, separators=(",", ":"))


def build_control_envelope(
    msg_type: str,
    *,
    request_id: str | None = None,
    ok: bool | None = None,
    payload: Any | None = None,
    error: ControlErrorPayload | None = None,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {"channel": "control", "type": msg_type}
    if request_id is not None:
        envelope["id"] = request_id
    if ok is not None:
        envelope["ok"] = ok
    if payload is not None:
        envelope["payload"] = payload
    if error is not None:
        envelope["error"] = error
    return envelope


def build_control_error(code: str, message: str, request_id: str | None = None) -> dict[str, Any]:
    return build_control_envelope(
        "control.error",
        request_id=request_id,
        ok=False,
        error={"code": code, "message": message},
    )


def build_control_version_request(request_id: str) -> dict[str, Any]:
    return build_control_envelope(
        "control.version",
        request_id=request_id,
        payload={"protocol": CONTROL_PROTOCOL},
    )


def build_control_connect_request(request_id: str) -> dict[str, Any]:
    return build_control_envelope("control.connect", request_id=request_id, payload={})


def build_acheron_envelope(
    msg_type: str,
    *,
    tag: int | None = None,
    ok: bool | None = None,
    payload: Any | None = None,
    error: AcheronErrorPayload | None = None,
    **extra: Any,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {"channel": "acheron", "type": msg_type}
    if tag is not None:
        envelope["tag"] = tag
    if ok is not None:
        envelope["ok"] = ok
    if payload is not None:
        envelope["payload"] = payload
    if error is not None:
        envelope["error"] = error
    envelope.update(extra)
    return envelope


def build_acheron_error(code: str, message: str, tag: int | None = None) -> dict[str, Any]:
    return build_acheron_envelope(
        "acheron.error",
        tag=tag,
        ok=False,
        error={"code": code, "message": message},
    )


def build_acheron_fs_error(errno: int, message: str, tag: int | None = None) -> dict[str, Any]:
    return build_acheron_envelope(
        "acheron.err_fs",
        tag=tag,
        ok=False,
        error={"errno": errno, "message": message},
    )


def build_acheron_version_request(tag: int, msize: int = 1_048_576) -> dict[str, Any]:
    return build_acheron_envelope(
        "acheron.t_version",
        tag=tag,
        msize=msize,
        version=ACHERON_RUNTIME_VERSION,
    )


def build_acheron_attach_request(tag: int, fid: int = 1) -> dict[str, Any]:
    return build_acheron_envelope("acheron.t_attach", tag=tag, fid=fid)


def build_fs_hello_request(tag: int) -> dict[str, Any]:
    return build_acheron_envelope(
        "acheron.t_fs_hello",
        tag=tag,
        payload={"protocol": NODE_FS_PROTOCOL, "proto": NODE_FS_PROTO},
    )


class ControlClient:
    def __init__(self, transport: TextTransport) -> None:
        self._transport = transport

    async def negotiate_version(self, request_id: str = "control-version") -> dict[str, Any]:
        return await self.request("control.version", request_id, {"protocol": CONTROL_PROTOCOL})

    async def connect(self, request_id: str = "control-connect") -> dict[str, Any]:
        return await self.request("control.connect", request_id, {})

    async def request(self, msg_type: str, request_id: str, payload: Any | None = None) -> dict[str, Any]:
        await self._transport.send_text(
            stringify_envelope(build_control_envelope(msg_type, request_id=request_id, payload=payload))
        )
        while True:
            envelope = parse_envelope(await self._transport.receive_text())
            if envelope["channel"] != "control":
                continue
            if envelope.get("id") != request_id:
                continue
            if envelope["type"] == "control.error":
                raise _protocol_error_from_control(envelope)
            return envelope


class AcheronClient:
    def __init__(self, transport: TextTransport) -> None:
        self._transport = transport

    async def negotiate_version(self, tag: int = 1, msize: int = 1_048_576) -> dict[str, Any]:
        return await self.request(build_acheron_version_request(tag, msize), "acheron.r_version")

    async def attach(self, tag: int = 2, fid: int = 1) -> dict[str, Any]:
        return await self.request(build_acheron_attach_request(tag, fid), "acheron.r_attach")

    async def request(
        self,
        envelope: dict[str, Any],
        expected_type: str,
        *,
        on_event: Any | None = None,
    ) -> dict[str, Any]:
        await self._transport.send_text(stringify_envelope(envelope))
        while True:
            parsed = parse_envelope(await self._transport.receive_text())
            if parsed["channel"] != "acheron":
                continue
            if _is_acheron_event(parsed):
                if on_event is not None:
                    await _maybe_await(on_event(parsed))
                continue
            if parsed.get("tag") != envelope.get("tag"):
                continue
            if parsed["type"] in {"acheron.error", "acheron.err_fs"}:
                raise _protocol_error_from_acheron(parsed)
            if parsed["type"] != expected_type:
                raise SpiderProtocolError(
                    "unexpected_type",
                    f"expected {expected_type} but received {parsed['type']}",
                    parsed,
                )
            return parsed


class FsClient:
    def __init__(self, transport: TextTransport) -> None:
        self._acheron = AcheronClient(transport)

    async def hello(self, tag: int = 1) -> dict[str, Any]:
        return await self._acheron.request(build_fs_hello_request(tag), "acheron.r_fs_hello")

    async def lookup(self, tag: int, node: int, name: str) -> dict[str, Any]:
        return await self._request("acheron.t_fs_lookup", "acheron.r_fs_lookup", tag, node=node, payload={"name": name})

    async def getattr(self, tag: int, node: int) -> dict[str, Any]:
        return await self._request("acheron.t_fs_getattr", "acheron.r_fs_getattr", tag, node=node, payload={})

    async def readdirp(self, tag: int, node: int, cookie: int = 0, count: int = 128) -> dict[str, Any]:
        return await self._request(
            "acheron.t_fs_readdirp",
            "acheron.r_fs_readdirp",
            tag,
            node=node,
            payload={"cookie": cookie, "count": count},
        )

    async def open(self, tag: int, node: int, mode: str = "r") -> dict[str, Any]:
        return await self._request("acheron.t_fs_open", "acheron.r_fs_open", tag, node=node, payload={"mode": mode})

    async def read(self, tag: int, handle: int, offset: int = 0, count: int = 4096) -> dict[str, Any]:
        return await self._request(
            "acheron.t_fs_read",
            "acheron.r_fs_read",
            tag,
            h=handle,
            payload={"offset": offset, "count": count},
        )

    async def write(self, tag: int, handle: int, data: bytes | str, offset: int = 0) -> dict[str, Any]:
        return await self._request(
            "acheron.t_fs_write",
            "acheron.r_fs_write",
            tag,
            h=handle,
            payload={"offset": offset, "data_b64": encode_data_b64(data)},
        )

    async def close(self, tag: int, handle: int) -> dict[str, Any]:
        return await self._request("acheron.t_fs_close", "acheron.r_fs_close", tag, h=handle, payload={})

    async def _request(self, msg_type: str, expected_type: str, tag: int, **extra: Any) -> dict[str, Any]:
        envelope = build_acheron_envelope(msg_type, tag=tag, **extra)
        return await self._acheron.request(envelope, expected_type)


def _parse_json_object(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SpiderProtocolError("invalid_json", "message is not valid JSON", exc) from exc
    if not isinstance(value, dict):
        raise SpiderProtocolError("invalid_envelope", "message must decode to an object", value)
    return cast(dict[str, Any], value)


def _expect_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise SpiderProtocolError("missing_field", f"{key} must be a string", payload)
    return value


def _protocol_error_from_control(envelope: dict[str, Any]) -> SpiderProtocolError:
    error = envelope.get("error")
    if not isinstance(error, dict):
        return SpiderProtocolError("control_error", "control request failed", envelope)
    return SpiderProtocolError(
        cast(str, error.get("code", "control_error")),
        cast(str, error.get("message", "control request failed")),
        envelope,
    )


def _protocol_error_from_acheron(envelope: dict[str, Any]) -> SpiderProtocolError:
    error = envelope.get("error")
    if not isinstance(error, dict):
        return SpiderProtocolError("acheron_error", "acheron request failed", envelope)
    if isinstance(error.get("errno"), int):
        return SpiderProtocolError(
            "acheron_fs_error",
            cast(str, error.get("message", "acheron fs request failed")),
            envelope,
        )
    return SpiderProtocolError(
        cast(str, error.get("code", "acheron_error")),
        cast(str, error.get("message", "acheron request failed")),
        envelope,
    )


def _is_acheron_event(envelope: dict[str, Any]) -> bool:
    return envelope.get("type") in {"acheron.e_fs_inval", "acheron.e_fs_inval_dir"}


async def _maybe_await(value: Any) -> Any:
    if asyncio.iscoroutine(value):
        return await value
    return value

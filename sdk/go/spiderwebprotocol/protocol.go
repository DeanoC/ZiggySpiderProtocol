package spiderwebprotocol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type SpiderProtocolError struct {
	Code    string
	Message string
	Details any
}

func (err *SpiderProtocolError) Error() string {
	return err.Message
}

type ControlErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type AcheronErrorPayload struct {
	Code    string `json:"code,omitempty"`
	Errno   *int   `json:"errno,omitempty"`
	Message string `json:"message"`
}

type ControlEnvelope map[string]any
type AcheronEnvelope map[string]any
type ParsedEnvelope map[string]any

type TextTransport interface {
	SendText(ctx context.Context, text string) error
	ReceiveText(ctx context.Context) (string, error)
	Close() error
}

type WebSocketDialOptions struct {
	Subprotocols []string
	Headers      http.Header
	Dialer       *websocket.Dialer
}

type WebSocketTextTransport struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
}

func DialWebSocketTextTransport(
	ctx context.Context,
	url string,
	options *WebSocketDialOptions,
) (*WebSocketTextTransport, error) {
	dialer := websocket.Dialer{}
	if options != nil && options.Dialer != nil {
		dialer = *options.Dialer
	} else {
		dialer = *websocket.DefaultDialer
	}

	if options != nil && len(options.Subprotocols) > 0 {
		dialer.Subprotocols = append([]string(nil), options.Subprotocols...)
	}

	headers := http.Header(nil)
	if options != nil && options.Headers != nil {
		headers = options.Headers.Clone()
	}

	conn, _, err := dialer.DialContext(ctx, url, headers)
	if err != nil {
		return nil, &SpiderProtocolError{
			Code:    "websocket_open_failed",
			Message: "websocket connection failed before open",
			Details: err,
		}
	}

	return &WebSocketTextTransport{conn: conn}, nil
}

func (transport *WebSocketTextTransport) SendText(ctx context.Context, text string) error {
	if err := transport.applyDeadline(ctx, true); err != nil {
		return err
	}
	transport.writeMu.Lock()
	defer transport.writeMu.Unlock()
	return transport.conn.WriteMessage(websocket.TextMessage, []byte(text))
}

func (transport *WebSocketTextTransport) ReceiveText(ctx context.Context) (string, error) {
	if err := transport.applyDeadline(ctx, false); err != nil {
		return "", err
	}
	messageType, payload, err := transport.conn.ReadMessage()
	if err != nil {
		return "", err
	}
	if messageType != websocket.TextMessage {
		return "", &SpiderProtocolError{
			Code:    "invalid_frame_type",
			Message: "websocket transport expected a text frame",
			Details: messageType,
		}
	}
	return string(payload), nil
}

func (transport *WebSocketTextTransport) Close() error {
	return transport.conn.Close()
}

func (transport *WebSocketTextTransport) applyDeadline(ctx context.Context, write bool) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Time{}
	}

	if write {
		return transport.conn.SetWriteDeadline(deadline)
	}
	return transport.conn.SetReadDeadline(deadline)
}

func EncodeDataB64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func EncodeStringDataB64(data string) string {
	return EncodeDataB64([]byte(data))
}

func DecodeDataB64(dataB64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(dataB64)
}

func ParseEnvelope(raw string) (ParsedEnvelope, error) {
	payload, err := parseJSONObject(raw)
	if err != nil {
		return nil, err
	}
	if err := ValidateEnvelope(payload); err != nil {
		return nil, err
	}
	return ParsedEnvelope(payload), nil
}

func ValidateEnvelope(payload map[string]any) error {
	channel, err := expectString(payload, "channel")
	if err != nil {
		return err
	}

	msgType, err := expectString(payload, "type")
	if err != nil {
		return err
	}

	switch channel {
	case "control":
		if !strings.HasPrefix(msgType, "control.") {
			return &SpiderProtocolError{
				Code:    "namespace_mismatch",
				Message: "control channel requires a control.* type",
				Details: payload,
			}
		}
		if containsString(LegacyRejectedControlMessageTypes, msgType) {
			return &SpiderProtocolError{
				Code:    "unsupported_legacy_type",
				Message: fmt.Sprintf("legacy control type %s is rejected", msgType),
				Details: payload,
			}
		}
		if !containsString(ControlMessageTypes, msgType) {
			return &SpiderProtocolError{
				Code:    "unsupported_type",
				Message: fmt.Sprintf("unsupported control type %s", msgType),
				Details: payload,
			}
		}
		if rawID, ok := payload["id"]; ok {
			if _, ok := rawID.(string); !ok {
				return &SpiderProtocolError{
					Code:    "invalid_id",
					Message: "control id must be a string",
					Details: payload,
				}
			}
		}
		return nil
	case "acheron":
		if !strings.HasPrefix(msgType, "acheron.") {
			return &SpiderProtocolError{
				Code:    "namespace_mismatch",
				Message: "acheron channel requires an acheron.* type",
				Details: payload,
			}
		}
		if containsString(LegacyRejectedAcheronMessageTypes, msgType) {
			return &SpiderProtocolError{
				Code:    "unsupported_legacy_type",
				Message: fmt.Sprintf("legacy acheron type %s is rejected", msgType),
				Details: payload,
			}
		}
		if !containsString(AcheronMessageTypes, msgType) {
			return &SpiderProtocolError{
				Code:    "unsupported_type",
				Message: fmt.Sprintf("unsupported acheron type %s", msgType),
				Details: payload,
			}
		}
		if rawTag, ok := payload["tag"]; ok {
			if _, ok := integerValue(rawTag); !ok {
				return &SpiderProtocolError{
					Code:    "invalid_tag",
					Message: "acheron tag must be an integer",
					Details: payload,
				}
			}
		}
		return nil
	default:
		return &SpiderProtocolError{
			Code:    "invalid_channel",
			Message: fmt.Sprintf("unsupported channel %s", channel),
			Details: payload,
		}
	}
}

func StringifyEnvelope(envelope map[string]any) (string, error) {
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

type ControlEnvelopeOptions struct {
	RequestID string
	OK        *bool
	Payload   any
	Error     *ControlErrorPayload
}

func BuildControlEnvelope(msgType string, options ControlEnvelopeOptions) ControlEnvelope {
	envelope := ControlEnvelope{
		"channel": "control",
		"type":    msgType,
	}
	if options.RequestID != "" {
		envelope["id"] = options.RequestID
	}
	if options.OK != nil {
		envelope["ok"] = *options.OK
	}
	if options.Payload != nil {
		envelope["payload"] = options.Payload
	}
	if options.Error != nil {
		envelope["error"] = options.Error
	}
	return envelope
}

func BuildControlAck(msgType string, requestID string, payload any) ControlEnvelope {
	ok := true
	return BuildControlEnvelope(msgType, ControlEnvelopeOptions{
		RequestID: requestID,
		OK:        &ok,
		Payload:   payload,
	})
}

func BuildControlError(code string, message string, requestID string) ControlEnvelope {
	ok := false
	return BuildControlEnvelope("control.error", ControlEnvelopeOptions{
		RequestID: requestID,
		OK:        &ok,
		Error: &ControlErrorPayload{
			Code:    code,
			Message: message,
		},
	})
}

func BuildControlVersionRequest(requestID string) ControlEnvelope {
	return BuildControlEnvelope("control.version", ControlEnvelopeOptions{
		RequestID: requestID,
		Payload: map[string]any{
			"protocol": ControlProtocol,
		},
	})
}

func BuildControlConnectRequest(requestID string) ControlEnvelope {
	return BuildControlEnvelope("control.connect", ControlEnvelopeOptions{
		RequestID: requestID,
		Payload:   map[string]any{},
	})
}

type AcheronEnvelopeOptions struct {
	Tag     *int
	OK      *bool
	Payload any
	Error   *AcheronErrorPayload
	Extra   map[string]any
}

func BuildAcheronEnvelope(msgType string, options AcheronEnvelopeOptions) AcheronEnvelope {
	envelope := AcheronEnvelope{
		"channel": "acheron",
		"type":    msgType,
	}
	if options.Tag != nil {
		envelope["tag"] = *options.Tag
	}
	if options.OK != nil {
		envelope["ok"] = *options.OK
	}
	if options.Payload != nil {
		envelope["payload"] = options.Payload
	}
	if options.Error != nil {
		envelope["error"] = options.Error
	}
	for key, value := range options.Extra {
		envelope[key] = value
	}
	return envelope
}

func BuildAcheronResponse(msgType string, tag int, payload any) AcheronEnvelope {
	ok := true
	return BuildAcheronEnvelope(msgType, AcheronEnvelopeOptions{
		Tag:     &tag,
		OK:      &ok,
		Payload: payload,
	})
}

func BuildAcheronError(code string, message string, tag *int) AcheronEnvelope {
	ok := false
	return BuildAcheronEnvelope("acheron.error", AcheronEnvelopeOptions{
		Tag: tag,
		OK:  &ok,
		Error: &AcheronErrorPayload{
			Code:    code,
			Message: message,
		},
	})
}

func BuildAcheronFsError(errno int, message string, tag *int) AcheronEnvelope {
	ok := false
	return BuildAcheronEnvelope("acheron.err_fs", AcheronEnvelopeOptions{
		Tag: tag,
		OK:  &ok,
		Error: &AcheronErrorPayload{
			Errno:   &errno,
			Message: message,
		},
	})
}

func BuildAcheronEvent(msgType string, payload any) AcheronEnvelope {
	return BuildAcheronEnvelope(msgType, AcheronEnvelopeOptions{
		Payload: payload,
	})
}

func BuildAcheronVersionRequest(tag int, msize int, version string) AcheronEnvelope {
	if msize == 0 {
		msize = 1_048_576
	}
	if version == "" {
		version = AcheronRuntimeVersion
	}
	return BuildAcheronEnvelope("acheron.t_version", AcheronEnvelopeOptions{
		Tag: &tag,
		Extra: map[string]any{
			"msize":   msize,
			"version": version,
		},
	})
}

func BuildAcheronAttachRequest(tag int, fid int) AcheronEnvelope {
	if fid == 0 {
		fid = 1
	}
	return BuildAcheronEnvelope("acheron.t_attach", AcheronEnvelopeOptions{
		Tag: &tag,
		Extra: map[string]any{
			"fid": fid,
		},
	})
}

func BuildFsHelloRequest(tag int, payload map[string]any) AcheronEnvelope {
	if payload == nil {
		payload = map[string]any{
			"protocol": NodeFSProtocol,
			"proto":    NodeFSProto,
		}
	}
	return BuildAcheronEnvelope("acheron.t_fs_hello", AcheronEnvelopeOptions{
		Tag:     &tag,
		Payload: payload,
	})
}

type ControlClient struct {
	transport TextTransport
}

func NewControlClient(transport TextTransport) *ControlClient {
	return &ControlClient{transport: transport}
}

func (client *ControlClient) NegotiateVersion(ctx context.Context, requestID string) (ControlEnvelope, error) {
	if requestID == "" {
		requestID = "control-version"
	}
	return client.Request(ctx, "control.version", requestID, map[string]any{"protocol": ControlProtocol})
}

func (client *ControlClient) Connect(ctx context.Context, requestID string) (ControlEnvelope, error) {
	if requestID == "" {
		requestID = "control-connect"
	}
	return client.Request(ctx, "control.connect", requestID, map[string]any{})
}

func (client *ControlClient) Request(
	ctx context.Context,
	msgType string,
	requestID string,
	payload any,
) (ControlEnvelope, error) {
	message, err := StringifyEnvelope(BuildControlEnvelope(msgType, ControlEnvelopeOptions{
		RequestID: requestID,
		Payload:   payload,
	}))
	if err != nil {
		return nil, err
	}
	if err := client.transport.SendText(ctx, message); err != nil {
		return nil, err
	}

	for {
		raw, err := client.transport.ReceiveText(ctx)
		if err != nil {
			return nil, err
		}
		envelope, err := ParseEnvelope(raw)
		if err != nil {
			return nil, err
		}
		if envelopeValue(envelope, "channel") != "control" {
			continue
		}
		if envelopeValue(envelope, "id") != requestID {
			continue
		}
		if envelopeValue(envelope, "type") == "control.error" {
			return nil, protocolErrorFromControlEnvelope(envelope)
		}
		return ControlEnvelope(envelope), nil
	}
}

type AcheronClient struct {
	transport TextTransport
}

func NewAcheronClient(transport TextTransport) *AcheronClient {
	return &AcheronClient{transport: transport}
}

func (client *AcheronClient) NegotiateVersion(ctx context.Context, tag int, msize int) (AcheronEnvelope, error) {
	if tag == 0 {
		tag = 1
	}
	return client.Request(ctx, BuildAcheronVersionRequest(tag, msize, ""), "acheron.r_version", nil)
}

func (client *AcheronClient) Attach(ctx context.Context, tag int, fid int) (AcheronEnvelope, error) {
	if tag == 0 {
		tag = 2
	}
	return client.Request(ctx, BuildAcheronAttachRequest(tag, fid), "acheron.r_attach", nil)
}

func (client *AcheronClient) Request(
	ctx context.Context,
	envelope AcheronEnvelope,
	expectedType string,
	onEvent func(AcheronEnvelope),
) (AcheronEnvelope, error) {
	message, err := StringifyEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if err := client.transport.SendText(ctx, message); err != nil {
		return nil, err
	}

	expectedTag, _ := integerValue(envelope["tag"])
	for {
		raw, err := client.transport.ReceiveText(ctx)
		if err != nil {
			return nil, err
		}
		parsed, err := ParseEnvelope(raw)
		if err != nil {
			return nil, err
		}
		if envelopeValue(parsed, "channel") != "acheron" {
			continue
		}
		if isAcheronEvent(parsed) {
			if onEvent != nil {
				onEvent(AcheronEnvelope(parsed))
			}
			continue
		}
		if tag, ok := integerValue(parsed["tag"]); !ok || tag != expectedTag {
			continue
		}
		switch envelopeValue(parsed, "type") {
		case "acheron.error", "acheron.err_fs":
			return nil, protocolErrorFromAcheronEnvelope(parsed)
		case expectedType:
			return AcheronEnvelope(parsed), nil
		default:
			return nil, &SpiderProtocolError{
				Code:    "unexpected_type",
				Message: fmt.Sprintf("expected %s but received %s", expectedType, envelopeValue(parsed, "type")),
				Details: parsed,
			}
		}
	}
}

type FsClient struct {
	acheron *AcheronClient
}

func NewFsClient(transport TextTransport) *FsClient {
	return &FsClient{acheron: NewAcheronClient(transport)}
}

func (client *FsClient) Hello(ctx context.Context, tag int, payload map[string]any) (AcheronEnvelope, error) {
	if tag == 0 {
		tag = 1
	}
	return client.acheron.Request(ctx, BuildFsHelloRequest(tag, payload), "acheron.r_fs_hello", nil)
}

func (client *FsClient) Lookup(ctx context.Context, tag int, node uint64, name string) (AcheronEnvelope, error) {
	return client.request(ctx, "acheron.t_fs_lookup", "acheron.r_fs_lookup", tag, map[string]any{
		"node":    node,
		"payload": map[string]any{"name": name},
	})
}

func (client *FsClient) Getattr(ctx context.Context, tag int, node uint64) (AcheronEnvelope, error) {
	return client.request(ctx, "acheron.t_fs_getattr", "acheron.r_fs_getattr", tag, map[string]any{
		"node":    node,
		"payload": map[string]any{},
	})
}

func (client *FsClient) Readdirp(
	ctx context.Context,
	tag int,
	node uint64,
	cookie uint64,
	count uint32,
) (AcheronEnvelope, error) {
	if count == 0 {
		count = 128
	}
	return client.request(ctx, "acheron.t_fs_readdirp", "acheron.r_fs_readdirp", tag, map[string]any{
		"node": node,
		"payload": map[string]any{
			"cookie": cookie,
			"count":  count,
		},
	})
}

func (client *FsClient) Open(ctx context.Context, tag int, node uint64, mode string) (AcheronEnvelope, error) {
	if mode == "" {
		mode = "r"
	}
	return client.request(ctx, "acheron.t_fs_open", "acheron.r_fs_open", tag, map[string]any{
		"node":    node,
		"payload": map[string]any{"mode": mode},
	})
}

func (client *FsClient) Read(
	ctx context.Context,
	tag int,
	handle uint64,
	offset uint64,
	count uint32,
) (AcheronEnvelope, error) {
	if count == 0 {
		count = 4096
	}
	return client.request(ctx, "acheron.t_fs_read", "acheron.r_fs_read", tag, map[string]any{
		"h": handle,
		"payload": map[string]any{
			"offset": offset,
			"count":  count,
		},
	})
}

func (client *FsClient) Write(
	ctx context.Context,
	tag int,
	handle uint64,
	data []byte,
	offset uint64,
) (AcheronEnvelope, error) {
	return client.request(ctx, "acheron.t_fs_write", "acheron.r_fs_write", tag, map[string]any{
		"h": handle,
		"payload": map[string]any{
			"offset":   offset,
			"data_b64": EncodeDataB64(data),
		},
	})
}

func (client *FsClient) Close(ctx context.Context, tag int, handle uint64) (AcheronEnvelope, error) {
	return client.request(ctx, "acheron.t_fs_close", "acheron.r_fs_close", tag, map[string]any{
		"h":       handle,
		"payload": map[string]any{},
	})
}

func (client *FsClient) request(
	ctx context.Context,
	msgType string,
	expectedType string,
	tag int,
	extra map[string]any,
) (AcheronEnvelope, error) {
	envelope := BuildAcheronEnvelope(msgType, AcheronEnvelopeOptions{
		Tag:   &tag,
		Extra: extra,
	})
	return client.acheron.Request(ctx, envelope, expectedType, nil)
}

func parseJSONObject(raw string) (map[string]any, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()

	payload := map[string]any{}
	if err := decoder.Decode(&payload); err != nil {
		return nil, &SpiderProtocolError{
			Code:    "invalid_json",
			Message: "message is not valid JSON",
			Details: err,
		}
	}

	if err := ensureNoTrailingJSON(decoder); err != nil {
		return nil, err
	}

	return payload, nil
}

func ensureNoTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return &SpiderProtocolError{
			Code:    "invalid_json",
			Message: "message is not valid JSON",
			Details: err,
		}
	}
	return &SpiderProtocolError{
		Code:    "invalid_json",
		Message: "message contains trailing JSON values",
		Details: trailing,
	}
}

func expectString(payload map[string]any, key string) (string, error) {
	value, ok := payload[key]
	if !ok {
		return "", &SpiderProtocolError{
			Code:    "missing_field",
			Message: fmt.Sprintf("%s must be a string", key),
			Details: payload,
		}
	}
	stringValue, ok := value.(string)
	if !ok {
		return "", &SpiderProtocolError{
			Code:    "missing_field",
			Message: fmt.Sprintf("%s must be a string", key),
			Details: payload,
		}
	}
	return stringValue, nil
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func integerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		number, err := typed.Int64()
		return number, err == nil
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		if uint64(typed) > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case uint8:
		return int64(typed), true
	case uint16:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		if typed > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case float64:
		if math.Trunc(typed) != typed {
			return 0, false
		}
		return int64(typed), true
	default:
		return 0, false
	}
}

func envelopeValue(envelope map[string]any, key string) string {
	value, _ := envelope[key].(string)
	return value
}

func isAcheronEvent(envelope map[string]any) bool {
	msgType := envelopeValue(envelope, "type")
	return msgType == "acheron.e_fs_inval" || msgType == "acheron.e_fs_inval_dir"
}

func protocolErrorFromControlEnvelope(envelope map[string]any) error {
	errorObject, _ := envelope["error"].(map[string]any)
	code := "control_error"
	message := "control request failed"
	if value, ok := errorObject["code"].(string); ok {
		code = value
	}
	if value, ok := errorObject["message"].(string); ok {
		message = value
	}
	return &SpiderProtocolError{
		Code:    code,
		Message: message,
		Details: envelope,
	}
}

func protocolErrorFromAcheronEnvelope(envelope map[string]any) error {
	errorObject, _ := envelope["error"].(map[string]any)
	message := "acheron request failed"
	if value, ok := errorObject["message"].(string); ok {
		message = value
	}
	if _, ok := integerValue(errorObject["errno"]); ok {
		return &SpiderProtocolError{
			Code:    "acheron_fs_error",
			Message: message,
			Details: envelope,
		}
	}
	code := "acheron_error"
	if value, ok := errorObject["code"].(string); ok {
		code = value
	}
	return &SpiderProtocolError{
		Code:    code,
		Message: message,
		Details: envelope,
	}
}

# Acheron Namespace Driver ABI v1

Status: active

This document defines the first executable runtime contract for node-exported
namespace services.

## Scope

ABI v1 currently standardizes `runtime.type = "native_proc"` drivers.
`native_inproc` and `wasm` remain reserved for later phases.

## Manifest Contract

Service manifests that should expose a live executable namespace must include:

- `service_id` (`string`)
- `runtime.type = "native_proc"`
- `runtime.abi = "namespace-driver-v1"` (recommended; treated as metadata)
- `runtime.executable_path` (`string`, required for namespace execution)
- `runtime.args` (`array<string>`, optional)

If `runtime.executable_path` is omitted, the service can still be published in
the catalog, but no executable namespace export is created.

## Namespace Projection

For each executable service, the node runtime creates a namespace export with:

- export name: `svc-<service_id>`
- source id/path seed: `service:<service_id>`

Projected files:

- `README.md`
- `SCHEMA.json`
- `result.json`
- `status.json`
- `last_error.txt`
- `control/invoke.json` (writable)
- `control/reset` (writable)

## Invoke Contract

Invocation is file-driven:

- write a JSON object payload to `control/invoke.json`
- runtime executes the configured process
- payload bytes are sent to process `stdin`

Operational reset:

- write any payload to `control/reset`
- runtime resets:
  - `result.json` -> `{"state":"idle"}`
  - `status.json` -> `{"state":"idle"}`
  - `last_error.txt` -> empty string

Result mapping:

- process exit code `0`
  - `result.json` = process `stdout` (or `{}` if empty)
  - `last_error.txt` = `""`
  - `status.json.state` = `"ok"`
- non-zero exit (or runtime failure)
  - `last_error.txt` = process `stderr` (or fallback error text)
  - `status.json.state` = `"error"`
  - `status.json.exit_code` populated

Writes trigger FS invalidation events on updated files.

## Process Rules

- `stdin`: full invoke JSON payload
- `stdout`: JSON result payload (recommended)
- `stderr`: human-readable diagnostic text
- max collected output follows node write-size guardrails

Drivers should treat each invocation as stateless, idempotent where possible,
and return structured JSON on `stdout`.

## Error Mapping

Node runtime maps invocation issues to FS-RPC errors:

- invalid invoke payload JSON -> `EINVAL`
- denied invocation -> `EPERM`
- process/runtime failures -> `EIO`

## Compatibility

ABI versioning is manifest-declared.
Future runtime types (`native_inproc`, `wasm`) must preserve the same
filesystem-facing control surface (`control/invoke.json`, `result.json`,
`status.json`, `last_error.txt`) for stable agent workflows.

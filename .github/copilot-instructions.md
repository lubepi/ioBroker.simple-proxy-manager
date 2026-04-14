# ioBroker.simple-proxy-manager Copilot Instructions

**Version:** 0.5.7
**Template Source:** https://github.com/DrozmotiX/ioBroker-Copilot-Instructions
**Template Metadata:** https://raw.githubusercontent.com/DrozmotiX/ioBroker-Copilot-Instructions/main/config/metadata.json

These instructions guide GitHub Copilot for this repository.

## Project Context

This repository contains the ioBroker adapter `simple-proxy-manager`.

- Purpose: HTTPS/HTTP reverse proxy management with virtual host routing
- Runtime: Node.js >= 20
- Main implementation: `main.js`
- Admin UI config: `admin/jsonConfig.json`
- Translations: `admin/i18n/{de,en,es,fr,it,nl,pl,pt,ru,uk,zh-cn}.json`

Adapter-specific scenarios and edge cases:

- Keep dual listener architecture intact: HTTP and HTTPS run in parallel, and routing decisions are host-specific.
- Preserve per-host protocol behavior:
  - backend with certificate: HTTP -> 301 to HTTPS, HTTPS serves backend
  - backend without certificate: HTTPS -> 302 to HTTP, HTTP serves backend
- Unknown hosts must stay deterministic:
  - HTTP unknown host -> 404
  - HTTPS unknown host -> TLS handshake rejection (SNI callback)
- ACME challenge forwarding must remain functional for `/.well-known/acme-challenge/*` when `acmePort` is configured.
- Treat `default` certificate as mandatory runtime prerequisite; startup should fail if default cert key/cert pair is missing.
- CIDR parsing is fail-closed: invalid CIDR config should terminate startup rather than allowing broad access.
- WebSocket upgrade handling must enforce same rules as HTTP/HTTPS requests (host validity, protocol matching, IP filtering).

## Code Quality and Style

- Follow `@iobroker/eslint-config` rules.
- Keep lint warnings at zero. Use the same strictness as CI.
- Prefer clear, short functions and explicit error handling over clever one-liners.
- Keep CommonJS style consistent with current codebase (`require`, `module.exports`).

## ioBroker Adapter Practices

- Use adapter APIs (`this.setState`, `this.getForeignObjectAsync`, `this.subscribeStates`, etc.) consistently.
- Always clean up resources in unload (`this.clearInterval`, server close handlers, event listeners).
- Keep `info.connection` semantics strict: true only when proxy listeners are actually ready.
- Use acked states (`ack: true`) for adapter-generated status values.

## Proxy and Logging Rules

- Keep HTTP and HTTPS behavior deterministic and fail-safe.
- If a certificate is configured but unavailable, fail closed for secure traffic paths.
- Treat transient backend outages as expected events (for example: `ECONNREFUSED`, `ECONNRESET`, `EPIPE`, `ETIMEDOUT`, `EHOSTUNREACH`, `ENOTFOUND`, `EAI_AGAIN`).
- Log expected transient backend restart phases on debug or warn level without flooding startup logs.
- For proxy errors with empty message, include fallback fields (`code`, `syscall`, `address`, `port`) in diagnostics.

Service-specific error mapping and retry constraints:

- Keep configuration errors as hard failures during startup (invalid hostname, target URL, CIDR, missing default cert).
- Do not add automatic retry loops in proxy request handlers; runtime recovery is event-driven via backend availability and periodic certificate reload checks.
- When a configured certificate collection is unavailable, keep affected host(s) disabled for HTTPS/WSS until recovery (no silent fallback to unrelated certificates).
- Preserve `hasReadyCertificateForHost` checks before serving HTTPS/WSS traffic.
- Keep transient backend connection errors (`isTransientBackendError`) on debug level; non-transient proxy failures remain error level.
- Keep security-relevant denials (`403`, websocket deny) controlled by `logSecurity` to avoid noisy logs in normal operation.

## Admin JSON Config and i18n

- Keep `admin/jsonConfig.json` and all `admin/i18n/*.json` files in sync.
- Any new or changed `label`/`help` text requires updates in all translation files.
- Do not leave orphaned translation keys after UI changes.
- Preserve existing key naming and structure for predictable reviews.

## Testing Expectations

- Use the official `@iobroker/testing` harness for adapter behavior tests.
- Prefer integration tests for runtime behavior over direct `main.js` loading.
- Keep package scripts aligned with repository defaults:
  - `npm run test`
  - `npm run test:package`
  - `npm run test:integration`
- Add regression tests for bug fixes whenever feasible.

## CI and Release Alignment

- Keep lint-first workflow behavior intact.
- Maintain Node.js compatibility matrix (20.x, 22.x, 24.x) as used in CI.
- Avoid introducing CI steps that bypass existing `ioBroker/testing-action-*` jobs.
- Keep user-facing change notes in `README.md` changelog section when behavior changes.

## Dependency and API Guidance

- Prefer native Node.js APIs when practical (for example `fetch` in Node 20+).
- Keep dependencies minimal and justified.
- Avoid large refactors mixed with dependency upgrades in one change.

Repository-specific rollout and migration constraints:

- Preserve CommonJS module style in `main.js` unless there is an explicit migration decision.
- Keep adapter checker compatibility (states, roles, cleanup, lifecycle behavior) aligned with current ioBroker expectations.
- Any behavior change affecting users must include a changelog entry in `README.md` under the active changelog section used by this repository (versioned entries in normal flow, `WORK IN PROGRESS` during release preparation).
- For admin config changes, update all i18n files in the same change and avoid partial translation rollouts.
- Keep CI matrix compatibility for Node.js 20.x, 22.x, and 24.x when changing syntax or dependencies.
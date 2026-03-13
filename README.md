# ioBroker.simple-proxy-manager

Simple HTTPS/HTTP reverse proxy manager for ioBroker.

## Features

- **HTTPS + HTTP in parallel** – both servers always run
- **Per-host protocol** – backend with certificate = HTTPS, without = HTTP
- **Certificate per virtual host** – ACME (Let's Encrypt), self-signed or manual collections
- **Configurable backends** via the admin interface
- **IP filtering** for internal services (CIDR-based, IPv4 + IPv6, multiple networks)
- **HTTP → HTTPS redirect** with ACME challenge forwarding
- **Automatic SSL certificate reload** on ACME renewal
- **Certificate expiry warning** in the log
- **HSTS** (Strict-Transport-Security)
- **WebSocket support** (e.g. for ioBroker Admin)
- **Dual-stack** IPv4 + IPv6
- **Change Origin** option

## Prerequisites

- **Node.js** >= 20
- **ioBroker** with js-controller >= 6.0.11
- **ACME adapter** for automatic SSL certificates (optional – also usable without certificates)
- The configured ports must be available (defaults: 80 for HTTP, 443 for HTTPS)

## Installation

Install the adapter via the ioBroker Admin UI:

1. Open the **Adapters** page in ioBroker Admin
2. Search for **simple-proxy-manager**
3. Click **Install**

## Configuration

### Tab "General"

| Setting | Default | Description |
|---|---|---|
| HTTPS Port | 443 | Port for HTTPS |
| HTTP Port | 80 | Port for HTTP – backends without a certificate are served here; with certificate → redirect to HTTPS |
| ACME Adapter Port | 0 | Internal port of the ACME adapter (0 = disabled) |
| Enable HSTS | ✓ | Strict-Transport-Security header (HTTPS only) |
| HSTS max-age | 31536000 | HSTS validity duration in seconds (1 year) |
| Check interval | 1 | How often certificates are checked (hours) |
| Expiry warning | 0 | Warn X days before expiry (0 = disabled) |
| Log security events | ✗ | Log denied access (IP filtering, WebSocket) |
| Log requests | ✗ | Log every incoming request (IP, host, URL) |

### Tab "Backends"

Each backend defines a virtual host:

| Field | Description |
|---|---|
| **Active** | Enable/disable backend |
| **Hostname** | Domain that points to this server via DNS |
| **Target URL** | Backend address (`http://IP:Port`) |
| **Certificate** | Certificate from `system.certificates`. **With certificate** = HTTPS + automatic HTTP→HTTPS redirect. **Without certificate** = HTTP only (no HTTPS for this host). |
| **Allowed Networks** | Comma-separated CIDR networks/IPs (e.g. `192.168.0.0/24, fd00::/8`). Empty = access from anywhere allowed. |
| **Change Origin** | Rewrite the Host header to the target IP |

### Example Configuration

| Hostname | Target URL | Certificate | Allowed Networks | Change Origin |
|---|---|---|---|---|
| `website.example.com` | `http://127.0.0.1:3000` | `acme` | – | ✗ |
| `iobroker.example.com` | `http://127.0.0.1:8081` | `default` (ioBroker self-signed) | `192.168.0.0/24` | ✗ |
| `host.example.com` | `http://192.168.0.1` | *(no certificate)* | `192.168.0.0/24, 10.0.0.0/8` | ✓ |

In this example:
- `website.example.com` → **HTTPS** with Let's Encrypt certificate, HTTP redirects to HTTPS
- `iobroker.example.com` → **HTTPS** with ioBroker default certificate (`default`), local network only
- `host.example.com` → **HTTP** (no certificate), local network only

## States

| State | Type | Description |
|---|---|---|
| `info.connection` | boolean | Proxy is running |
| `certificates.<name>.expires` | string | Expiry date of the certificate (per collection) |
| `certificates.<name>.daysLeft` | number | Days until expiry (per collection) |

Certificate states are created dynamically for each used certificate collection (e.g. `certificates.acme.daysLeft`, `certificates.default.expires`).

## ACME Adapter Configuration

The ACME adapter must run on a port other than 80, if the proxy runs on the default port 80.
ACME challenges are automatically forwarded by the proxy to the configured ACME port.

1. Set the ACME adapter port to **8080** (or any desired port)
2. Set the same value as the ACME adapter port in the proxy manager
3. Enter all desired domains in the ACME adapter

## Certificates

The adapter reads certificates from `system.certificates` and offers three types:

### 1. Individual Certificates by Naming Convention

These are certificates that the user can add manually through the ioBroker system settings. All key/certificate pairs stored in `system.certificates → native.certificates` can be used, provided they follow this naming convention:

| Key | Content |
|---|---|
| `{name}Private` | Private key (PEM) |
| `{name}Public` | Certificate (PEM) |
| `{name}Chained` | Full certificate chain (PEM, preferred over `Public`) |

The base name `{name}` is what appears in the dropdown and is stored in the config.

> **Example:** If ioBroker has stored the keys `myCertPrivate` and `myCertChained`,
> `myCert` will appear in the dropdown.

#### The ioBroker Default Certificate

The self-signed certificate shipped with ioBroker is stored under the names `defaultPrivate` and `defaultPublic` in `system.certificates`. It follows the same convention as any other certificate:

- Base name: **`default`**
- Appears in the dropdown as `default`
- Ideal for internal services that do not require a publicly signed certificate

### 2. ACME Collections

Let's Encrypt certificates automatically generated by the ACME adapter. They are stored in `system.certificates → native.collections` under the name assigned to the collection in the ACME adapter configuration. ACME challenges on port 80 are automatically forwarded by the proxy to the configured ACME port.

### Per-Host Protocol

The adapter decides **per backend** whether HTTPS or HTTP is used:

| Backend Certificate | HTTP Request | HTTPS Request |
|---|---|---|
| Set | 301 redirect → HTTPS | Served with SNI certificate |
| Empty | Served directly (HTTP) | 302 redirect → HTTP |

Both servers run **in parallel**. Each backend can have its own certificate source. **SNI** (Server Name Indication) automatically selects the correct certificate for the requested hostname during the TLS handshake.

Hosts with an unknown hostname are rejected at the TLS level – no fallback certificate is used.

All certificates loaded at startup are printed to the log.

## Changelog
### **WORK IN PROGRESS**

### 0.1.5 (2026-03-13)
- Fix GitHub repository checker issues (E8903, E8912)
- Migrate dependabot automerge workflow to new iobroker-bot-orga action
- Add github-actions ecosystem to dependabot config
- Add CI workflow dependency: adapter-tests now requires check-and-lint
- Add auto-merge configuration

### 0.1.4
- Add CI/CD workflows (test-and-release) and adapter tests
- Add dependabot auto-merge workflow
- Fix: use `this.setInterval`/`this.clearInterval` per ioBroker best practices
- Fix: remove redundant mocha devDependency (included in @iobroker/testing)
- Clean up README installation section

### 0.1.3
- Add ESLint with @iobroker/eslint-config, auto-fix all issues
- Add @alcalzone/release-script with all plugins
- Add .vscode/settings.json with JSON schema definitions

### 0.1.2
- Update dependencies to satisfy adapter checker requirements
- Add responsive layout (xs/lg/xl) to jsonConfig
- Add Changelog and License sections to README

### 0.1.1
- Fix crash on unknown HTTPS host (421 response instead of UNCAUGHT_EXCEPTION)
- Add i18n for all 11 ioBroker languages
- Update dependencies (@iobroker/adapter-core, @iobroker/testing)

### 0.1.0
- Initial release

## License

MIT License

Copyright (c) 2026 lubepi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

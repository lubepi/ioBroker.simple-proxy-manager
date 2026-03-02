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
- **Change Origin** option (e.g. for FritzBox)

## Prerequisites

- **Node.js** >= 18
- **ioBroker** with js-controller >= 5.0.0
- **ACME adapter** for automatic SSL certificates (optional – also usable without certificates)
- Ports 80 and 443 must be available

### Port Binding (important!)

Ports below 1024 (such as 80 and 443) require elevated privileges on Linux.

**Option 1 – setcap (recommended):**

```bash
sudo setcap 'cap_net_bind_service=+ep' $(which node)
```

> **Note:** This must be re-run after every Node.js update.

**Option 2 – Ports above 1024 + router forwarding:**

Configure the adapter to use e.g. port 8443/8080 and set up port forwarding in your router:
- Router port 443 → server port 8443
- Router port 80 → server port 8080

## Installation

### Local Installation (Development)

```bash
cd /opt/iobroker
npm install /path/to/ioBroker.simple-proxy-manager
iobroker add simple-proxy-manager
```

### Via GitHub URL

```bash
cd /opt/iobroker
iobroker url https://github.com/lubepi/ioBroker.simple-proxy-manager
```

## Configuration

### Tab "General"

| Setting | Default | Description |
|---|---|---|
| HTTPS Port | 443 | Port for HTTPS |
| HTTP Port | 80 | Port for HTTP – backends without a certificate are served here; with certificate → redirect to HTTPS |
| ACME Adapter Port | 8080 | Internal port of the ACME adapter (0 = disabled) |
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
| `info.certificateExpires` | string | Certificate expiry date |
| `info.certificateDaysLeft` | number | Days until expiry |

## ACME Adapter Configuration

The ACME adapter must run on a port other than 80, as port 80 is taken by the proxy.
ACME challenges are automatically forwarded by the proxy to the configured ACME port.

1. Set the ACME adapter port to **8080** (or any desired port)
2. Set the same value as the ACME adapter port in the proxy manager
3. Enter all desired domains in the ACME adapter

## Certificates

The adapter reads certificates from `system.certificates` and offers three types:

### 1. Individual Certificates by Naming Convention

All key/certificate pairs stored in `system.certificates → native.certificates` can be used, provided they follow this naming convention:

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

Automatically generated Let's Encrypt certificates. The collection name is assigned in the ACME adapter (e.g. `acme`). ACME challenges on port 80 are automatically forwarded by the proxy to the configured ACME port.

### 3. Manual Collections

Certificate collections from `system.certificates → native.collections` created by the web adapter or manually.

### Per-Host Protocol

The adapter decides **per backend** whether HTTPS or HTTP is used:

| Backend Certificate | HTTP Request | HTTPS Request |
|---|---|---|
| Set | 301 redirect → HTTPS | Served with SNI certificate |
| Empty | Served directly (HTTP) | 302 redirect → HTTP |

Both servers run **in parallel**. Each backend can have its own certificate source. **SNI** (Server Name Indication) automatically selects the correct certificate for the requested hostname during the TLS handshake.

Hosts with an unknown hostname are rejected at the TLS level – no fallback certificate is used.

All certificates loaded at startup are printed to the log.

## Licence

MIT License – see [LICENSE](LICENSE)

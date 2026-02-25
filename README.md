# ioBroker.simple-proxy-manager

Einfacher HTTPS/HTTP Reverse Proxy Manager für ioBroker.

## Features

- **HTTPS Reverse Proxy** mit virtuellen Hosts (SNI)
- **HTTP-only Modus** – ohne Zertifikat läuft der Proxy als reiner HTTP-Proxy
- **Zertifikat pro Virtual Host** – ACME (Let’s Encrypt), Self-Signed oder manuelle Collections
- **Konfigurierbare Backends** über die Admin-Oberfläche
- **IP-Filterung** für interne Dienste (CIDR-basiert, IPv4 + IPv6, mehrere Netzwerke)
- **HTTP → HTTPS Redirect** mit ACME-Challenge-Weiterleitung
- **Automatischer SSL-Zertifikat-Reload** bei ACME-Erneuerung
- **Zertifikats-Ablaufwarnung** im Log
- **HSTS** (Strict-Transport-Security)
- **WebSocket-Unterstützung** (z.B. für iobroker Admin)
- **Dual-Stack** IPv4 + IPv6
- **Change Origin** Option (z.B. für FritzBox)

## Voraussetzungen

- **Node.js** >= 18
- **ioBroker** mit js-controller >= 5.0.0
- **ACME-Adapter** für automatische SSL-Zertifikate (optional – auch ohne Zertifikat nutzbar)
- Ports 80 und 443 müssen verfügbar sein

### Port-Binding (wichtig!)

Ports unter 1024 (wie 80 und 443) benötigen unter Linux besondere Berechtigungen

**Option 1 – setcap (empfohlen):**

```bash
sudo setcap 'cap_net_bind_service=+ep' $(which node)
```

> **Hinweis:** Dies muss nach jedem Node.js-Update erneut ausgeführt werden.

**Option 2 – Ports über 1024 + Router-Weiterleitung:**

Konfiguriere den Adapter auf z.B. Port 8443/8080 und richte im Router eine Port-Weiterleitung ein:
- Router Port 443 → Server Port 8443
- Router Port 80 → Server Port 8080

## Installation

### Lokale Installation (Entwicklung)

```bash
cd /opt/iobroker
npm install /pfad/zu/ioBroker.simple-proxy-manager
iobroker add simple-proxy-manager
```

### Über GitHub URL

```bash
cd /opt/iobroker
iobroker url https://github.com/user/ioBroker.simple-proxy-manager
```

## Konfiguration

### Tab "Allgemein"

| Einstellung | Standard | Beschreibung |
|---|---|---|
| HTTPS Port | 443 | Port für HTTPS (nur wenn Zertifikat konfiguriert) |
| HTTP Port | 80 | HTTP-only Port (ohne Zertifikat) oder HTTP→HTTPS Redirect (mit Zertifikat, 0 = deaktiviert) |
| ACME Adapter Port | 8080 | Interner Port des ACME-Adapters |
| HSTS aktivieren | ✓ | Strict-Transport-Security Header (nur HTTPS) |
| HSTS max-age | 31536000 | HSTS Gültigkeitsdauer in Sekunden (1 Jahr) |
| Standard-Zertifikat | – | Zertifikat als Fallback. Wenn nirgends ein Zertifikat gesetzt → HTTP-only |
| Prüfintervall | 1 | Wie oft Zertifikate geprüft werden (Stunden) |
| Ablaufwarnung | 14 | Warnung X Tage vor Ablauf |
| Anfragen protokollieren | ✗ | Jede Anfrage loggen (IP, Host, URL) |

### Tab "Backends"

Jedes Backend definiert einen virtuellen Host:

| Feld | Beschreibung |
|---|---|
| **Aktiv** | Backend aktiviert/deaktiviert |
| **Hostname** | Domain, die per DNS auf diesen Server zeigt |
| **Ziel-URL** | Backend-Adresse (`http://IP:Port`) |
| **Zertifikat** | Zertifikat aus `system.certificates` – ACME-Collection, Self-Signed oder über Dropdown wählbar. Leer = Standard-Zertifikat. |
| **Erlaubte Netze** | Kommaseparierte CIDR-Netzwerke/IPs (z.B. `192.168.0.0/24, fd00::/8`). Leer = Zugriff von überall erlaubt. |
| **Change Origin** | Host-Header auf Ziel-IP umschreiben |

### Beispiel-Konfiguration

| Hostname | Ziel-URL | Zertifikat | Erlaubte Netze | Change Origin |
|---|---|---|---|---|
| `wakeup.example.de` | `http://127.0.0.1:3000` | `acme` | – | ✗ |
| `iobroker.example.de` | `http://127.0.0.1:8081` | Self-Signed | `192.168.0.0/24` | ✗ |
| `fritz.example.de` | `http://192.168.0.1` | `defaultCollection` | `192.168.0.0/24, 10.0.0.0/8` | ✓ |

## States

| State | Typ | Beschreibung |
|---|---|---|
| `info.connection` | boolean | Proxy läuft |
| `info.certificateExpires` | string | Ablaufdatum des Zertifikats |
| `info.certificateDaysLeft` | number | Tage bis zum Ablauf |

## ACME-Adapter Konfiguration

Der ACME-Adapter muss auf einem anderen Port als 80 laufen, da Port 80 vom Proxy übernommen wird.
ACME-Challenges werden automatisch vom Proxy an den konfigurierten ACME-Port weitergeleitet.

1. ACME-Adapter Port auf **8080** setzen (oder gewünschten Port)
2. Im Proxy-Manager den ACME Adapter Port auf denselben Wert setzen
3. Alle gewünschten Domains im ACME-Adapter eintragen

## Zertifikate

Der Adapter bietet drei Zertifikat-Optionen im Dropdown:

### 1. Standard (Self-Signed)
ioBrokers eingebaute Self-Signed Zertifikate (`defaultPrivate`/`defaultPublic` aus `system.certificates`). Ideal für interne Netzwerke.

### 2. ACME-Collections
Automatisch generierte Let’s Encrypt Zertifikate (der Collection-Name wird im ACME-Adapter vergeben, z.B. `acme`).

### 3. Manuelle Collections
Vom Web-Adapter oder manuell erstellte Zertifikat-Collections.

### HTTP-only Modus
Wenn weder ein Standard-Zertifikat noch ein Backend-Zertifikat konfiguriert ist, läuft der Proxy **ohne Verschlüsselung** auf dem HTTP-Port. Dies ist nur für interne/isolierte Netzwerke gedacht.

Jedes Backend kann eine eigene Zertifikat-Quelle zugewiesen bekommen. Per **SNI** (Server Name Indication) wird beim TLS-Handshake automatisch das richtige Zertifikat ausgewählt.

Alle verfügbaren Zertifikate werden beim Adapterstart im Log ausgegeben.

## Lizenz

MIT License – siehe [LICENSE](LICENSE)

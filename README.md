# ioBroker.simple-proxy-manager

Einfacher HTTPS/HTTP Reverse Proxy Manager für ioBroker.

## Features

- **HTTPS + HTTP parallel** – beide Server laufen immer
- **Per-Host Protokoll** – Backend mit Zertifikat = HTTPS, ohne = HTTP
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
| HTTPS Port | 443 | Port für HTTPS |
| HTTP Port | 80 | Port für HTTP – Backends ohne Zertifikat werden hier bedient, mit Zertifikat → Redirect auf HTTPS |
| ACME Adapter Port | 8080 | Interner Port des ACME-Adapters |
| HSTS aktivieren | ✓ | Strict-Transport-Security Header (nur HTTPS) |
| HSTS max-age | 31536000 | HSTS Gültigkeitsdauer in Sekunden (1 Jahr) |
| Standard-Zertifikat | – | Zertifikat als HTTPS-Fallback für unbekannte Hostnamen |
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
| **Zertifikat** | Zertifikat aus `system.certificates`. **Mit Zertifikat** = HTTPS + automatischer HTTP→HTTPS Redirect. **Ohne Zertifikat** = nur HTTP (kein HTTPS für diesen Host). |
| **Erlaubte Netze** | Kommaseparierte CIDR-Netzwerke/IPs (z.B. `192.168.0.0/24, fd00::/8`). Leer = Zugriff von überall erlaubt. |
| **Change Origin** | Host-Header auf Ziel-IP umschreiben |

### Beispiel-Konfiguration

| Hostname | Ziel-URL | Zertifikat | Erlaubte Netze | Change Origin |
|---|---|---|---|---|
| `wakeup.example.de` | `http://127.0.0.1:3000` | `acme` | – | ✗ |
| `iobroker.example.de` | `http://127.0.0.1:8081` | `default` (ioBroker Self-Signed) | `192.168.0.0/24` | ✗ |
| `fritz.example.de` | `http://192.168.0.1` | *(kein Zertifikat)* | `192.168.0.0/24, 10.0.0.0/8` | ✓ |

In diesem Beispiel:
- `wakeup.example.de` → **HTTPS** mit Let’s Encrypt Zertifikat, HTTP leitet auf HTTPS um
- `iobroker.example.de` → **HTTPS** mit ioBroker-Standard-Zertifikat (`default`), nur aus dem lokalen Netz
- `fritz.example.de` → **HTTP** (kein Zertifikat), nur aus dem lokalen Netz

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

Der Adapter liest Zertifikate aus `system.certificates` und bietet im Dropdown drei Arten an:

### 1. Einzelne Zertifikate nach Namenskonvention

Alle in `system.certificates → native.certificates` gespeicherten Schlüssel/Zertifikat-Paare können verwendet werden, sofern sie der folgenden Namenskonvention entsprechen:

| Schlüssel | Inhalt |
|---|---|
| `{name}Private` | Privater Schlüssel (PEM) |
| `{name}Public` | Zertifikat (PEM) |
| `{name}Chained` | Vollständige Zertifikatskette (PEM, bevorzugt gegenüber `Public`) |

Im Dropdown erscheint und wird gespeichert jeweils der Basisname `{name}`.

> **Beispiel:** Hat ioBroker die Schlüssel `myCertPrivate` und `myCertChained` gespeichert,
> erscheint `myCert` im Dropdown.

#### Das ioBroker-Standard-Zertifikat

Das von ioBroker mitgelieferte Self-Signed-Zertifikat ist unter den Namen `defaultPrivate` und `defaultPublic` in `system.certificates` gespeichert. Es folgt damit denselben Konventionen wie jedes andere Zertifikat:

- Basisname: **`default`**
- Erscheint im Dropdown als `default`
- Ideal für interne Dienste, bei denen kein öffentlich signiertes Zertifikat benötigt wird

### 2. ACME-Collections

Automatisch generierte Let's Encrypt Zertifikate. Der Collection-Name wird im ACME-Adapter vergeben (z.B. `acme`). ACME-Challenges auf Port 80 werden vom Proxy automatisch an den konfigurierten ACME-Port weitergeleitet.

### 3. Manuelle Collections

Vom Web-Adapter oder manuell angelegte Zertifikat-Collections aus `system.certificates → native.collections`.

### HTTP-only Modus

Wird keinem Backend und keinem Standard-Zertifikat eine Zertifikat-Quelle zugewiesen, startet der Adapter **ohne HTTPS-Server**. Es läuft dann nur der HTTP-Server. Sobald mindestens ein Backend ein Zertifikat hat, wird der HTTPS-Server automatisch gestartet.

### Per-Host Protokoll

Der Adapter entscheidet **pro Backend**, ob HTTPS oder HTTP verwendet wird:

| Backend-Zertifikat | HTTP-Anfrage | HTTPS-Anfrage |
|---|---|---|
| Gesetzt | 301 Redirect → HTTPS | Bedient mit SNI-Zertifikat |
| Leer | Direkt bedient (HTTP) | 302 Redirect → HTTP |

Beide Server laufen **parallel**. Jedes Backend kann eine eigene Zertifikat-Quelle erhalten. Per **SNI** (Server Name Indication) wird beim TLS-Handshake automatisch das richtige Zertifikat für den angefragten Hostnamen ausgewählt.

Alle beim Start geladenen Zertifikate werden im Log ausgegeben.
## Lizenz

MIT License – siehe [LICENSE](LICENSE)

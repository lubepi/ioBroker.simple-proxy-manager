# ioBroker.simple-proxy-manager

Einfacher HTTPS Reverse Proxy Manager für ioBroker.

## Features

- **HTTPS Reverse Proxy** mit virtuellen Hosts (SNI)
- **Zertifikat pro Virtual Host** – Auswahl aus allen verfügbaren Collections in `system.certificates` (ACME, Self-Signed, etc.)
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
- **ACME-Adapter** für automatische SSL-Zertifikate (Let's Encrypt)
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
| HTTPS Port | 443 | Port für den Reverse Proxy |
| HTTP Port | 80 | Port für HTTP→HTTPS Redirect (0 = deaktiviert) |
| ACME Adapter Port | 8080 | Interner Port des ACME-Adapters |
| HSTS aktivieren | ✓ | Strict-Transport-Security Header |
| HSTS max-age | 31536000 | HSTS Gültigkeitsdauer in Sekunden (1 Jahr) |
| Standard-Zertifikat | – | Collection-Name für Fallback (unbekannte Hostnamen) |
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
| **Zertifikat** | Name der Zertifikat-Collection aus `system.certificates` (z.B. `acme`, `defaultCollection`) |
| **Erlaubte Netze** | Kommaseparierte CIDR-Netzwerke/IPs (z.B. `192.168.0.0/24, fd00::/8`). Leer = Zugriff von überall erlaubt. |
| **Change Origin** | Host-Header auf Ziel-IP umschreiben |

### Beispiel-Konfiguration

| Hostname | Ziel-URL | Zertifikat | Erlaubte Netze | Change Origin |
|---|---|---|---|---|
| `wakeup.example.de` | `http://127.0.0.1:3000` | `acme` | – | ✗ |
| `iobroker.example.de` | `http://127.0.0.1:8081` | `acme` | `192.168.0.0/24` | ✗ |
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

Der Adapter liest alle Zertifikat-Collections aus `system.certificates`. Das beinhaltet:

- **ACME-Collections** (z.B. `acme`) – automatisch generierte Let’s Encrypt Zertifikate (der Name wird im ACME-Adapter vergeben)
- **Self-Signed / manuelle Collections** (z.B. `defaultCollection`) – vom Web-Adapter oder manuell erstellte Zertifikate

Jedes Backend kann eine eigene Collection zugewiesen bekommen. Per **SNI** (Server Name Indication) wird beim TLS-Handshake automatisch das richtige Zertifikat für den angefragten Hostnamen ausgewählt.

Alle verfügbaren Collection-Namen werden beim Adapterstart im Log ausgegeben.

## Lizenz

MIT License – siehe [LICENSE](LICENSE)

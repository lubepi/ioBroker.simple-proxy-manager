'use strict';

const utils = require('@iobroker/adapter-core');
const https = require('https');
const http = require('http');
const httpProxy = require('http-proxy');
const tls = require('tls');

class SimpleProxyManager extends utils.Adapter {
  constructor(options) {
    super({
      ...options,
      name: 'simple-proxy-manager',
    });
    this.on('ready', this.onReady.bind(this));
    this.on('message', this.onMessage.bind(this));
    this.on('unload', this.onUnload.bind(this));

    this.httpsServer = null;
    this.httpServer = null;
    this.proxy = null;
    this.certCheckInterval = null;
    this.certContexts = {};   // hostname -> tls.SecureContext
    this.certHashes = {};     // collectionName -> cert string (Änderungserkennung)
    this.backends = {};
    this.hstsHeader = null;
  }

  // ============ ADAPTER START ============

  async onReady() {
    const config = this.config;

    // Backends aus Konfiguration laden
    if (!config.backends || config.backends.length === 0) {
      this.log.warn('Keine Backends konfiguriert – Adapter wartet auf Konfiguration');
      return;
    }

    for (const entry of config.backends) {
      if (!entry.enabled || !entry.hostname || !entry.target) continue;
      // allowedNetworks: kommaseparierter String → Array
      let networks = [];
      if (entry.allowedNetworks) {
        networks = entry.allowedNetworks.split(',').map(s => s.trim()).filter(Boolean);
      }
      this.backends[entry.hostname] = {
        target: entry.target,
        allowExternal: !!entry.allowExternal,
        allowedNetworks: networks,
        changeOrigin: !!entry.changeOrigin,
        certificate: entry.certificate || '',
      };
    }

    if (Object.keys(this.backends).length === 0) {
      this.log.warn('Keine aktiven Backends konfiguriert');
      return;
    }

    // HSTS-Header vorbereiten
    if (config.enableHSTS) {
      this.hstsHeader = 'max-age=' + (config.hstsMaxAge || 31536000) + '; includeSubDomains';
    }

    // SSL-Zertifikate laden (pro Backend konfigurierbar via SNI)
    const sslOptions = await this.loadAllCertificates();
    if (!sslOptions) return;

    // Proxy starten
    this.startProxy(sslOptions);
  }

  // ============ SSL ZERTIFIKATE AUS IOBROKER ============

  /**
   * Löst eine Zertifikat-Collection aus system.certificates auf.
   * Unterstützt:
   *  - ACME-Style: key (PEM) + chain[] (PEM-Array)
   *  - Referenz-Style: key/cert verweisen auf Namen in native.certificates
   */
  resolveCertCollection(collectionName, certsObj) {
    const collections = certsObj.native.collections || {};
    const certificates = certsObj.native.certificates || {};

    if (!collections[collectionName]) return null;

    const coll = collections[collectionName];
    let key, cert;

    if (coll.chain && Array.isArray(coll.chain) && coll.chain.length > 0) {
      // ACME-Style: key ist PEM direkt, chain ist Array von PEM-Zertifikaten
      key = coll.key;
      cert = coll.chain.join('');
    } else {
      // Referenz-Style: key/cert sind Namen die auf native.certificates zeigen
      key = certificates[coll.key] || coll.key;
      cert = certificates[coll.cert] || coll.cert;
    }

    if (!key || !cert) return null;

    return {
      key,
      cert,
      tsExpires: coll.tsExpires || null,
      domains: coll.domains || [],
    };
  }

  /**
   * Lädt alle von Backends benötigten Zertifikate und erstellt pro Hostname
   * einen tls.SecureContext für SNI.
   */
  async loadAllCertificates() {
    try {
      const obj = await this.getForeignObjectAsync('system.certificates');
      if (!obj || !obj.native) {
        this.log.error('system.certificates nicht gefunden');
        return null;
      }

      // Verfügbare Collections anzeigen
      const availableCollections = Object.keys(obj.native.collections || {});
      this.log.info('Verfügbare Zertifikat-Collections: ' + availableCollections.join(', '));

      // Alle von Backends verwendeten Collection-Namen sammeln
      const usedCollections = new Set();
      for (const backend of Object.values(this.backends)) {
        if (backend.certificate) usedCollections.add(backend.certificate);
      }

      // Default-Zertifikat aus Konfiguration hinzufügen
      const defaultCertName = this.config.defaultCertificate;
      if (defaultCertName) usedCollections.add(defaultCertName);

      if (usedCollections.size === 0) {
        this.log.error('Keine Zertifikat-Collections konfiguriert – bitte in den Backend-Einstellungen eine Collection zuweisen');
        return null;
      }

      let defaultSslOptions = null;
      let minDaysLeft = Infinity;
      let earliestExpiry = null;

      // Jede Collection auflösen und SecureContexts erstellen
      for (const collName of usedCollections) {
        const resolved = this.resolveCertCollection(collName, obj);
        if (!resolved) {
          this.log.error('Zertifikat-Collection "' + collName + '" nicht gefunden oder unvollständig');
          continue;
        }

        // Cert-Inhalt für Änderungserkennung cachen
        this.certHashes[collName] = resolved.cert;

        // SecureContext für jeden Hostname erstellen der diese Collection nutzt
        const ctx = tls.createSecureContext({ key: resolved.key, cert: resolved.cert });
        for (const [hostname, backend] of Object.entries(this.backends)) {
          if (backend.certificate === collName) {
            this.certContexts[hostname] = ctx;
          }
        }

        // Default-Zertifikat: explizit konfiguriertes oder erstes verfügbares
        if (collName === defaultCertName || !defaultSslOptions) {
          defaultSslOptions = { key: resolved.key, cert: resolved.cert };
        }

        // Ablauf tracken (nur für Collections mit tsExpires, z.B. ACME)
        if (resolved.tsExpires) {
          const daysLeft = Math.floor((resolved.tsExpires - Date.now()) / (1000 * 60 * 60 * 24));
          if (daysLeft < minDaysLeft) {
            minDaysLeft = daysLeft;
            earliestExpiry = new Date(resolved.tsExpires);
          }
          this.log.info('Zertifikat "' + collName + '": Domains=' + resolved.domains.join(', ') + ', gültig bis ' + new Date(resolved.tsExpires).toLocaleDateString('de-DE'));
          if (daysLeft < (this.config.certWarnDays || 14)) {
            this.log.warn('Zertifikat "' + collName + '" läuft in ' + daysLeft + ' Tagen ab!');
          }
        } else {
          this.log.info('Zertifikat "' + collName + '" geladen (Self-Signed / kein Ablaufdatum)');
        }
      }

      // States aktualisieren (frühester Ablauf aller Zertifikate)
      if (earliestExpiry) {
        await this.setStateAsync('info.certificateExpires', earliestExpiry.toLocaleDateString('de-DE'), true);
        await this.setStateAsync('info.certificateDaysLeft', minDaysLeft, true);
      }

      if (!defaultSslOptions) {
        this.log.error('Kein gültiges Zertifikat geladen – Proxy kann nicht starten');
        return null;
      }

      return defaultSslOptions;
    } catch (e) {
      this.log.error('Fehler beim Laden der Zertifikate: ' + e.message);
      return null;
    }
  }

  /**
   * Prüft alle verwendeten Zertifikat-Collections auf Änderungen
   * und aktualisiert die SNI-Kontexte bei Bedarf.
   */
  async checkCertificateRenewal() {
    try {
      const obj = await this.getForeignObjectAsync('system.certificates');
      if (!obj || !obj.native) return;

      let changed = false;
      let minDaysLeft = Infinity;
      let earliestExpiry = null;
      let newDefault = null;

      const defaultCertName = this.config.defaultCertificate;
      const checkedCollections = new Set();

      for (const [hostname, backend] of Object.entries(this.backends)) {
        const collName = backend.certificate;
        if (!collName || checkedCollections.has(collName)) continue;
        checkedCollections.add(collName);

        const resolved = this.resolveCertCollection(collName, obj);
        if (!resolved) continue;

        // Prüfen ob sich der Cert-Inhalt geändert hat
        if (resolved.cert !== this.certHashes[collName]) {
          const ctx = tls.createSecureContext({ key: resolved.key, cert: resolved.cert });
          // Alle Hostnames aktualisieren die diese Collection nutzen
          for (const [h, b] of Object.entries(this.backends)) {
            if (b.certificate === collName) {
              this.certContexts[h] = ctx;
            }
          }
          this.certHashes[collName] = resolved.cert;
          changed = true;
          this.log.info('Zertifikat "' + collName + '" automatisch neu geladen');
        }

        // Ablauf tracken
        if (resolved.tsExpires) {
          const daysLeft = Math.floor((resolved.tsExpires - Date.now()) / (1000 * 60 * 60 * 24));
          if (daysLeft < minDaysLeft) {
            minDaysLeft = daysLeft;
            earliestExpiry = new Date(resolved.tsExpires);
          }
          if (daysLeft < (this.config.certWarnDays || 14)) {
            this.log.warn('Zertifikat "' + collName + '" läuft in ' + daysLeft + ' Tagen ab!');
          }
        }

        // Default-Cert für Server-Kontext merken
        if (collName === defaultCertName || !newDefault) {
          newDefault = resolved;
        }
      }

      // Default Server-Kontext aktualisieren wenn sich etwas geändert hat
      if (changed && newDefault && this.httpsServer) {
        this.httpsServer.setSecureContext({ key: newDefault.key, cert: newDefault.cert });
      }

      // States aktualisieren
      if (earliestExpiry) {
        await this.setStateAsync('info.certificateExpires', earliestExpiry.toLocaleDateString('de-DE'), true);
        await this.setStateAsync('info.certificateDaysLeft', minDaysLeft, true);
      }
    } catch (e) {
      this.log.error('Fehler bei Zertifikat-Prüfung: ' + e.message);
    }
  }

  // ============ IP-PARSING (CIDR) ============

  static parseIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    const bytes = parts.map(Number);
    if (bytes.some(b => isNaN(b) || b < 0 || b > 255)) return null;
    return [0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, bytes[0], bytes[1], bytes[2], bytes[3]];
  }

  static parseIPv6(ip) {
    if (ip.startsWith('::ffff:') && ip.includes('.')) {
      return SimpleProxyManager.parseIPv4(ip.substring(7));
    }
    const halves = ip.split('::');
    if (halves.length > 2) return null;
    let groups;
    if (halves.length === 2) {
      const left = halves[0] ? halves[0].split(':') : [];
      const right = halves[1] ? halves[1].split(':') : [];
      const missing = 8 - left.length - right.length;
      if (missing < 0) return null;
      groups = [...left, ...Array(missing).fill('0'), ...right];
    } else {
      groups = ip.split(':');
    }
    if (groups.length !== 8) return null;
    const bytes = [];
    for (const g of groups) {
      const val = parseInt(g, 16);
      if (isNaN(val) || val < 0 || val > 0xffff) return null;
      bytes.push((val >> 8) & 0xff, val & 0xff);
    }
    return bytes;
  }

  static parseIP(ip) {
    if (!ip) return null;
    ip = ip.trim();
    if (ip.startsWith('::ffff:') && ip.includes('.')) {
      return SimpleProxyManager.parseIPv4(ip.substring(7));
    }
    if (ip.includes(':')) return SimpleProxyManager.parseIPv6(ip);
    return SimpleProxyManager.parseIPv4(ip);
  }

  static parseCIDR(cidr) {
    cidr = cidr.trim();
    const parts = cidr.split('/');
    const ipStr = parts[0];
    const isV6 = ipStr.includes(':');
    const bytes = SimpleProxyManager.parseIP(ipStr);
    if (!bytes) return null;
    let prefixLen;
    if (parts.length === 2) {
      prefixLen = parseInt(parts[1], 10);
      if (isNaN(prefixLen)) return null;
      if (!isV6) prefixLen += 96;
    } else {
      prefixLen = 128;
    }
    if (prefixLen < 0 || prefixLen > 128) return null;
    return { bytes, prefixLen };
  }

  static ipMatchesCIDR(ipBytes, network) {
    for (let i = 0; i < 16; i++) {
      const bits = Math.min(8, Math.max(0, network.prefixLen - i * 8));
      if (bits === 0) break;
      const mask = (0xff << (8 - bits)) & 0xff;
      if ((ipBytes[i] & mask) !== (network.bytes[i] & mask)) return false;
    }
    return true;
  }

  // ============ IP-PRÜFUNG ============

  getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) return forwarded.split(',')[0].trim();

    const ip = req.socket.remoteAddress || (req.connection && req.connection.remoteAddress);

    // IPv6-mapped IPv4 Adressen konvertieren (::ffff:192.168.0.1 -> 192.168.0.1)
    if (ip && ip.startsWith('::ffff:') && ip.includes('.')) return ip.substring(7);

    return ip;
  }

  isAllowedIP(clientIP, backend) {
    if (!clientIP) return false;

    // Localhost ist immer erlaubt
    if (clientIP === '127.0.0.1' || clientIP === '::1') return true;

    const networks = backend.allowedNetworks;
    if (!networks || networks.length === 0) return false;

    const ipBytes = SimpleProxyManager.parseIP(clientIP);
    if (!ipBytes) return false;

    for (const cidr of networks) {
      const network = SimpleProxyManager.parseCIDR(cidr);
      if (!network) continue;
      if (SimpleProxyManager.ipMatchesCIDR(ipBytes, network)) return true;
    }
    return false;
  }

  // ============ REQUEST HANDLER ============

  handleRequest(req, res) {
    const host = (req.headers.host || '').split(':')[0];
    const clientIP = this.getClientIP(req);
    const backend = this.backends[host];

    if (this.config.logRequests) {
      this.log.info(clientIP + ' -> ' + host + req.url);
    }

    // Unbekannter Host
    if (!backend) {
      this.log.debug('Unbekannter Host: ' + host);
      const headers = { 'Content-Type': 'text/html; charset=utf-8' };
      if (this.hstsHeader) headers['Strict-Transport-Security'] = this.hstsHeader;
      res.writeHead(404, headers);
      res.end('<h1>404 Not Found</h1><p>Unbekannte Domain.</p>');
      return;
    }

    // IP-Filterung für interne Dienste
    if (!backend.allowExternal) {
      if (!this.isAllowedIP(clientIP, backend)) {
        this.log.warn('Zugriff verweigert für ' + clientIP + ' auf ' + host);
        const headers = { 'Content-Type': 'text/html; charset=utf-8' };
        if (this.hstsHeader) headers['Strict-Transport-Security'] = this.hstsHeader;
        res.writeHead(403, headers);
        res.end('<h1>403 Forbidden</h1><p>Zugriff nur aus dem lokalen Netzwerk erlaubt.</p>');
        return;
      }
    }

    // Request an Backend weiterleiten
    this.proxy.web(req, res, {
      target: backend.target,
      changeOrigin: backend.changeOrigin,
    });
  }

  handleUpgrade(req, socket, head) {
    const host = (req.headers.host || '').split(':')[0];
    const clientIP = this.getClientIP(req);
    const backend = this.backends[host];

    if (!backend) {
      socket.destroy();
      return;
    }

    // IP-Filterung auch für WebSockets
    if (!backend.allowExternal) {
      if (!this.isAllowedIP(clientIP, backend)) {
        this.log.warn('WebSocket-Zugriff verweigert für ' + clientIP);
        socket.destroy();
        return;
      }
    }

    this.proxy.ws(req, socket, head, {
      target: backend.target,
      changeOrigin: backend.changeOrigin,
    });
  }

  // ============ PROXY STARTEN ============

  startProxy(sslOptions) {
    const config = this.config;

    // Proxy-Server erstellen
    this.proxy = httpProxy.createProxyServer({
      xfwd: true,         // X-Forwarded-* Headers hinzufügen
      ws: true,            // WebSocket-Unterstützung
      proxyTimeout: 30000, // 30s Backend-Timeout
      timeout: 30000,      // 30s Socket-Timeout
    });

    // Fehlerbehandlung für Proxy
    this.proxy.on('error', (err, req, res) => {
      this.log.error('Proxy-Fehler: ' + err.message);
      if (res && res.writeHead) {
        const headers = { 'Content-Type': 'text/html; charset=utf-8' };
        if (this.hstsHeader) headers['Strict-Transport-Security'] = this.hstsHeader;
        res.writeHead(502, headers);
        res.end('<h1>502 Bad Gateway</h1><p>Backend nicht erreichbar.</p>');
      }
    });

    // HSTS-Header für alle Proxy-Antworten
    if (this.hstsHeader) {
      this.proxy.on('proxyRes', (proxyRes) => {
        proxyRes.headers['strict-transport-security'] = this.hstsHeader;
      });
    }

    // HTTPS-Server mit SNI (Server Name Indication) für per-Host Zertifikate
    this.httpsServer = https.createServer({
      ...sslOptions,
      SNICallback: (servername, cb) => {
        const ctx = this.certContexts[servername];
        cb(null, ctx || null); // null = Default-Zertifikat verwenden
      },
    }, (req, res) => {
      this.handleRequest(req, res);
    });

    // WebSocket-Upgrade Handler
    this.httpsServer.on('upgrade', (req, socket, head) => {
      this.handleUpgrade(req, socket, head);
    });

    // HTTPS-Server starten (Dual-Stack: IPv4 und IPv6)
    const httpsPort = config.httpsPort || 443;
    this.httpsServer.listen(httpsPort, '::', () => {
      this.log.info('HTTPS Reverse Proxy läuft auf Port ' + httpsPort + ' (IPv4 + IPv6)');
      this.log.info('Konfigurierte Backends:');
      for (const [host, cfg] of Object.entries(this.backends)) {
        this.log.info('  ' + host + ' -> ' + cfg.target + ' [cert: ' + (cfg.certificate || 'default') + ']' + (cfg.allowExternal ? ' (extern)' : ' (lokal: ' + cfg.allowedNetworks.join(', ') + ')'));
      }
      this.setState('info.connection', true, true);
    });

    this.httpsServer.on('error', (err) => {
      this.log.error('HTTPS-Server Fehler: ' + err.message);
      if (err.code === 'EADDRINUSE') {
        this.log.error('Port ' + httpsPort + ' wird bereits verwendet!');
      } else if (err.code === 'EACCES') {
        this.log.error('Keine Berechtigung für Port ' + httpsPort + ' – siehe README für setcap');
      }
      this.setState('info.connection', false, true);
    });

    // HTTP -> HTTPS Redirect
    const httpPort = config.httpPort;
    if (httpPort && httpPort > 0) {
      const acmePort = config.acmePort || 8080;

      this.httpServer = http.createServer((req, res) => {
        // ACME-Challenge an den ACME-Adapter weiterleiten
        if (req.url.startsWith('/.well-known/acme-challenge/')) {
          this.proxy.web(req, res, { target: 'http://127.0.0.1:' + acmePort });
          return;
        }
        // Alles andere → HTTPS-Redirect
        const host = (req.headers.host || '').split(':')[0];
        res.writeHead(301, { Location: 'https://' + host + req.url });
        res.end();
      });

      this.httpServer.listen(httpPort, '::', () => {
        this.log.info('HTTP->HTTPS Redirect aktiv auf Port ' + httpPort + ' (IPv4 + IPv6)');
      });

      this.httpServer.on('error', (err) => {
        this.log.error('HTTP-Server Fehler: ' + err.message);
        if (err.code === 'EADDRINUSE') {
          this.log.error('Port ' + httpPort + ' wird bereits verwendet!');
        } else if (err.code === 'EACCES') {
          this.log.error('Keine Berechtigung für Port ' + httpPort + ' – siehe README für setcap');
        }
      });
    }

    // Zertifikat-Auto-Reload
    const checkIntervalMs = (config.certCheckHours || 1) * 3600000;
    this.certCheckInterval = setInterval(() => {
      this.checkCertificateRenewal();
    }, checkIntervalMs);

    this.log.info('Zertifikat-Prüfintervall: alle ' + (config.certCheckHours || 1) + ' Stunde(n)');
  }

  // ============ MESSAGE HANDLER (Admin UI) ============

  /**
   * Wird von der Admin-Oberfläche aufgerufen (selectSendTo).
   * Liefert die verfügbaren Zertifikat-Collections aus system.certificates.
   */
  async onMessage(obj) {
    if (!obj || !obj.command) return;

    if (obj.command === 'getCertificateCollections') {
      try {
        const certsObj = await this.getForeignObjectAsync('system.certificates');
        const collections = certsObj && certsObj.native && certsObj.native.collections
          ? Object.keys(certsObj.native.collections)
          : [];

        const result = collections.map(name => ({ value: name, label: name }));

        if (obj.callback) {
          this.sendTo(obj.from, obj.command, result, obj.callback);
        }
      } catch (e) {
        this.log.error('Fehler beim Abrufen der Zertifikat-Collections: ' + e.message);
        if (obj.callback) {
          this.sendTo(obj.from, obj.command, [], obj.callback);
        }
      }
    }
  }

  // ============ ADAPTER STOP ============

  onUnload(callback) {
    try {
      this.log.info('Reverse Proxy wird gestoppt...');

      if (this.certCheckInterval) {
        clearInterval(this.certCheckInterval);
        this.certCheckInterval = null;
      }

      if (this.httpsServer) {
        this.httpsServer.close();
      }

      if (this.httpServer) {
        this.httpServer.close();
      }

      if (this.proxy) {
        this.proxy.close();
      }

      this.setState('info.connection', false, true);
    } catch (e) {
      // Fehler beim Cleanup ignorieren
    }
    callback();
  }
}

// Adapter-Export
if (require.main !== module) {
  module.exports = (options) => new SimpleProxyManager(options);
} else {
  (() => new SimpleProxyManager())();
}

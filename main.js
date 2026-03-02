'use strict';

const utils = require('@iobroker/adapter-core');
const https = require('https');
const http = require('http');
const httpProxy = require('http-proxy');
const tls = require('tls');
const crypto = require('crypto');

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
    this.certHashes = {};     // collectionName -> cert string (change detection)
    this.backends = {};
    this.hstsHeader = null;
  }

  // ============ ADAPTER STARTUP ============

  async onReady() {
    const config = this.config;

    // Load backends from configuration
    if (!config.backends || config.backends.length === 0) {
      this.log.warn('No backends configured – adapter waiting for configuration');
      return;
    }

    for (const entry of config.backends) {
      if (!entry.enabled) continue;

      // Hostname and target URL are required fields
      if (!entry.hostname) {
        this.log.error('Configuration error: A backend has no hostname – please check the configuration.');
        this.terminate('Invalid configuration: hostname missing');
        return;
      }

      // Validate hostname (RFC 1123)
      if (!SimpleProxyManager.isValidHostname(entry.hostname)) {
        this.log.error('Configuration error: Invalid hostname "' + entry.hostname + '".');
        this.log.error('Allowed: letters, digits, hyphens and dots. No port suffix, max. 253 characters.');
        this.terminate('Invalid configuration: hostname "' + entry.hostname + '"');
        return;
      }
      if (!entry.target) {
        this.log.error('Configuration error: Backend "' + entry.hostname + '" has no target (target URL missing).');
        this.terminate('Invalid configuration: target URL missing for ' + entry.hostname);
        return;
      }

      // Validate target URL
      try {
        new URL(entry.target);
      } catch (_) {
        this.log.error('Configuration error: Invalid target URL for "' + entry.hostname + '": ' + entry.target);
        this.terminate('Invalid configuration: target URL for ' + entry.hostname);
        return;
      }

      // allowedNetworks: comma-separated string → array
      let networks = [];
      if (entry.allowedNetworks) {
        networks = entry.allowedNetworks.split(',').map(s => s.trim()).filter(Boolean);
      }

      // Parse CIDR networks – invalid entries terminate the adapter
      const parsedNetworks = [];
      for (const cidr of networks) {
        const parsed = SimpleProxyManager.parseCIDR(cidr);
        if (parsed === null) {
          this.log.error('Configuration error: Invalid CIDR entry "' + cidr + '" for backend "' + entry.hostname + '".');
          this.log.error('Without valid IP filtering all IPs would be allowed – adapter is stopping.');
          this.terminate('Invalid configuration: CIDR "' + cidr + '" for ' + entry.hostname);
          return;
        }
        parsedNetworks.push(parsed);
      }

      this.backends[entry.hostname.toLowerCase()] = {
        target: entry.target,
        allowedNetworks: networks,
        parsedNetworks: parsedNetworks,
        changeOrigin: !!entry.changeOrigin,
        certificate: entry.certificate || '',
      };
    }

    if (Object.keys(this.backends).length === 0) {
      this.log.warn('No active backends configured');
      return;
    }

    // Prepare HSTS header (only relevant for HTTPS backends)
    if (config.enableHSTS) {
      this.hstsHeader = 'max-age=' + (config.hstsMaxAge || 31536000) + '; includeSubDomains';
    }

    // Check ioBroker default certificate (mandatory prerequisite)
    const certsObj = await this.getForeignObjectAsync('system.certificates');
    const sysCerts = (certsObj && certsObj.native && certsObj.native.certificates) || {};
    if (!sysCerts.defaultPrivate || !(sysCerts.defaultPublic || sysCerts.defaultChained)) {
      this.log.error('=== ioBroker default certificate missing! ===');
      this.log.error('The adapter requires the ioBroker default certificate (defaultPrivate + defaultPublic).');
      this.log.error('Please create it with: iobroker cert create');
      this.log.error('Adapter is stopping.');
      if (typeof this.terminate === 'function') {
        this.terminate('ioBroker default certificate missing');
      }
      return;
    }

    // Load SSL certificates
    const sslOptions = await this.loadAllCertificates();
    if (sslOptions === null) return;

    // Start proxy (HTTP + HTTPS)
    this.startProxy(sslOptions);
  }

  // ============ SSL CERTIFICATES FROM IOBROKER ============

  /**
   * Resolves a certificate source from system.certificates.
   * Supports:
   *  - Named certificates following the convention: {baseName}Private (key),
   *    {baseName}Chained or {baseName}Public (cert) – checked first.
   *    Also applies to the ioBroker default certificate (base name: "default")
   *  - ACME-style collections: key (PEM) + chain[] (PEM array)
   *  - Reference-style collections: key/cert point to names in native.certificates
   */
  resolveCertCollection(collectionName, certsObj) {
    const collections = certsObj.native.collections || {};
    const certificates = certsObj.native.certificates || {};

    // Named certificates: {baseName}Private / {baseName}Chained / {baseName}Public
    // Also applies to the ioBroker default certificate (base name: "default")
    const namedKey = certificates[collectionName + 'Private'];
    const namedCert = certificates[collectionName + 'Chained'] || certificates[collectionName + 'Public'];
    if (namedKey && namedCert) {
      return { key: namedKey, cert: namedCert, tsExpires: null, domains: [] };
    }

    if (!collections[collectionName]) return null;

    const coll = collections[collectionName];
    let key, cert;

    if (coll.chain && Array.isArray(coll.chain) && coll.chain.length > 0) {
      // ACME-style: key is PEM directly, chain is array of PEM certificates
      key = coll.key;
      cert = coll.chain.join('');
    } else {
      // Reference-style: key/cert are names pointing to native.certificates
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
   * Loads all certificates required by backends and creates a
   * tls.SecureContext per hostname for SNI.
   */
  /**
   * Loads all certificates required by the configured backends plus the
   * ioBroker default certificate. Creates TLS SecureContexts for SNI,
   * removes stale per-certificate states from previous configurations,
   * and writes fresh expiry states for each loaded certificate.
   * Returns the SSL options for the default HTTPS server, or null on failure.
   */
  async loadAllCertificates() {
    try {
      const obj = await this.getForeignObjectAsync('system.certificates');
      if (!obj || !obj.native) {
        this.log.error('system.certificates not found');
        return null;
      }

      // Log available ACME/named collections from system.certificates
      const availableCollections = Object.keys(obj.native.collections || {});
      this.log.info('Available certificate collections: ' + availableCollections.join(', '));

      // Collect all collection names used by backends
      const usedCollections = new Set();
      for (const backend of Object.values(this.backends)) {
        if (backend.certificate) usedCollections.add(backend.certificate);
      }

      // ioBroker default certificate (always "default")
      const defaultCertName = 'default';
      usedCollections.add(defaultCertName);

      // Remove states for certificates no longer assigned to any backend
      const existingChannels = await this.getChannelsOfAsync('certificates');
      for (const channel of (existingChannels || [])) {
        const certName = channel._id.split('.').pop();
        if (!usedCollections.has(certName)) {
          await this.delObjectAsync('certificates.' + certName + '.expires');
          await this.delObjectAsync('certificates.' + certName + '.daysLeft');
          await this.delObjectAsync('certificates.' + certName);
          this.log.info('Removed stale certificate states for "' + certName + '"');
        }
      }

      let defaultSslOptions = null;

      // Resolve each collection and create SecureContexts
      for (const collName of usedCollections) {
        const resolved = this.resolveCertCollection(collName, obj);
        if (!resolved) {
          this.log.error('Certificate collection "' + collName + '" not found or incomplete');
          continue;
        }

        // Cache cert content for change detection
        this.certHashes[collName] = resolved.cert;

        // Create SecureContext for every hostname that uses this collection
        const ctx = tls.createSecureContext({ key: resolved.key, cert: resolved.cert });
        for (const [hostname, backend] of Object.entries(this.backends)) {
          if (backend.certificate === collName) {
            this.certContexts[hostname] = ctx;
          }
        }

        // Default certificate for HTTPS server
        if (collName === defaultCertName || !defaultSslOptions) {
          defaultSslOptions = { key: resolved.key, cert: resolved.cert };
        }

        // Track expiry and create per-certificate states
        await this.ensureCertStates(collName);
        const expiryDate = SimpleProxyManager.getExpiryFromPem(resolved.cert);
        if (expiryDate && !isNaN(expiryDate.getTime())) {
          const daysLeft = Math.floor((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
          await this.setStateAsync('certificates.' + collName + '.expires', expiryDate.toLocaleDateString('en-GB'), true);
          await this.setStateAsync('certificates.' + collName + '.daysLeft', daysLeft, true);
          this.log.info('Certificate "' + collName + '": valid until ' + expiryDate.toLocaleDateString('en-GB') + ' (' + daysLeft + ' days)');
          if (this.config.certWarnDays > 0 && daysLeft < this.config.certWarnDays) {
            this.log.warn('Certificate "' + collName + '" expires in ' + daysLeft + ' days!');
          }
        } else {
          await this.setStateAsync('certificates.' + collName + '.expires', '', true);
          await this.setStateAsync('certificates.' + collName + '.daysLeft', 0, true);
          this.log.info('Certificate "' + collName + '" loaded (expiry date unknown)');
        }
      }

      if (!defaultSslOptions) {
        this.log.error('All configured certificate collections failed to load – HTTPS server cannot start');
        return null;
      }

      return defaultSslOptions;
    } catch (e) {
      this.log.error('Error loading certificates: ' + e.message);
      return null;
    }
  }

  /**
   * Periodically checks all active certificates for content changes and
   * refreshes SNI contexts + expiry states. Called on the certCheckHours
   * interval. Covers the default certificate and all backend-assigned certs.
   */
  async checkCertificateRenewal() {
    try {
      const obj = await this.getForeignObjectAsync('system.certificates');
      if (!obj || !obj.native) return;

      let changed = false;
      let newDefault = null;

      const defaultCertName = 'default';
      const usedCertNames = new Set();

      // Always check default certificate
      usedCertNames.add(defaultCertName);
      for (const backend of Object.values(this.backends)) {
        if (backend.certificate) usedCertNames.add(backend.certificate);
      }

      for (const collName of usedCertNames) {

        const resolved = this.resolveCertCollection(collName, obj);
        if (!resolved) continue;

        // Check whether cert content has changed
        if (resolved.cert !== this.certHashes[collName]) {
          const ctx = tls.createSecureContext({ key: resolved.key, cert: resolved.cert });
          // Update all hostnames that use this collection
          for (const [h, b] of Object.entries(this.backends)) {
            if (b.certificate === collName) {
              this.certContexts[h] = ctx;
            }
          }
          this.certHashes[collName] = resolved.cert;
          changed = true;
          this.log.info('Certificate "' + collName + '" automatically reloaded');
        }

        // Update per-certificate states
        const expiryDate = SimpleProxyManager.getExpiryFromPem(resolved.cert);
        if (expiryDate && !isNaN(expiryDate.getTime())) {
          const daysLeft = Math.floor((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
          await this.setStateAsync('certificates.' + collName + '.expires', expiryDate.toLocaleDateString('en-GB'), true);
          await this.setStateAsync('certificates.' + collName + '.daysLeft', daysLeft, true);
          if (this.config.certWarnDays > 0 && daysLeft < this.config.certWarnDays) {
            this.log.warn('Certificate "' + collName + '" expires in ' + daysLeft + ' days!');
          }
        }

        // Track default cert – needed to update the server's base SecureContext
        if (collName === defaultCertName || !newDefault) {
          newDefault = resolved;
        }
      }

      // Update default server context if anything changed
      if (changed && newDefault && this.httpsServer) {
        this.httpsServer.setSecureContext({ key: newDefault.key, cert: newDefault.cert });
      }
    } catch (e) {
      this.log.error('Error checking certificates: ' + e.message);
    }
  }

  // ============ HOSTNAME VALIDATION ============

  /**
   * Checks whether a hostname is valid according to RFC 1123.
   * Allowed: a-z, A-Z, 0-9, hyphens, dots.
   * No label may start or end with a hyphen.
   * Max. 253 characters total, max. 63 characters per label.
   * No port suffix allowed.
   */
  static isValidHostname(hostname) {
    if (!hostname || typeof hostname !== 'string') return false;
    if (hostname.includes(':')) return false; // no port allowed
    if (hostname.length > 253) return false;
    const labels = hostname.split('.');
    return labels.every(label =>
      label.length > 0 &&
      label.length <= 63 &&
      /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label)
    );
  }

  // ============ PER-CERTIFICATE STATE OBJECTS ============

  /**
   * Extracts the expiry date from a PEM certificate string.
   * Returns a Date object, or null if parsing fails.
   * Uses Node.js crypto.X509Certificate (available since Node 15).
   */
  static getExpiryFromPem(certPem) {
    try {
      const x509 = new crypto.X509Certificate(certPem);
      return new Date(x509.validTo);
    } catch (_) {
      return null;
    }
  }

  /**
   * Creates the dynamic state objects for a certificate collection
   * under certificates.<name>.expires and certificates.<name>.daysLeft.
   * Uses setObjectNotExistsAsync so existing objects are not overwritten.
   */
  async ensureCertStates(collName) {
    await this.setObjectNotExistsAsync('certificates.' + collName, {
      type: 'channel',
      common: { name: 'Certificate: ' + collName },
      native: {},
    });
    await this.setObjectNotExistsAsync('certificates.' + collName + '.expires', {
      type: 'state',
      common: {
        role: 'text',
        name: 'Expiry date',
        type: 'string',
        read: true,
        write: false,
        def: '',
      },
      native: {},
    });
    await this.setObjectNotExistsAsync('certificates.' + collName + '.daysLeft', {
      type: 'state',
      common: {
        role: 'value',
        name: 'Days until expiry',
        type: 'number',
        read: true,
        write: false,
        unit: 'days',
        def: 0,
      },
      native: {},
    });
  }

  // ============ IP PARSING (CIDR) ============

  static parseIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    const bytes = parts.map(Number);
    if (bytes.some(b => isNaN(b) || b < 0 || b > 255)) return null;
    // Return as 16-byte IPv6-mapped IPv4 address (::ffff:x.x.x.x)
    // so all IP comparisons can be done uniformly in 128-bit space.
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
      // IPv4 prefixes are shifted by 96 bits (128 − 32) to match
      // the IPv6-mapped IPv4 representation used internally.
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

  // ============ IP FILTERING ============

  /**
   * Determines the real client IP from the socket.
   * X-Forwarded-For is NOT trusted (spoofing protection).
   * The proxy uses xfwd:true and adds the header correctly for backends.
   */
  getClientIP(req) {
    const ip = req.socket.remoteAddress;
    // Convert IPv6-mapped IPv4 addresses (::ffff:192.168.0.1 -> 192.168.0.1)
    if (ip && ip.startsWith('::ffff:') && ip.includes('.')) return ip.substring(7);
    return ip;
  }

  /**
   * Checks whether a client IP is allowed to access a backend.
   * Returns true if no networks are configured (open access),
   * if the client is localhost, or if the IP matches one of the
   * configured CIDR ranges.
   */
  isAllowedIP(clientIP, backend) {
    if (!clientIP) return false;

    const networks = backend.parsedNetworks;
    // No networks configured = all IPs allowed
    if (!networks || networks.length === 0) return true;

    // Localhost is always allowed
    if (clientIP === '127.0.0.1' || clientIP === '::1') return true;

    const ipBytes = SimpleProxyManager.parseIP(clientIP);
    if (!ipBytes) return false;

    for (const network of networks) {
      if (SimpleProxyManager.ipMatchesCIDR(ipBytes, network)) return true;
    }
    return false;
  }

  // ============ REQUEST HANDLERS ============

  /**
   * Removes incoming X-Forwarded-* headers to prevent spoofing.
   * http-proxy (xfwd:true) then re-adds them with correct values from the socket.
   */
  stripForwardedHeaders(req) {
    delete req.headers['x-forwarded-for'];
    delete req.headers['x-forwarded-proto'];
    delete req.headers['x-forwarded-host'];
    delete req.headers['x-forwarded-port'];
  }

  /**
   * HTTPS request handler: serves only backends that have a certificate.
   * Backends without a certificate receive an HTTP redirect.
   */
  handleRequest(req, res) {
    this.stripForwardedHeaders(req);
    const host = (req.headers.host || '').split(':')[0].toLowerCase();
    const clientIP = this.getClientIP(req);
    const backend = this.backends[host];

    if (this.config.logRequests) {
      this.log.info(clientIP + ' -> HTTPS ' + host + req.url);
    }

    // Backend without certificate → only reachable via HTTP
    // (unknown hosts are already rejected at TLS level in SNICallback)
    if (!backend.certificate) {
      const httpPort = this.config.httpPort || 80;
      const portSuffix = httpPort === 80 ? '' : ':' + httpPort;
      res.writeHead(302, { Location: 'http://' + host + portSuffix + req.url });
      res.end();
      return;
    }

    // IP filtering
    if (!this.isAllowedIP(clientIP, backend)) {
      if (this.config.logSecurity) this.log.warn('Access denied for ' + clientIP + ' on ' + host);
      const headers = { 'Content-Type': 'text/html; charset=utf-8' };
      if (this.hstsHeader) headers['Strict-Transport-Security'] = this.hstsHeader;
      res.writeHead(403, headers);
      res.end('<h1>403 Forbidden</h1>');
      return;
    }

    // HSTS only for HTTPS backends
    if (this.hstsHeader) {
      res.setHeader('Strict-Transport-Security', this.hstsHeader);
    }

    // Forward request to backend
    this.proxy.web(req, res, {
      target: backend.target,
      changeOrigin: backend.changeOrigin,
    });
  }

  /**
   * HTTP request handler: serves backends without a certificate directly.
   * Backends with a certificate are redirected to HTTPS.
   * ACME challenges are always forwarded.
   */
  handleHttpRequest(req, res) {
    this.stripForwardedHeaders(req);
    // Forward ACME challenge (only when acmePort is configured)
    if (this.config.acmePort && req.url.startsWith('/.well-known/acme-challenge/')) {
      this.proxy.web(req, res, { target: 'http://127.0.0.1:' + this.config.acmePort });
      return;
    }

    const host = (req.headers.host || '').split(':')[0].toLowerCase();
    const clientIP = this.getClientIP(req);
    const backend = this.backends[host];

    if (this.config.logRequests) {
      this.log.info(clientIP + ' -> HTTP ' + host + req.url);
    }

    // Unknown host
    if (!backend) {
      this.log.debug('Unknown host (HTTP): ' + host);
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<h1>404 Not Found</h1>');
      return;
    }

    // Backend with certificate → redirect to HTTPS
    if (backend.certificate) {
      const httpsPort = this.config.httpsPort || 443;
      const portSuffix = httpsPort === 443 ? '' : ':' + httpsPort;
      res.writeHead(301, { Location: 'https://' + host + portSuffix + req.url });
      res.end();
      return;
    }

    // IP filtering
    if (!this.isAllowedIP(clientIP, backend)) {
      if (this.config.logSecurity) this.log.warn('Access denied for ' + clientIP + ' on ' + host + ' (HTTP)');
      res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<h1>403 Forbidden</h1>');
      return;
    }

    // Forward request to backend (HTTP)
    this.proxy.web(req, res, {
      target: backend.target,
      changeOrigin: backend.changeOrigin,
    });
  }

  /**
   * WebSocket upgrade handler for both HTTPS (WSS) and HTTP (WS).
   * Enforces IP filtering and protocol/certificate consistency:
   * WSS upgrades are only forwarded for backends with a certificate,
   * WS upgrades only for backends without.
   */
  handleUpgrade(req, socket, head) {
    this.stripForwardedHeaders(req);
    const host = (req.headers.host || '').split(':')[0].toLowerCase();
    const clientIP = this.getClientIP(req);
    const backend = this.backends[host];
    const isHttps = req.socket.encrypted;

    if (this.config.logRequests) {
      this.log.info(clientIP + ' -> WS' + (isHttps ? 'S' : '') + ' ' + host + req.url);
    }

    if (!backend) {
      socket.destroy();
      return;
    }

    // HTTPS upgrade only for backends with certificate, HTTP upgrade only for those without
    if (isHttps && !backend.certificate) {
      socket.destroy();
      return;
    }
    if (!isHttps && backend.certificate) {
      socket.destroy();
      return;
    }

    // IP filtering for WebSockets as well
    if (!this.isAllowedIP(clientIP, backend)) {
      if (this.config.logSecurity) this.log.warn('WebSocket access denied for ' + clientIP);
      socket.destroy();
      return;
    }

    this.proxy.ws(req, socket, head, {
      target: backend.target,
      changeOrigin: backend.changeOrigin,
    });
  }

  // ============ PROXY STARTUP ============

  startProxy(sslOptions) {
    const config = this.config;

    // Create proxy server
    this.proxy = httpProxy.createProxyServer({
      xfwd: true,         // add X-Forwarded-* headers
      ws: true,            // WebSocket support
      proxyTimeout: 30000, // 30s backend timeout
      timeout: 30000,      // 30s socket timeout
    });

    // Error handling for proxy (res can be a socket during WebSocket upgrades)
    this.proxy.on('error', (err, req, res) => {
      this.log.error('Proxy error: ' + err.message);
      if (res && typeof res.writeHead === 'function' && !res.headersSent) {
        const headers = { 'Content-Type': 'text/html; charset=utf-8' };
        if (this.hstsHeader) headers['Strict-Transport-Security'] = this.hstsHeader;
        res.writeHead(502, headers);
        res.end('<h1>502 Bad Gateway</h1>');
      } else if (res && typeof res.destroy === 'function') {
        // WebSocket upgrade: res is a net.Socket
        res.destroy();
      }
    });

    // HSTS header for all proxy responses (HTTPS only)
    if (this.hstsHeader) {
      this.proxy.on('proxyRes', (proxyRes, req) => {
        // Only set HSTS for encrypted connections
        if (req.socket.encrypted) {
          proxyRes.headers['strict-transport-security'] = this.hstsHeader;
        }
      });
    }

    // ---- HTTPS server (always on, default certificate is mandatory) ----
    this.httpsServer = https.createServer({
      ...sslOptions,
      SNICallback: (servername, cb) => {
        const name = (servername || '').toLowerCase();
        const ctx = this.certContexts[name];
        if (ctx) {
          // Known host with its own certificate
          cb(null, ctx);
        } else if (this.backends[name]) {
          // Backend without own certificate → default context for HTTP redirect
          cb(null, null);
        } else {
          // Unknown hostname → reject TLS handshake
          this.log.debug('TLS handshake rejected for unknown host: ' + servername);
          cb(new Error('Unknown hostname'));
        }
      },
    }, (req, res) => {
      this.handleRequest(req, res);
    });

    this.httpsServer.on('upgrade', (req, socket, head) => {
      this.handleUpgrade(req, socket, head);
    });

    const httpsPort = config.httpsPort || 443;
    this.httpsServer.listen(httpsPort, '::', () => {
      this.log.info('HTTPS reverse proxy running on port ' + httpsPort + ' (IPv4 + IPv6)');
      this.setState('info.connection', true, true);
    });

    this.httpsServer.on('error', (err) => {
      this.log.error('HTTPS server error: ' + err.message);
      if (err.code === 'EADDRINUSE') {
        this.log.error('Port ' + httpsPort + ' is already in use!');
      } else if (err.code === 'EACCES') {
        this.log.error('No permission for port ' + httpsPort + ' – elevated privileges required for ports < 1024');
      }
      this.setState('info.connection', false, true);
    });

    // ---- HTTP server (always on) ----
    const httpPort = config.httpPort || 80;
    this.httpServer = http.createServer((req, res) => {
      this.handleHttpRequest(req, res);
    });

    this.httpServer.on('upgrade', (req, socket, head) => {
      this.handleUpgrade(req, socket, head);
    });

    this.httpServer.listen(httpPort, '::', () => {
      this.log.info('HTTP server running on port ' + httpPort + ' (IPv4 + IPv6)');
    });

    this.httpServer.on('error', (err) => {
      this.log.error('HTTP server error: ' + err.message);
      if (err.code === 'EADDRINUSE') {
        this.log.error('Port ' + httpPort + ' is already in use!');
      } else if (err.code === 'EACCES') {
        this.log.error('No permission for port ' + httpPort + ' – elevated privileges required for ports < 1024');
      }
    });

    // Log backend overview
    this.log.info('Configured backends:');
    for (const [host, cfg] of Object.entries(this.backends)) {
      const proto = cfg.certificate ? 'HTTPS' : 'HTTP';
      const certInfo = cfg.certificate ? ' [cert: ' + cfg.certificate + ']' : '';
      const netInfo = cfg.allowedNetworks.length > 0 ? ' (networks: ' + cfg.allowedNetworks.join(', ') + ')' : ' (all IPs)';
      this.log.info('  ' + host + ' -> ' + cfg.target + ' [' + proto + ']' + certInfo + netInfo);
    }

    // Certificate auto-reload
    const checkIntervalMs = (config.certCheckHours || 1) * 3600000;
    this.certCheckInterval = setInterval(() => {
      this.checkCertificateRenewal();
    }, checkIntervalMs);

    this.log.info('Certificate check interval: every ' + (config.certCheckHours || 1) + ' hour(s)');
  }

  // ============ MESSAGE HANDLER (Admin UI) ============

  /**
   * Called by the admin UI (selectSendTo).
   * Returns available certificate collections from system.certificates.
   */
  async onMessage(obj) {
    if (!obj || !obj.command) return;

    if (obj.command === 'getCertificateCollections') {
      try {
        const certsObj = await this.getForeignObjectAsync('system.certificates');
        const result = [
          { value: '', label: '(no certificate)' },
        ];

        if (certsObj && certsObj.native) {
          const certs = certsObj.native.certificates || {};

          // Named certificates: {name}Private / {name}Public / {name}Chained
          // Also includes the ioBroker default certificate (base name: "default")
          const certBases = new Set();
          for (const key of Object.keys(certs)) {
            if (key.endsWith('Private')) {
              const base = key.slice(0, -'Private'.length);
              if (certs[base + 'Public'] || certs[base + 'Chained']) {
                certBases.add(base);
              }
            }
          }
          for (const base of [...certBases].sort()) {
            result.push({ value: base, label: base });
          }

          // Collections (ACME, manual, etc.)
          const collections = Object.keys(certsObj.native.collections || {});
          for (const name of collections) {
            result.push({ value: name, label: name });
          }
        }

        if (obj.callback) {
          this.sendTo(obj.from, obj.command, result, obj.callback);
        }
      } catch (e) {
        this.log.error('Error fetching certificate collections: ' + e.message);
        if (obj.callback) {
          this.sendTo(obj.from, obj.command, [], obj.callback);
        }
      }
    }
  }

  // ============ ADAPTER STOP ============

  onUnload(callback) {
    try {
      this.log.info('Reverse proxy stopping...');

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
      // Ignore cleanup errors
    }
    callback();
  }
}

// Adapter export
if (require.main !== module) {
  module.exports = (options) => new SimpleProxyManager(options);
} else {
  (() => new SimpleProxyManager())();
}

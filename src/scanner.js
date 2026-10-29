'use strict';
const net = require('node:net');
const tls = require('node:tls');
const dns = require('node:dns/promises');
const fs = require('node:fs');
const path = require('node:path');
const { constants } = require('node:crypto');
const { parsePeerChain } = require('./certificate');
const { negotiateStartTLS } = require('./starttls');

const STARTTLS_PORTS = { 25: 'smtp', 587: 'smtp', 143: 'imap', 110: 'pop3', 21: 'ftp', 389: 'ldap' };
const TLS_VERSIONS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
const SECURE_OPTIONS = new Set([
  'SSL_OP_NO_SSLv2', 'SSL_OP_NO_SSLv3', 'SSL_OP_NO_TLSv1', 'SSL_OP_NO_TLSv1_1',
  'SSL_OP_NO_TLSv1_2', 'SSL_OP_NO_TLSv1_3', 'SSL_OP_NO_COMPRESSION',
  'SSL_OP_NO_RENEGOTIATION', 'SSL_OP_CIPHER_SERVER_PREFERENCE',
  'SSL_OP_LEGACY_SERVER_CONNECT', 'SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION'
]);
function validateTarget(target) {
  if (!target || typeof target !== 'object' || Array.isArray(target)) throw new Error('Target must be an object');
  if (typeof target.host !== 'string' || !target.host.trim()) throw new Error('Target requires a host string');
  if (!Number.isInteger(target.port) || target.port < 1 || target.port > 65535) throw new Error(`Invalid port for ${target.host}`);
  if (target.sni !== undefined && typeof target.sni !== 'boolean' && typeof target.sni !== 'string') throw new Error('sni must be true, false, or a DNS name');
  if (target.sni === true && net.isIP(target.host)) throw new Error('sni: true on an IP target requires an explicit DNS name');
  if (typeof target.sni === 'string' && (!target.sni || net.isIP(target.sni))) throw new Error('sni must be a DNS name (not an IP address)');
  if (target.verifyHostname !== undefined && typeof target.verifyHostname !== 'string') throw new Error('verifyHostname must be a string');
  if (target.tls !== undefined && (!target.tls || typeof target.tls !== 'object' || Array.isArray(target.tls))) throw new Error('tls must be a mapping');
  const options = target.tls || {};
  for (const v of ['minVersion', 'maxVersion']) if (options[v] && !TLS_VERSIONS.includes(options[v])) throw new Error(`Unsupported ${v}: ${options[v]}`);
  if (options.minVersion && options.maxVersion && TLS_VERSIONS.indexOf(options.minVersion) > TLS_VERSIONS.indexOf(options.maxVersion)) throw new Error('minVersion must be <= maxVersion');
  if (options.rejectUnauthorized !== undefined && typeof options.rejectUnauthorized !== 'boolean') throw new Error('tls.rejectUnauthorized must be boolean');
  if (options.ALPNProtocols && (!Array.isArray(options.ALPNProtocols) || options.ALPNProtocols.some(s => typeof s !== 'string'))) throw new Error('tls.ALPNProtocols must be a list of strings');
  if (options.secureOptions && (!Array.isArray(options.secureOptions) || options.secureOptions.some(s => !SECURE_OPTIONS.has(s) || typeof constants[s] !== 'number'))) throw new Error(`tls.secureOptions must contain supported option names (${[...SECURE_OPTIONS].join(', ')})`);
  for (const key of ['ciphers', 'sigalgs', 'ecdhCurve']) if (options[key] !== undefined && typeof options[key] !== 'string') throw new Error(`tls.${key} must be a string`);
  if (target.timeoutMs !== undefined && (!Number.isInteger(target.timeoutMs) || target.timeoutMs < 100 || target.timeoutMs > 300000)) throw new Error('timeoutMs must be 100..300000');
  if (target.starttls === undefined || target.starttls === null || target.starttls === false) return;
  const st = typeof target.starttls === 'object' ? target.starttls : { protocol: target.starttls };
  let protocol = st.protocol === true ? STARTTLS_PORTS[target.port] : st.protocol;
  if (typeof protocol !== 'string' || !['smtp', 'imap', 'pop3', 'ftp', 'ldap'].includes(protocol.toLowerCase())) throw new Error('starttls requires protocol smtp, imap, pop3, ftp, or ldap (or true on a known port)');
}
function getStartTLS(target) {
  if (target.starttls == null || target.starttls === false) return null;
  const st = typeof target.starttls === 'object' ? target.starttls : { protocol: target.starttls };
  return { ...st, protocol: st.protocol === true ? STARTTLS_PORTS[target.port] : st.protocol.toLowerCase() };
}
function sniFor(target) {
  if (target.sni === false) return null;
  if (typeof target.sni === 'string') return target.sni;
  return net.isIP(target.host) ? null : target.host;
}
function loadTLSOptions(target, configDir) {
  const src = target.tls || {};
  const tlsOptions = {
    rejectUnauthorized: src.rejectUnauthorized ?? false, // Inspection mode: keep untrusted certificates visible.
    minVersion: src.minVersion || 'TLSv1.2',
    ...(src.maxVersion ? { maxVersion: src.maxVersion } : {}),
    ...(src.ciphers ? { ciphers: src.ciphers } : {}),
    ...(src.sigalgs ? { sigalgs: src.sigalgs } : {}),
    ...(src.ecdhCurve ? { ecdhCurve: src.ecdhCurve } : {}),
    ...(src.ALPNProtocols ? { ALPNProtocols: src.ALPNProtocols } : {}),
    ...(src.honorCipherOrder !== undefined ? { honorCipherOrder: src.honorCipherOrder } : {})
  };
  if (src.secureOptions) tlsOptions.secureOptions = src.secureOptions.reduce((a, name) => a | constants[name], 0);
  for (const [configName, tlsName] of [['caFile', 'ca'], ['clientCertFile', 'cert'], ['clientKeyFile', 'key']]) {
    if (src[configName]) tlsOptions[tlsName] = fs.readFileSync(path.resolve(configDir, src[configName]));
  }
  if (src.clientKeyPassphrase) tlsOptions.passphrase = src.clientKeyPassphrase;
  return tlsOptions;
}
function freshResult(target, starttls, servername, timeoutMs) {
  return {
    id: target.id || `${target.host}:${target.port}`,
    target: { host: target.host, port: target.port, starttls: starttls?.protocol || null,
      sni: servername, verifyHostname: target.verifyHostname || servername || target.host,
      timeoutMs,
      tls: { ...target.tls, rejectUnauthorized: target.tls?.rejectUnauthorized ?? false,
        minVersion: target.tls?.minVersion || 'TLSv1.2' } },
    success: false,
    error: null,
    startedAt: new Date().toISOString(),
    durationMs: null,
    resolvedAddresses: [],
    endpoints: null,
    starttlsTranscript: [],
    negotiated: null,
    authorization: null,
    certificates: []
  };
}
function sanitizeTargetOutput(result) {
  // Never place private key paths, key passwords, or private key material in JSON.
  if (result.target?.tls) {
    for (const name of ['clientKeyFile', 'clientCertFile', 'caFile', 'clientKeyPassphrase']) delete result.target.tls[name];
  }
  return result;
}
function waitForConnect(socket, event) {
  return new Promise((resolve, reject) => {
    const onSuccess = () => { cleanup(); resolve(); };
    const onError = err => { cleanup(); reject(err); };
    const onClose = () => { cleanup(); reject(Object.assign(new Error('Connection closed before TLS handshake completed'), { code: 'ECONNRESET' })); };
    function cleanup() { socket.off(event, onSuccess); socket.off('error', onError); socket.off('close', onClose); }
    socket.once(event, onSuccess);
    socket.once('error', onError);
    socket.once('close', onClose);
  });
}
async function resolveAddresses(host, timeoutMs) {
  if (net.isIP(host)) return [{ address: host, family: net.isIP(host) }];
  // getaddrinfo follows the system resolver; do not delay the scan indefinitely.
  let timer;
  try {
    return await Promise.race([
      dns.lookup(host, { all: true }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('DNS lookup timed out')), timeoutMs); })
    ]);
  } finally { clearTimeout(timer); }
}
async function scanTarget(target, { configDir = process.cwd(), defaultTimeoutMs = 10000 } = {}) {
  const began = process.hrtime.bigint();
  const timeoutMs = target?.timeoutMs ?? defaultTimeoutMs;
  let socket;
  let timeout;
  let starttls;
  let servername;
  let result;
  try {
    validateTarget(target);
    starttls = getStartTLS(target);
    servername = sniFor(target);
    result = freshResult(target, starttls, servername, timeoutMs);
    const options = loadTLSOptions(target, configDir);
    result.target.tls = { ...result.target.tls,
      ...(options.secureOptions !== undefined ? { secureOptionsMask: options.secureOptions } : {}) };
    result.resolvedAddresses = await resolveAddresses(target.host, Math.min(timeoutMs, 3000))
      .catch(err => { result.dnsError = err.message; return []; });
    const tlsOpts = { ...options, host: target.host, port: target.port,
      // An empty string suppresses SNI; undefined could trigger automatic SNI.
      servername: servername || '' };
    if (starttls) {
      socket = net.connect({ host: target.host, port: target.port });
      timeout = setTimeout(() => socket.destroy(Object.assign(new Error(`Connection exceeded ${timeoutMs}ms`), { code: 'ETIMEDOUT' })), timeoutMs);
      await waitForConnect(socket, 'connect');
      await negotiateStartTLS(socket, starttls, result.starttlsTranscript);
      socket = tls.connect({ ...tlsOpts, socket, host: undefined, port: undefined });
    } else {
      socket = tls.connect(tlsOpts);
      timeout = setTimeout(() => socket.destroy(Object.assign(new Error(`Connection exceeded ${timeoutMs}ms`), { code: 'ETIMEDOUT' })), timeoutMs);
    }
    await waitForConnect(socket, 'secureConnect');
    clearTimeout(timeout);
    timeout = null;
    const socketInfo = {
      localAddress: socket.localAddress || null, localPort: socket.localPort || null,
      remoteAddress: socket.remoteAddress || null, remotePort: socket.remotePort || null,
      remoteFamily: socket.remoteFamily || null
    };
    result.endpoints = socketInfo;
    result.negotiated = {
      protocol: socket.getProtocol(),
      cipher: socket.getCipher() || null,
      ephemeralKey: socket.getEphemeralKeyInfo() || null,
      alpnProtocol: socket.alpnProtocol || null,
      sharedSignatureAlgorithms: socket.getSharedSigalgs() || [],
      sessionReused: socket.isSessionReused(),
      servernameSent: servername,
      tlsVersionRequested: { min: options.minVersion, max: options.maxVersion || null }
    };
    const verifyName = target.verifyHostname || servername || target.host;
    result.certificates = parsePeerChain(socket, verifyName);
    result.authorization = {
      authorized: socket.authorized,
      authorizationError: socket.authorizationError || null,
      hostnameMatches: result.certificates[0]?.hostnameCheck?.matched ?? null,
      hostnameChecked: verifyName,
      verificationEnforced: options.rejectUnauthorized,
      note: options.rejectUnauthorized ? 'Node TLS peer verification enforced during handshake' :
        'Inventory mode: verification errors are recorded but do not abort TLS handshakes'
    };
    result.success = true;
  } catch (err) {
    if (!result) {
      result = {
        id: target?.id || (target?.host ? `${target.host}:${target.port}` : null),
        target: { host: target?.host ?? null, port: target?.port ?? null },
        success: false, startedAt: new Date().toISOString(), certificates: []
      };
    }
    result.error = { code: err.code || 'SCAN_FAILED', message: err.message };
  } finally {
    clearTimeout(timeout);
    if (socket) socket.destroy();
    result.durationMs = Math.round(Number(process.hrtime.bigint() - began) / 1e6);
    result.completedAt = new Date().toISOString();
  }
  return sanitizeTargetOutput(result);
}
async function scanAll(targets, opts = {}) {
  const count = Math.min(Math.max(opts.concurrency || 5, 1), 50);
  const results = new Array(targets.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(count, targets.length) }, async () => {
    while (cursor < targets.length) {
      const index = cursor++;
      results[index] = await scanTarget(targets[index], opts);
    }
  }));
  return results;
}
module.exports = { scanTarget, scanAll, validateTarget };

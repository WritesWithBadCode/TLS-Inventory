'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const { execFileSync } = require('node:child_process');
const { scanTarget } = require('../src/scanner');

let cert, key, dir;
try {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tls-inventory-test-'));
  const crt = path.join(dir, 'cert.pem');
  const priv = path.join(dir, 'key.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
    '-keyout', priv, '-out', crt, '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
    '-addext', 'extendedKeyUsage=serverAuth',
    '-addext', 'basicConstraints=critical,CA:FALSE'
  ], { stdio: 'ignore' });
  cert = fs.readFileSync(crt);
  key = fs.readFileSync(priv);
} catch { /* Test will skip when OpenSSL executable is unavailable. */ }
process.on('exit', () => { if (dir) fs.rmSync(dir, { recursive: true, force: true }); });

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}
async function close(server) {
  server.close();
  await new Promise(resolve => server.once('close', resolve));
}
function assertCert(result) {
  assert.equal(result.success, true, result.error?.message);
  assert.equal(result.negotiated.protocol.startsWith('TLSv1'), true);
  assert.ok(result.negotiated.cipher.name);
  assert.equal(result.certificates.length >= 1, true);
  const leaf = result.certificates[0];
  assert.ok(leaf.fingerprints.sha256);
  assert.ok(leaf.fingerprints.sha1);
  assert.ok(leaf.fingerprints.sha512);
  assert.ok(leaf.subject.includes('CN=localhost'));
  assert.ok(leaf.serialNumber);
  assert.equal(leaf.hostnameCheck.matched, true);
  assert.ok(leaf.dnsNames.includes('localhost'));
  assert.ok(leaf.ipAddresses.includes('127.0.0.1'));
  assert.ok(leaf.subjectKeyIdentifier);
  assert.ok(leaf.authorityKeyIdentifier.keyIdentifier);
  assert.ok(leaf.keyUsage.includes('digitalSignature'));
  assert.ok(leaf.extendedKeyUsage.some(e => e.name === 'serverAuth'));
  assert.equal(leaf.basicConstraints.ca, false);
  assert.ok(leaf.validity.notAfter);
  assert.ok(leaf.extensions.find(e => e.name === 'subjectAlternativeName'));
}

test('direct TLS records handshake, addresses, certificate extensions, validity', { skip: !cert }, async () => {
  const server = tls.createServer({ cert, key }, socket => socket.end());
  const port = await listen(server);
  try {
    const result = await scanTarget({ host: '127.0.0.1', port, sni: 'localhost', tls: { rejectUnauthorized: false } });
    assertCert(result);
    assert.equal(result.authorization.authorized, false); // self-signed cert
    assert.equal(result.authorization.verificationEnforced, false);
    assert.equal(result.endpoints.remoteAddress, '127.0.0.1');
  } finally { await close(server); }
});

test('failed connection stays a structured JSON result', async () => {
  const server = net.createServer();
  const port = await listen(server);
  await close(server);
  const result = await scanTarget({ host: '127.0.0.1', port, tls: { rejectUnauthorized: false } }, { defaultTimeoutMs: 2500 });
  assert.equal(result.success, false);
  assert.ok(result.error.code);
  assert.ok(result.durationMs >= 0);
});

test('config error is a structured failure', async () => {
  const result = await scanTarget({ host: 'x', port: -1 });
  assert.equal(result.success, false);
  assert.equal(result.error.code, 'SCAN_FAILED');
});

for (const protocol of ['smtp', 'imap', 'pop3', 'ftp', 'ldap']) {
  test(`STARTTLS ${protocol} upgrades to TLS`, { skip: !cert }, async () => {
    const context = tls.createSecureContext({ cert, key });
    const server = net.createServer(socket => {
      let buffer = Buffer.alloc(0);
      let stage = 0;
      if (protocol === 'smtp') socket.write('220 local SMTP ready\r\n');
      if (protocol === 'imap') socket.write('* OK local IMAP ready\r\n');
      if (protocol === 'pop3') socket.write('+OK local POP3 ready\r\n');
      if (protocol === 'ftp') socket.write('220 local FTP ready\r\n');
      function upgrade() {
        socket.removeListener('data', onData);
        const secured = new tls.TLSSocket(socket, { isServer: true, secureContext: context });
        secured.on('error', () => {});
        secured.on('secure', () => secured.end());
      }
      function onData(chunk) {
        buffer = Buffer.concat([buffer, chunk]);
        if (protocol === 'ldap') {
          if (buffer.length < 2) return;
          socket.write(Buffer.from('300c02010178070a010004000400', 'hex'), upgrade);
          buffer = Buffer.alloc(0);
          return;
        }
        let idx;
        while ((idx = buffer.indexOf('\n')) !== -1) {
          const line = buffer.subarray(0, idx).toString('ascii');
          buffer = buffer.subarray(idx + 1);
          if (protocol === 'smtp') {
            if (stage === 0 && /^EHLO /i.test(line)) { socket.write('250-localhost\r\n250 STARTTLS\r\n'); stage++; }
            else if (stage === 1 && line.startsWith('STARTTLS')) { socket.write('220 Begin TLS\r\n', upgrade); return; }
          }
          if (protocol === 'imap') {
            if (line.startsWith('T001 CAPABILITY')) socket.write('* CAPABILITY IMAP4rev1 STARTTLS\r\nT001 OK done\r\n');
            else if (line.startsWith('T002 STARTTLS')) { socket.write('T002 OK TLS start\r\n', upgrade); return; }
          }
          if (protocol === 'pop3' && line.startsWith('STLS')) { socket.write('+OK begin TLS\r\n', upgrade); return; }
          if (protocol === 'ftp' && line.startsWith('AUTH TLS')) { socket.write('234 AUTH TLS accepted\r\n', upgrade); return; }
        }
      }
      socket.on('data', onData);
    });
    const port = await listen(server);
    try {
      const result = await scanTarget({
        host: '127.0.0.1', port, sni: 'localhost', starttls: protocol,
        tls: { rejectUnauthorized: false }
      }, { defaultTimeoutMs: 5000 });
      assertCert(result);
      assert.equal(result.target.starttls, protocol);
      assert.ok(result.starttlsTranscript.length >= 2);
    } finally { await close(server); }
  });
}


test('an explicitly constrained TLS 1.2 connection negotiates TLS 1.2', { skip: !cert }, async () => {
  const server = tls.createServer({ cert, key });
  const port = await listen(server);
  try {
    const result = await scanTarget({ host: '127.0.0.1', port, sni: 'localhost',
      tls: { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' } });
    assert.equal(result.success, true, result.error?.message);
    assert.equal(result.negotiated.protocol, 'TLSv1.2');
  } finally { await close(server); }
});

test('strict trust verification rejects self-signed server and reports error', { skip: !cert }, async () => {
  const server = tls.createServer({ cert, key });
  server.on('tlsClientError', () => {});
  const port = await listen(server);
  try {
    const result = await scanTarget({ host: '127.0.0.1', port, sni: 'localhost',
      tls: { rejectUnauthorized: true } });
    assert.equal(result.success, false);
    assert.ok(result.error.code);
  } finally { await close(server); }
});

test('STARTTLS true is rejected on unknown port rather than guessed', async () => {
  const result = await scanTarget({ host: '127.0.0.1', port: 12345, starttls: true });
  assert.equal(result.success, false);
  assert.match(result.error.message, /starttls requires protocol/);
});

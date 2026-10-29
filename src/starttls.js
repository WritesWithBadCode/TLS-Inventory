'use strict';

const { readTLV } = require('./asn1');

function tlsError(message, code = 'STARTTLS_FAILED') {
  const err = new Error(message);
  err.code = code;
  return err;
}
class PlainReader {
  constructor(socket, transcript) {
    this.socket = socket;
    this.transcript = transcript;
    this.buffer = Buffer.alloc(0);
    this.pending = null;
    this.failed = null;
    this.onData = chunk => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      if (this.buffer.length > 1024 * 1024) return this.fail(tlsError('STARTTLS response exceeds 1 MiB'));
      this.pending?.();
    };
    this.onError = err => this.fail(err);
    this.onClose = () => this.fail(tlsError('Connection closed during STARTTLS', 'ECONNRESET'));
    socket.on('data', this.onData);
    socket.on('error', this.onError);
    socket.on('close', this.onClose);
  }
  fail(err) {
    this.failed = err;
    if (this.pending) { const pending = this.pending; this.pending = null; pending(); }
  }
  async untilData() {
    if (this.failed) throw this.failed;
    await new Promise(resolve => { this.pending = resolve; });
    this.pending = null;
    if (this.failed) throw this.failed;
  }
  async bytes(length) {
    while (this.buffer.length < length) await this.untilData();
    const b = this.buffer.subarray(0, length);
    this.buffer = this.buffer.subarray(length);
    return b;
  }
  async line() {
    for (;;) {
      const pos = this.buffer.indexOf(0x0a);
      if (pos !== -1) {
        let result = this.buffer.subarray(0, pos);
        if (result.at(-1) === 0x0d) result = result.subarray(0, result.length - 1);
        this.buffer = this.buffer.subarray(pos + 1);
        const line = result.toString('utf8');
        this.record('server', line);
        return line;
      }
      if (this.buffer.length > 65536) throw tlsError('STARTTLS line exceeds 64 KiB');
      await this.untilData();
    }
  }
  record(direction, message) {
    if (this.transcript.length < 80) this.transcript.push({ direction, message: String(message).slice(0, 2048) });
  }
  send(message) {
    this.record('client', message.trimEnd());
    this.socket.write(message);
  }
  detach() {
    this.socket.pause();
    this.socket.off('data', this.onData);
    this.socket.off('error', this.onError);
    this.socket.off('close', this.onClose);
    if (this.buffer.length && !this.socket.destroyed) this.socket.unshift(this.buffer);
    this.pending = null;
    this.buffer = Buffer.alloc(0);
  }
}

async function numericReply(reader, expected, label) {
  const lines = [];
  let replyCode;
  for (let i = 0; i < 200; i++) {
    const line = await reader.line();
    lines.push(line);
    const m = /^(\d{3})([- ])/.exec(line);
    if (!m) continue;
    if (replyCode === undefined) replyCode = m[1];
    if (m[1] === replyCode && m[2] === ' ') {
      if (!expected.includes(Number(replyCode))) {
        throw tlsError(`${label}: unexpected reply ${line}`);
      }
      return lines;
    }
  }
  throw tlsError(`${label}: too many response lines`);
}
async function smtp(reader, options) {
  await numericReply(reader, [220], 'SMTP greeting');
  const ehlo = options.ehloName || 'tls-inventory.local';
  if (!/^[a-zA-Z0-9.-]{1,255}$/.test(ehlo)) throw tlsError('Invalid SMTP ehloName');
  reader.send(`EHLO ${ehlo}\r\n`);
  const lines = await numericReply(reader, [250], 'SMTP EHLO');
  if (!lines.some(s => /^250[ -]STARTTLS(?:\s|$)/i.test(s))) {
    throw tlsError('SMTP server did not advertise STARTTLS', 'STARTTLS_NOT_ADVERTISED');
  }
  reader.send('STARTTLS\r\n');
  await numericReply(reader, [220], 'SMTP STARTTLS');
}
async function imap(reader) {
  const greeting = await reader.line();
  if (!/^\* OK(?:\s|$)/i.test(greeting)) throw tlsError(`Invalid IMAP greeting: ${greeting}`);
  reader.send('T001 CAPABILITY\r\n');
  let supports = false;
  let capOK = false;
  for (let i = 0; i < 100; i++) {
    const line = await reader.line();
    if (/^\* CAPABILITY\s/i.test(line) && /\bSTARTTLS\b/i.test(line)) supports = true;
    if (/^T001 (OK|NO|BAD)(?:\s|$)/i.test(line)) {
      capOK = /^T001 OK(?:\s|$)/i.test(line);
      break;
    }
  }
  if (!capOK) throw tlsError('IMAP CAPABILITY request failed');
  if (!supports) throw tlsError('IMAP server did not advertise STARTTLS', 'STARTTLS_NOT_ADVERTISED');
  reader.send('T002 STARTTLS\r\n');
  for (let i = 0; i < 100; i++) {
    const line = await reader.line();
    if (/^T002 (OK|NO|BAD)(?:\s|$)/i.test(line)) {
      if (!/^T002 OK(?:\s|$)/i.test(line)) throw tlsError(`IMAP STARTTLS rejected: ${line}`);
      return;
    }
  }
  throw tlsError('IMAP STARTTLS response not received');
}
async function pop3(reader) {
  const greeting = await reader.line();
  if (!/^\+OK(?:\s|$)/i.test(greeting)) throw tlsError(`Invalid POP3 greeting: ${greeting}`);
  reader.send('STLS\r\n');
  const line = await reader.line();
  if (!/^\+OK(?:\s|$)/i.test(line)) throw tlsError(`POP3 STLS rejected: ${line}`);
}
async function ftp(reader) {
  await numericReply(reader, [220], 'FTP greeting');
  reader.send('AUTH TLS\r\n');
  await numericReply(reader, [234], 'FTP AUTH TLS');
}
function der(tag, data) {
  let length;
  if (data.length < 128) length = Buffer.from([data.length]);
  else if (data.length <= 255) length = Buffer.from([0x81, data.length]);
  else length = Buffer.from([0x82, data.length >> 8, data.length & 255]);
  return Buffer.concat([Buffer.from([tag]), length, data]);
}
async function ldap(reader) {
  // LDAP StartTLS ExtendedRequest OID 1.3.6.1.4.1.1466.20037, RFC 4511.
  const requestName = der(0x80, Buffer.from('1.3.6.1.4.1.1466.20037', 'ascii'));
  const request = der(0x30, Buffer.concat([der(0x02, Buffer.from([1])), der(0x77, requestName)]));
  reader.record('client', `LDAP StartTLS ExtendedRequest (${request.length} bytes)`);
  reader.socket.write(request);
  const header = await reader.bytes(2);
  if (header[0] !== 0x30) throw tlsError('Invalid LDAP response envelope');
  let len = header[1];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (!n || n > 3) throw tlsError('Invalid LDAP response length');
    const b = await reader.bytes(n);
    len = 0;
    for (const byte of b) len = len * 256 + byte;
  }
  if (len > 65536) throw tlsError('LDAP response too large');
  const content = await reader.bytes(len);
  const messageID = readTLV(content);
  if (messageID.tag !== 0x02 || messageID.value[0] !== 1) throw tlsError('Unexpected LDAP message ID');
  const response = readTLV(content, messageID.next);
  if (response.tag !== 0x78) throw tlsError('LDAP response is not ExtendedResponse');
  const result = readTLV(response.value);
  if (result.tag !== 0x0a || result.value.length !== 1) throw tlsError('LDAP response missing resultCode');
  reader.record('server', `LDAP StartTLS resultCode=${result.value[0]}`);
  if (result.value[0] !== 0) throw tlsError(`LDAP StartTLS rejected, resultCode=${result.value[0]}`);
}

async function negotiateStartTLS(socket, settings, transcript) {
  const reader = new PlainReader(socket, transcript);
  try {
    switch (settings.protocol) {
      case 'smtp': await smtp(reader, settings); break;
      case 'imap': await imap(reader); break;
      case 'pop3': await pop3(reader); break;
      case 'ftp': await ftp(reader); break;
      case 'ldap': await ldap(reader); break;
      default: throw tlsError(`Unsupported STARTTLS protocol: ${settings.protocol}`);
    }
    reader.detach();
  } catch (err) {
    reader.detach();
    throw err;
  }
}
module.exports = { negotiateStartTLS };

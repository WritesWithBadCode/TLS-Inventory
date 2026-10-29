'use strict';

// Small, strict, dependency-free DER reader for inspecting certificate extensions.
// Not a general-purpose BER/ASN.1 implementation or certificate validator.

function readTLV(buf, offset = 0) {
  if (!Buffer.isBuffer(buf) || offset < 0 || offset + 2 > buf.length) throw new Error('Truncated DER tag');
  const start = offset;
  const tag = buf[offset++];
  if ((tag & 0x1f) === 0x1f) throw new Error('High-tag-number DER unsupported');
  let length = buf[offset++];
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || offset + count > buf.length) throw new Error('Invalid DER length');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + buf[offset++];
  }
  const end = offset + length;
  if (end > buf.length) throw new Error('Truncated DER value');
  return { tag, start, valueStart: offset, end, next: end, value: buf.subarray(offset, end) };
}
function children(buf) {
  const result = [];
  let pos = 0;
  while (pos < buf.length) {
    const n = readTLV(buf, pos);
    result.push(n);
    pos = n.next;
  }
  return result;
}
function expect(node, tag) {
  if (!node || node.tag !== tag) throw new Error(`Expected DER tag 0x${tag.toString(16)}`);
  return node;
}
function seq(buf) { return children(expect(readTLV(buf), 0x30).value); }
function oid(buf) {
  const values = [];
  let current = 0n;
  let partial = false;
  for (const byte of buf) {
    partial = true;
    current = (current << 7n) | BigInt(byte & 0x7f);
    if (!(byte & 0x80)) { values.push(current); current = 0n; partial = false; }
  }
  if (partial || !values.length) throw new Error('Malformed object identifier');
  const first = values.shift();
  const a = first < 40n ? 0n : first < 80n ? 1n : 2n;
  return [a, first - 40n * a, ...values].join('.');
}
function int(buf) {
  if (!buf.length || buf.length > 8) return `0x${buf.toString('hex').toUpperCase()}`;
  let value = 0n;
  for (const byte of buf) value = value * 256n + BigInt(byte);
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
}
const hex = b => b.toString('hex').toUpperCase();
function formatIP(buf) {
  if (buf.length === 4) return Array.from(buf).join('.');
  if (buf.length === 16) {
    // URL's IPv6 serializer uses RFC 5952-style compressed representation.
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(buf.readUInt16BE(i).toString(16));
    const url = new URL(`http://[${groups.join(':')}]/`);
    return url.hostname.slice(1, -1);
  }
  return `0x${hex(buf)}`;
}
function generalNames(value) {
  const names = [];
  for (const n of children(value)) {
    const item = { type: 'other', tag: n.tag, valueHex: hex(n.value) };
    if (n.tag === 0x81) { item.type = 'email'; item.value = n.value.toString('ascii'); delete item.valueHex; }
    else if (n.tag === 0x82) { item.type = 'DNS'; item.value = n.value.toString('ascii'); delete item.valueHex; }
    else if (n.tag === 0x86) { item.type = 'URI'; item.value = n.value.toString('ascii'); delete item.valueHex; }
    else if (n.tag === 0x87) { item.type = 'IP'; item.value = formatIP(n.value); delete item.valueHex; }
    else if (n.tag === 0x88) { item.type = 'registeredID'; item.value = oid(n.value); delete item.valueHex; }
    else if (n.tag === 0xa4) { item.type = 'directoryName'; item.valueHex = hex(n.value); }
    else if (n.tag === 0xa0) { item.type = 'otherName'; }
    names.push(item);
  }
  return names;
}
const KEY_USAGE_BITS = [
  'digitalSignature', 'contentCommitment', 'keyEncipherment', 'dataEncipherment',
  'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'
];
function keyUsage(data) {
  const bitString = expect(readTLV(data), 0x03).value;
  if (!bitString.length) throw new Error('Invalid keyUsage BIT STRING');
  const bytes = bitString.subarray(1);
  return KEY_USAGE_BITS.filter((_, index) => (bytes[Math.floor(index / 8)] || 0) & (0x80 >> (index % 8)));
}
const EKU_NAMES = {
  '1.3.6.1.5.5.7.3.1': 'serverAuth', '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '1.3.6.1.5.5.7.3.3': 'codeSigning', '1.3.6.1.5.5.7.3.4': 'emailProtection',
  '1.3.6.1.5.5.7.3.8': 'timeStamping', '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
  '2.5.29.37.0': 'anyExtendedKeyUsage'
};
function extendedKeyUsage(data) {
  return seq(data).map(n => {
    const value = oid(expect(n, 0x06).value);
    return { oid: value, name: EKU_NAMES[value] || null };
  });
}
function basicConstraints(data) {
  const nodes = seq(data);
  return { ca: nodes.some(n => n.tag === 0x01 && n.value[0] !== 0),
    pathLength: nodes.find(n => n.tag === 0x02) ? int(nodes.find(n => n.tag === 0x02).value) : null };
}
function authorityKeyIdentifier(data) {
  const result = { keyIdentifier: null, authorityCertIssuer: [], authorityCertSerialNumber: null };
  for (const n of seq(data)) {
    if (n.tag === 0x80) result.keyIdentifier = hex(n.value);
    if (n.tag === 0xa1) {
      // GeneralNames is IMPLICIT, so the content consists of GeneralName TLVs.
      result.authorityCertIssuer = generalNames(n.value);
    }
    if (n.tag === 0x82) result.authorityCertSerialNumber = hex(n.value);
  }
  return result;
}
function nameConstraints(data) {
  const out = { permitted: [], excluded: [] };
  for (const n of seq(data)) {
    if (n.tag !== 0xa0 && n.tag !== 0xa1) continue;
    const key = n.tag === 0xa0 ? 'permitted' : 'excluded';
    // RFC 5280 uses IMPLICIT [0]/[1] tags replacing SEQUENCE OF.
    for (const subtree of children(n.value)) {
      const fields = children(expect(subtree, 0x30).value);
      if (!fields.length) continue;
      const gn = generalNames(Buffer.concat([Buffer.from([fields[0].tag]), encodeLength(fields[0].value.length), fields[0].value]))[0];
      const entry = { base: gn, minimum: 0, maximum: null };
      for (const f of fields.slice(1)) {
        if (f.tag === 0x80) entry.minimum = int(f.value);
        if (f.tag === 0x81) entry.maximum = int(f.value);
      }
      out[key].push(entry);
    }
  }
  return out;
}
function encodeLength(len) {
  if (len < 128) return Buffer.from([len]);
  const bytes = [];
  while (len) { bytes.unshift(len & 255); len = Math.floor(len / 256); }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function policyConstraints(data) {
  const result = { requireExplicitPolicy: null, inhibitPolicyMapping: null };
  for (const n of seq(data)) {
    if (n.tag === 0x80) result.requireExplicitPolicy = int(n.value);
    if (n.tag === 0x81) result.inhibitPolicyMapping = int(n.value);
  }
  return result;
}
function crlDistributionPoints(data) {
  return seq(data).map(dp => {
    const point = { fullNames: [], relativeNameDerHex: null, reasonsDerHex: null, crlIssuer: [] };
    for (const field of children(expect(dp, 0x30).value)) {
      if (field.tag === 0xa0) {
        // distributionPoint [0] EXPLICIT contains a CHOICE whose fullName is
        // context [0] IMPLICIT GeneralNames.
        const name = readTLV(field.value);
        if (name.tag === 0xa0) point.fullNames = generalNames(name.value);
        if (name.tag === 0xa1) point.relativeNameDerHex = hex(name.value);
      }
      if (field.tag === 0x81) point.reasonsDerHex = hex(field.value);
      if (field.tag === 0xa2) point.crlIssuer = generalNames(field.value);
    }
    return point;
  });
}
function certificatePolicies(data) {
  return seq(data).map(p => {
    const s = children(expect(p, 0x30).value);
    return oid(expect(s[0], 0x06).value);
  });
}
function authorityInfoAccess(data) {
  const names = {
    '1.3.6.1.5.5.7.48.1': 'OCSP',
    '1.3.6.1.5.5.7.48.2': 'caIssuers'
  };
  return seq(data).map(e => {
    const s = children(expect(e, 0x30).value);
    const methodOID = oid(expect(s[0], 0x06).value);
    const value = generalNames(Buffer.concat([Buffer.from([s[1].tag]), encodeLength(s[1].value.length), s[1].value]))[0];
    return { methodOID, method: names[methodOID] || null, location: value };
  });
}
const EXTENSION_NAMES = {
  '2.5.29.14': 'subjectKeyIdentifier', '2.5.29.15': 'keyUsage',
  '2.5.29.17': 'subjectAlternativeName', '2.5.29.18': 'issuerAlternativeName',
  '2.5.29.19': 'basicConstraints', '2.5.29.30': 'nameConstraints',
  '2.5.29.32': 'certificatePolicies', '2.5.29.35': 'authorityKeyIdentifier',
  '2.5.29.36': 'policyConstraints', '2.5.29.37': 'extendedKeyUsage',
  '2.5.29.54': 'inhibitAnyPolicy', '1.3.6.1.5.5.7.1.1': 'authorityInformationAccess',
  '2.5.29.31': 'crlDistributionPoints'
};
const SIGNATURE_ALGORITHMS = {
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'rsassaPss',
  '1.2.840.10045.4.3.2': 'ecdsaWithSHA256',
  '1.2.840.10045.4.3.3': 'ecdsaWithSHA384',
  '1.2.840.10045.4.3.4': 'ecdsaWithSHA512',
  '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448'
};
function algorithmIdentifier(tlv) {
  const s = children(expect(tlv, 0x30).value);
  const identifier = oid(expect(s[0], 0x06).value);
  return { oid: identifier, name: SIGNATURE_ALGORITHMS[identifier] || null,
    parametersDerHex: s[1] ? hex(Buffer.concat([Buffer.from([s[1].tag]), encodeLength(s[1].value.length), s[1].value])) : null };
}
function parseCertificateDer(der) {
  const out = {
    signatureAlgorithm: null,
    extensions: [],
    subjectAlternativeNames: [],
    issuerAlternativeNames: [],
    subjectKeyIdentifier: null,
    authorityKeyIdentifier: null,
    keyUsage: [],
    extendedKeyUsage: [],
    basicConstraints: null,
    nameConstraints: null,
    policyConstraints: null,
    inhibitAnyPolicy: null,
    certificatePolicies: [],
    crlDistributionPoints: [],
    authorityInformationAccess: []
  };
  const certificateNodes = seq(der);
  if (certificateNodes.length < 3) throw new Error('Incomplete X.509 certificate');
  out.signatureAlgorithm = algorithmIdentifier(certificateNodes[1]);
  const tbsNodes = children(expect(certificateNodes[0], 0x30).value);
  const versionNode = tbsNodes[0]?.tag === 0xa0 ? readTLV(tbsNodes[0].value) : null;
  out.version = versionNode ? Number(int(expect(versionNode, 0x02).value)) + 1 : 1;
  const extensionsNode = tbsNodes.find(n => n.tag === 0xa3);
  if (!extensionsNode) return out;
  const extensionSeq = expect(readTLV(extensionsNode.value), 0x30);
  for (const extension of children(extensionSeq.value)) {
    const parts = children(expect(extension, 0x30).value);
    if (parts.length < 2) continue;
    const id = oid(expect(parts[0], 0x06).value);
    const critical = parts.some(n => n.tag === 0x01 && n.value[0] !== 0);
    const payload = expect(parts[parts.length - 1], 0x04).value;
    const record = { oid: id, name: EXTENSION_NAMES[id] || null, critical,
      valueDerBase64: payload.toString('base64') };
    try {
      switch (id) {
        case '2.5.29.14': out.subjectKeyIdentifier = hex(expect(readTLV(payload), 0x04).value); break;
        case '2.5.29.15': out.keyUsage = keyUsage(payload); break;
        case '2.5.29.17': out.subjectAlternativeNames = generalNames(expect(readTLV(payload), 0x30).value); break;
        case '2.5.29.18': out.issuerAlternativeNames = generalNames(expect(readTLV(payload), 0x30).value); break;
        case '2.5.29.19': out.basicConstraints = basicConstraints(payload); break;
        case '2.5.29.30': out.nameConstraints = nameConstraints(payload); break;
        case '2.5.29.32': out.certificatePolicies = certificatePolicies(payload); break;
        case '2.5.29.31': out.crlDistributionPoints = crlDistributionPoints(payload); break;
        case '2.5.29.35': out.authorityKeyIdentifier = authorityKeyIdentifier(payload); break;
        case '2.5.29.36': out.policyConstraints = policyConstraints(payload); break;
        case '2.5.29.37': out.extendedKeyUsage = extendedKeyUsage(payload); break;
        case '2.5.29.54': out.inhibitAnyPolicy = int(expect(readTLV(payload), 0x02).value); break;
        case '1.3.6.1.5.5.7.1.1': out.authorityInformationAccess = authorityInfoAccess(payload); break;
      }
    } catch (err) { record.decodeError = err.message; }
    out.extensions.push(record);
  }
  return out;
}
module.exports = { readTLV, children, parseCertificateDer, formatIP };

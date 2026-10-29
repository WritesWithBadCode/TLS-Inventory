'use strict';
const { X509Certificate, createHash } = require('node:crypto');
const { parseCertificateDer } = require('./asn1');

function dateISO(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? null : date.toISOString();
}
function keyDescription(key) {
  if (!key) return null;
  const details = key.asymmetricKeyDetails || {};
  return {
    type: key.asymmetricKeyType || null,
    ...(['modulusLength', 'publicExponent', 'namedCurve', 'hashAlgorithm', 'mgf1HashAlgorithm', 'saltLength']
      .reduce((o, field) => {
        if (details[field] !== undefined) o[field] = typeof details[field] === 'bigint' ? details[field].toString() : details[field];
        return o;
      }, {})),
    spkiSha256: createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex').toUpperCase()
  };
}
function serializeCertificate(raw, index, expectedHostname, legacy = {}) {
  const x509 = new X509Certificate(raw);
  const extensionData = parseCertificateDer(raw);
  const decodedSANs = extensionData.subjectAlternativeNames;
  const dnsNames = decodedSANs.filter(n => n.type === 'DNS').map(n => n.value);
  const ipAddresses = decodedSANs.filter(n => n.type === 'IP').map(n => n.value);
  const emailAddresses = decodedSANs.filter(n => n.type === 'email').map(n => n.value);
  const uris = decodedSANs.filter(n => n.type === 'URI').map(n => n.value);
  let matchedName = null;
  if (index === 0 && expectedHostname) {
    try {
      matchedName = require('node:net').isIP(expectedHostname) ? x509.checkIP(expectedHostname) : x509.checkHost(expectedHostname);
    } catch { matchedName = null; }
  }
  const notBefore = dateISO(x509.validFrom);
  const notAfter = dateISO(x509.validTo);
  return {
    position: index,
    version: extensionData.version,
    commonName: legacy.subject?.CN || null,
    subjectAttributes: legacy.subject || null,
    issuerAttributes: legacy.issuer || null,
    subject: x509.subject,
    issuer: x509.issuer,
    serialNumber: x509.serialNumber,
    fingerprints: { sha1: x509.fingerprint, sha256: x509.fingerprint256, sha512: x509.fingerprint512 },
    subjectAlternativeNames: decodedSANs,
    dnsNames,
    ipAddresses,
    emailAddresses,
    uris,
    subjectKeyIdentifier: extensionData.subjectKeyIdentifier,
    authorityKeyIdentifier: extensionData.authorityKeyIdentifier,
    keyUsage: extensionData.keyUsage,
    extendedKeyUsage: extensionData.extendedKeyUsage,
    basicConstraints: extensionData.basicConstraints,
    nameConstraints: extensionData.nameConstraints,
    policyConstraints: extensionData.policyConstraints,
    inhibitAnyPolicy: extensionData.inhibitAnyPolicy,
    certificatePolicies: extensionData.certificatePolicies,
    crlDistributionPoints: extensionData.crlDistributionPoints,
    issuerAlternativeNames: extensionData.issuerAlternativeNames,
    authorityInformationAccess: extensionData.authorityInformationAccess,
    extensions: extensionData.extensions,
    signatureAlgorithm: extensionData.signatureAlgorithm,
    publicKey: keyDescription(x509.publicKey),
    validity: {
      notBefore, notAfter,
      currentlyValid: notBefore !== null && notAfter !== null && Date.now() >= Date.parse(notBefore) && Date.now() <= Date.parse(notAfter),
      daysRemaining: notAfter ? Math.round((Date.parse(notAfter) - Date.now()) / 86400000 * 100) / 100 : null
    },
    isCA: x509.ca,
    selfIssued: x509.subject === x509.issuer,
    hostnameCheck: index === 0 ? { checkedName: expectedHostname || null, matched: expectedHostname ? Boolean(matchedName) : null, matchingName: matchedName || null } : null
  };
}
function parsePeerChain(socket, expectedHostname) {
  // Node's legacy API retains the actual peer-supplied chain; issuerCertificate
  // on a root may point back to itself, so dedupe by SHA-256.
  const certs = [];
  const seen = new Set();
  let node = socket.getPeerCertificate(true);
  while (node && Buffer.isBuffer(node.raw) && certs.length < 32) {
    const sha = createHash('sha256').update(node.raw).digest('hex');
    if (seen.has(sha)) break;
    seen.add(sha);
    try {
      certs.push(serializeCertificate(node.raw, certs.length, expectedHostname, node));
    } catch (err) {
      certs.push({ position: certs.length, parseError: err.message, fingerprints: { sha256: sha.toUpperCase() } });
    }
    node = node.issuerCertificate;
  }
  return certs;
}
module.exports = { parsePeerChain, serializeCertificate };

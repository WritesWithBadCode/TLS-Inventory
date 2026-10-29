# TLS Inventory CLI

A Node.js command-line application that connects to every target in a YAML file, using direct TLS or explicit STARTTLS, and emits machine-readable JSON describing each attempted connection and the server's X.509 certificate chain.

**Requirements:** Node.js 20+ and npm. Only one runtime dependency (`yaml`). The DER/X.509 extension decoder uses Node's built-in crypto APIs, not an external command or certificate parsing service.

## Quick start

```bash
npm install
node index.js --config targets.yaml --output results.json
# or stream JSON to a pipeline:
node index.js -c targets.yaml --compact > results.json
npm test
```

Exit codes: `0` when all targets scanned successfully; `1` when at least one target failed; `2` for a CLI/configuration-level failure. A successful scan means a TLS handshake completed, **not** that the certificate was trusted or matched the intended hostname. Inspect `authorization`.

## YAML schema

```yaml
concurrency: 5
timeoutMs: 10000
```

See [`targets.yaml`](./targets.yaml) for a ready-to-edit working configuration. Keys:

- `targets`: required list of objects with `host` (DNS or IP), `port` (integer), and optional `id`.
- `defaults`: optional options applied to every target, with `tls` merged per-target.
- `timeoutMs`: global default timeout per connection attempt, including STARTTLS exchange, excluding preliminary DNS address enumeration (default 10000). Can be overridden per target.
- `concurrency`: number of simultaneous scans (default 5, maximum 50).
- `sni`: DNS name to send as SNI; `false` to disable; omitted/`true` uses the `host` if it is a DNS name. For IP targets supply a DNS string explicitly.
- `verifyHostname`: hostname/IP to match against the leaf certificate SANs (default: SNI name if supplied, otherwise target host). This is reported separately from PKI trust verification.
- `starttls`: `false`/omitted for immediate TLS; a protocol string (`smtp`, `imap`, `pop3`, `ftp`, `ldap`); `{ protocol: smtp, ehloName: scan.example }`; or `true` for inference from standard ports (SMTP 25/587; IMAP 143; POP3 110; FTP 21; LDAP 389).
- `tls.minVersion`, `tls.maxVersion`: `TLSv1`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`.
- `tls.ciphers`: OpenSSL cipher list (can also specify TLS 1.3 suite names if supported by the local Node/OpenSSL build).
- `tls.sigalgs`: OpenSSL signature algorithm preferences.
- `tls.ecdhCurve`: supported group/curve preference string (for example `X25519:prime256v1`).
- `tls.ALPNProtocols`: string list (for example `['h2', 'http/1.1']`).
- `tls.honorCipherOrder`: boolean (client-side option; generally server-side precedence).
- `tls.secureOptions`: array of supported OpenSSL `SSL_OP_*` constant names.
- `tls.rejectUnauthorized`: `false` (default for inventory) or `true` to abort untrusted handshakes.
- `tls.caFile`, `tls.clientCertFile`, `tls.clientKeyFile`, `tls.clientKeyPassphrase`: optional paths for custom CA / mutual TLS; file paths resolved relative to config file. Private-key paths and passphrases are intentionally removed from output.

No user credentials or application payloads are sent. STARTTLS commands are limited to negotiating encryption. SMTP EHLO name is configurable and sanitized.

## JSON output

Top-level shape:

```json
{
  "schemaVersion": "1.0",
  "scanner": { "name": "tls-inventory-cli", "version": "1.0.0", "nodeVersion": "...", "opensslVersion": "..." },
  "generatedAt": "...",
  "summary": { "targets": 3, "succeeded": 2, "failed": 1 },
  "results": [
    {
      "id": "public-https",
      "target": { "host": "example.com", "port": 443, "sni": "example.com", "starttls": null },
      "success": true,
      "resolvedAddresses": [{ "address": "...", "family": 4 }],
      "endpoints": { "remoteAddress": "...", "remotePort": 443 },
      "negotiated": { "protocol": "TLSv1.3", "cipher": { "name": "...", "standardName": "..." }, "alpnProtocol": null },
      "authorization": { "authorized": true, "authorizationError": null, "hostnameMatches": true },
      "certificates": [
        {
          "position": 0, "subject": "...", "issuer": "...", "serialNumber": "...",
          "fingerprints": { "sha1": "...", "sha256": "...", "sha512": "..." },
          "subjectAlternativeNames": [{ "type": "DNS", "value": "example.com" }],
          "dnsNames": ["example.com"], "ipAddresses": [],
          "subjectKeyIdentifier": "...",
          "authorityKeyIdentifier": { "keyIdentifier": "...", "authorityCertIssuer": [], "authorityCertSerialNumber": null },
          "keyUsage": ["digitalSignature"],
          "extendedKeyUsage": [{ "oid": "1.3.6.1.5.5.7.3.1", "name": "serverAuth" }],
          "basicConstraints": { "ca": false, "pathLength": null },
          "nameConstraints": null, "policyConstraints": null,
          "signatureAlgorithm": { "oid": "...", "name": "..." },
          "validity": { "notBefore": "...", "notAfter": "...", "currentlyValid": true, "daysRemaining": 42.5 },
          "extensions": [{ "oid": "2.5.29.17", "name": "subjectAlternativeName", "critical": false, "valueDerBase64": "..." }]
        }
      ],
      "error": null
    }
  ]
}
```

Each certificate chain member includes the same set of decoded extensions, and each extension also retains its raw DER payload in Base64, which allows downstream decoding of unknown or uncommon OIDs. IP SANs are distinct from DNS resolution (`resolvedAddresses`) and the actual remote socket address (`endpoints.remoteAddress`). The certificate `hostnameCheck` compares the leaf certificate with `verifyHostname` or SNI/host as appropriate.

## Security and limitations

- **Inspection mode:** `rejectUnauthorized: false` intentionally permits TLS handshakes with expired, untrusted, or hostname-mismatched certificates, so information can be collected. This does **not** make the connection trusted. This tool does not send authenticated user data. For strict handshake enforcement set `rejectUnauthorized: true` (a rejected handshake may not expose peer certificates).
- STARTTLS protocols implemented: SMTP, IMAP, POP3, FTP, LDAP. Not implemented: XMPP, PostgreSQL SSLRequest negotiation, custom protocols, HTTP CONNECT/SOCKS proxying, QUIC/DTLS, server-side client authentication flows that require credentials. STARTTLS upgrade is **never** attempted silently when the server does not advertise it (SMTP and IMAP).
- A connection reveals only the **negotiated cipher suite**, protocol, supported-group/key-exchange info (when provided by Node), ALPN, shared signature algorithms, and peer certificate data. The complete ClientHello/ServerHello wire transcript, TLS 1.3 traffic secrets, peer's offered cipher suites, and individual handshake messages are not exposed by Node's normal TLS APIs. This tool does not claim to capture them.
- Node/OpenSSL's crypto policies may forbid outdated TLS and cipher suites even if requested; failed attempts are recorded as errors. Only explicitly lower OpenSSL security levels in isolated authorized test environments.
- Some STARTTLS services require authentication or vendor-specific extensions before negotiation; those are out of scope.
- The peer-supplied chain might not include the root CA; the scanner does not synthesize missing chain members. Trust stores and chain building are handled by OpenSSL/Node, not the DER decoder.
- Parsing is best-effort for unrecognized X.509 extension OIDs. Such extensions are listed with OID/criticality and Base64 DER; supported name constraints may contain complex `otherName`/directoryName values preserved as hex rather than textual interpretations.
- Multiple IPs for the same DNS hostname are enumerated but only **one connection per YAML entry** is performed. To test every IP, list each address as an explicit target (and set SNI where appropriate).
- Use this tool only against systems you own or are authorized to audit.

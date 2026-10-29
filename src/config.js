'use strict';
const fs = require('node:fs');
const path = require('node:path');

function readConfig(configPath) {
  let YAML;
  try { YAML = require('yaml'); }
  catch (e) { throw new Error("Missing YAML dependency. Run 'npm install' in the project directory."); }
  const absolute = path.resolve(configPath);
  const doc = YAML.parseDocument(fs.readFileSync(absolute, 'utf8'), { uniqueKeys: true, merge: false, strict: true });
  if (doc.errors.length) throw new Error(`Invalid YAML: ${doc.errors.map(e => e.message).join('; ')}`);
  const data = doc.toJS({ maxAliasCount: 50 });
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Config must contain a YAML mapping');
  if (!Array.isArray(data.targets) || !data.targets.length) throw new Error('Config must contain a nonempty targets array');
  if (data.defaults && (typeof data.defaults !== 'object' || Array.isArray(data.defaults))) throw new Error('defaults must be a mapping');
  if (data.concurrency !== undefined && (!Number.isInteger(data.concurrency) || data.concurrency < 1 || data.concurrency > 50)) throw new Error('concurrency must be an integer from 1 to 50');
  if (data.timeoutMs !== undefined && (!Number.isInteger(data.timeoutMs) || data.timeoutMs < 100 || data.timeoutMs > 300000)) throw new Error('timeoutMs must be 100..300000');
  const defaults = data.defaults || {};
  const targets = data.targets.map((t, i) => {
    if (!t || typeof t !== 'object' || Array.isArray(t)) throw new Error(`targets[${i}] must be a mapping`);
    return {
      ...defaults, ...t,
      tls: { ...(defaults.tls || {}), ...(t.tls || {}) },
      ...((typeof defaults.starttls === 'object' && typeof t.starttls === 'object' && t.starttls !== null)
        ? { starttls: { ...defaults.starttls, ...t.starttls } } : {})
    };
  });
  return { targets, configDir: path.dirname(absolute), concurrency: data.concurrency ?? 5,
    timeoutMs: data.timeoutMs ?? 10000 };
}
module.exports = { readConfig };

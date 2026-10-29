#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { readConfig } = require('./src/config');
const { scanAll } = require('./src/scanner');
const pkg = require('./package.json');

function help() {
  return `TLS Inventory ${pkg.version}
Usage:
  node index.js --config targets.yaml [--output results.json] [--concurrency N] [--pretty]

Options:
  --config FILE        YAML configuration file (default: targets.yaml)
  --output FILE        Write JSON to FILE instead of stdout
  --concurrency N      Override number of simultaneous scans (1-50)
  --pretty             Pretty-print JSON (default)
  --compact            Compact one-line JSON
  --help               Show this help

Only probe systems you own or are authorized to inspect.
`;
}
function getArgs(argv) {
  const args = { config: 'targets.yaml', pretty: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') args.help = true;
    else if (a === '--pretty') args.pretty = true;
    else if (a === '--compact') args.pretty = false;
    else if (a === '--config' || a === '-c' || a === '--output' || a === '-o' || a === '--concurrency') {
      if (!argv[i + 1]) throw new Error(`${a} requires a value`);
      const value = argv[++i];
      if (a === '--config' || a === '-c') args.config = value;
      else if (a === '--output' || a === '-o') args.output = value;
      else args.concurrency = Number(value);
    } else throw new Error(`Unknown option: ${a}`);
  }
  if (args.concurrency !== undefined && (!Number.isInteger(args.concurrency) || args.concurrency < 1 || args.concurrency > 50)) throw new Error('--concurrency must be 1..50');
  return args;
}
async function main() {
  const args = getArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(help()); return; }
  const cfg = readConfig(args.config);
  const startedAt = new Date().toISOString();
  const results = await scanAll(cfg.targets, {
    configDir: cfg.configDir, concurrency: args.concurrency ?? cfg.concurrency,
    defaultTimeoutMs: cfg.timeoutMs
  });
  const output = {
    schemaVersion: '1.0',
    scanner: { name: pkg.name, version: pkg.version, nodeVersion: process.version,
      opensslVersion: process.versions.openssl },
    generatedAt: new Date().toISOString(),
    startedAt,
    summary: { targets: results.length, succeeded: results.filter(r => r.success).length,
      failed: results.filter(r => !r.success).length },
    results
  };
  const serialized = JSON.stringify(output, null, args.pretty ? 2 : 0) + '\n';
  if (args.output && args.output !== '-') {
    const dest = path.resolve(args.output);
    fs.writeFileSync(dest, serialized, { flag: 'w', mode: 0o600 });
    console.error(`Wrote ${results.length} target results to ${dest}`);
  } else process.stdout.write(serialized);
  if (output.summary.failed) process.exitCode = 1;
}
main().catch(error => {
  console.error(`Fatal: ${error.message}`);
  process.exitCode = 2;
});

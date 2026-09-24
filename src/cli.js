// Command line interface.
import fs from 'node:fs';
import path from 'node:path';
import { analyzeNode, analyzeNodes } from './analyze.js';
import { render, renderText, defaultOutPath, VERSION } from './report.js';
import { listCandidates } from './candidates.js';

const HELP = [
  'sni-recon \u2014 find a defensible SNI cover identity for a TLS node',
  '',
  'USAGE',
  '  sni-recon <address[:port]> [more addresses...] [options]',
  '  sni-recon selftest [options]',
  '',
  'WHAT IT DOES',
  '  1. Maps which candidate names the node accepts as SNI.',
  '  2. Verifies each accepted certificate OFFLINE against the public trust store.',
  '  3. Identifies the hosting operator behind the address (ASN, org, datacenter flag).',
  '  4. Compares proxied content byte-for-byte with the real site.',
  '  5. Reports whether the node is masking a domain it does not own.',
  '',
  'OPTIONS',
  '  --server-names <a,b>   Test exactly these names instead of the built-in corpus.',
  '  --candidates <a,b>     Add these names to the chosen corpus.',
  '  --fast                 Use the 20-name quick corpus.',
  '  --regional             Add region-specific names (RU and others).',
  '  --port <n>             Target port (default 443).',
  '  --timeout <ms>         Per-operation timeout (default 8000).',
  '  --concurrency <n>      Parallel handshakes during discovery (default 10).',
  '  --repeat <n>           Handshakes per name for the stability sample (default 5).',
  '  --max-deep <n>         How many accepted names get full analysis (default 10).',
  '  --assets <a,b>         Static asset paths compared byte-for-byte, e.g. /favicon.ico',
  '  --no-reference         Skip comparison against the real site (discovery only).',
  '  --no-deep              Map the whitelist only; skip per-name detail.',
  '  --no-hoster            Skip operator lookup and masking verdict.',
  '  --no-follow            Do not follow redirects.',
  '  --tui / --no-tui       Force the interactive UI on or off.',
  '  --format <md|json|text>  Output format (default md).',
  '  --json                 Shorthand for --format json.',
  '  --out <file|->         Write the report to a file (\'-\' for stdout).',
  '  --list-candidates      Print the built-in corpus and exit.',
  '  --quiet                Suppress progress output.',
  '  --verbose              Print progress detail to stderr.',
  '  -h, --help             Show this help.',
  '  -v, --version          Show the version.',
  '',
  'EXIT CODES',
  '  0 success  \u00b7  1 node unreachable or no cover name  \u00b7  2 usage error',
  '',
  'SAFETY',
  '  Read-only: TLS handshakes and GET requests only. Point it at infrastructure you own',
  '  or are authorised to test.'
].join('\n');

function parseArgs(argv) {
  const opts = {
    targets: [],
    serverNames: [],
    candidates: [],
    assets: [],
    format: 'md',
    out: null,
    verbose: false,
    quiet: false,
    command: 'analyze'
  };
  const args = argv.slice();
  if (args[0] === 'selftest') {
    opts.command = 'selftest';
    args.shift();
  } else if (args[0] === 'analyze' || args[0] === 'scan') {
    args.shift();
  }
  function need(i, name) {
    if (i + 1 >= args.length) throw new Error(name + ' requires a value');
    return args[i + 1];
  }
  function list(s) {
    return String(s).split(',').map(function (x) { return x.trim(); }).filter(Boolean);
  }
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    switch (a) {
      case '-h': case '--help': opts.help = true; break;
      case '-v': case '--version': opts.version = true; break;
      case '--server-names': opts.serverNames = opts.serverNames.concat(list(need(i, a))); i++; break;
      case '--candidates': opts.candidates = opts.candidates.concat(list(need(i, a))); i++; break;
      case '--assets': opts.assets = opts.assets.concat(list(need(i, a))); i++; break;
      case '--fast': opts.fast = true; break;
      case '--regional': opts.regional = true; break;
      case '--port': opts.port = Number(need(i, a)); i++; break;
      case '--timeout': opts.timeout = Number(need(i, a)); i++; break;
      case '--concurrency': opts.concurrency = Number(need(i, a)); i++; break;
      case '--repeat': opts.repeat = Number(need(i, a)); i++; break;
      case '--max-deep': opts.maxDeep = Number(need(i, a)); i++; break;
      case '--format': opts.format = need(i, a); i++; break;
      case '--json': opts.format = 'json'; break;
      case '--out': opts.out = need(i, a); i++; break;
      case '--no-reference': opts.reference = false; break;
      case '--no-deep': opts.deep = false; break;
      case '--no-hoster': opts.hoster = false; break;
      case '--no-follow': opts.followRedirects = false; break;
      case '--tui': opts.tui = true; break;
      case '--no-tui': opts.tui = false; break;
      case '--list-candidates': opts.listCandidates = true; break;
      case '--quiet': opts.quiet = true; break;
      case '--verbose': opts.verbose = true; break;
      default:
        if (a.charAt(0) === '-') throw new Error('unknown option: ' + a);
        opts.targets.push(a);
    }
  }
  if (opts.format === 'markdown') opts.format = 'md';
  if (opts.format === 'txt') opts.format = 'text';
  return opts;
}

function parseTarget(t) {
  const m = /^(.*):(\d+)$/.exec(t);
  if (m && m[1].indexOf(']') === -1) return { address: m[1], port: Number(m[2]) };
  return { address: t };
}

function writeOut(target, text) {
  if (target === '-') {
    process.stdout.write(text);
    return;
  }
  const dir = path.dirname(path.resolve(target));
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(target, text, 'utf8');
  process.stderr.write('[sni-recon] wrote ' + target + '\n');
}

export async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    process.stderr.write('error: ' + e.message + '\n\n' + HELP + '\n');
    return 2;
  }
  if (opts.help) {
    process.stdout.write(HELP + '\n');
    return 0;
  }
  if (opts.version) {
    process.stdout.write(VERSION + '\n');
    return 0;
  }
  if (opts.listCandidates) {
    process.stdout.write(listCandidates() + '\n');
    return 0;
  }
  if (opts.command === 'selftest') {
    const mod = await import('./selftest.js');
    return mod.runSelftest(opts);
  }
  if (!opts.targets.length) {
    process.stderr.write(HELP + '\n');
    return 2;
  }

  const nodes = opts.targets.map(parseTarget);
  const wantTui = opts.tui !== undefined ? opts.tui : !opts.quiet && process.stdout.isTTY;
  let tui = null;
  let unsubscribeEvent = null;

  const runOpts = {
    port: opts.port,
    timeout: opts.timeout,
    concurrency: opts.concurrency,
    repeat: opts.repeat,
    maxDeep: opts.maxDeep,
    reference: opts.reference,
    deep: opts.deep,
    followRedirects: opts.followRedirects,
    assets: opts.assets,
    serverNames: opts.serverNames,
    candidates: opts.candidates,
    fast: opts.fast,
    regional: opts.regional,
    hoster: opts.hoster,
    verbose: opts.verbose && !opts.quiet
  };

  if (wantTui) {
    const { createTui } = await import('./tui.js');
    tui = createTui({ targets: nodes, color: !process.env.NO_COLOR });
    tui.start();
  }

  const onEvent = function (evt) {
    if (tui) {
      if (evt.type === 'candidate') tui.addCandidate(evt.candidate);
      else tui.onEvent(evt);
    }
  };

  let payload;
  try {
    if (nodes.length === 1) {
      payload = await analyzeNode(nodes[0], Object.assign({ onEvent: function (e) {
        if (e.type === 'phase' && e.phase === 'hoster') {
          // hoster details are attached to the finished result; refresh after completion
        }
        onEvent(e);
      } }, runOpts));
      if (tui && payload.hoster) tui.setHoster(payload.hoster);
    } else {
      const results = [];
      for (let i = 0; i < nodes.length; i++) {
        if (tui) tui.setTarget(nodes[i], i);
        const r = await analyzeNode(nodes[i], Object.assign({ onEvent: onEvent }, runOpts));
        if (tui && r.hoster) tui.setHoster(r.hoster);
        results.push(r);
      }
      payload = { schemaVersion: 1, kind: 'sni-recon-multi', count: results.length, nodes: results };
    }
  } finally {
    if (tui) {
      tui.finish(payloadForTui(payload, nodes));
      tui.stop();
    }
    if (unsubscribeEvent) unsubscribeEvent();
  }

  const text = render(payload, opts.format);
  const multi = nodes.length > 1;

  if (opts.out === null) {
    if (multi && opts.format !== 'json') {
      for (const r of payload.nodes) writeOut(defaultOutPath(r, opts.format), render(r, opts.format));
      process.stdout.write(textSummary(payload) + '\n');
    } else {
      process.stdout.write(text + (text.endsWith('\n') ? '' : '\n'));
    }
  } else {
    writeOut(opts.out, text);
  }

  if (multi) {
    return payload.nodes.some(function (r) { return !r.reachable; }) ? 1 : 0;
  }
  return payload.reachable && payload.best ? 0 : 1;
}

function payloadForTui(payload, nodes) {
  if (!payload) return { reachable: false, node: nodes[0], summary: { message: 'aborted' } };
  if (payload.nodes) return payload.nodes[payload.nodes.length - 1];
  return payload;
}

function textSummary(payload) {
  const out = [];
  for (const r of payload.nodes) {
    if (!r.reachable) {
      out.push(r.node.address + ': unreachable \u2014 ' + (r.summary ? r.summary.message : ''));
      continue;
    }
    const mask = r.masking && r.masking.masking ? ' [MASKING: ' + r.masking.method + ']' : '';
    if (r.best) {
      out.push(r.node.address + ': ' + r.best.name + ' (score ' + r.best.score + ', ' + r.best.grade + '), ' + r.whitelist.accepted + '/' + r.whitelist.tested + ' names accepted' + mask);
    } else {
      out.push(r.node.address + ': no cover name found (' + r.whitelist.accepted + '/' + r.whitelist.tested + ' names accepted)' + mask);
    }
  }
  return out.join('\n');
}

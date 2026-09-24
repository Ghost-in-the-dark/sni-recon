// Command line interface.
import fs from 'node:fs';
import path from 'node:path';
import { analyzeNode, analyzeNodes } from './analyze.js';
import { render, renderText, defaultOutPath, VERSION } from './report.js';
import { listCandidates } from './candidates.js';
import { localizer, localeFromEnv, normalizeLocale, LOCALES, DEFAULT_LOCALE, localeList } from './i18n/index.js';
import { renderMsg, renderList } from './messages.js';
import { redactOperatorDetails } from './redact.js';

/** Help text, assembled at call time so it can be translated. */
function helpText(t) {
  return [
    t('help.summary'),
    '',
    t('help.usageHeading'),
    '  sni-recon <address[:port]> [more addresses...] [options]',
    '  sni-recon selftest [options]',
    '',
    t('help.whatHeading'),
    '  1. ' + t('help.what1'),
    '  2. ' + t('help.what2'),
    '  3. ' + t('help.what3'),
    '  4. ' + t('help.what4'),
    '  5. ' + t('help.what5'),
    '',
    t('help.optionsHeading'),
    '  --server-names <a,b>   ' + t('help.optServerNames'),
    '  --candidates <a,b>     ' + t('help.optCandidates'),
    '  --fast                 ' + t('help.optFast'),
    '  --regional             ' + t('help.optRegional'),
    '  --port <n>             ' + t('help.optPort'),
    '  --timeout <ms>         ' + t('help.optTimeout'),
    '  --concurrency <n>      ' + t('help.optConcurrency'),
    '  --repeat <n>           ' + t('help.optRepeat'),
    '  --max-deep <n>         ' + t('help.optMaxDeep'),
    '  --assets <a,b>         ' + t('help.optAssets'),
    '  --no-reference         ' + t('help.optNoReference'),
    '  --no-deep              ' + t('help.optNoDeep'),
    '  --no-hoster            ' + t('help.optNoHoster'),
    '  --no-follow            ' + t('help.optNoFollow'),
    '  --no-operator-details  ' + t('help.optNoOperatorDetails'),
    '  --tui / --no-tui       ' + t('help.optTui'),
    '  -L, --lang <code>      ' + t('help.optLang', { list: localeList() }),
    '  --format <md|json|text>  ' + t('help.optFormat'),
    '  --json                 ' + t('help.optJson'),
    '  --out <file|->         ' + t('help.optOut'),
    '  --list-candidates      ' + t('help.optListCandidates'),
    '  --quiet                ' + t('help.optQuiet'),
    '  --verbose              ' + t('help.optVerbose'),
    '  -h, --help             ' + t('help.optHelp'),
    '  -v, --version          ' + t('help.optVersion'),
    '',
    t('help.exitHeading'),
    '  ' + t('help.exitCodes'),
    '',
    t('help.safetyHeading'),
    '  ' + t('help.safety')
  ].join('\n');
}

/**
 * Find --lang before the full parse, so that a usage error is reported in the language
 * the user already asked for rather than in English.
 */
function prescanLocale(argv) {
  for (let i = 0; i < argv.length; i++) {
    if ((argv[i] === '--lang' || argv[i] === '-L') && i + 1 < argv.length) {
      const hit = normalizeLocale(argv[i + 1]);
      if (hit) return hit;
    }
  }
  return null;
}

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
    return String(s)
      .split(',')
      .map(function (x) {
        return x.trim();
      })
      .filter(Boolean);
  }
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    switch (a) {
      case '-h': case '--help': opts.help = true; break;
      case '-v': case '--version': opts.version = true; break;
      case '-L': case '--lang': opts.lang = need(i, a); i++; break;
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
      case '--no-operator-details': opts.redactOperator = true; break;
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

function writeOut(target, text, t) {
  if (target === '-') {
    process.stdout.write(text);
    return;
  }
  const dir = path.dirname(path.resolve(target));
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(target, text, 'utf8');
  process.stderr.write('[sni-recon] ' + t('progress.wrote', { path: target }) + '\n');
}

export async function main(argv) {
  // Locale: explicit flag, then the environment, then English.
  const early = prescanLocale(argv) || localeFromEnv(process.env);
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    const t = localizer(early);
    process.stderr.write(t('cli.error') + ': ' + e.message + '\n\n' + helpText(t) + '\n');
    return 2;
  }
  const locale = (opts.lang && normalizeLocale(opts.lang)) || early || DEFAULT_LOCALE;
  const t = localizer(locale);
  if (opts.lang && !normalizeLocale(opts.lang) && LOCALES.indexOf(String(opts.lang).toLowerCase().split('-')[0]) === -1) {
    process.stderr.write('[sni-recon] ' + t('cli.unknownLocale', { lang: opts.lang, list: LOCALES.join(', ') }) + '\n');
  }

  if (opts.help) {
    process.stdout.write(helpText(t) + '\n');
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
    return mod.runSelftest(opts, t);
  }
  if (!opts.targets.length) {
    process.stderr.write(helpText(t) + '\n');
    return 2;
  }

  const nodes = opts.targets.map(parseTarget);
  const wantTui = opts.tui !== undefined ? opts.tui : !opts.quiet && process.stdout.isTTY;
  let tui = null;

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
    tui = createTui({ targets: nodes, color: !process.env.NO_COLOR, t: t, locale: locale });
    tui.start();
  }

  const onEvent = function (evt) {
    if (!tui) return;
    if (evt.type === 'candidate') tui.addCandidate(evt.candidate);
    else tui.onEvent(evt);
  };

  let payload;
  try {
    if (nodes.length === 1) {
      payload = await analyzeNode(nodes[0], Object.assign({ onEvent: onEvent }, runOpts));
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
  }

  // Redaction runs after analysis and before rendering, so it can never change a verdict.
  if (opts.redactOperator) payload = applyRedaction(payload);

  const text = render(payload, opts.format, t);
  const multi = nodes.length > 1;

  if (opts.out === null) {
    if (multi && opts.format !== 'json') {
      for (const r of payload.nodes) writeOut(defaultOutPath(r, opts.format, locale), render(r, opts.format, t), t);
      process.stdout.write(textSummary(payload, t) + '\n');
    } else {
      process.stdout.write(text + (text.endsWith('\n') ? '' : '\n'));
    }
  } else {
    writeOut(opts.out, text, t);
  }

  if (multi) {
    return payload.nodes.some(function (r) {
      return !r.reachable;
    })
      ? 1
      : 0;
  }
  return payload.reachable && payload.best ? 0 : 1;
}

/** Returns a redacted COPY of the payload; the analysis result is left untouched. */
function applyRedaction(payload) {
  if (!payload) return payload;
  if (payload.nodes) {
    const nodes = payload.nodes.map(function (r) {
      const out = redactOperatorDetails(r);
      out.result.redaction = { fields: out.fields };
      return out.result;
    });
    return Object.assign({}, payload, { nodes: nodes });
  }
  const out = redactOperatorDetails(payload);
  out.result.redaction = { fields: out.fields };
  return out.result;
}

function payloadForTui(payload, nodes) {
  if (!payload) return { reachable: false, node: nodes[0], summary: { message: 'aborted' } };
  if (payload.nodes) return payload.nodes[payload.nodes.length - 1];
  return payload;
}

function textSummary(payload, t) {
  const out = [];
  for (const r of payload.nodes) {
    if (!r.reachable) {
      out.push(r.node.address + ': ' + t('verdict.unreachable') + ' \u2014 ' + renderMsg(t, r.summary && r.summary.message, { t: t }));
      continue;
    }
    const mask = r.masking && r.masking.masking ? ' [' + t('masking.detected') + ': ' + t('method.' + r.masking.method) + ']' : '';
    if (r.best) {
      out.push(
        r.node.address + ': ' + r.best.name +
          ' (' + t('ranking.score').toLowerCase() + ' ' + r.best.score + ', ' + t('grade.' + r.best.grade) + '), ' +
          r.whitelist.accepted + '/' + r.whitelist.tested + ' ' + t('identity.namesAccepted').toLowerCase() + mask
      );
    } else {
      out.push(
        r.node.address + ': ' + t('conclusion.noName') +
          ' (' + r.whitelist.accepted + '/' + r.whitelist.tested + ')' + mask
      );
    }
  }
  return out.join('\n');
}

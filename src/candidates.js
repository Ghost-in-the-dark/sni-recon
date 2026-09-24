// Candidate SNI corpus.
//
// These are names a passively-inspecting middlebox is unlikely to block, grouped by
// how innocuous they look on the wire. They are only ever used as `serverNames` in a
// TLS handshake and as `Host` headers on requests to the node under test.
//
// Nothing here is a claim about which names any particular node has been configured to
// accept; that is exactly what the tool measures.

// High-reputation infrastructure and cloud names: the safest cover class, because a
// blocked handshake to them would break ordinary browsing.
export const INFRA = [
  'www.microsoft.com',
  'www.apple.com',
  'www.amazon.com',
  'www.cloudflare.com',
  'cdn.jsdelivr.net',
  'ajax.googleapis.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'cdnjs.cloudflare.com',
  'unpkg.com',
  'www.bing.com',
  'objects.githubusercontent.com',
  'raw.githubusercontent.com',
  'registry.npmjs.org',
  'deb.debian.org',
  'archive.ubuntu.com',
  'nodejs.org',
  'static.crates.io',
  'www.python.org',
  'files.pythonhosted.org',
  'go.dev',
  'proxy.golang.org',
  'repo.maven.apache.org',
  'www.gnu.org',
  'www.kernel.org',
  'fastly.com',
  'www.digitalocean.com',
  'www.linode.com',
  'www.vultr.com',
  'www.hetzner.com'
];

// Developer platforms and tooling vendors — very common cover, ordinary traffic shape.
export const DEV = [
  'www.jetbrains.com',
  'jetbrains.com',
  'download.jetbrains.com',
  'plugins.jetbrains.com',
  'github.com',
  'api.github.com',
  'gitlab.com',
  'bitbucket.org',
  'www.atlassian.com',
  'stackoverflow.com',
  'www.docker.com',
  'registry-1.docker.io',
  'hub.docker.com',
  'www.rust-lang.org',
  'crates.io',
  'www.npmjs.com',
  'pypi.org',
  'www.postgresql.org',
  'redis.io',
  'www.mongodb.com',
  'www.elastic.co',
  'grafana.com',
  'www.ansible.com',
  'www.vagrantup.com'
];

// Consumer hardware and enterprise vendors — heavy CDN presence, rarely blocked.
export const VENDOR = [
  'www.samsung.com',
  'image.samsung.com',
  'legal.samsungdm.com',
  'www.sony.com',
  'www.lg.com',
  'www.intel.com',
  'www.amd.com',
  'www.nvidia.com',
  'www.dell.com',
  'www.hp.com',
  'www.lenovo.com',
  'www.siemens.com',
  'www.bosch.com',
  'www.philips.com',
  'www.oracle.com',
  'www.ibm.com',
  'www.salesforce.com',
  'www.adobe.com',
  'www.autodesk.com',
  'www.vmware.com'
];

// Collaboration, media and AI services.
export const SERVICES = [
  'openai.com',
  'api.openai.com',
  'chat.openai.com',
  'www.anthropic.com',
  'claude.ai',
  'api.anthropic.com',
  'huggingface.co',
  'cdn-avatars.huggingface.co',
  'www.figma.com',
  'slack.com',
  'www.notion.so',
  'www.zoom.us',
  'www.dropbox.com',
  'www.spotify.com',
  'www.netflix.com',
  'www.reddit.com',
  'www.wikipedia.org'
];

// Region-specific names. Worth including when the clients behind the node are in that
// region, but each carries its own blocking risk, so they are scored, never assumed.
export const REGIONAL = [
  'www.yandex.ru',
  'mail.ru',
  'vk.com',
  'www.avito.ru',
  'ozon.ru',
  'www.wildberries.ru',
  'www.kinopoisk.ru',
  'lenta.ru',
  'ria.ru',
  'www.gosuslugi.ru',
  'www.sberbank.ru'
];

export const DEFAULT_CANDIDATES = [].concat(INFRA, DEV, VENDOR, SERVICES);

// Slim list for a quick first pass.
export const FAST_CANDIDATES = [
  'www.microsoft.com',
  'www.apple.com',
  'www.amazon.com',
  'www.cloudflare.com',
  'www.bing.com',
  'cdn.jsdelivr.net',
  'www.jetbrains.com',
  'github.com',
  'www.samsung.com',
  'www.sony.com',
  'www.intel.com',
  'www.nvidia.com',
  'www.oracle.com',
  'www.adobe.com',
  'openai.com',
  'www.anthropic.com',
  'www.figma.com',
  'www.zoom.us',
  'www.spotify.com',
  'www.wikipedia.org'
];

export const GROUPS = { INFRA, DEV, VENDOR, SERVICES, REGIONAL };

/** Which named group a candidate belongs to, for reporting. */
export function groupOf(name) {
  for (const key of Object.keys(GROUPS)) {
    if (GROUPS[key].indexOf(name) !== -1) return key.toLowerCase();
  }
  return 'custom';
}

export function candidatesFor(opts) {
  const o = opts || {};
  if (o.serverNames && o.serverNames.length) return o.serverNames.slice();
  if (o.candidates && o.candidates.length) return o.candidates.slice();
  if (o.fast) return FAST_CANDIDATES.slice();
  if (o.regional) return DEFAULT_CANDIDATES.concat(REGIONAL);
  return DEFAULT_CANDIDATES.slice();
}

/** Human-readable dump of the whole corpus, for --list-candidates. */
export function listCandidates() {
  const out = [];
  for (const key of Object.keys(GROUPS)) {
    out.push(key + ' (' + GROUPS[key].length + '):');
    for (const n of GROUPS[key]) out.push('  ' + n);
    out.push('');
  }
  out.push('total unique: ' + dedupeNames(DEFAULT_CANDIDATES.concat(REGIONAL)).length);
  return out.join('\n');
}

export function dedupeNames(list) {
  const seen = new Set();
  const out = [];
  for (const n of list || []) {
    const v = String(n || '').trim().toLowerCase().replace(/\.$/, '');
    if (!v || seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

# sni-recon

Reconnaissance for TLS nodes used as cover for a censored or filtered connection.

Given one or more addresses, it answers three questions that are usually guessed at:

1. **Which names does the node accept as SNI?** — not which names it *should*.
2. **Is the certificate it presents real, or a lookalike?** — verified offline against the public trust store.
3. **Is a domain being masked, and by whom?** — the hosting operator behind the address, and whether the node is serving a domain it does not own.

Built to correct a specific failure mode: a node that whitelists its SNI will reject the probe name that common scanners use, and get reported as having no valid certificate when it is in fact perfectly healthy.

Reports and interface are available in **English** and **Russian** (`--lang ru`).

---

## Why the usual scan misses

The widespread approach is to send a TLS handshake with SNI `invalid2.invalid` and check whether the certificate's common name matches. On a node with an SNI whitelist, `invalid2.invalid` is not on the list, so the handshake fails — and the node is written off.

That verdict is wrong. The node may be forwarding traffic for a domain that *is* on its list, with a genuine certificate. You cannot discover the list by asking for a name that is definitely not on it.

`sni-recon` inverts the approach. It walks a corpus of candidate names, records which handshakes complete, then verifies the resulting certificates **offline** and compares forwarded content **byte-for-byte** with the real site.

---

## Install

Requires Node.js 18 or newer. No dependencies.

```bash
git clone https://github.com/Ghost-in-the-dark/sni-recon.git
cd sni-recon
node bin/sni-recon.js --help
```

Install the `sni-recon` command globally:

```bash
npm link
sni-recon --help
```

Verify the installation (the fixture step needs `openssl` in `PATH`):

```bash
npm test              # unit tests
sni-recon selftest    # end-to-end checks against local fake nodes
```

---

## Usage

```bash
sni-recon <address[:port]> [more addresses...] [options]
```

A full run, interactive UI and Markdown report:

```bash
sni-recon 203.0.113.7
```

### The interactive frame

The interface draws a live frame: the operator, progress through the whitelist, and each candidate as its certificate and forwarding are resolved.

```
┌ sni-recon · SNI cover analysis ────────────────────────────────────────────────┐
│ target    203.0.113.7:443                                                   12s │
│ operator  AS64500 EXAMPLE HOSTING LTD · Example City, ZZ  [datacenter]          │
│ phase     verifying 3 accepted names                                            │
└─────────────────────────────────────────────────────────────────────────────────┘

 whitelist  ██████████████████████░░░░░░░░░░░░░░░░░░░░░░  41/120 probed, 3 accepted

   candidate               presented as            certificate forward      score  ms
   www.example.com         www.example.com         genuine     identical       90  12
   other.example           www.example.com         lookalike   failed         -40
   api.example             api.example             genuine     comparable      30   5

 q detach UI (scan continues) · ctrl-c abort
```

Press `q` to detach — the scan keeps running and the report is still written. Below about 78 columns the table drops to names and verdicts rather than wrapping; in a short terminal the *newest* candidates are the ones kept, and the header, footer and recommendation always stay on screen. When stdout is not a terminal (a pipe, a redirect, CI) the frame degrades to line-by-line progress on stderr and the report still goes to stdout untouched.

### Language

The locale comes from the flag first, then the environment, then English:

```bash
sni-recon 203.0.113.7 --lang ru      # or -L ru
LANG=ru_RU.UTF-8 sni-recon 203.0.113.7
```

`LC_ALL` and `LC_MESSAGES` take precedence over `LANG`, as POSIX specifies. An unshipped locale such as `de_DE` falls back to English rather than guessing.

The report carries the language it was rendered in by design: the engine stores findings as *structured values*, not as finished sentences, so a JSON consumer never has to parse prose to act on a signal.

### More examples

Quick pass with a 20-name corpus:

```bash
sni-recon 203.0.113.7 --fast
```

Include region-specific names (RU and others):

```bash
sni-recon 203.0.113.7 --regional
```

Several nodes at once — writes one report per node and prints a summary:

```bash
sni-recon 203.0.113.7 198.51.100.4 192.0.2.9
```

Machine-readable output:

```bash
sni-recon 203.0.113.7 --format json --out report.json
```

Stronger forwarding evidence, using static assets rather than a personalised landing page:

```bash
sni-recon 203.0.113.7 --server-names www.example.com --assets /favicon.ico,/robots.txt
```

When the node's list is already known, skip discovery and just verify it:

```bash
sni-recon 203.0.113.7 --server-names www.example.com --repeat 10
```

### Options

| Option | Meaning |
| --- | --- |
| `--server-names a,b` | Test exactly these names instead of the built-in corpus |
| `--candidates a,b` | Add these names to the chosen corpus |
| `--fast` | Use the 20-name quick corpus |
| `--regional` | Add region-specific names (RU and others) |
| `--port n` | Target port (default 443) |
| `--timeout ms` | Per-operation timeout (default 8000) |
| `--concurrency n` | Parallel handshakes during discovery (default 10) |
| `--repeat n` | Handshakes per name for the stability sample (default 5) |
| `--max-deep n` | How many accepted names get full analysis (default 10) |
| `--assets a,b` | Static asset paths compared byte-for-byte |
| `--no-reference` | Discovery only; skip comparison against the real site |
| `--no-deep` | Map the whitelist only |
| `--no-hoster` | Skip operator lookup and the masking verdict |
| `--no-follow` | Do not follow redirects |
| `--no-operator-details` | Blank the operator name, ASN and location in the report |
| `-L, --lang code` | Report and interface language (`en`, `ru`) |
| `--tui` / `--no-tui` | Force the interactive UI on or off |
| `--format md\|json\|text` | Output format (default md) |
| `--out file\|-` | Write the report to a file |
| `--list-candidates` | Print the built-in corpus |

Exit codes: `0` success, `1` node unreachable or no cover name found, `2` usage error.

### Publishing a report without naming your provider

A scan report names the hosting operator behind the node. That is useful to you and sensitive to everyone else, so it can be removed without losing anything that matters:

```bash
sni-recon 203.0.113.7 --no-operator-details --out public-report.md
```

Redaction is applied **after** the analysis and **before** rendering, so it can never change a conclusion — it only affects how much of the infrastructure is disclosed. Certificate verdicts, whitelist mapping and forward comparison are all independent of who runs the box; the datacenter flag survives, because the masking verdict leans on it. A note in the report records that details were withheld, so a reader is not misled into thinking the lookup simply failed.

---

## How the report is laid out

The reader is told the **answer first**:

1. **Conclusion** — the recommended SNI, a ready-to-paste configuration, the two or three facts that justify it, and the masking verdict with its evidence table.
2. **Candidate ranking** — every name, scored.
3. **Notes and rejected names.**
4. **Appendix** — node identity, per-name detail, and a side-by-side comparison with the real site.
5. **Method and caveats** — identical in every report, so it sits at the end.

The comparison is a three-column table rather than two paragraphs the reader has to diff by eye:

| Check | Through node | Real site | Result |
| --- | --- | --- | --- |
| HTTP status | 200 | 200 | match |
| Body size | 51234 B | 51234 B | match |
| Body SHA-256 | `3F2A9C10E4B7…` | `3F2A9C10E4B7…` | identical |
| Time to first byte | 191.5 ms | 142.5 ms | — |
| Leaf certificate | `A1B2C3D4E5F6…` | `A1B2C3D4E5F6…` | identical |

---

## Masking detection

The question "is this host masking a domain?" has no single answer, so it is resolved through three independent channels. Each contributes weighted evidence, and the verdict records which channel carried it.

### 1. Forged certificate

The presented chain is verified **offline** against Node's bundled trust store: validity windows, signature links between each pair of certificates, and a trusted anchor at the top.

A node that mints its own certificate for a popular hostname fails this immediately. The verdict is `identified-by-forged-certificate` at **high** confidence, because no legitimate reason exists to serve a self-issued certificate for a name the node does not own.

This is the strongest signal available, and it cannot be produced by a handshake test alone — the handshake succeeds, TLS looks fine, and only chain verification exposes it.

### 2. Operator mismatch

The address is resolved to an ASN and organisation through keyless services (ip-api.com and RDAP), as is the address of the real service. A node run by a hosting provider while the cover domain runs on a CDN is a fact about the network, not an inference.

When the operator matches *and* the certificate is honestly issued, the node is reported as `genuine-front` — it is simply the service's own infrastructure, and flagging it would be a false positive on every legitimate front-end.

### 3. Transparent forwarding

One request goes to the node's address with the candidate as both SNI and `Host`; the identical request goes to the real site's own address. Status, length, TTFB and body SHA-256 are compared.

Byte-identical content served from unrelated infrastructure is `identified-by-transparent-forward`.

### The catch-all trap

Many CDN edges answer *any* SNI — including names the site cannot own — with the site's own certificate. Treating that as evidence of masking marks every genuine front-end as guilty.

So the tool probes the real site with an undeclared name too. If the genuine edge behaves the same way, the catch-all signal is recorded with **weight 0** and an explicit explanation, rather than counted against the node:

```
0  catch-all-certificate-is-upstream
+1 accepts-undeclared-names
+2 operator-mismatch
+1 node-is-datacenter
```

That behaviour is a property of the upstream, and is reported as such.

### Verdicts

Verdict and method ids are stable machine identifiers and are never translated; only their labels are.

| Verdict | Meaning |
| --- | --- |
| `identified-by-forged-certificate` | Certificates minted for a domain the node does not own |
| `identified-by-transparent-forward` | Relaying for a domain it does not own |
| `identified-by-content-substitution` | Serving different content from unrelated infrastructure |
| `identified-by-generic-certificate` | Catch-all certificate, not matched by the real site |
| `genuine-front` | Same operator, honestly issued certificate |
| `suspicious` / `inconclusive` | Indicators present, below the confidence threshold |

---

## Scoring

The ranking scores each name out of 100 from weighted components: chain verification (+35 / −25), fingerprint match against the real site (±20), byte-identical forwarding (+25), handshake stability, certificate determinism, remaining validity, and key-exchange parity.

Grades are stable ids — `excellent` (80+), `good` (60+), `fair` (40+), `poor` — and are rendered in the report's language.

---

## Method

| Stage | What it does |
| --- | --- |
| Controls | Handshake with no SNI, with `invalid2.invalid`, and with a random undeclared name |
| Discovery | Handshake with each corpus name; records only whether it completes |
| Identity | Offline chain verification and hostname coverage per accepted name |
| Reference | Resolves the real site independently of the node, via DNS-over-HTTPS |
| Forwarding | IP-pinned request through the node vs. the real address; body hashes compared |
| Operator | ASN and organisation for both addresses, plus the upstream catch-all control |

Requests are **IP-pinned**: the socket goes to a chosen address while carrying an independent `Host` header and SNI. That holds the network path constant and varies only the identity the node is asked to present — which is what makes the comparison meaningful.

Resolution uses DNS-over-HTTPS first, so a local fake-IP resolver cannot silently redirect the reference comparison.

---

## Caveats

**A verified chain proves the node presents the genuine certificate, not that it is the genuine operator.** A well-configured node that transparently forwards to the real site is indistinguishable from the real site — by design.

**Scores are relative.** They rank names on one node against each other. They are not absolute safety guarantees.

**Small samples.** Repeated handshakes catch instability, not sophisticated traffic analysis.

**Landing pages are personalised.** Static asset hashes are the stronger evidence; pass `--assets`.

**A certificate that does not cover the name is not always hostile.** Some hosts legitimately serve a default certificate for unknown names.

**Reachability from one vantage point says nothing about blocking elsewhere.**

---

## Adding a language

Copy `src/i18n/en.js`, translate the values, and register the catalogue in `src/i18n/index.js`. The test suite compares key sets across catalogues and fails on any missing key, so a partial translation cannot ship silently. It also renders a full report in every shipped locale and asserts that no raw message key leaks into the output.

Message values are structured: `msg('evidence.operator-mismatch', { node, reference })` records *what happened* and the renderer decides how to say it. That is what makes a scan re-renderable in another language without repeating it.

---

## Tests

```bash
npm test           # unit tests
sni-recon selftest # end-to-end against local fake masking nodes
```

The self test stands up three loopback listeners — one presenting a genuine certificate, one minting a forged one, one serving a catch-all — and asserts the verdicts, the scoring order, per-locale rendering, redaction, and the absence of raw keys in output. Hoster fixtures in the tests are fictional (`AS64500 EXAMPLE HOSTING LTD`); a guard test fails the build if a real provider's identity ever appears in the repository.

The unit suite also drives the interactive frame through a fake TTY: it asserts that the first draw does not throw, that every event type renders, that no line exceeds the terminal width at 60/80/120/160 columns, and that a short terminal still shows the newest candidates. That harness exists because the crash-free path was the *non-interactive* one — a render bug could ship without a single test noticing.

---

## Scope and legality

This tool is read-only. It performs TLS handshakes and HTTP GET requests, and nothing else: no exploitation, no authentication attempts, no traffic generation beyond ordinary requests.

Use it on infrastructure you own or are explicitly authorised to test. Probe addresses you control or have permission to examine — port scanning and service enumeration of third-party systems is regulated in many jurisdictions.

---

## License

MIT

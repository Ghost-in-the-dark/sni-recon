// English message catalogue.
//
// Every user-visible string in the tool lives here. Keys are grouped by the part of
// the report they appear in. Placeholders use {braces} and are substituted by t().
//
// Adding a language means copying this file and translating the values; the key set
// is checked against this one by the test suite, so a missing translation fails loudly
// rather than silently falling back.

export default {
  // --- document ------------------------------------------------------------
  'doc.title': 'SNI cover analysis — {address}:{port}',
  'doc.generated': 'Generated {at} · sni-recon v{version}',

  // --- conclusion (top block) ---------------------------------------------
  'conclusion.heading': 'Conclusion',
  'conclusion.best': 'Recommended SNI: **{name}** — {score}/100, {grade}',
  'conclusion.noName': 'No usable cover name was found on this node.',
  'conclusion.unreachable': 'The node did not complete a TLS handshake.',
  'conclusion.noneAccepted': 'The node completes a handshake but accepts none of the {tested} tested names.',
  'conclusion.bullet.genuine': 'the certificate is genuinely issued for this name and chains to a public trust store',
  'conclusion.bullet.forged': 'the certificate is NOT publicly trusted — this name is a lookalike identity',
  'conclusion.bullet.identical': 'the node relays content byte-identical to the real site',
  'conclusion.bullet.differs': 'proxied content differs from the real site',
  'conclusion.bullet.stable': 'stable across {ok}/{attempts} handshakes',
  'conclusion.bullet.unstable': 'unreliable: only {ok}/{attempts} handshakes succeeded',
  'conclusion.bullet.masking': 'hoster-level masking detected: {verdict}',
  'conclusion.bullet.maskingNone': 'no hoster-level masking detected ({verdict})',
  'conclusion.bestWeak': 'No usable cover identity was found. Best of the tested names: **{name}** ({score}/100, {grade}).',
  'conclusion.warning': 'Do not use a name from this node as cover without checking the ranking below.',
  'conclusion.config': 'Configuration',
  'conclusion.configNote': 'Keep {code} as a hostname rather than a literal IP so the node resolves it itself. The same name must be present in the client configuration.',

  // --- verdict table -------------------------------------------------------
  'table.field': 'Field',
  'table.value': 'Value',
  'verdict.score': 'Score',
  'verdict.handshakes': 'Handshake success',
  'verdict.medianLatency': 'Median handshake latency',
  'verdict.validFor': 'Certificate valid for',
  'verdict.days': 'days',
  'verdict.certificate': 'Certificate',
  'verdict.forwarding': 'Forwarding',

  // --- certificate verdicts ------------------------------------------------
  'cert.notInspected': 'not inspected',
  'cert.genuine': 'genuine (chain verified)',
  'cert.lookalike': 'lookalike (not publicly trusted)',
  'cert.invalid': 'chain invalid',

  'cert.short.genuine': 'genuine',
  'cert.short.lookalike': 'lookalike',
  'cert.short.invalid': 'invalid chain',
  'cert.short.none': 'not checked',
  'forward.short.identical': 'identical',
  'forward.short.comparable': 'comparable',
  'forward.short.differs': 'differs',
  'forward.short.failed': 'failed',
  // --- forward verdicts ----------------------------------------------------
  'forward.identical': 'identical',
  'forward.comparable': 'comparable',
  'forward.differs': 'differs',
  'forward.failed': 'failed',

  // --- grades --------------------------------------------------------------
  'grade.excellent': 'excellent',
  'grade.good': 'good',
  'grade.fair': 'fair',
  'grade.poor': 'poor',

  // --- masking -------------------------------------------------------------
  'masking.heading': 'Hoster-level domain masking',
  'masking.detected': 'Masking detected',
  'masking.notDetected': 'No masking detected',
  'masking.inconclusive': 'Inconclusive',
  'masking.verdict': 'Verdict',
  'masking.verdictKind': 'Verdict kind',
  'masking.signalsPositive': 'signals above zero',
  'masking.method': 'Method',
  'masking.confidence': 'Confidence',
  'masking.weight': 'Signal weight',
  'masking.nodeOperator': 'Node operator',
  'masking.datacenter': 'Datacenter address',
  'masking.referenceOperator': 'Real service operator',
  'masking.sameOperator': 'Same operator',
  'masking.evidence': 'Evidence',
  'masking.evidenceSignal': 'Signal',
  'masking.evidenceWeight': 'Weight',
  'masking.evidenceDetail': 'Detail',

  'confidence.high': 'high',
  'confidence.medium': 'medium',
  'confidence.low': 'low',

  'method.forged-certificate': 'forged certificate',
  'method.transparent-forward': 'transparent forward',
  'method.generic-default-certificate': 'generic default certificate',
  'method.none': 'none',

  'verdict.identified-by-forged-certificate': 'identified by forged certificate',
  'verdict.identified-by-transparent-forward': 'identified by transparent forward',
  'verdict.identified-by-generic-certificate': 'identified by generic certificate',
  'verdict.identified-by-content-substitution': 'identified by content substitution',
  'verdict.possible-forward-operator-unknown': 'possible forward, operator unknown',
  'verdict.genuine-front': 'genuine front-end',
  'verdict.suspicious': 'suspicious',
  'verdict.inconclusive': 'inconclusive',
  'verdict.unreachable': 'unreachable',
  'verdict.no-candidate-accepted': 'no candidate accepted',

  'masking.headline.identified-by-forged-certificate':
    'Hoster-level domain masking: the node mints certificates for a domain it does not own.',
  'masking.headline.identified-by-transparent-forward':
    'Hoster-level domain masking: the node relays for a domain it does not own.',
  'masking.headline.identified-by-generic-certificate':
    'Hoster-level domain masking: one catch-all certificate is served for every name.',
  'masking.headline.identified-by-content-substitution':
    'Hoster-level domain masking: the node serves content that does not match the real service while running on unrelated infrastructure.',
  'masking.headline.possible-forward-operator-unknown':
    'Possible domain masking: the node relays for another domain, but the operator could not be identified.',
  'masking.headline.genuine-front': 'No masking detected: the node behaves as the domain’s own infrastructure.',
  'masking.headline.suspicious': 'Masking indicators present, but below the confidence threshold for a verdict.',
  'masking.headline.inconclusive': 'Inconclusive: not enough signals to judge whether a domain is being masked.',
  'masking.reasoning.identified-by-forged-certificate':
    'the node issues certificates for a domain it does not own.',
  'masking.reasoning.identified-by-transparent-forward':
    'the node relays traffic for a domain it does not own.',
  'masking.reasoning.identified-by-generic-certificate':
    'the same certificate is served for every name.',
  'masking.reasoning.identified-by-content-substitution':
    'the node serves content that does not match the real service, from infrastructure that is not the domain’s own.',
  'masking.reasoning.possible-forward-operator-unknown':
    'the node relays a foreign domain, but its operator could not be determined.',
  'masking.reasoning.genuine-front':
    'the node behaves as the domain’s own infrastructure.',
  'masking.reasoning.suspicious':
    'indicators are present, but their weight is below the threshold for a verdict.',
  'masking.reasoning.inconclusive':
    'not enough signals to judge whether a domain is being masked.',

  // --- masking evidence ----------------------------------------------------
  'evidence.untrusted-certificate-for-foreign-domain':
    'the node serves {count} name(s) with a certificate that does not chain to a public trust store ({names}); issuer "{issuer}"',
  'evidence.catch-all-certificate-is-upstream':
    'the node serves one certificate for every name, but so does the real service ({name} answers an undeclared name with the same certificate) — this is CDN edge behaviour, not masking',
  'evidence.single-certificate-for-all-names':
    'the same certificate is returned for every SNI tested, including names the node cannot own — the signature of a catch-all reverse proxy rather than a real service',
  'evidence.accepts-undeclared-names':
    'a random undeclared name ({name}) completes a handshake, so name-based routing is not enforced',
  'evidence.content-served-from-elsewhere':
    'the node relays byte-identical content for "{name}" while the address is not operated by the domain’s own provider',
  'evidence.operator-mismatch':
    'the node runs on {node}, while the real service runs on {reference} — different operators',
  'evidence.operator-match': 'node and the real service are operated by the same organisation ({node})',
  'evidence.node-is-datacenter':
    'the address belongs to a hosting/datacenter provider, not to the domain’s own network ({node})',
  'evidence.tls-parameters-differ':
    'the node negotiates a different key exchange group ({via}) than the real service ({reference})',
  'evidence.certificate-differs-anchored':
    'the certificate is validly issued but is not the one the site serves on its own infrastructure',
  'evidence.certificate-differs-untrusted':
    'the certificate presented is not the one the real service serves, and it is not publicly trusted',

  // --- node identity (appendix) -------------------------------------------
  'identity.heading': 'Node identity',
  'identity.probe': 'Probe',
  'identity.handshake': 'Handshake',
  'identity.leafCn': 'Certificate CN',
  'identity.anchored': 'Anchored',
  'identity.noSni': 'no SNI',
  'identity.randomName': 'random .invalid name',
  'identity.ok': 'ok',
  'identity.failed': 'failed',
  'identity.accepted': 'accepted',
  'identity.rejected': 'rejected',
  'identity.property': 'Property',
  'identity.namesTested': 'Names tested',
  'identity.namesAccepted': 'Names accepted',
  'identity.distinctCerts': 'Distinct certificates seen',
  'identity.generic': 'Single certificate for every SNI',
  'identity.arbitrary': 'Accepts arbitrary undeclared names',
  'identity.strictCompatible': 'Compatible with a strict invalid2.invalid scan',

  // --- ranking -------------------------------------------------------------
  'ranking.heading': 'Candidate ranking',
  'ranking.sameRows': '{n} more names with the same score ({score})',
  'ranking.name': 'Name',
  'ranking.group': 'Group',
  'ranking.score': 'Score',
  'ranking.grade': 'Grade',
  'ranking.certificate': 'Certificate',
  'ranking.forward': 'Forward',
  'ranking.medianMs': 'Median ms',
  'ranking.rank': '#',

  // --- comparison ----------------------------------------------------------
  'compare.heading': 'Comparison with the real site',
  'compare.check': 'Check',
  'compare.throughNode': 'Through node',
  'compare.realSite': 'Real site',
  'compare.result': 'Result',
  'compare.status': 'HTTP status',
  'compare.bytes': 'Body size',
  'compare.bodyHash': 'Body SHA-256',
  'compare.leaf': 'Leaf certificate',
  'compare.timing': 'Time to first byte',
  'compare.hopCount': 'Redirect hops',
  'compare.match': 'match',
  'compare.differ': 'differ',
  'compare.identical': 'identical',
  'compare.notComparable': 'not comparable',
  'compare.referenceAddress': 'Reference address',
  'unit.ms': 'ms',
  // ASCII unit for latency in the framed terminal report. In a terminal "ms" and "мс" are
  // both narrow, but "мс" widens every latency cell, and "ms" is unambiguous in Russian
  // technical writing.


  // --- assets --------------------------------------------------------------
  'assets.heading': 'Static assets',
  'assets.asset': 'Asset',
  'assets.identical': 'Identical',

  // --- stability -----------------------------------------------------------
  'stability.line':
    'Stability: {ok}/{attempts} handshakes, {determinism}, latency min/median/max {min}/{median}/{max} ms.',
  'stability.deterministic': 'identical certificate each time',
  'stability.varied': 'certificate varied',
  'stability.unknown': 'not measured (no successful handshake)',
  'stability.label': 'Certificate across attempts',
  'stability.spread': 'Latency min / max',

  // --- differences ---------------------------------------------------------
  'differences.heading': 'Differences from the real site',
  'difference.status': 'HTTP status differs',
  'difference.bytes': 'body length differs by {n} bytes',
  'difference.content': 'body length matches but content differs (dynamic page or injected content)',
  'difference.certificate': 'presented certificate is not the real site certificate',
  'difference.asset': 'asset differs from the real site: {path}',

  // --- notes ---------------------------------------------------------------
  'notes.heading': 'Notes',
  'note.genericIdentity':
    'the node presents one certificate for every SNI, including names it cannot own. Verify this on the real site too before treating it as a red flag.',
  'note.strictRejected':
    'SNI "invalid2.invalid" is rejected, so a scanner that only sends that name will report this node as having no valid certificate.',
  'note.allLookalike': 'every accepted name is served with a certificate that is not publicly trusted.',
  'note.weakCover': 'no strong cover identity found on this node.',
  'note.redacted': 'operator details were redacted from this report on request.',

  // --- rejected ------------------------------------------------------------
  'rejected.heading': 'Names rejected by the node',

  // --- score components ----------------------------------------------------
  'score.certGenuine': 'certificate chain verified offline against the public trust store',
  'score.certForged': 'certificate is NOT anchored in a public trust store (lookalike identity)',
  'score.fpMatch': 'leaf fingerprint is byte-identical to the real site',
  'score.fpDiffer': 'leaf fingerprint differs from the real site',
  'score.fpUnknown': 'no reference fingerprint available (real hostname not resolvable from here)',
  'score.forwardIdentical': 'proxied content is byte-identical to the real site',
  'score.forwardComparable': 'proxied response matches the real site on status and size',
  'score.forwardError': 'could not verify the forward path through the node',
  'score.forwardNone': 'forward path not verified',
  'score.forwardNotComparable': 'forward path was checked but is not comparable: status, size or body hash differs from the real site',
  'score.stableAll': 'handshake succeeded on every attempt',
  'score.stableMost': 'handshake mostly stable ({rate})',
  'score.unstable': 'handshake unreliable ({rate})',
  'score.deterministic': 'identical certificate on every attempt',
  'score.varying': 'presented certificate varies between attempts',
  'score.validLong': 'certificate valid for another {days} days',
  'score.validShort': 'certificate valid for another {days} days',
  'score.expiring': 'certificate expires in {days} days',
  'score.groupMatch': 'offers the same key exchange group as the real site ({group})',
  'score.groupDiffer': 'key exchange group differs from the real site ({via} vs {reference})',

  // --- method / caveats ----------------------------------------------------
  'method.heading': 'Method',
  'method.step1': '**Whitelist mapping** — raw TLS handshakes with each candidate as SNI, recording only whether the handshake completes.',
  'method.step2': '**Identity check** — the presented chain is verified **offline** against Node’s bundled trust store: validity windows, signature links, and a trusted anchor.',
  'method.step3': '**Operator identification** — the node address and the real service address are resolved to an ASN and organisation.',
  'method.step4': '**Forward verification** — one request goes to the node’s address with the candidate as both SNI and {code}, and the same request to the real site’s own address; status, length and body SHA-256 are compared.',
  'method.controls': 'Control probes (no SNI, {code}, a random undeclared name) establish what the node does with names it does not own.',

  'caveats.heading': 'Caveats',
  'caveat.chain': 'A verified chain proves the node presents the genuine certificate, **not** that it is the genuine operator. A node that transparently forwards to the real site is indistinguishable here from the real site itself — by design.',
  'caveat.sample': 'Sample sizes are small. Scores rank names on one node against each other; they are not absolute safety guarantees.',
  'caveat.personalised': 'Landing pages are often personalised. Static asset hashes are stronger evidence; add them with {code}.',
  'caveat.vantage': 'Reachability from this vantage point says nothing about blocking from the client’s network.',

  // --- appendix ------------------------------------------------------------
  'appendix.heading': 'Appendix',
  'appendix.detail': 'Per-name detail',
  'appendix.noDeep': 'Run without {code} to collect certificate, latency and forward-verification detail.',

  // --- transport / dead ends ----------------------------------------------
  'transport.heading': 'Details',
  'result.heading': 'Result',
  'result.noHandshake': 'No TLS handshake completed, with or without SNI.',
  'unreachable.message':
    'no TLS handshake completed, with or without SNI: {error}. The node may be down, firewalled, or not speaking TLS on this port.',
  'noCandidates.message':
    'the node completes a handshake but accepts none of the {tested} tested names. It likely whitelists a different set; pass --server-names with the names it is configured for.',

// --- progress (TUI and stderr) -------------------------------------------
  'progress.controls': 'control probes (no SNI, invalid2.invalid, random name)',
  'progress.discovery': 'probing {count} candidate names',
  'progress.deep': 'verifying {count} accepted names',
  'progress.catchall': 'checking whether the real site also serves a catch-all certificate',
  'progress.hoster': 'identifying the operator and checking for domain masking',
  'progress.scanning': 'scanning (non-interactive: progress goes to stderr)',
  'progress.detached': 'UI detached; the scan is still running and the report will be written.',
  'progress.wrote': 'wrote {path}',
  'progress.discoveryShort': 'discovery {done}/{total}',
  'progress.deepShort': 'deep {index}/{total} {name}',
  'progress.unreachableShort': 'unreachable: {message}',

// --- CLI -----------------------------------------------------------------
  'cli.error': 'error',
  'cli.unknownLocale': 'unknown language "{lang}"; available: {list}',

  'help.summary': 'sni-recon — find a defensible SNI cover identity for a TLS node',
  'help.usageHeading': 'USAGE',
  'help.whatHeading': 'WHAT IT DOES',
  'help.what1': 'Maps which candidate names the node accepts as SNI.',
  'help.what2': 'Verifies each accepted certificate OFFLINE against the public trust store.',
  'help.what3': 'Identifies the hosting operator behind the address (ASN, org, datacenter flag).',
  'help.what4': 'Compares proxied content byte-for-byte with the real site.',
  'help.what5': 'Reports whether the node is masking a domain it does not own.',
  'help.optionsHeading': 'OPTIONS',
  'help.optServerNames': 'Test exactly these names instead of the built-in corpus.',
  'help.optCandidates': 'Add these names to the chosen corpus.',
  'help.optFast': 'Use the 20-name quick corpus.',
  'help.optRegional': 'Add region-specific names (RU and others).',
  'help.optPort': 'Target port (default 443).',
  'help.optTimeout': 'Per-operation timeout (default 8000).',
  'help.optConcurrency': 'Parallel handshakes during discovery (default 10).',
  'help.optRepeat': 'Handshakes per name for the stability sample (default 5).',
  'help.optMaxDeep': 'How many accepted names get full analysis (default 10).',
  'help.optAssets': 'Static asset paths compared byte-for-byte, e.g. /favicon.ico',
  'help.optNoReference': 'Skip comparison against the real site (discovery only).',
  'help.optNoDeep': 'Map the whitelist only; skip per-name detail.',
  'help.optNoHoster': 'Skip operator lookup and masking verdict.',
  'help.optNoFollow': 'Do not follow redirects.',
  'help.optNoOperatorDetails': 'Blank the operator name, ASN and location in the report, keeping every verdict.',
  'help.optTui': 'Force the interactive UI on or off.',
  'help.optLang': 'Report and interface language. Available: {list}',
  'help.optFormat': 'Output format (default text).',
  'help.optWidth': 'Wrap the report to this many columns (default: terminal width).',
  'help.optJson': 'Shorthand for --format json.',
  'help.optOut': "Write the report to a file ('-' for stdout).",
  'help.optListCandidates': 'Print the built-in corpus and exit.',
  'help.optQuiet': 'Suppress progress output.',
  'help.optVerbose': 'Print progress detail to stderr.',
  'help.optHelp': 'Show this help.',
  'help.optVersion': 'Show the version.',
  'help.exitHeading': 'EXIT CODES',
  'help.exitCodes': '0 success  ·  1 node unreachable or no cover name  ·  2 usage error',
  'help.safetyHeading': 'SAFETY',
  'help.safety': 'Read-only: TLS handshakes and GET requests only. Point it at infrastructure you own or are authorised to test.',

  // --- TUI -----------------------------------------------------------------
  'tui.title': 'SNI cover analysis',
  'tui.target': 'target',
  'tui.operator': 'operator',
  'tui.phase': 'phase',
  'tui.phase.starting': 'starting',
  'tui.phase.complete': 'complete',
  'tui.whitelist': 'whitelist',
  'tui.probed': 'probed',
  'tui.accepted': 'accepted',
  'tui.deep': 'deep',
  'tui.candidate': 'candidate',
  'tui.presentedAs': 'presented as',
  'tui.certificate': 'certificate',
  'tui.forward': 'forward',
  'tui.score': 'score',
  'tui.ms': 'ms',
  'tui.pending': 'pending',
  'tui.genuine': 'genuine',
  'tui.lookalike': 'lookalike',
  'tui.invalid': 'invalid',
  'tui.recent': 'recent probe results',
  'tui.waiting': 'waiting for the first results…',
  'tui.earlier': '{n} earlier candidates',
  'tui.recommended': 'recommended SNI',
  'tui.noName': 'no usable cover name found',
  'tui.note': 'note',
  'tui.quit': 'report below · press q to exit',
  'tui.detachHint': 'q detach UI (scan continues) · ctrl-c abort',
  'tui.datacenter': 'datacenter',
  'tui.notDatacenter': 'not a datacenter',

// --- self test -----------------------------------------------------------
  'selftest.heading': 'selftest',
  'selftest.pass': 'PASS',
  'selftest.fail': 'FAIL',
  'selftest.summary': '{passed}/{total} checks passed',
  'selftest.fixturesMissing': 'selftest: fixtures missing. Generate them with: npm run fixtures',
  'selftest.fixtureLoads': 'fixture certificate loads',
  'selftest.fixtureNotTrusted': 'fixture certificate is NOT in the public trust store',
  'selftest.forgedAccepted': 'forged node: both configured names accepted',
  'selftest.forgedUntrusted': 'forged node: certificate is flagged as not publicly trusted',
  'selftest.forgedLookalike': 'forged node: verdict is a lookalike identity, not genuine',
  'selftest.forgedCatchall': 'forged node: random undeclared name is accepted (catch-all)',
  'selftest.maskingForged': 'masking: forged certificate identified',
  'selftest.maskingHigh': 'masking: confidence is high',
  'selftest.maskingOperator': 'masking: operator mismatch recorded',
  'selftest.maskingEvidenceLocalised': 'masking: evidence is structured, not pre-formatted prose',
  'selftest.catchallGeneric': 'catch-all node: single certificate served for every SNI',
  'selftest.mdRenders': 'markdown report renders',
  'selftest.mdMasking': 'markdown report includes the masking section',
  'selftest.mdConfig': 'markdown report recommends a configuration',
  'selftest.mdConclusionFirst': 'markdown report puts the conclusion before the method',
  'selftest.txtRenders': 'text report renders',
  'selftest.jsonParses': 'json report parses',
  'selftest.localeParity': 'every locale defines every key',
  'selftest.localeNoKeyLeak': 'no locale leaks a raw message key into a report',
  'selftest.ruReportIsRussian': 'the Russian report is actually Russian',
  'selftest.redaction': 'redaction blanks operator fields',
  'selftest.redactionKeepsVerdicts': 'redaction leaves every verdict intact',
  'selftest.redactionNoLeak': 'redacted report no longer names the operator',
  'selftest.scoring': 'scoring: a genuine identity outranks a forged one',
  'selftest.detail.forgedStandIn': 'this is what makes it a usable stand-in for a forged identity',
  'selftest.detail.noAnchor': 'every candidate lacks a trusted anchor',
  'selftest.detail.chainRejects': 'offline chain verification rejects it',
  'selftest.detail.answersEverySni': 'the listener answers every SNI',
  'selftest.detail.nodeVsReference': 'node vs reference operator',
  'selftest.detail.structuredEvidence': 'evidence carries a key and parameters',
  'selftest.detail.answerFirst': 'the answer precedes the methodology',
  'selftest.detail.fieldsBlanked': 'fields blanked',
  'selftest.detail.verdictsIntact': 'same verdict and score before and after redaction',
  'selftest.detail.operatorGone': 'operator name and location absent from the rendered report',
  'selftest.textFramed': 'the text report is drawn as a frame',
  'selftest.textFitsWidth': 'no line of the text report exceeds the requested width',
  'selftest.textNarrow': 'a narrow Russian report still fits its width',
  'selftest.envLangRoundTrip': 'the remembered language round-trips through .env',
  'selftest.envLangPreserves': 'writing the language leaves unrelated .env lines intact',
  'selftest.envMissingIsEmpty': 'a missing .env is empty, not an error',
  'selftest.detail.unrelatedIntact': 'commented and unrelated assignments survive',


  'selftest.redactionNonDestructive': 'redaction does not modify the analysis result',
  'selftest.detail.sourceIntact': 'the caller’s hoster records were left untouched',
  'selftest.mdNoConfigForWeak': 'markdown report withholds a configuration for a weak name',
  'selftest.detail.noConfigForWeak': 'a poor score must not be presented as a recommendation',
// --- plain-text report -----------------------------------------------
  'text.summary': 'Conclusion',
  'progressSection': 'Progress and stability',
  'verdictSection': 'Verdict',
  'text.recommend': 'Recommended SNI',
  'text.score': 'Score',
  'text.certificate': 'Certificate',
  'text.forward': 'Forwarding',

  // --- language prompt / persistence ---------------------------------------
  'lang.prompt': 'Choose interface language',
  'lang.default': 'default',
  'lang.remember': 'The choice is saved to .env and used by every later run. Pass --lang to override it once.',
  'lang.saved': 'interface language saved to {path}',

  'tui.more': '{above} above · {below} below',
  'tui.help.title': 'Keys',
  'tui.help.body': '↑ ↓ move between names · PgUp PgDn page · Home End jump · c print the configuration again · ? this help · q detach (the scan keeps running) · ctrl-c abort',
  'tui.help.close': '? or q closes this help',

  // --- misc ----------------------------------------------------------------
  'misc.na': 'n/a',
  'misc.yes': 'yes',
  'misc.no': 'no',
  'misc.unknown': 'unknown',
  'misc.redacted': 'redacted'
};
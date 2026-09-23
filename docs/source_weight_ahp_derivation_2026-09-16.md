# AHP Source-Weight Derivation — 2026-09-16

Status: `AHP_DERIVED_ADMISSION_AWARE`

This document derives source-specific scoring multipliers with the Analytic
Hierarchy Process (AHP), using Saaty's 1–9 pairwise scale. It is a documented
judgment model, not a statistically fitted weight model. The three criteria
have equal importance (`1/3` each).

## Scope and admission decision

The AHP comparison includes seven sources:

`feodotracker`, `c2_trackers`, `spamhaus`, `tor_exit_nodes`,
`sslblacklist`, `threatfox`, and `virustotal`.

Production admission is a separate gate from the AHP ranking:

| Source | AHP status | Production status |
|---|---|---|
| `feodotracker` | included | active scoring |
| `c2_trackers` | included | active scoring |
| `spamhaus` | included | active scoring |
| `tor_exit_nodes` | included | active scoring |
| `sslblacklist` | included | active scoring |
| `threatfox` | included | active scoring, with timeout fallback |
| `virustotal` | included | report-only pending local telemetry |

ThreatFox has three-window operational telemetry of 720/720 successful calls.
This is historical reliability evidence from 2026-09-15, collected before the
CV allowlist was later restricted to non-API sources. The reliability sampling
itself explicitly included ThreatFox. Operational success does not establish
detection correctness.

VirusTotal has no local reliability telemetry in the available three-window
collection. Its AHP judgments use vendor documentation only. Its Public API
limits are documented separately from the AHP criteria.

## Evidence register

- [F1 — Feodo Tracker Blocklist](https://feodotracker.abuse.ch/blocklist/)
- [F2 — Feodo Tracker FAQ](https://feodotracker.abuse.ch/faq/)
- [C1 — montysecurity C2-Tracker](https://github.com/montysecurity/C2-Tracker)
- [C2 — C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds)
- [S1 — Spamhaus dataset documentation](https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/030-datasets.html)
- [S2 — Spamhaus data anatomy](https://docs.spamhaus.com/sia/docs/source/02-data-explained/data-anatomy.html)
- [S3 — Spamhaus listing removals](https://www.spamhaus.com/faqs/listing-removals/)
- [T1 — Tor Exit List Service](https://blog.torproject.org/changes-tor-exit-list-service/)
- [T2 — Tor relay types](https://community.torproject.org/relay/types-of-relays/)
- [L1 — SSLBL About](https://sslbl.abuse.ch/about/)
- [L2 — SSLBL Blacklist](https://sslbl.abuse.ch/blacklist/)
- [X1 — ThreatFox About](https://threatfox.abuse.ch/about/)
- [X2 — ThreatFox Community API](https://threatfox.abuse.ch/api/)
- [X3 — ThreatFox exports](https://threatfox.abuse.ch/export/)
- [V1 — VirusTotal How it works](https://docs.virustotal.com/docs/how-it-works)
- [V2 — VirusTotal false positives](https://docs.virustotal.com/docs/false-positive)
- [V3 — VirusTotal antivirus-statistics limitations](https://docs.virustotal.com/docs/antivirus-stats)
- [V4 — VirusTotal Public vs Premium API](https://docs.virustotal.com/reference/public-vs-premium-api)

## Criterion 1 — Verification rigor

Interpretation: strength of the source's documented process for confirming an
IOC before publication. Relay membership, scanner detection, and community
submission are not treated as equivalent to direct C2 confirmation.

Matrix order: `F, C, S, T, L, X, V`.

```text
      F    C    S    T    L    X    V
F     1    5    3    9    3    3    3
C   1/5    1  1/2    5  1/2    1  1/2
S   1/3    2    1    5    2    2    1
T   1/9  1/5  1/5    1  1/5  1/3  1/3
L   1/3    2  1/2    5    1    2    1
X   1/3    1  1/2    3  1/2    1  1/2
V   1/3    2    1    3    1    2    1
```

Non-equal judgments and source evidence:

- `F>C=5`: Feodo requires a valid botnet-C2 response; C2 feeds include community scanning and verified/unverified subsets [F1][C2].
- `F>S=3`: Feodo uses direct C2 confirmation; Spamhaus has formal governance but multiple dataset semantics [F1][S1][S3].
- `F>T=9`: Tor confirms active exit-relay status, not maliciousness [F1][T1][T2].
- `F>L=3`: Feodo confirms C2 behavior directly; SSLBL records C2-associated certificates/JA3 [F1][L1][L2].
- `F>X=3`: ThreatFox requires confirmed/vetted submissions but is independently crowdsourced [F1][X1][X2].
- `F>V=3`: VirusTotal aggregates scanners and does not create its own verdict [F1][V1][V2][V3].
- `S>C=2`: Spamhaus has more formal listing/removal controls than community C2 feeds [S1][S3][C1][C2].
- `C>T=5`: verified C2 feeds add validation beyond Tor's relay-role measurement [C2][T1].
- `L>C=2`: SSLBL provides listing reason and certificate/C2 context [L1][L2][C2].
- `V>C=2`: VT's multi-engine evidence is stronger than an unverified C2-feed record [V1][V2][C2].
- `S>T=5`: Spamhaus listing governance is stronger than Tor's non-malicious relay classification [S1][S3][T1].
- `S>L=2`: Spamhaus has clearer formal removal governance; SSLBL is a best-effort collection [S3][L1][L2].
- `S>X=2`: Spamhaus has more formal list governance than crowdsourced ThreatFox [S1][S3][X1][X2].
- `L>T=5`: SSLBL contains malware-C2 association evidence; Tor contains exit status [L1][L2][T1].
- `X>T=3`: ThreatFox requires confirmed/vetted IOC submission; Tor does not verify threat intent [X2][T1][T2].
- `V>T=3`: VT has multiple detection engines; Tor is not a maliciousness verdict [V1][V2][T1].
- `L>X=2`: SSLBL provides technical C2 evidence; ThreatFox is broader crowdsourced IOC data [L1][L2][X1][X2].
- `V>X=2`: VT combines many scanners; ThreatFox publishes submitted IOC records [V1][V2][X1][X2].

Priority vector:

| Source | Priority |
|---|---:|
| feodotracker | 0.3647910404 |
| c2_trackers | 0.0852297391 |
| spamhaus | 0.1643469303 |
| tor_exit_nodes | 0.0307901795 |
| sslblacklist | 0.1342746505 |
| threatfox | 0.0834317007 |
| virustotal | 0.1371357595 |

`lambda_max=7.1975958397`, `CI=0.0329326400`, `CR=0.0249489697`.

## Criterion 2 — Specificity of scope

Interpretation: how narrowly the source targets a defined threat or IOC scope,
not whether that scope is inherently malicious.

```text
      F    C    S    T    L    X    V
F     1    2    5    3    2    5    7
C   1/2    1    3  1/2  1/2    3    5
S   1/5  1/3    1  1/5  1/3    3    5
T   1/3    2    5    1  1/2    3    5
L   1/2    2    3    2    1    3    5
X   1/5  1/3  1/3  1/3  1/3    1    2
V   1/7  1/5  1/5  1/5  1/5  1/2    1
```

Non-equal judgments and source evidence:

- `F>C=2`: Feodo targets botnet-C2 IPs; C2 feeds cover C2 infrastructure, tools, and botnets [F1][C2].
- `F>S=5`: Spamhaus combines multiple reputation datasets [F1][S1].
- `F>T=3`: Feodo is threat-specific; Tor is relay-role-specific [F1][T1].
- `F>L=2`: Feodo identifies C2 IPs; SSLBL identifies certificates/JA3 artifacts [F1][L1].
- `F>X=5`: ThreatFox supports IP, domain, URL, and hash threat types [F1][X2].
- `F>V=7`: VT covers files, URLs, domains, and IPs [F1][V1].
- `C>S=3`: C2 tracker scope is narrower than Spamhaus's multiple dataset types [C2][S1].
- `C>T=2`: C2 trackers identify threat infrastructure; Tor identifies relay function [C2][T1].
- `L>C=2`: SSLBL is restricted to C2-associated certificate/JA3 artifacts [L1][L2][C2].
- `C>X=3`: C2 tracker scope is narrower than ThreatFox's multiple IOC types [C2][X1][X2].
- `C>V=5`: C2 tracker scope is narrower than VT's resource coverage [C2][V1].
- `T>S=5`: Tor is limited to exit relays; Spamhaus spans multiple datasets [T1][S1].
- `L>S=3`: SSLBL is a focused botnet-C2 certificate feed [L1][S1].
- `X>S=3`: ThreatFox focuses on malware-associated IOCs; Spamhaus is broader [X2][S1].
- `L>T=2`: SSLBL is a malicious-C2 artifact feed; Tor is relay membership [L1][T1].
- `T>X=3`: Tor has one narrow relay scope; ThreatFox has multiple IOC/threat types [T1][X2].
- `T>V=5`: Tor is narrower than VT's multi-resource scope [T1][V1].
- `L>X=3`: SSLBL is certificate/JA3-specific; ThreatFox is broader [L1][X2].
- `L>V=5`: SSLBL is much narrower than VT [L1][V1].
- `V>X=2`: VT covers a broader set of resource types than ThreatFox [V1][X2].

Priority vector:

| Source | Priority |
|---|---:|
| feodotracker | 0.3198580888 |
| c2_trackers | 0.1365757259 |
| spamhaus | 0.0787379046 |
| tor_exit_nodes | 0.1808242810 |
| sslblacklist | 0.2047463141 |
| threatfox | 0.0498331211 |
| virustotal | 0.0294245645 |

`lambda_max=7.4839504622`, `CI=0.0806584104`, `CR=0.0611048563`.

## Criterion 3 — Maintenance and delisting policy

Interpretation: clarity and regularity of refresh, expiry, validity, and
removal behavior.

```text
      F    C    S    T    L    X    V
F     1    5    2    2    1    3    2
C   1/5    1  1/3  1/2  1/3  1/2  1/2
S   1/2    3    1    2    1    3    2
T   1/2    2  1/2    1  1/2    2    2
L     1    3    1    2    1    3    2
X   1/3    2  1/3  1/2  1/3    1    1
V   1/2    2  1/2  1/2  1/2    1    1
```

Non-equal judgments and source evidence:

- `F>C=5`: Feodo refreshes every 5 minutes and publishes active/time-window lists; C2 updates are less uniform [F1][C1][C2].
- `F>S=2`: Feodo cadence is more frequent; Spamhaus re-evaluates listings several times per day and exposes validity/removal controls [F1][S2][S3].
- `F>T=2`: Feodo exposes explicit active/past windows; Tor uses active measurements without malicious delisting semantics [F1][T1].
- `F>X=3`: ThreatFox expires IOCs older than 6 months, but has less granular active-window semantics [F1][X2][X3].
- `F>V=2`: VT updates dynamically, but has no centralized blocklist delisting policy [F1][V1][V2].
- `S>C=3`: Spamhaus provides validity and formal removal procedures [S2][S3][C1][C2].
- `T>C=2`: Tor's list is maintained from active measurements; C2 coverage is less uniform [T1][C1][C2].
- `L>C=3`: SSLBL has 5-minute generation and first/last-seen/listing metadata [L2][C1][C2].
- `X>C=2`: ThreatFox has six-month expiry and export filtering [X2][X3][C2].
- `V>C=2`: VT vendor/signature updates are dynamic; C2 feeds can be weekly or archived [V1][C1][C2].
- `S>T=2`: Spamhaus has explicit validity/removal controls [S2][S3][T1].
- `S>X=3`: Spamhaus lifecycle governance is more explicit than ThreatFox's expiry-only boundary [S2][S3][X2].
- `S>V=2`: Spamhaus has list lifecycle controls; VT is a dynamic detection aggregation [S2][S3][V1][V2].
- `L>T=2`: SSLBL has listing date/last-seen metadata and fixed generation cadence [L2][T1].
- `T>X=2`: Tor uses active measurements; ThreatFox can retain records until six-month expiry [T1][X2].
- `T>V=2`: Tor's active/inactive semantics are clearer than VT's changing detection ratio [T1][V1].
- `L>X=3`: SSLBL has listing metadata and cadence; ThreatFox relies mainly on expiry [L2][X2][X3].
- `L>V=2`: SSLBL has an explicit blacklist lifecycle; VT has vendor-specific changes [L2][V1][V2].

Priority vector:

| Source | Priority |
|---|---:|
| feodotracker | 0.2496967886 |
| c2_trackers | 0.0540246177 |
| spamhaus | 0.1904078224 |
| tor_exit_nodes | 0.1262947716 |
| sslblacklist | 0.2078943258 |
| threatfox | 0.0782775067 |
| virustotal | 0.0934041672 |

`lambda_max=7.1397003340`, `CI=0.0232833890`, `CR=0.0176389311`.

## Equal-weight aggregation and multiplier mapping

The three criterion vectors are averaged with weights `1/3, 1/3, 1/3`.
The resulting priority vector is then scaled by:

```text
scale_factor = 1.5 / 0.3114486393 = 4.8162034144
```

This preserves the former maximum score multiplier while replacing the
unsupported intermediate constants with proportional AHP-derived values.

| Source | Combined priority | AHP multiplier | Admission |
|---|---:|---:|---|
| feodotracker | 0.3114486393 | 1.500000 | active scoring |
| sslblacklist | 0.1823050968 | 0.878018 | active scoring |
| spamhaus | 0.1444975524 | 0.695930 | active scoring |
| tor_exit_nodes | 0.1126364107 | 0.542480 | active scoring |
| c2_trackers | 0.0919433609 | 0.442818 | active scoring |
| virustotal | 0.0866548304 | 0.417347 | report-only |
| threatfox | 0.0705141095 | 0.339610 | active scoring |

These are AHP-derived weights, not statistically fitted weights. They must not
be interpreted as calibrated probabilities or as proof of detection accuracy.

## Notable rank changes from legacy mapping

### Tor versus C2 Trackers

`tor_exit_nodes` receives a higher multiplier than `c2_trackers`
(`0.542480` versus `0.442818`) even though the legacy policy treated Tor as a
Low/context source. This is not an error. Tor receives a high specificity
priority because its scope is narrowly limited to exit relays. At the same
time, its verification-rigor priority is the lowest in the matrices:

```text
F > T = 9
```

This result is a documented trade-off between specificity and verification
rigor, not a claim that Tor exit status proves maliciousness.

### ThreatFox admission versus weight

ThreatFox receives the lowest multiplier among the seven sources (`0.339610`)
even though it has been admitted to active scoring. It loses comparatively on
all three criteria because it is crowdsourced, has broader IOC scope, and has
less granular maintenance semantics than the strongest feeds.

Admission is a different question from relative weight. ThreatFox passed the
admission evidence gate through 720/720 successful calls in the measured
workload, documented confirmed/vetted submission requirements, and a documented
six-month expiry policy. That is sufficient to use it as an active source with
fallback handling, but it does not make it the highest-quality source in the
AHP comparison.

## Availability and timeout constraint — separate from AHP

The reliability telemetry recorded ThreatFox latency as follows:

| Metric | Value |
|---|---:|
| Rows | 720 |
| Success | 720 |
| Latency above current 15s pipeline deadline | 2 (`0.277778%`) |
| Both slow rows | URL type, malicious-labelled |
| Maximum latency | 20,478.0 ms |

The collection runner called ThreatFox directly with the HTTP client's 30s
configuration timeout, so the two rows above were recorded as successful. The
production investigation wrapper has a 15s per-source deadline.

For ThreatFox, production timeout behavior is therefore:

1. mark the source `unavailable`;
2. do not retry;
3. do not block the investigation pipeline;
4. exclude the source from that round's score calculation; and
5. never interpret the missing result as clean.

VirusTotal remains report-only because local reliability telemetry is absent and
the official Public API limit is 4 requests/minute and 500 requests/day [V4].
Those availability constraints are not mixed into the three AHP pairwise
criteria.

## No unknown-source fallback

There is no AHP or production fallback multiplier for unknown/untiered sources.
Sources outside the admitted six-source set, including VirusTotal, remain
report-only until a separate admission decision is made.

[F1]: https://feodotracker.abuse.ch/blocklist/ "Feodo Tracker Blocklist"
[F2]: https://feodotracker.abuse.ch/faq/ "Feodo Tracker FAQ"
[C1]: https://github.com/montysecurity/C2-Tracker "montysecurity C2-Tracker"
[C2]: https://github.com/drb-ra/C2IntelFeeds "C2IntelFeeds"
[S1]: https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/030-datasets.html "Spamhaus datasets"
[S2]: https://docs.spamhaus.com/sia/docs/source/02-data-explained/data-anatomy.html "Spamhaus data anatomy"
[S3]: https://www.spamhaus.com/faqs/listing-removals/ "Spamhaus listing removals"
[T1]: https://blog.torproject.org/changes-tor-exit-list-service/ "Tor Exit List Service"
[T2]: https://community.torproject.org/relay/types-of-relays/ "Tor relay types"
[L1]: https://sslbl.abuse.ch/about/ "SSLBL About"
[L2]: https://sslbl.abuse.ch/blacklist/ "SSLBL Blacklist"
[X1]: https://threatfox.abuse.ch/about/ "ThreatFox About"
[X2]: https://threatfox.abuse.ch/api/ "ThreatFox Community API"
[X3]: https://threatfox.abuse.ch/export/ "ThreatFox exports"
[V1]: https://docs.virustotal.com/docs/how-it-works "VirusTotal How it works"
[V2]: https://docs.virustotal.com/docs/false-positive "VirusTotal false positives"
[V3]: https://docs.virustotal.com/docs/antivirus-stats "VirusTotal antivirus-statistics limitations"
[V4]: https://docs.virustotal.com/reference/public-vs-premium-api "VirusTotal Public vs Premium API"

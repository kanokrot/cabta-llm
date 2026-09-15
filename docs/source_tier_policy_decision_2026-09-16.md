# Source Tier Policy Decision — 2026-09-16

Status: `POLICY_FROZEN_PRODUCTION_MAPPING_UNCHANGED`

This document closes the current tier decision without changing
`src/scoring/intelligent_scoring.py`.  Three separate axes are retained:

1. **Nominal scoring tier** — the existing multiplier used by the legacy
   scorer: High `1.5`, Medium `1.0`, Low `0.5`.
2. **Production eligibility** — whether the source is in the Group-A critical
   path or the Group-B supplemental/excluded path.
3. **Evidence status** — operational/content evidence available for review;
   it is not silently converted into a learned weight.

## Frozen nominal mapping

| Nominal tier | Existing multiplier | Sources | Decision |
|---|---:|---|---|
| High | 1.5 | `virustotal`, `abuseipdb`, `feodotracker`, `threatfox`, `malwarebazaar` | Keep unchanged |
| Medium | 1.0 | `alienvault`, `urlhaus`, `c2_trackers`, `greynoise`, `shodan`, `criminalip`, `ipqualityscore`, `spamhaus`, `pulsedive`, `censys`, `ip2proxy`, `threatzone`, `triage`, `usom` | Keep unchanged |
| Low | 0.5 | `tor_exit_nodes`, `circl`, `phishtank`, `sslblacklist` | Keep unchanged |
| Untiered fallback | 0.8 | `smet_nrd`, `hagezi_nrd`, `mb_recent_sha256`, `misp_circl_feed_osint`, `talos`, and unknown sources | Keep fallback unchanged; no promotion |

The fallback is deliberately recorded as `UNTIERED`, not presented as a
validated confidence tier.

## Production eligibility boundary

The following sources remain Group-B excluded from the critical production
aggregate, independent of their nominal tier:

```text
virustotal, abuseipdb, shodan, alienvault, greynoise, censys,
pulsedive, criminalip, ipqualityscore, phishtank, ip2proxy,
triage, threatzone
```

This means a source can retain a nominal High/Medium/Low mapping for backward
compatibility while still being supplemental or excluded operationally.  No
Group-A/B boundary was changed by this decision.

## Evidence used for the decision

- Three valid reliability windows aggregated to `9,375` rows and `3,615`
  executable non-Talos rows, with `3,614` successes and one MalwareBazaar 5xx
  failure.  This is operational completion evidence, not detection ground
  truth.
- Source-specific live controls passed for FeodoTracker, Tor, SSLBL SHA1, and
  USOM.  These controls establish integration behavior, not learned source
  weights.
- Six-source CV and same-dataset holdout/calibration remain exploratory.  The
  internal calibration gate did not pass for production use.
- The independent public-data proxy holdout is balanced and disjoint, but its
  clean labels are proxy labels.  Its source-overlap results were: Spamhaus
  `18/120`, C2 Trackers `7/180`, FeodoTracker `0/120`, Tor `0/120`, USOM
  `0/180`, and SSLBL SHA1 `0/60`; SSLBL IP is deprecated/unavailable.
- CIRCL Passive DNS is a permanent CV exclusion because partner authorization
  is unavailable.  Its nominal legacy Low mapping remains unchanged solely to
  preserve production behavior.

## Final decision

- The current production tier mapping is accepted as the frozen policy for the
  deadline deliverable.
- No learned coefficient replaces any nominal multiplier.
- No source is promoted or demoted based on the inadequate proxy holdout.
- The six-source coefficients remain `preliminary_signal_only`.
- Future learned weights require a labelled dataset with independent labels and
  source-specific feature variance; another popularity list alone does not
  satisfy that requirement.

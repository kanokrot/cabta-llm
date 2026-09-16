# Source Tier Policy Decision — 2026-09-16

Status: `POLICY_UPDATED_AHP_SCORING`

## Active scoring amendment — AHP-derived source multipliers

The active production IOC scorer admits six explicitly approved sources. The
source-specific multipliers below are derived from the seven-source AHP model
in [`docs/source_weight_ahp_derivation_2026-09-16.md`](source_weight_ahp_derivation_2026-09-16.md).
Admission is a separate availability/evidence gate from the AHP ranking.

| Source | AHP-derived multiplier | Production status |
|---|---:|---|
| `feodotracker` | 1.500000 | active scoring |
| `sslblacklist` | 0.878018 | active scoring |
| `spamhaus` | 0.695930 | active scoring |
| `tor_exit_nodes` | 0.542480 | active scoring |
| `c2_trackers` | 0.442818 | active scoring |
| `threatfox` | 0.339610 | active scoring with timeout fallback |
| `virustotal` | 0.417347 | report-only; admission gate not passed |

The AHP comparison includes VirusTotal so its documented evidence and relative
priority remain auditable. Its multiplier is not used by production scoring.

There is no unknown-source fallback in the active scorer. A source must have
an explicit AHP-derived multiplier and pass the separate admission policy before
it can score. Unavailable or stale results are not converted into clean
evidence.

ThreatFox timeout handling uses the existing 15-second per-source deadline:
timeout → `unavailable`, no retry, no pipeline block, and exclusion from that
round's score calculation. The result is never interpreted as clean.
Unavailable or stale results are not converted into clean evidence.

The original API-inclusive mapping below is retained as historical policy
context only; it is not the active scoring configuration.

The following section is retained as historical context from the former
API-inclusive scorer. The active policy is the feed-only amendment above.
Three separate axes are retained:

1. **Nominal scoring tier** — the existing multiplier used by the legacy
   scorer: High `1.5`, Medium `1.0`, Low `0.5`.
2. **Production eligibility** — whether the source is in the Group-A critical
   path or the Group-B supplemental/excluded path.
3. **Evidence status** — operational/content evidence available for review;
   it is not silently converted into a learned weight.

## Historical API-inclusive mapping (not active)

| Nominal tier | Existing multiplier | Sources | Decision |
|---|---:|---|---|
| High | 1.5 | `virustotal`, `abuseipdb`, `feodotracker`, `threatfox`, `malwarebazaar` | Keep unchanged |
| Medium | 1.0 | `alienvault`, `urlhaus`, `c2_trackers`, `greynoise`, `shodan`, `criminalip`, `ipqualityscore`, `spamhaus`, `pulsedive`, `censys`, `ip2proxy`, `threatzone`, `triage`, `usom` | Keep unchanged |
| Low | 0.5 | `tor_exit_nodes`, `circl`, `phishtank`, `sslblacklist` | Keep unchanged |
| Untiered fallback | 0.8 | `smet_nrd`, `hagezi_nrd`, `mb_recent_sha256`, `misp_circl_feed_osint`, `talos`, and unknown sources | Keep fallback unchanged; no promotion |

The fallback is deliberately recorded as `UNTIERED`, not presented as a
validated confidence tier.

## Historical Group-B eligibility boundary

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
- The historical six-source CV and same-dataset holdout/calibration remain exploratory.  The
  internal calibration gate did not pass for production use.
- The independent public-data proxy holdout is balanced and disjoint, but its
  clean labels are proxy labels.  Its source-overlap results were: Spamhaus
  `18/120`, C2 Trackers `7/180`, FeodoTracker `0/120`, Tor `0/120`, USOM
  `0/180`, and SSLBL SHA1 `0/60`; SSLBL IP is deprecated/unavailable.
- CIRCL Passive DNS is a permanent CV exclusion because partner authorization
  is unavailable.  Its nominal legacy Low mapping remains unchanged solely to
  preserve production behavior.

## AHP decision and limitations

- The three AHP criteria are verification rigor, specificity of scope, and
  maintenance/delisting policy, each weighted equally.
- Consistency ratios are `0.024949`, `0.061105`, and `0.017639`, all below
  `0.1`.
- ThreatFox telemetry contained `720/720` successful calls across three
  historical windows. Two rows (`2/720`, `0.277778%`) exceeded the current
  15-second production deadline; both were URL records. The telemetry runner
  used a 30-second HTTP client timeout, so this limitation is documented rather
  than hidden.
- VirusTotal has no local reliability telemetry. It remains report-only despite
  having an AHP-derived candidate multiplier; its official Public API limits
  are a separate availability constraint.

## Final decision

- The feed-only production admission and tier mapping above are the active
  policy for the deadline deliverable.
- AHP-derived multipliers replace the unsupported active legacy constants; they
  are documented judgments, not learned coefficients or calibrated
  probabilities.
- ThreatFox is admitted based on operational evidence and documented vetting/
  expiry controls, but its lower AHP weight is a separate relative-quality
  conclusion.
- VirusTotal remains report-only until local reliability telemetry is available.
- No source is promoted or demoted based on the inadequate proxy holdout; source
  admission and AHP ranking remain separate decisions.
- The prior statistical CV artifacts remain `preliminary_signal_only`.
- Future learned weights require a labelled dataset with independent labels and
  source-specific feature variance; another popularity list alone does not
  satisfy that requirement.

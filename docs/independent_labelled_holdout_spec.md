# Independent Labelled Holdout Specification

Status: `NOT_READY_FOR_WEIGHT_FIT`

This holdout is intended for source-weight validation only. It must remain
disjoint from `scripts/eval/eval_results_group_a_v2.jsonl` and from every
positive-control record used only to validate an integration.

## Target design

The first practical panel is 240 records with balanced labels:

| IOC stratum | MALICIOUS | CLEAN | Required source overlap |
|---|---:|---:|---|
| IPv4 | 60 | 60 | FeodoTracker, Tor, Spamhaus, C2 Trackers, USOM |
| SHA1 certificate hash | 30 | 30 | SSLBL certificate feed |
| Domain | 30 | 30 | USOM and C2 Trackers |
| **Total** | **120** | **120** | |

The same independently labelled malicious IOC may satisfy overlap requirements
for more than one target source. A source-positive intersection is evidence of
coverage, not the label itself.

## Label rules

- `MALICIOUS` requires an independent ground-truth provider, evidence URL or
  immutable evidence reference, confirmation date, and rationale. The source
  being measured cannot be the sole label provider.
- `CLEAN` means clean as of the collection timestamp with documented provenance;
  it is not an eternal-clean guarantee.
- Never use `found=false`, `not listed`, or a target source's negative response
  as a clean label.
- Candidate sources for malicious labels are independent public incident/feed
  providers such as MISP event evidence, with a second corroborating provider
  where available. Candidate sources must be recorded per record.
- Candidate sources for clean labels are independently documented known-good
  services/domains and their observed DNS/TLS material, with collection time
  and provenance recorded.

## Required record fields

Each final record must contain:

```json
{
  "record_id": "stable-id",
  "ioc": "indicator",
  "ioc_type": "ip|domain|sha1",
  "expected_label": "MALICIOUS|CLEAN",
  "label_provenance": {
    "provider": "independent-provider",
    "evidence_ref": "url-or-immutable-reference",
    "confirmation_date": "YYYY-MM-DD",
    "rationale": "why this is the label"
  },
  "selection_provenance": {
    "candidate_source": "provider-or-panel",
    "collected_at": "ISO-8601 UTC",
    "disjoint_from_group_a_eval": true
  },
  "target_source_overlap": {
    "feodotracker": false,
    "tor_exit_nodes": false,
    "sslblacklist": false,
    "usom": false,
    "spamhaus": false,
    "c2_trackers": false
  }
}
```

Target-source overlap fields are populated only after source calls or a
source-feed intersection check; they must never be copied into label
provenance.

## Current readiness audit

The current local material is insufficient for a final independent holdout:

- `evidence/reliability_sampling/reliability_sample_set_2026-09-15.json` is
  balanced at 120/120, but 150/240 records are from `benchmark_iocs_v2` and
  therefore cannot be reused as independent test records.
- `evidence/source_telemetry_2026-09-15/source_positive_controls_2026-09-15.json`
  contains live integration controls only. Those records are not model labels.
- The bounded MISP audit verified IOC-type coverage but intentionally did not
  persist IOC values, so it cannot directly populate this holdout.
- The current 894-record Group-A evaluation and all derived cache rows are
  excluded from this holdout by design.
- The latest observed Feodo feed snapshot contained only 5 usable IP entries;
  a 30-positive Feodo panel cannot be claimed from that snapshot alone.

The machine-readable gate result is recorded in
`evidence/source_weights_2026-09-16/independent_holdout_readiness_2026-09-16.json`.
Until the missing independent records and provenance are supplied, no new CV
fit or production weight change is authorized by this specification.

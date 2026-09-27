# Group A and VT-independent holdout results

This folder is a self-contained, reproducible snapshot of two evaluations. The
raw JSONL copies and the 221-record labeled holdout reference are included so a
reviewer can inspect the inputs directly. The metrics script uses only the
Python standard library and makes no network or VirusTotal calls.

## Reproduce

From this folder, run:

```text
python compute_metrics.py
```

Every count and metric is computed at runtime from the local files. The binary
metric convention is `MALICIOUS` as the positive class; all other verdicts are
the negative class. The Group A file contains `SUSPICIOUS` predictions, so
those predictions are counted as negative rather than excluded. The Group A
label/source field used by the filter is `source`.

## Why Group A has two numbers

The confirmed Group A source file contains 908 rows. Its `source` field records
the label/source provenance. The unfiltered result uses all 908 rows and is
the transparent all-label-sources result.

The headline Group A result applies the previously specified filter, excluding
rows whose `source` is exactly either:

```text
circl_misp_feed_osint
malwarebazaar_recent_detections
```

That leaves 694 rows and reproduces the previously reported `597/694`, or
86.023055%, result. The filtered result is the headline number requested for
this snapshot; the unfiltered result remains visible so the denominator and
effect of the filter are not hidden.

These names identify label/source values associated with the CIRCL MISP OSINT
feed and recent MalwareBazaar detections. The repository documents the source
names and their use as provenance, but the exact original rationale for
excluding these two sources from the headline metric is not yet documented.
The filter is retained because it reproduces the previously reported number;
it is not presented here as a newly established independence or quality claim.

## Why the VT-independent holdout exists

The Group A evaluation measures the production six-source scoring path against
source-backed labels, including ThreatFox in the broader Group A source set.
That creates a circularity concern when a label source is also part of the
scoring path.

The VT-independent holdout separates labels from the production six-source
scoring path. Its labels were assigned from VirusTotal reports using the locked
three-tier rule:

```text
EXCLUDED_ENGINES = {"MalwareURL", "Hunt.io Intelligence", "Criminal IP"}
0 non-excluded malicious engines  -> CLEAN
1-2 non-excluded malicious engines -> AMBIGUOUS
3+ non-excluded malicious engines  -> MALICIOUS
```

The 200-record holdout consists of the original 200-record holdout plus 21
usable batch-3 records. Batch 1 supplied ThreatFox-malicious candidates, batch
2 supplied a clean-pool control set, and batch 3 added malicious-candidate URLs
to close the URL-class gap. Ambiguous records and VT 404 records without
`last_analysis_results` were excluded from scoring. The included holdout is
therefore 94 CLEAN and 106 MALICIOUS scoring records.

## Final three-way headline comparison

These are the values computed by `compute_metrics.py` from the included raw
files:

| Evaluation | Records | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| Group A unfiltered / all label sources | 908 | 71.255507% | 1.000000 | 0.639004 | 0.779747 |
| Group A filtered / excluding the two named label sources | 694 | 86.023055% | 1.000000 | 0.809430 | 0.894680 |
| VT-independent holdout | 200 | 91.000000% | 0.968085 | 0.858491 | 0.910000 |

The script also prints the confusion counts and checks the filtered `597/694`
headline, reporting a discrepancy plainly if the live data do not produce it.

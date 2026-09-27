# Flow B/C Operational Metrics - 2026-09-27

## What this measures

This report measures operational behavior for two investigation flows:

- **Flow B**: `agent_loop.py` sessions where `playbook_id IS NULL`.
- **Flow C**: `playbook_engine.py` sessions where `playbook_id IS NOT NULL`.

The report defines three operational metrics in `compute_operational_metrics.py`:

- `step_success_rate`: successful recorded tool steps divided by recorded tool steps. Flow B uses successful `audit_log` tool-call rows; Flow C uses `agent_steps` tool-call rows whose JSON result does not contain an `error` key.
- `completion_rate`: sessions with `status='completed'` divided by sessions in the flow.
- `human_override_rate`: rejected approval decisions divided by completed approval decisions. A zero denominator is emitted as `0.000000` by the script, but it is not evidence that the measured rate is 0%.

The CSV also includes completion-rate breakdown rows for step-limit aborts and other non-completed sessions.

## How to reproduce

From the repository root, run the copied script against the live database:

```powershell
python evidence/operational_metrics_2026-09-27/compute_operational_metrics.py --db-path "C:\Users\ACER\.blue-team-assistant\cache\agent.db"
```

The database is opened read-only. The CSV is written beside the script as `operational_metrics_output.csv`.

## Raw results

| group | metric | numerator | denominator | rate |
|---|---|---:|---:|---:|
| Flow B | step_success_rate | 85 | 86 | 0.988372 |
| Flow B | completion_rate | 14 | 15 | 0.933333 |
| Flow B | completion_rate_step_limit_abort_breakdown | 0 | 1 | 0.000000 |
| Flow B | completion_rate_other_non_completed_breakdown | 1 | 1 | 1.000000 |
| Flow B | human_override_rate | 0 | 0 | 0.000000 |
| Flow C | step_success_rate | 15 | 20 | 0.750000 |
| Flow C | completion_rate | 4 | 4 | 1.000000 |
| Flow C | completion_rate_step_limit_abort_breakdown | 0 | 0 | 0.000000 |
| Flow C | completion_rate_other_non_completed_breakdown | 0 | 0 | 0.000000 |
| Flow C | human_override_rate | 0 | 5 | 0.000000 |

## Sample sizes and caveats

- Flow B: **n=15 sessions** (test goals fired via `scripts/adhoc/generate_flow_b_sessions.py`). Flow C: **n=4 sessions** (organic, from prior testing). Both are small samples, not production-scale.
- Flow B `human_override_rate` is **0/0**: no approval gate was ever triggered across the 15 test sessions. This is **not the same as 0%** and should not be presented as a clean rate.
- Flow C `human_override_rate` is **0/5=0%**: 5 real approval gates were hit, all were granted, and none were rejected. This is a real measured rate but based on a small sample.
- Flow B `completion_rate` (**14/15**) is a conservative lower bound: one `failed` session (`3ff001cbb6c7`) actually produced a correct, complete `MALICIOUS` verdict (threat score 80, AbuseIPDB 22 reports) but was mislabeled `failed` due to a transient Ollama LLM non-response after evidence-gathering was already complete. The root cause was confirmed at `src/agent/agent_loop.py:623-629`: `state.phase` is set to `FAILED` when `_think()` returns `None` twice in a row, even though `_generate_summary()` at line 972 runs unconditionally afterward and can still succeed. This is a reliability/infrastructure limitation (local LLM backend availability), not a reasoning/logic failure of the agent.

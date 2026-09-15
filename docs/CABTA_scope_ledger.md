# CABTA Scope Ledger

**Last updated:** 15 Sep 2026
**Rule:** Section A ต้องปิดให้หมดก่อนเริ่ม Section B (backlog เดิม) เว้นแต่ Section A ข้อนั้น block อยู่จริงๆ

**Status:** ⬜ Not started | 🔍 Investigating | 📝 Fix drafted | ✅ Verified | 🚫 Blocked
**Evidence Tier:** T1 = Fully verified with evidence | T2 = Wired but not fully verified | T3 = Known limitation

---

## A. Advisor Comments (ตอบก่อนพรีเซนต์ครั้งหน้า)

| # | Comment | Status | Evidence Tier | Definition of Done | Next Action |
|---|---------|--------|----------------|---------------------|-------------|
| 1 | Severity levels: Malicious/Suspicious/Clean/Unknown vs Critical/High/Medium/Low | ✅ | T1 | ยืนยันว่า CABTA มี severity mapping อยู่แล้ว 3 ชั้น ไม่ใช่ gap ที่ต้องออกแบบใหม่: per-IOC (`src/utils/wazuh_severity.py:33-66`, `src/utils/helpers.py:63-95`) ใช้ score >=70 → CRITICAL, >=40 → HIGH, <40 → LOW และ verdict MALICIOUS→CRITICAL, SUSPICIOUS→HIGH, CLEAN/UNKNOWN→LOW; correlation (`src/agent/correlation.py:646-736`) รวม additive score แล้ว map >=60/40/20/10/else → critical/high/medium/low/info; external Wazuh alert (`src/utils/wazuh_severity.py:83-119`) map rule.level 14-15/12-13/7-11/0-6 → CRITICAL/HIGH/MEDIUM/LOW | ปิดแล้ว — ไม่ต้อง design ใหม่ เตรียมพูดประเด็น asymmetry ระหว่าง 3-tier (per-IOC) กับ 5-tier (correlation) เผื่ออาจารย์ถามต่อ |
| 2 | Base score 1.3 คำนวณจากอะไร | ⬜ | - | ได้ raw code ของ formula ครบ (บรรทัด, ไฟล์, ตัวแปรทุกตัวที่เข้าสมการ) | investigation prompt: `rg "base_score" src/` แล้วดู scoring module เต็มไฟล์ |
| 3 | Source ไหนน่าเชื่อถือที่สุด (ที่มาของ weight) | ⬜ | - | ได้ raw config/code ที่ผูก weight กับแต่ละ source + เหตุผลอ้างอิงได้ (เช่น MISP confidence, FIRST.org) | `rg "weight" src/integrations/threat_intel.py` + config.yaml |
| 4 | ช่องทางแจ้งเตือนผูกกับ severity ระดับไหน | ⬜ | - | ตาราง severity → channel (Email/LINE/Teams) ที่ตรงกับโค้ดจริง | เช็ค `notifications.py` ว่ามี mapping logic จริงหรือ hardcode |
| 5 | ความถี่แจ้งเตือน (IOC ใหม่เข้าทุกวัน) | ⬜ | - | policy เขียนชัด: real-time (Malicious) / digest (Suspicious) / none (Clean) + throttle/dedup rule | เช็คว่ามี throttle logic อยู่แล้วหรือต้องออกแบบใหม่ |
| 6 | Role definition + user manual ต่อ role + scope | ⬜ | - | ตาราง role × scope × ผู้เกี่ยวข้อง + manual สั้นต่อ role | เช็คว่ามี RBAC ในโค้ดหรือยัง (`rg "role" src/`) — ถ้าไม่มี ต้อง report เป็น gap ตรงๆ |
| 7 | ทฤษฎีการคำนวณ + trust source ต้องอธิบายได้ | ⬜ | - | เอกสาร 1 หน้า: formula + ที่มาทางทฤษฎี + เหตุผล trust ranking (ต่อเนื่องจากข้อ 2+3) | รวมผลจากข้อ 2, 3 มาเขียนเป็นเอกสารเดียว |
| 8 | Approval gate ที่ Detection Rule ทำไมต้องมี / SOC แก้ได้ไหม | ✅ | T1 | ยืนยัน 2 ประเด็น: (1) approval gate เป็น human gate เพื่อป้องกัน false positive หลุด production ตามเคส AlienVault ที่พบ และสร้าง accountability ผ่าน audit trail `approved_by/approved_at/deployed_by/deployed_at`; workflow validate → approve → deploy → export/ZIP implement ครบและบังคับผ่าน `_require_rule_export_approval()` (`src/web/routes/reports.py:107-118`) (2) SOC แก้เนื้อหา rule ได้แล้วจริงตั้งแต่ commit `f49aabc` ผ่าน `PUT /{analysis_id}/rules/{rule_type}` โดยใช้ `StrictStr`, เรียก `validate_rule()` ก่อน save และ hash-invalidation ใน `_get_rule_export_state()` (`src/web/routes/reports.py:87-104`) ทำงานอัตโนมัติเมื่อ content เปลี่ยน ยืนยันด้วย test แล้ว | ปิดแล้ว — เตรียมสไลด์ 2 ประเด็น (1) gate+audit trail (2) edit workflow ใหม่ที่ validate ก่อน save และ auto-invalidate approval เดิมเมื่อ content เปลี่ยน |

### A1. Severity mapping evidence (15 Sep 2026)

ระบบแยก severity เป็น 3 ระดับตามสิ่งที่กำลังประเมิน ไม่ใช่ scale เดียว:

| ระดับ | สิ่งที่ประเมิน | Mapping ที่มีอยู่แล้ว | Evidence |
|---|---|---|---|
| Per-IOC severity | IOC เดี่ยว / สัญญาณเดียว | `score >=70 → CRITICAL`, `>=40 → HIGH`, `<40 → LOW`; verdict `MALICIOUS→CRITICAL`, `SUSPICIOUS→HIGH`, `CLEAN/UNKNOWN→LOW` | `src/utils/wazuh_severity.py:33-66`; threshold ต้นทาง `src/utils/helpers.py:63-95` |
| Per-incident/correlation severity | เหตุการณ์ที่เชื่อมหลาย IOC/TTP | additive score: `>=60 critical`, `>=40 high`, `>=20 medium`, `>=10 low`, else `info`; แปลงต่อด้วย `correlation_to_wazuh_severity()` เป็น Wazuh 4-tier | `_assess_severity()` ที่ `src/agent/correlation.py:646-736`; conversion ที่ `src/utils/wazuh_severity.py:69-81` |
| External Wazuh alert ingestion | Wazuh `rule.level` 0-15 | `14-15 → CRITICAL`, `12-13 → HIGH`, `7-11 → MEDIUM`, `0-6 → LOW`; อิง significance cutoff `email_alert_level=12` | `src/utils/wazuh_severity.py:83-119` |

Correlation additive scoring แบบเต็ม:

- Overlap: ถ้ามี high-overlap อย่างน้อย 3 รายการ (`overlap.count >= 3`) ให้ `+30`; มิฉะนั้นถ้ามี overlap ให้ `+10 × min(number_of_overlaps, 5)`
- TTP tactic: `impact +25`, `credential-access +15`, `lateral-movement +15`, `command-and-control +15`
- Tactic coverage: ถ้ามีอย่างน้อย 4 tactics ให้ `+10`
- Finding verdict: malicious ตั้งแต่ 2 แหล่งขึ้นไป `+20`; 1 แหล่ง `+10`
- รวมคะแนนแล้ว map เป็น `>=60 critical`, `>=40 high`, `>=20 medium`, `>=10 low`, ต่ำกว่านั้น `info`

### A2. Detection rule edit endpoint (15 Sep 2026)

Commit: `f49aabc` (`feat: allow SOC to edit detection rules`)

| ไฟล์ | สิ่งที่เพิ่ม/ยืนยัน | Evidence |
|---|---|---|
| `src/web/analysis_manager.py` | `update_detection_rule()` ทำ read-modify-write ภายใต้ `self._lock` เดียวกับ `complete_job()`, serialize result ทั้งก้อนกลับ DB และคืน `False` โดยไม่ throw เมื่อไม่พบ job, parse result ไม่ได้, ไม่มี `detection_rules` หรือไม่มี `rule_type` | `src/web/analysis_manager.py:81-128` |
| `src/web/routes/reports.py` | เพิ่ม `PUT /{analysis_id}/rules/{rule_type}`; `RuleContentUpdateRequest` บังคับ `content: StrictStr`; validate ก่อน save; invalid ได้ 422; ไม่มี logic invalidate แยก เพราะ content hash ใน `_get_rule_export_state()` reset approval เป็น `pending_export` อัตโนมัติ | `src/web/routes/reports.py:54`, `:87-104`, `:264-301` |
| `tests/test_rule_export.py` | ครอบคลุม edit สำเร็จและ invalidate approval, field อื่นไม่หาย, persistence ข้าม `AnalysisManager` instance, invalid syntax, rule type ไม่มีจริง, list content ถูก reject ที่ schema, และ job ที่ไม่มี `detection_rules` คืน `False` | `tests/test_rule_export.py:195-288`; ผลรัน `57 passed` |

Known limitation: lock เป็นระดับ `AnalysisManager` ทั้งก้อน ไม่ใช่ต่อ job
หรือ `analysis_id`; SOC หลายคนที่แก้คนละ analysis พร้อมกันจะรอคิวบน
`self._lock` แต่ไม่ error อาจช้าลงตามจำนวน concurrent edits ยอมรับได้ใน
สเกลปัจจุบัน และไม่อยู่ใน scope ที่ต้องแก้รอบนี้

---

## B. Backlog (ห้ามแทรกก่อน Section A เสร็จ เว้นแต่ blocked)

| Item | Status | Notes |
|------|--------|-------|
| FuzzyHashAnalyzer ssdeep/tlsh fix | ⬜ | scoped ~15-20 lines, รอตัดสินใจ investigate vs direct fix |
| DGA `_extract_sld()` subdomain gap | 🔍 | รอ rg เพิ่มก่อนเขียน fix |
| RAG auto-seeding on startup | ⬜ | ยังไม่ยืนยันว่า `kb.seed()` รันตอน uvicorn startup |
| Email-level RAG references (Flow B) | 📝 | prompt ส่งให้ Codex แล้ว รอผล |
| HTML report 404 (3 playbooks) | ⬜ | pre-existing gap, ทราบ root cause แล้ว |
| Detection Rule Export remaining gaps | ✅ | ผิด — investigate แล้วพบว่า validate/approve/deploy/download/zip ครบใน `src/web/routes/reports.py` (ดู Section A #8 และ A2) gap จริงมีแค่ edit content ซึ่งตอนนี้ implement แล้วที่ commit `f49aabc` เช่นกัน ปิดแถวนี้ |
| Teams notification | ⬜ | paused, prompt drafted |
| Test Case checklist (Excel) | ⬜ | not yet requested |
| UDP visibility in netstat_collect | ⬜ | low priority unless demo needs it |
| RAG coverage matrix | ⬜ | backlog |
| ATT&CK STIX/TAXII ingestion | ⬜ | backlog |

---

## C. Group A Eval (สถานะปัจจุบัน)

| Item | Status | Evidence Tier | Evidence / Current State | Next Action |
|------|--------|----------------|--------------------------|-------------|
| Dataset และ default limit | ✅ | T1 | `eval_benchmark.py` ใช้ `benchmark_iocs_v2.json` จำนวน 894 รายการ และ `--malicious-limit=0` เพื่อรันครบชุด | ปล่อยให้ eval รันจนจบ |
| Resume และ graceful Ctrl+C | ✅ | T1 | `load_existing_results()` ข้าม malformed JSON พร้อม warning; loop flush ผลทีละ record และจับ `KeyboardInterrupt` ก่อนปิดไฟล์ | ใช้ `--resume` ต่อหลังหยุด/เครื่องกลับมา |
| Fit/score result path | ✅ | T1 | `scripts/eval/fit_source_weights.py` และ `scripts/adhoc/score_eval_results.py` ชี้ไป `scripts/eval/eval_results_group_a_v2.jsonl`; ตรวจ syntax ของ fit script แล้ว แต่ยังไม่รันระหว่าง eval ไม่ครบ | รันหลังผลครบ 894 รายการ |
| Group A eval execution | 🔍 | T1 | Snapshot เวลา 14 Sep 2026 11:41:44: เขียนแล้ว 54/894 รายการ, unique 54, invalid JSON 0, เหลือ 840 รายการ; พบ Python process ที่เกี่ยวข้อง 2 โปรเซส | เฝ้าดูผลลัพธ์และไม่รัน fit/score จนกว่าจะครบ |
| แยก workflow ออกจาก `scripts/adhoc/` | ✅ | T1 | ย้าย `eval_benchmark.py`, `fit_source_weights.py` และ `group_b_exclusion_rationale.md` ไป `scripts/eval/`; เพิ่ม explicit unignore ที่ `.gitignore:99-100`; scratch files คงอยู่ใน `scripts/adhoc/` | ใช้ `scripts/eval/` สำหรับ repeatable evaluation/documentation; ไม่ย้าย `score_eval_results.py` |

### Group A files and evidence

- Dataset: `data/benchmark/benchmark_iocs_v2.json` — 894 records (`MALICIOUS=709`, `CLEAN=185`)
- Running script: `scripts/eval/eval_benchmark.py`
- Incremental results: `scripts/eval/eval_results_group_a_v2.jsonl`
- Analysis tools: `scripts/eval/fit_source_weights.py`, `scripts/adhoc/score_eval_results.py`
- Current result file is local/generated and must not be edited while eval is running.

---

## D. Session handoff — ThreatFox verification, Group A/B scoring boundary, and evidence

**Session date:** 14 Sep 2026

**Scope rule:** งานในส่วนนี้ไม่แตะ `src/mcp_servers/**`, `mcp_client.py`,
`src/web/websocket.py` หรือ `config.yaml` และยังไม่มี commit

### D1. ThreatFox configuration and live verification

- ตรวจ `config.yaml` แบบไม่พิมพ์ค่า secret: `api_keys.threatfox = True`,
  `api_keys.abusech = False`
- `check_threatfox()` ที่ `src/integrations/threat_intel.py:542` ใช้ key จาก
  `threatfox` ก่อน fallback ไป `abusech`; request อยู่ที่ `:550`
- `investigate_ioc_comprehensive()` เรียก ThreatFox แบบ unconditional ที่ `:954`
  ดังนั้นยังมี task สำหรับ IPv4, domain, URL และ hash ที่ส่งเข้า investigation
- Live direct-call sample จาก session เดียวกันตอบ HTTP 200 ครบ 5 รายการ:

| IOC type | IOC label | Latency | Result |
|---|---|---:|---|
| IPv4 | `8.8.8.8` | 905.5 ms | `Not listed` |
| Domain | `example.com` | 492.7 ms | `No exact match` |
| URL | `https://example.com/` | 644.9 ms | `Not listed` |
| MD5 | `44d88612fea8...` | 502.8 ms | `Not listed` |
| SHA256 | `0123456789ab...` | 487.4 ms | `Not listed` |

Summary: average **606.7 ms**, median **502.8 ms**, range **487.4-905.5 ms**;
ไม่พบ timeout, exception หรือ HTTP error ใน sample นี้ จึงคง ThreatFox ไว้
ใน Group A

### D2. Group B exclusion design and implementation

Group B ที่ถูก exclude จาก scoring/verdict มี 13 source:

```text
virustotal, abuseipdb, shodan, alienvault, greynoise, censys,
pulsedive, criminalip, ipqualityscore, phishtank, ip2proxy,
triage, threatzone
```

เหตุผลเป็น **dependency/source-path reliability gate** ไม่ใช่การตัดสินว่า
information content ของ source เหล่านี้เป็นเท็จ: auth gate, rate limit และ
timeout ที่ observe ได้ทำให้ไม่เหมาะกับ critical scoring path แต่ยังมีประโยชน์
เป็น supplemental evidence

| จุด | สถานะหลังแก้ | Evidence |
|---|---|---|
| Constant | ✅ | `src/integrations/threat_intel.py:24` — `GROUP_B_EXCLUDE` |
| Raw source retention | ✅ | `threat_intel.py:1096` ยังคงคืน `sources: results` ครบทุก source |
| Threat-intel aggregate | ✅ | `threat_intel.py:1074-1076` skip Group B ก่อนนับ flag/รวม score; `threat_score` aggregate จึงเป็น Group A |
| IOC weighted scoring | ✅ | `src/scoring/intelligent_scoring.py:131`, `:184` skip Group B ก่อน `_get_source_score`; `:213-215` ใช้ Group A flag count สำหรับ boost |
| Coverage transparency | ✅ | `intelligent_scoring.py:235-254` แยก `coverage.group_a` และ `coverage.group_b`; top-level historical fields mirror Group A ที่ `:299-300` |
| Verdict coverage | ✅ | `src/utils/helpers.py:63-85` ไม่ต้องแก้เพิ่ม เพราะ `determine_verdict()` อ่าน top-level coverage ที่ถูกตั้งเป็น Group A แล้ว |
| Informational attempted count | ✅ | `threat_intel.py:1091` `sources_checked` ยังนับทุก task ที่พยายามเรียก รวม Group B ตาม design |

### D3. Timeout finding

`safe_execute()` ที่ `threat_intel.py:1026-1029` ใช้ `asyncio.wait_for(coro,
timeout=15.0)` กับทุก task โดยรันผ่าน `gather()` ที่ `:1054` แบบ concurrent ดังนั้น
แต่ละ task มี deadline ของตัวเอง แต่ policy เป็นค่าเดียว global สำหรับทุก source
ไม่ใช่ per-source timeout

ตาม scope decision รอบนี้จึง **ยังไม่ลดเป็น 3 วินาทีและไม่ทำ per-source timeout**:
Group B ถูกกันออกจาก scoring แล้ว แต่ยัง best-effort และอาจกินเวลารอได้ถึง 15 วินาที
เพื่อไม่ขยาย scope โดยไม่จำเป็น

### D4. Test update and verification

ปรับเฉพาะ test files ที่อนุญาต:

- `tests/test_censys_scoring.py` — Censys assertion ย้ายไป `coverage['group_b']`
- `tests/test_scoring_confidence.py` — generic aggregation ใช้ synthetic source names,
  strict expected dict เพิ่ม `group_a/group_b`, missing-key tests ตรวจ Group B
- `tests/test_threat_intel_source_accounting.py` — hash accounting แยก Group A/B

Verification results:

| Check | Result | Interpretation |
|---|---:|---|
| `python -m py_compile` ของ test files | Pass | ไม่มี syntax error |
| Tests ที่แก้โดยตรง | **22 passed** | ทั้ง 15 design-change failures เดิมถูกอัปเดตแล้ว |
| Full `pytest -q` | Blocked at collection | `tests/test_remote_tools.py` import `paramiko` ไม่ได้ใน environment (`ModuleNotFoundError`) |
| Suite excluding `test_remote_tools.py` และ network-dependent `test_mcp_threat_intel.py` | จบรัน 100% ไม่มี failure เพิ่ม | ไม่พบ unexpected regression ใน suite ที่ environment รองรับ |
| Network-dependent MCP tests | Environment failure | URLhaus ถูก block ด้วย socket permission (`WinError 10013`) ไม่ใช่ test assertion regression |

ไม่แก้ test เพิ่มนอก allowlist และไม่แก้ dependency/environment ใน session นี้

### D5. Source research and documentation artifacts

- รายงาน feed research อยู่ที่ `scripts/adhoc/source_research.md` ครอบคลุม domain/hash
  non-API/no-auth sources, URL/format/cadence/license และ effort estimate
- เอกสาร rationale ถูกย้ายไป `scripts/eval/group_b_exclusion_rationale.md`
- `scripts/eval/eval_benchmark.py` และ `scripts/eval/fit_source_weights.py` ถูกย้ายออก
  จาก ignored `scripts/adhoc/`; path ภายในไฟล์ถูกอัปเดตให้ชี้ `scripts/eval/`
- `scripts/benchmark/build_benchmark_dataset.py` ไม่ย้ายและไม่แก้ เพราะ reference
  เดิมเป็น self-reference ของไฟล์เดียวกัน ไม่ใช่ `eval_benchmark.py`
- `scripts/adhoc/score_eval_results.py` ยังอยู่ที่เดิมตาม scope
- `.gitignore:97` เดิมไม่ถูกลบ; เพิ่ม `!scripts/eval/` และ `!scripts/eval/**` ที่
  `:99-100` เพื่อให้ evaluation tooling/documentation track ได้

### D6. Current handoff state

Git working tree มีการเปลี่ยนแปลงที่ตั้งใจไว้ใน source/scoring, tests, documentation
และไฟล์ใหม่ใน `scripts/eval/`; ยังไม่มี commit รอผู้ใช้ confirm ก่อน commit

### D7. Static-list fast-lane integration (historical pre-MISP): Smet NRD, HaGeZi NRD, and MalwareBazaar recent SHA256

**Session date:** 14 Sep 2026

**Context and scope.** These three sources were selected from
`scripts/adhoc/source_research.md` as effort-S, public static feeds. The
implementation follows the existing SSL Blacklist pattern in
`src/integrations/threat_feeds.py` (`_FeedCache` plus lazy TTL refresh), not the
uncached per-call URL pattern used by FeodoTracker and Tor exit nodes. The
scoring tier lists were intentionally left unchanged; all three sources use
the existing unknown-source fallback weight of `0.8`.

| Source | IOC type | Feed | Research context | Implemented semantics |
|---|---|---|---|---|
| Smet NRD | domain | `https://smet.cz/nrd/data/today.txt` | Public TXT feed, current-day/newly observed domains, updated throughout the day; CC BY 4.0 attribution; effort S | Lowercase exact domain membership in a cached set |
| HaGeZi NRD | domain | `https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt` | Public plain domain list, daily, GPL-3.0; NRD presence is not by itself a malicious verdict; effort S | Lowercase exact domain membership in a cached set |
| MalwareBazaar recent SHA256 | sha256 | `https://bazaar.abuse.ch/export/txt/sha256/recent/` | Public TXT export with comments/header and recent-only window; abuse.ch Terms/Fair Use require separate legal review; effort S | Exact lowercase membership for valid 64-character hexadecimal SHA256 values |

#### D7.1 Reference pattern and cache lifecycle

- `_FeedCache` remains the shared holder at `threat_feeds.py:64-75`:
  TTL, `last_update`, and an in-memory `Set[str]`.
- The common TTL is read from `config['timeouts']['feed_cache_ttl']` at
  `threat_feeds.py:112-114`, with the existing default of 3,600 seconds (one
  hour). No new hardcoded TTL was introduced.
- New cache instances are created per `ThreatFeeds` instance at
  `threat_feeds.py:125-128`: `_smet_nrd`, `_hagezi_nrd`, and
  `_mb_recent_sha256`.
- Each `_refresh_*_cache()` is lazy: the first check fetches the feed because
  the set is empty; later checks reuse it until `_FeedCache.is_stale()` says
  the shared TTL has expired. There is no startup job, cron integration, local
  feed snapshot, or persistent feed database.
- Refresh uses the existing `_session()` and `_fetch_text()` helpers. A
  successful refresh replaces the corresponding set and calls `mark_fresh()`.
- This feed cache is separate from `IOCCache`: the latter stores per-IOC result
  rows in `~/.blue-team-assistant/cache/ioc_cache.db` and is not the bulk feed
  snapshot.

#### D7.2 Source implementation

Implemented in `src/integrations/threat_feeds.py`:

- Feed constants: `:105-107`.
- Smet refresh/check: `:345-380`.
- HaGeZi refresh/check: `:386-421`.
- MalwareBazaar recent refresh/check: `:427-474`.
- Domain parsing strips whitespace/BOM, lowercases values, and skips blank,
  `#`, and `!` comment lines. Matching is exact set membership; there is no
  substring or regex matching.
- Hash parsing accepts only 64-character hexadecimal lines, lowercases them,
  and uses exact set membership. Header/comment lines are excluded by
  validation.
- Results use the existing `FeedResult` shape. A positive Smet/HaGeZi match
  returns score 85; a positive MalwareBazaar recent match returns score 95;
  clean results return `found: false` and score 0; exceptions return the
  standard error status.

The existing per-hash `check_malwarebazaar()` API lookup was not repurposed. It
still handles the single-hash `get_info` query; `check_mb_recent()` is a
separate bulk recent-export source.

#### D7.3 Comprehensive investigator wiring

Implemented in `src/integrations/threat_intel.py`:

- `source_defaults` includes `smet_nrd`, `hagezi_nrd`, and
  `mb_recent_sha256` at `:930-932`. This gives them `not_applicable: true`
  for unrelated IOC types.
- Domain tasks are appended under `if ioc_type == 'domain'` at `:991-999`.
- Hash tasks are appended under
  `if ioc_type in ['md5', 'sha1', 'sha256', 'hash']` at `:1012-1014`.
- `attempted_source_names` accounting includes a new source only when its
  task branch is selected, while defaults keep coverage explicit for other
  IOC types.

#### D7.4 Group A and untiered scoring decision

No new source was added to `GROUP_B_EXCLUDE`. The current code has no separate
Group A allowlist: any source not in `GROUP_B_EXCLUDE` is Group A by default
(`threat_intel.py:24-28`, `:1074-1076`; also
`intelligent_scoring.py:261-265`).

The three source names were intentionally not added to
`high_confidence_sources`, `medium_confidence_sources`, or
`low_confidence_sources`. Until a future verdict/scoring redesign assigns
explicit tiers, `IntelligentScoring` uses its unknown-source fallback weight
`0.8`. This decision is encoded as an explicit `UNTIERED_SOURCES` exemption
in `tests/test_threat_intel_source_accounting.py:59-63` rather than modifying
the scoring module.

NRD feeds indicate newly registered or recently observed domains, and recent
MalwareBazaar membership indicates recent sample presence. None of these
signals should be interpreted as an automatic standalone malicious verdict or
hard-block policy.

#### D7.5 Test fixture and accounting updates

Only the explicitly allowed test files were adjusted for the new task surface:

- `tests/test_threat_intel_cache_fallback.py:34-41` adds clean AsyncMocks for
  Smet and HaGeZi so cache/timeout tests for other sources do not fail during
  task construction.
- `tests/test_threat_intel_source_accounting.py:109-115` adds clean
  `check_mb_recent` to the SSL/wiring fixture.
- The hash accounting fixture at `:154-158` also supplies `check_mb_recent`,
  because the new source is genuinely scheduled for the hash lane.
- Hash accounting now reflects seven attempted sources, three clean Group A
  attempts, and 11 Group A not-applicable placeholders; Group B remains four
  attempted sources with nine not-applicable entries.
- The tier/task one-to-one test subtracts exactly
  `{'smet_nrd', 'hagezi_nrd', 'mb_recent_sha256'}` with a comment documenting
  the temporary fallback-weight decision.

#### D7.6 Verification evidence

| Check | Result | Evidence / interpretation |
|---|---:|---|
| `py_compile` | Pass | Compiled both integration files and both modified test files with `.venv\\Scripts\\python.exe`. |
| Targeted threat-intel tests | **9 passed** | Cache fallback, source accounting, fixture wiring, and untiered exemption all pass. |
| Full `.venv` pytest | **1350 passed, 0 failed** | `.venv\\Scripts\\python.exe -m pytest -q`; 8 subtests passed and 11 warnings remained. Runtime 66.94 seconds. |
| Live domain investigation | Pass | `example.com` through `investigate_ioc_comprehensive()` returned `smet_nrd` and `hagezi_nrd` in `sources` as clean, with no error/timeout. |
| Live hash investigation | Pass | Synthetic all-zero SHA256 through the same investigator returned `mb_recent_sha256` in `sources` as clean, with no error/timeout. |
| Diff/scope audit | Pass | Changes were limited to the two integration files and the two explicitly allowed test files before this documentation update; `git diff --check` passed; no commit was created. |

The first system-Python test attempt could not collect because `paramiko` was
missing, and an earlier sandboxed live attempt had HTTPS egress denied. The
final validation used the repository `.venv` and an approved network-enabled
run for the live feed checks.

#### D7.7 Remaining follow-up

- Decide explicit confidence tiers after the verdict/scoring redesign; remove
  the test exemption at that time.
- Add positive-match fixtures or controlled test feed responses if deterministic
  malicious examples are required; this session verified live wiring and clean
  non-error behavior, not a positive match for each feed.
- Revisit feed metadata/HTTP validators, attribution/legal handling, and any
  requirement for durable snapshots before production deployment.

### D8. MISP CIRCL public-feed integration (current session)

**Session date:** 15 Sep 2026

**Decision locked by user.** MISP is integrated as one additional source named
`MISP` in user-facing results. The implementation uses only the CIRCL public
OSINT feed (`manifest.json` plus `<event-uuid>.json`) and a full-feed
in-memory cache. MISP REST API, API credentials, per-IOC MISP network lookups,
and a user-selectable feed/API mode are explicitly out of scope.

The internal source/telemetry identifier is `misp_circl_feed_osint`; it is
intentionally separate from the existing `circl` passive-DNS integration and
the existing `circl_misp_feed_check()` function in
`src/mcp_servers/free_osint_tools.py`. Neither forbidden integration was
modified.

#### D8.1 Implementation and data model

- New module: `src/integrations/misp_feed.py`.
- Feed endpoints are defined at `misp_feed.py:23-24`:
  `https://www.circl.lu/doc/misp/feed-osint/manifest.json` and the event
  JSON URL template.
- `MISPFeed` owns an in-memory set index for `ip`, `domain`, `url`, and
  `hash`, plus per-event parsed values and timestamps. There is no persistent
  disk snapshot or database cache.
- `_parse_event()` reads both `Event.Attribute` and every
  `Event.Object[].Attribute` (`misp_feed.py:110-135`). Attribute mapping is:
  `ip-src/ip-dst -> ip`, `domain/hostname -> domain`, `url/uri -> url`,
  and MD5/SHA-family types (including `sha3-*`) -> `hash`.
- `check_misp(ioc, ioc_type)` performs local set membership only and returns
  `status`, `found`, `score`, `feed_status`,
  `latest_event_timestamp`, `cache_fetched_at`,
  `last_successful_refresh`, and refresh-failure metadata
  (`misp_feed.py:326-365`).
- A missing match is not reported as an unqualified clean result when the feed
  is `stale` or `unavailable`; it uses the warning status and preserves
  freshness metadata.

#### D8.2 Refresh lifecycle and FIX 1-3

- The first IOC check lazily schedules a background full-feed refresh. The
  check itself does not await network activity, so the first result may be
  `unavailable` or `stale` while refresh is running.
- Refresh is incremental after the initial load. `_cursor_timestamp` is the
  global timestamp cursor (`misp_feed.py:53-57`, `:252-263`); the
  per-event timestamp map remains the retry-safe fallback for events that
  failed during a partial cycle.
- **FIX 1 — partial failures:** the cycle calculates `failures / total` at
  `misp_feed.py:293-307`. A maximum 10% failure ratio is treated as an
  acceptable refresh; if any event succeeded, `cache_fetched_at` and
  `latest_event_timestamp` are updated first (`:216-222`). Ratios above
  10% retain the successful event updates but keep failure/backoff state
  active. A manifest/session failure counts as a full refresh failure.
- **FIX 2 — one session:** `_refresh_events()` opens one
  `aiohttp.ClientSession` around manifest and all event requests
  (`misp_feed.py:229-234`, `:264-274`). The same session is passed to
  `_refresh_manifest()` and `_fetch_event()`.
- **FIX 3 — scheduling gate:** `_schedule_refresh()` checks both
  `_next_refresh_at` and `_circuit_open_until` before checking/creating a
  task (`misp_feed.py:312-324`).
- Refresh circuit settings are intentionally conservative: three consecutive
  failed cycles open the circuit; cooldown starts at 900 seconds and uses
  exponential backoff capped at one hour (`misp_feed.py:27-31`, `:194-205`).
  Existing cache data remains available as stale-but-usable data.

#### D8.3 Threat-intelligence wiring and classification

- `ThreatIntelligence` constructs `MISPFeed` at
  `src/integrations/threat_intel.py:77-78`.
- `source_defaults` includes the all-four-type capability message at
  `threat_intel.py:936`, so unrelated IOC types are marked not applicable.
- The same source is appended once in each supported task branch:
  IPv4 `:969`, domain `:997`, URL `:1009`, and hash `:1020`.
- `GROUP_B_EXCLUDE` was not changed. Under the current legacy accounting,
  sources absent from that set are Group A by default; this is separate from
  explicit confidence-tier assignment.
- MISP is intentionally provisional/untiered. It was added to the
  `UNTIERED_SOURCES` test exemption with the existing fallback-weight comment
  (`tests/test_threat_intel_source_accounting.py:59-68`).
  `src/scoring/intelligent_scoring.py` was not modified.

#### D8.4 Test changes and verified results

- `tests/test_threat_intel_cache_fallback.py:42-52` adds a clean async
  `check_misp` mock so unrelated cache/timeout tests do not perform MISP work.
- `tests/test_threat_intel_source_accounting.py:121-132` and `:174-185`
  provide clean MISP mocks for the wire and hash fixtures.
- Hash accounting was updated from 7 to 8 attempted sources. The actual hash
  task list contains eight sources because MISP is now scheduled at
  `threat_intel.py:1019-1027`. The fixture therefore correctly expects four
  clean Group-A attempts and four Group-A attempted sources at
  `tests/test_threat_intel_source_accounting.py:204-220`; this is test
  accounting, not a new score or tier decision.
- `.venv\\Scripts\\python.exe -m py_compile` passed for all four changed or
  created implementation/test files.
- MISP parser smoke test passed with synthetic attributes covering all four
  normalized IOC types from both event attribute locations.
- Targeted cache/accounting tests: **9 passed**.
- Full suite with workspace temp isolation: **1348 passed, 2 failed**. The two
  failures were pre-existing live URLhaus tests blocked by socket policy
  (`WinError 10013`), not MISP failures. Re-running with only those two tests
  deselected produced **1348 passed, 2 deselected**.
- No live CIRCL full-feed download was performed in this implementation
  session, so event-count coverage, feed freshness in production, and positive
  MISP matches remain unverified. The integration is therefore wired and
  parser-verified, but live-feed evidence is still T2 rather than T1.

#### D8.5 Commit and remaining follow-up

- Implementation commit: `24b8adf` (`Integrate CIRCL MISP feed cache`). It
  contains exactly the four approved files:
  `misp_feed.py`, `threat_intel.py`,
  `test_threat_intel_cache_fallback.py`, and
  `test_threat_intel_source_accounting.py`.
- This ledger update is a separate documentation change and is intentionally
  not included in that implementation commit.
- Follow-up before treating MISP as a permanent tier: run a controlled/live
  CIRCL refresh, measure event success ratio and freshness over time, inspect
  positive-match behavior, and then decide explicit confidence-tier placement
  without conflating it with Group A/B execution accounting.

## D9. Evidence-based source tiering and resilient execution redesign

### หัวข้อใหญ่

งานชุดนี้คือการเปลี่ยนจากการจัด tier ของ source จากโครงสร้างโค้ดหรือการคาดเดา ไปเป็นการจัดลำดับความสำคัญจากหลักฐานการทำงานจริงของแต่ละ source โดยแยกประเด็นที่มักถูกปนกันออกเป็นคนละแกน:

- **Execution tier**: ควรเรียก source ใดก่อนเพื่อประหยัดเวลา ลดการพึ่งพา network และลดโอกาสชน API quota
- **Evidence reliability**: source ทำงานสำเร็จ สม่ำเสมอ สด และมี latency อยู่ในระดับใด
- **Content credibility**: เนื้อหาที่ source รายงานมีความน่าเชื่อถือเชิงภัยคุกคามเพียงใด
- **Group A/B**: ขอบเขตที่ระบบ scoring ปัจจุบันอนุญาตให้นำ source ไปใช้

การแยกสี่เรื่องนี้มีเป้าหมายไม่ให้ source ที่เรียกง่ายหรือเร็วถูกตีความว่าเนื้อหาถูกต้องกว่าโดยอัตโนมัติ และไม่ให้ source ที่ใช้ API ถูกตัดสินว่าไม่น่าเชื่อถือเพียงเพราะมี quota สำหรับ execution tier นี้ CABTA ให้ความสำคัญกับ non-API, local/cache lookup และ coverage ที่กว้าง เพราะตรงกับเป้าหมายการประหยัดเวลาและลด dependency ภายนอก

### สถานะรวม

**กำลังเก็บหลักฐาน — ยังไม่พร้อมล็อก tier หรือแก้ scoring logic**

MISP มีสถานะ wired/parser-verified แล้ว แต่ยังไม่มี empirical production evidence จากการ refresh full feed จริงเพียงพอสำหรับตัดสิน tier ถาวร แผนด้านล่างจึงกำหนดลำดับตั้งแต่การตรวจ feed, เก็บ telemetry, ตรวจความพร้อมของ dataset, คำนวณ metrics, ทำ tier report, ไปจนถึงการแก้ scoring หลังได้รับ approval เท่านั้น

### เกณฑ์สถานะ

- `[x]` ทำตามขอบเขตของขั้นตอนนั้นแล้ว
- `[ ]` ยังไม่เสร็จ หรือทำได้เพียงบางส่วนและยังใช้เป็นหลักฐานตัดสิน tier ไม่ได้

## D9.1 ขั้นที่ 1 — ตรวจ MISP live feed แบบ read-only

**วัตถุประสงค์:** ยืนยันพฤติกรรมของ CIRCL public MISP feed จากการทำงานจริง ไม่สรุปจาก parser หรือจำนวน type ที่รองรับในโค้ดเพียงอย่างเดียว

**วิธีทำ:** fetch `manifest.json` แบบ read-only และบันทึกจำนวน event; fetch event ตาม manifest แล้วนับ success/failure; parse ทั้ง `Event.Attribute` และ `Event.Object[].Attribute`; normalize เป็น `ip`, `domain`, `url`, `hash`; บันทึก `latest_event_timestamp`, เวลา refresh และระยะเวลารวม; จากนั้นทดสอบ partial failure และ stale-cache เพื่อยืนยันว่า event ที่สำเร็จยังใช้ได้ และ `found=false` จาก feed ที่ stale/unavailable ไม่ถูกตีความว่า clean

**ทำเพื่ออะไร:** แยกให้เห็นว่า feed มีข้อมูลอะไร, refresh เชื่อถือได้เพียงใด และผลไม่พบ IOC มีความหมายเป็น clean หรือเป็นเพียง feed stale/unavailable

**ผลลัพธ์ที่ต้องได้:** หลักฐาน live ที่ระบุ event count, success/failure count, IOC coverage, freshness, refresh latency และพฤติกรรม partial-failure/stale-cache ได้ครบ

**สถานะ:** `[ ]` ยังไม่เสร็จ

**หลักฐานปัจจุบัน:** MISP ถูก wire และตรวจ parser แล้ว แต่ ledger เดิมระบุว่ายังไม่มีการรัน full-feed live ที่ใช้เป็น empirical production evidence จึงยังไม่มีตัวเลข CIRCL จริงสำหรับ event count, refresh duration และ failure ratio ที่จะใช้ล็อก tier

**ข้อสรุปชั่วคราว:** MISP คงสถานะ `provisional/untiered` ไม่ใช่ Tier A จากการมีโค้ดหรือ coverage ที่ออกแบบไว้

## D9.2 ขั้นที่ 2 — สร้าง telemetry collector

**วัตถุประสงค์:** สร้างวิธีวัด behavior ของ source ให้เป็นรูปแบบเดียวกันต่อ `source × IOC type` และเก็บ raw result เพื่อวิเคราะห์ซ้ำได้

**วิธีทำ:** collector เก็บ `source`, `ioc_type`, `timestamp`, `success/fail`, `latency_ms`, `error_type`, `cache_hit`, `feed_status` และ `found` โดยแยก latency เป็น `cold_refresh_latency`, `warm_cached_lookup_latency` และ `api_request_latency` เพราะ static feed ที่ query จาก memory ไม่ควรถูกเปรียบเทียบกับ API call ที่มี network และ quota แบบเดียวกัน

**คำสั่งที่ใช้:**

```powershell
.venv\Scripts\python.exe scripts\adhoc\collect_source_telemetry.py `
    --source smet_nrd `
    --ioc example.com `
    --ioc-type domain `
    --repeat 3 `
    --output evidence\source_telemetry.jsonl
```

**ตัวอย่างผลลัพธ์:**

```json
{
  "source": "smet_nrd",
  "ioc_type": "domain",
  "success": true,
  "fail": false,
  "latency_ms": 611.6,
  "latency_class": "cold_refresh",
  "cache_hit": false,
  "found": false
}
```

Warm lookup รอบถัดไปใช้เวลาประมาณ `0.0 ms` และมี `cache_hit=true`

**ทำเพื่ออะไร:** สร้างหลักฐานเชิงตัวเลขสำหรับ access mode, latency, cache behavior และ error behavior โดยไม่เหมารวม static/cache source กับ API source

**ผลลัพธ์:** มี collector ที่รันได้ มีการตรวจ `py_compile` และ source inventory แล้ว และยังไม่ได้ใช้ `--all-sources` เพื่อป้องกันการเรียก API quota โดยไม่ตั้งใจ

**สถานะ:** `[x]` สร้าง collector และทดสอบตัวอย่างแล้ว; `[ ]` การเก็บระยะยาวและการเก็บครบทุก source ยังไม่เสร็จ

**หลักฐาน:** `scripts/adhoc/collect_source_telemetry.py` และ output ที่บันทึกไว้ใน `evidence/` ตามคำสั่งข้างต้น

## D9.3 ขั้นที่ 3 — กำหนด sample และ protocol ให้ตายตัวก่อนรันจริง

**วัตถุประสงค์:** ป้องกันการจัด tier จาก sample เล็กหรือชุดข้อมูลที่เอนเอียง และทำให้ผลจากคนละช่วงเวลาทำซ้ำและเปรียบเทียบกันได้

**วิธีทำ:** เก็บอย่างน้อย 30 samples ต่อ `source × IOC type`; แยก `known-malicious` และ `known-clean` พร้อม provenance/วันที่ยืนยัน; ไม่เรียก source กับ IOC type ที่ไม่รองรับ; เก็บผลดิบทุก call; รันซ้ำหลายช่วงเวลาเพราะ latency, rate-limit, freshness และ availability เปลี่ยนตามเวลา; แยก cold refresh, warm lookup และ API request ตาม schema ข้อ 2

**ทำเพื่ออะไร:** ทำให้ `n`, success rate, error rate, p95 และ cache stability สะท้อนพฤติกรรมจริง ไม่ใช่ผลจากการทดลองครั้งเดียวหรือ IOC ชนิดเดียว

**ผลลัพธ์ที่ต้องได้:** sampling manifest ที่ระบุ source/type, รายการ IOC, label malicious/clean, ช่วงเวลารัน และ raw telemetry ที่ครบ minimum sample

**สถานะ:** `[x]` หลักเกณฑ์และ protocol ถูกกำหนดแล้ว; `[ ]` ยังเก็บ sample ครบตาม minimum และหลาย time window ไม่เสร็จ

**หลักฐาน:** `evidence/source_telemetry_2026-09-15/source_telemetry_report.md:34-37` กำหนด minimum known-malicious/known-clean และ readiness validation; รายงานเดียวกันระบุ dataset ปัจจุบันยังไม่พร้อมในบาง IOC type ที่ `:56-58`

### D9.3a Window 1 results (2026-09-15)

- Raw telemetry: `evidence/reliability_sampling/windows/window1_2026-09-15.jsonl`
- Result: `3,365` rows in one clean window; validation found no duplicate block and monotonically increasing timestamps.
- Sources covered (14): `feodotracker`, `c2_trackers`, `talos`, `spamhaus`, `usom`, `tor_exit_nodes`, `circl`, `sslblacklist`, `smet_nrd`, `hagezi_nrd`, `mb_recent_sha256`, `threatfox`, `urlhaus`, `malwarebazaar`.
- Excluded: `misp_circl_feed_osint` (separate MISP live-feed validation step) and the 13 Group B API-key sources: `virustotal`, `abuseipdb`, `shodan`, `alienvault`, `greynoise`, `censys`, `pulsedive`, `criminalip`, `ipqualityscore`, `phishtank`, `ip2proxy`, `triage`, `threatzone`.
- Key findings:
  - `talos`: `60/60` failures in this window and `120/120` failures including the prior invalid run. DNS SenderBase lookup timed out at approximately `5,000 ms`, matching the resolver timeout in `threat_intel_extended.py:105-106`. Evidence indicates the service is deprecated, not a CABTA code-path bug. See `evidence/reliability_sampling/invalid_runs/README.md`.
  - `tor_exit_nodes`: `0` failures in this clean window. The prior `429` responses came from duplicated concurrent load, so the prior `429` is not treated as normal source behavior.
  - `malwarebazaar`: `1/60` failure (`5xx`); repeat in windows 2 and 3.
- Window status: `[x]` window 1/3 of the minimum 3 time windows complete; `[ ]` window 2; `[ ]` window 3.
- No scoring or tier code was changed in this run, per the D9 gate.

## D9.4 ขั้นที่ 4 — สร้าง coverage matrix จากข้อมูลจริง

**วัตถุประสงค์:** แยกคำว่า “รองรับ type” ออกจาก “มีข้อมูลไม่ว่าง” และ “มี match ใน sample” ซึ่งเป็นคนละข้อเท็จจริง

**วิธีทำ:** ทำตารางแยก source และ IOC type โดยตรวจสี่มิติ: รองรับตามโครงสร้าง feed/check function; มีข้อมูล non-empty ใน feed/index จริง; มี match ใน known-malicious หรือ sample จริง; และมี error/timeout/schema failure ใน type นั้นหรือไม่

ห้ามใช้ `match_rate > 0` เป็น coverage เพียงอย่างเดียว เพราะ sample อาจไม่มี malicious IOC ที่ source นั้นรู้จัก การไม่มี matchจึงไม่เท่ากับ source ไม่มีข้อมูลหรือไม่มีความครอบคลุม

**ทำเพื่ออะไร:** ป้องกันการให้คะแนน coverage สูง/ต่ำผิดจากการเลือก sample และทำให้เห็นช่องว่างระหว่าง capability ตามโค้ดกับข้อมูลที่ source มีจริง

**ผลลัพธ์ที่ต้องได้:** coverage matrix พร้อม denominator, sample count, non-empty evidence, match count และ error count ต่อ cell

**สถานะ:** `[ ]` ยังไม่เสร็จ เพราะยังไม่มี matrix ที่คำนวณจาก telemetry และ live feed ครบทุก source/type

## D9.5 ขั้นที่ 5 — คำนวณ reliability และ execution metrics

**วัตถุประสงค์:** เปลี่ยน raw telemetry ให้เป็น metrics ที่ reproducible ก่อนนำไปจัด tier

**วิธีทำ:** คำนวณแยก source/type และบันทึกสูตร/threshold คู่กับผลลัพธ์ ได้แก่ Access Mode Score, Coverage Score จาก feed/data จริง, Wilson lower bound ของ success rate ที่ confidence 95%, p95 latency แยกตาม latency class, rolling error rate, cache stability และ refresh freshness จาก `latest_event_timestamp`, `cache_fetched_at` และ feed status

ต้องล็อก threshold ก่อนเห็นผล aggregate เพื่อไม่ให้เปลี่ยนเกณฑ์ย้อนหลังให้เข้ากับ source ที่ต้องการ

**ทำเพื่ออะไร:** ทำให้การตัดสินใจตรวจสอบซ้ำได้ และแยก execution priority ออกจาก content credibility และ verdict weight

**ผลลัพธ์ที่ต้องได้:** metrics artifact ที่มีสูตร, threshold, sample size, confidence method และผลต่อ source/type ครบถ้วน

**สถานะ:** `[ ]` ยังไม่เสร็จ; ตอนนี้มีแนวทางและสูตรระดับ design แต่ยังไม่มีผลคำนวณจาก telemetry ที่ครบและ threshold artifact ที่ผ่าน approval

## D9.6 ขั้นที่ 6 — จัด tier เป็นรายงานก่อนแก้ scoring

**วัตถุประสงค์:** ให้คนตรวจหลักฐานและอนุมัติการจัด tier ก่อนเปลี่ยน behavior ของ production scoring

**วิธีทำ:** สร้างตาราง `source | access mode | coverage | n | Wilson lower bound | p95 latency | error rate | cache stability | provisional/tier` พร้อม raw evidence links, assumptions และ unresolved gaps แล้วแสดงแยกกันระหว่าง Execution tier, Evidence reliability, Content credibility และ Group A/B

MISP ต้องคง `provisional/untiered` จนกว่าจะมีหลักฐาน live และ sample เพียงพอ ไม่ใช่ยกระดับเพราะเป็น MISP หรือเพราะ index รองรับสี่ IOC type ตาม design

**ทำเพื่ออะไร:** ทำให้การจัด tier เป็น decision record ที่ตรวจสอบได้ และลดความเสี่ยงที่การเปลี่ยน tier จะไปเปลี่ยน verdict โดยไม่มีหลักฐานรองรับ

**ผลลัพธ์ที่ต้องได้:** tier recommendation report พร้อม evidence, assumptions, gaps และ approval record

**สถานะ:** `[ ]` ยังไม่เสร็จ เพราะยังไม่มีตาราง metrics/tier จากข้อมูลจริงและยังไม่มี approval ให้แก้ scoring

## D9.7 ขั้นที่ 7 — ออกแบบ Circuit Breaker ให้ครบ source ที่จำเป็น

**วัตถุประสงค์:** ป้องกัน source ที่กำลังล้มเหลวหรือช้าผิดปกติทำให้ investigation ทั้งชุดช้า/พัง และควบคุม retry ไม่ให้เพิ่มปัญหา rate limit

**สถานะปัจจุบัน:** MISP มี circuit breaker เฉพาะ refresh และ fallback ไปใช้ stale cache ได้ แต่ยังไม่ใช่ policy กลางที่ใช้กับทุก source

**วิธีทำที่ต้องตัดสินใจก่อน implement:** เลือกว่าจะทำ breaker ในแต่ละ integration หรือ wrapper กลางใน investigator; กำหนด `closed`, `open`, `half-open`; ล็อก failure window, threshold, cooldown/backoff และ probe count; แยก refresh failure, quota/401, timeout, schema error และ stale-cache semantics; และกำหนดการบันทึก failure โดยไม่ทำให้ `sources_checked` หรือ verdict บิดเบือน

**ทำเพื่ออะไร:** ทำให้ resilience behavior สม่ำเสมอและควบคุม unstable dependency โดยไม่ปะปนกับ reliability/content score

**ผลลัพธ์ที่ต้องได้:** design ที่ได้รับ approval และ state machine/policy ที่ทดสอบได้สำหรับ source ใน scope

**สถานะ:** `[ ]` ยังไม่เสร็จ; มีเพียง MISP-specific implementation ยังไม่มีการตัดสินใจหรือ implementation แบบกลางสำหรับทุก source

## D9.8 ขั้นที่ 8 — แก้ scoring/tier logic หลัง approval

**วัตถุประสงค์:** นำ tier recommendation ที่มีหลักฐานไปใช้จริงโดยไม่แก้ scoring ก่อนข้อมูลพร้อม

**วิธีทำหลังได้รับ approval เท่านั้น:** เพิ่ม explicit source-to-tier mapping; ลบหรือปรับ `UNTIERED_SOURCES`; ตัดสินใจว่าจะคง fallback weight `0.8` หรือเปลี่ยนจากผล evidence; เพิ่ม tests สำหรับ threshold, Wilson bound, provisional gate และ circuit state; ตรวจว่า execution tier, Group A/B และ confidence/content weight ยังเป็นคนละแนวคิด

**ทำเพื่ออะไร:** ลดความเสี่ยงของการ lock-in design จากข้อมูลไม่พอ และทำให้ทุกการเปลี่ยน scoring มีเหตุผลกับหลักฐานที่ตรวจย้อนหลังได้

**ผลลัพธ์ที่ต้องได้:** code change ที่ผ่าน approval, tests และ ledger decision record ที่ชี้ว่า source ใดเปลี่ยน tier ด้วยเหตุผลใด

**สถานะ:** `[ ]` ยังไม่เริ่ม เพราะยังรอ live evidence, metrics report และ approval

## D9.9 ขั้นที่ 9 — Regression และ operational behavior

**วัตถุประสงค์:** ตรวจว่าการจัด tier/resilience ใหม่ไม่ทำให้ investigation เดิมเสียหาย และ behavior ตอนใช้งานจริงสอดคล้องกับ design

**วิธีทำ:** ตรวจ cache หลัง restart; ทำให้ feed stale แล้วตรวจ `feed_status` และความหมายของ `found=false`; ทำให้ source ล้มเหลว/timeout แล้วตรวจว่า investigation อื่นยังทำงานต่อ; ตรวจ `sources_checked`, coverage และ attempted/clean accounting; ตรวจว่า Group A/B ไม่ปนกับ confidence tier; และรัน unit/integration/regression tests เทียบ baseline

**ทำเพื่ออะไร:** ยืนยัน correctness, failure isolation และความหมายของข้อมูลที่ผู้ใช้เห็น ไม่ใช่ตรวจเฉพาะสูตรคำนวณ

**ผลลัพธ์ที่ต้องได้:** regression report, operational test evidence และ known limitations ที่ยังต้องติดตาม

**สถานะ:** `[ ]` ยังไม่เสร็จ; จะทำหลัง design และ tier report ได้รับ approval

## D9.10 ลำดับงานที่ควรทำต่อ

1. `[ ]` Live-validate MISP full feed แบบ read-only และเก็บหลักฐาน raw/summary
2. `[x]` ใช้ telemetry collector ที่สร้างแล้วเพื่อกำหนด schema และทดลองเก็บ behavior
3. `[ ]` เก็บ sample ให้ครบตาม minimum ต่อ source/type และหลายช่วงเวลา
4. `[ ]` คำนวณ coverage matrix และ reliability/execution metrics จาก raw evidence
5. `[ ]` ออกรายงาน tier ให้ตรวจและอนุมัติก่อนแก้ scoring; หลังจากนั้นจึงออกแบบ circuit breaker กลางและทำ regression

**ข้อสรุป:** ทิศทาง MCDA + Wilson lower bound + Circuit Breaker เป็นกรอบการทำงานที่เหมาะกับโจทย์นี้ในระดับ design แต่ tier ที่น่าเชื่อถือยังต้องรอหลักฐานจากการรันจริง ไม่ควรสรุปจากชื่อ source, การมี/ไม่มี API key หรือ parser coverage เพียงอย่างเดียว

## D10. Role-based login and RBAC (advisor requirement)

### หัวข้อใหญ่

นี่คือ requirement จากอาจารย์: ระบบต้องมี login แบ่ง 3 role ตาม Target User ได้แก่ `SOC Analyst Tier 1-2`, `Incident Responder` และ `Threat Hunter` โดยแต่ละ role เห็นข้อมูลและ flow ต่างกัน และต้องสามารถผูก Gmail ของ user แต่ละคนเข้ากับระบบแจ้งเตือนได้

### สถานะรวม

Phase 1 และ Phase 1.5 เสร็จแล้ว; RBAC enforcement, per-flow filtering, Gmail OAuth และ notification routing ราย user ยังไม่เริ่ม

### เกณฑ์สถานะ

- `[x]` ทำตามขอบเขตของขั้นตอนนั้นแล้ว
- `[ ]` ยังไม่เสร็จ หรือรอ phase ก่อนหน้า/approval ที่เกี่ยวข้อง

## D10.1 Phase 1 — Auth core (login/logout, JWT session)

**วัตถุประสงค์:** เพิ่ม authentication core สำหรับ login/logout, password hashing, JWT session issuance/verification และ session revocation

**วิธีทำ:** ใช้ bcrypt password hashing, HMAC-SHA256 JWT และ `get_current_user()` FastAPI dependency พร้อม `auth_sessions` สำหรับ revoke session

**ทำเพื่ออะไร:** ให้ระบบมีตัวตนของ user และ session ที่ตรวจสอบได้ก่อนเพิ่ม authorization

**ผลลัพธ์ที่ต้องได้:** endpoint login/logout และ current-user dependency ที่ใช้งานได้

**สถานะ:** `[x]` เสร็จแล้ว

**หลักฐาน:** `git log --oneline -- src/web/auth.py src/web/routes/auth.py` ยืนยัน commit `5b07b86 Add Phase 1 auth core: login/logout with JWT sessions`

## D10.2 Phase 1.5 — Admin invite-only registration

**วัตถุประสงค์:** ให้ admin เพิ่มสมาชิกใหม่แบบ invite-only โดยผู้ใช้ไม่สามารถสมัครหรือเลือก role ด้วยตัวเอง

**วิธีทำ:** ใช้ `POST /api/admin/users/invite` สำหรับ admin และ `POST /api/auth/accept-invite` สำหรับรับ invite, token ใช้ครั้งเดียวและหมดอายุใน 48 ชั่วโมง

**ทำเพื่ออะไร:** ควบคุมการเพิ่ม user และ role จากฝั่ง admin โดยตรง

**ผลลัพธ์ที่ต้องได้:** user ใหม่ถูกสร้างเป็น inactive ก่อน แล้วจึง activate พร้อม username/password จาก invite

**สถานะ:** `[x]` เสร็จแล้ว

**หลักฐาน:** commit `76670cd Add Phase 1.5: admin invite-only registration`

**Endpoint ที่มี:** `POST /api/admin/users/invite`, `POST /api/auth/accept-invite`

**Design decision:** ไม่มี teams table แยก ใช้ทีมเดียวโดย implicit; admin เพิ่มสมาชิกโดยตรงผ่าน email; ผู้ใช้ไม่มี self-select role; มี 4 role ได้แก่ 3 target-user role และ `admin`

## D10.3 Phase 2 — RBAC middleware

**วัตถุประสงค์:** บังคับสิทธิ์ตาม role กับ route และ flow ที่มีอยู่

**วิธีทำ:** ใช้ `require_role()` dependency ที่มีแล้วจาก Phase 1.5 ซึ่งถูกใช้กับ admin-only endpoint แล้ว และนำไป apply กับ route ของ Flow A/B/C ได้แก่ `agent.py`, `playbooks.py`, `chat.py` และ `websocket.py` ตาม 3 target-user role

**ทำเพื่ออะไร:** แยกสิทธิ์การเข้าถึงข้อมูลและ action ระหว่าง role อย่างเป็นระบบ

**ผลลัพธ์ที่ต้องได้:** route ที่เกี่ยวข้องมี role enforcement และ unauthorized access ได้ response ที่ถูกต้อง

**สถานะ:** `[ ]` ยังไม่เริ่ม

**ขอบเขตที่ต้องปลดล็อก:** ต้อง lift forbidden-file scope สำหรับ `src/web/websocket.py` เฉพาะรอบนี้ เพราะ Flow B วิ่งผ่าน WebSocket

## D10.4 Phase 3 — Per-flow filtering

**วัตถุประสงค์:** ทำให้ข้อมูลและ flow ที่แต่ละ role เห็นแตกต่างกันตาม requirement

**วิธีทำ:** กำหนด field/data visibility ต่อ role และใช้ filtering ในแต่ละ flow หลัง RBAC middleware พร้อมใช้งาน

**ทำเพื่ออะไร:** ให้ role ไม่ได้เพียง login ได้/ไม่ได้ แต่เห็นข้อมูลตามหน้าที่จริง

**ผลลัพธ์ที่ต้องได้:** SOC Analyst เห็น Flow A แบบ trim raw source field; Incident Responder ผูกกับ playbook approval gate; Threat Hunter เห็น Flow B เต็ม

**สถานะ:** `[ ]` ยังไม่เริ่ม รอ Phase 2 เสร็จก่อน

## D10.5 Phase 4 — Gmail OAuth (per-user)

**วัตถุประสงค์:** ผูก Gmail ของ user แต่ละคนเข้ากับระบบแจ้งเตือน

**วิธีทำ:** ใช้ OAuth2 Authorization Code flow ต่อ user และเก็บ refresh token แบบ encrypted

**ทำเพื่ออะไร:** ให้ระบบส่ง notification โดยอ้างอิง Gmail ที่ user คนนั้นอนุญาต แทนการมี recipient เดียวแบบ static

**ผลลัพธ์ที่ต้องได้:** user แต่ละคนสามารถ authorize Gmail ของตนเอง และระบบใช้ credential ต่อ user ได้

**สถานะ:** `[ ]` ยังไม่เริ่ม

**ขอบเขตที่ต้องปลดล็อก:** ต้อง lift config scope สำหรับ `config.yaml` เฉพาะ section ใหม่ ห้ามแตะ `smtp_*` เดิม

## D10.6 Phase 5 — Notification routing by role

**วัตถุประสงค์:** route notification ตาม role และ Gmail ที่ผูกไว้ต่อ user

**วิธีทำ:** ขยาย `NotificationManager.notify()` ให้ route ตาม role + Gmail ที่ผูกไว้จาก Phase 4 โดยเพิ่มจาก `to_addrs` static เดิม ไม่ใช่แทนที่

**ทำเพื่ออะไร:** ให้ notification ไปถึงผู้รับที่เกี่ยวข้องกับ role และ flow โดยยังคงรองรับ static recipient เดิม

**ผลลัพธ์ที่ต้องได้:** notification routing แยกตาม role/user ได้ และมี fallback/behavior ของ static `to_addrs` เดิมที่ตรวจสอบได้

**สถานะ:** `[ ]` ยังไม่เริ่ม

## D10.7 ลำดับงานที่ควรทำต่อ

1. `[ ]` Phase 2 — RBAC middleware (ถัดไป)
2. `[ ]` Phase 3 — Per-flow filtering
3. `[ ]` Phase 4 — Gmail OAuth
4. `[ ]` Phase 5 — Notification routing by role

## Weekly ritual (กันของหล่น)
1. ก่อนเริ่มแต่ละ session: เปิดไฟล์นี้ อัปเดต status เก่าก่อน แล้วค่อยเลือกงานถัดไป
2. ก่อนเริ่มแต่ละข้อ: เขียน DoD ใน column ให้ชัดก่อนสั่ง investigation prompt
3. จบแต่ละ session: อัปเดต status ทุกแถวที่แตะวันนี้ ห้ามปล่อยค้างเป็น 🔍 ข้ามคืนโดยไม่มี note
4. ก่อนพรีเซนต์: Section A ต้องไม่มีแถวไหนเป็น ⬜ — อย่างน้อยต้องเป็น 🔍 พร้อมคำตอบชั่วคราวที่มี evidence tier กำกับ

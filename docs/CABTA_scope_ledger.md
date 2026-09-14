# CABTA Scope Ledger

**Last updated:** 14 Sep 2026
**Rule:** Section A ต้องปิดให้หมดก่อนเริ่ม Section B (backlog เดิม) เว้นแต่ Section A ข้อนั้น block อยู่จริงๆ

**Status:** ⬜ Not started | 🔍 Investigating | 📝 Fix drafted | ✅ Verified | 🚫 Blocked
**Evidence Tier:** T1 = Fully verified with evidence | T2 = Wired but not fully verified | T3 = Known limitation

---

## A. Advisor Comments (ตอบก่อนพรีเซนต์ครั้งหน้า)

| # | Comment | Status | Evidence Tier | Definition of Done | Next Action |
|---|---------|--------|----------------|---------------------|-------------|
| 1 | Severity levels: Malicious/Suspicious/Clean/Unknown vs Critical/High/Medium/Low | ⬜ | - | ตัดสินใจ: เพิ่ม severity mapping จาก score (แยกจาก verdict) พร้อม threshold ที่เขียนไว้ชัด | เขียน design decision 1 ย่อหน้า + เช็คว่ามี field severity อยู่แล้วหรือไม่ (`rg "severity" src/`) |
| 2 | Base score 1.3 คำนวณจากอะไร | ⬜ | - | ได้ raw code ของ formula ครบ (บรรทัด, ไฟล์, ตัวแปรทุกตัวที่เข้าสมการ) | investigation prompt: `rg "base_score" src/` แล้วดู scoring module เต็มไฟล์ |
| 3 | Source ไหนน่าเชื่อถือที่สุด (ที่มาของ weight) | ⬜ | - | ได้ raw config/code ที่ผูก weight กับแต่ละ source + เหตุผลอ้างอิงได้ (เช่น MISP confidence, FIRST.org) | `rg "weight" src/integrations/threat_intel.py` + config.yaml |
| 4 | ช่องทางแจ้งเตือนผูกกับ severity ระดับไหน | ⬜ | - | ตาราง severity → channel (Email/LINE/Teams) ที่ตรงกับโค้ดจริง | เช็ค `notifications.py` ว่ามี mapping logic จริงหรือ hardcode |
| 5 | ความถี่แจ้งเตือน (IOC ใหม่เข้าทุกวัน) | ⬜ | - | policy เขียนชัด: real-time (Malicious) / digest (Suspicious) / none (Clean) + throttle/dedup rule | เช็คว่ามี throttle logic อยู่แล้วหรือต้องออกแบบใหม่ |
| 6 | Role definition + user manual ต่อ role + scope | ⬜ | - | ตาราง role × scope × ผู้เกี่ยวข้อง + manual สั้นต่อ role | เช็คว่ามี RBAC ในโค้ดหรือยัง (`rg "role" src/`) — ถ้าไม่มี ต้อง report เป็น gap ตรงๆ |
| 7 | ทฤษฎีการคำนวณ + trust source ต้องอธิบายได้ | ⬜ | - | เอกสาร 1 หน้า: formula + ที่มาทางทฤษฎี + เหตุผล trust ranking (ต่อเนื่องจากข้อ 2+3) | รวมผลจากข้อ 2, 3 มาเขียนเป็นเอกสารเดียว |
| 8 | Approval gate ที่ Detection Rule ทำไมต้องมี / SOC แก้ได้ไหม | ⬜ | - | คำตอบ design (ทำไมต้องมี human gate) + สถานะจริงของ edit/review endpoint ในโค้ด | เช็ค validate/review/export flow (รู้อยู่แล้วว่า gate ยัง unimplemented เต็ม — ต้องพูดตรงๆ ว่าอันไหน design อันไหน gap) |

---

## B. Backlog (ห้ามแทรกก่อน Section A เสร็จ เว้นแต่ blocked)

| Item | Status | Notes |
|------|--------|-------|
| FuzzyHashAnalyzer ssdeep/tlsh fix | ⬜ | scoped ~15-20 lines, รอตัดสินใจ investigate vs direct fix |
| DGA `_extract_sld()` subdomain gap | 🔍 | รอ rg เพิ่มก่อนเขียน fix |
| RAG auto-seeding on startup | ⬜ | ยังไม่ยืนยันว่า `kb.seed()` รันตอน uvicorn startup |
| Email-level RAG references (Flow B) | 📝 | prompt ส่งให้ Codex แล้ว รอผล |
| HTML report 404 (3 playbooks) | ⬜ | pre-existing gap, ทราบ root cause แล้ว |
| Detection Rule Export remaining gaps | ⬜ | validate/review gate, file download, ZIP, deploy — ทั้งหมด 0 matches (เชื่อมกับ comment #8) |
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

## Weekly ritual (กันของหล่น)
1. ก่อนเริ่มแต่ละ session: เปิดไฟล์นี้ อัปเดต status เก่าก่อน แล้วค่อยเลือกงานถัดไป
2. ก่อนเริ่มแต่ละข้อ: เขียน DoD ใน column ให้ชัดก่อนสั่ง investigation prompt
3. จบแต่ละ session: อัปเดต status ทุกแถวที่แตะวันนี้ ห้ามปล่อยค้างเป็น 🔍 ข้ามคืนโดยไม่มี note
4. ก่อนพรีเซนต์: Section A ต้องไม่มีแถวไหนเป็น ⬜ — อย่างน้อยต้องเป็น 🔍 พร้อมคำตอบชั่วคราวที่มี evidence tier กำกับ

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
| Fit/score result path | ✅ | T1 | `fit_source_weights.py` และ `score_eval_results.py` ชี้ไป `eval_results_group_a_v2.jsonl`; ตรวจ syntax แล้ว แต่ยังไม่รันระหว่าง eval ไม่ครบ | รันหลังผลครบ 894 รายการ |
| Group A eval execution | 🔍 | T1 | Snapshot เวลา 14 Sep 2026 11:41:44: เขียนแล้ว 54/894 รายการ, unique 54, invalid JSON 0, เหลือ 840 รายการ; พบ Python process ที่เกี่ยวข้อง 2 โปรเซส | เฝ้าดูผลลัพธ์และไม่รัน fit/score จนกว่าจะครบ |
| แยก workflow ออกจาก `scripts/adhoc/` | ⬜ | T1 | สำรวจแล้ว แต่ยังไม่ได้ย้ายไฟล์; `scripts/adhoc/` และ `data/benchmark/` ยังถูก `.gitignore` ครอบอยู่ | รอ confirm โครงสร้างโฟลเดอร์ใหม่ก่อนย้าย |

### Group A files and evidence

- Dataset: `data/benchmark/benchmark_iocs_v2.json` — 894 records (`MALICIOUS=709`, `CLEAN=185`)
- Running script: `scripts/eval/eval_benchmark.py`
- Incremental results: `scripts/eval/eval_results_group_a_v2.jsonl`
- Analysis tools: `scripts/eval/fit_source_weights.py`, `scripts/adhoc/score_eval_results.py`
- Current result file is local/generated and must not be edited while eval is running.

---

## Weekly ritual (กันของหล่น)
1. ก่อนเริ่มแต่ละ session: เปิดไฟล์นี้ อัปเดต status เก่าก่อน แล้วค่อยเลือกงานถัดไป
2. ก่อนเริ่มแต่ละข้อ: เขียน DoD ใน column ให้ชัดก่อนสั่ง investigation prompt
3. จบแต่ละ session: อัปเดต status ทุกแถวที่แตะวันนี้ ห้ามปล่อยค้างเป็น 🔍 ข้ามคืนโดยไม่มี note
4. ก่อนพรีเซนต์: Section A ต้องไม่มีแถวไหนเป็น ⬜ — อย่างน้อยต้องเป็น 🔍 พร้อมคำตอบชั่วคราวที่มี evidence tier กำกับ

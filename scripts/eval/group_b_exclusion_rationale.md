# Group B exclusion rationale

วันที่จัดทำ: 2026-09-14 (Asia/Bangkok)

สถานะ: documentation/design rationale เท่านั้น เอกสารนี้ไม่ได้เพิ่ม logic ใหม่
และไม่เปลี่ยน policy ที่ implement แล้วในขั้นที่ 2-3

## Problem statement

ระบบเรียก threat-intelligence sources หลายตัวแบบ best-effort พร้อมกัน แต่ผลลัพธ์
จาก source ที่มีปัญหาเชิงระบบ เช่น authentication gate, rate limit หรือ timeout
สามารถทำให้ latency ของ investigation สูงขึ้น และทำให้คะแนน/verdict ขึ้นกับ
availability ของ dependency มากกว่าความหมายของข้อมูลที่ได้จริง

หลักฐานเชิงประจักษ์ที่ใช้ประกอบการตัดสินใจ:

1. AlienVault OTX มีการ observe timeout ที่ 15 วินาทีใน integration path เดิม
   ซึ่งเป็น timeout ceiling ของ `safe_execute()` ไม่ใช่หลักฐานว่าเนื้อหา OTX
   ไม่น่าเชื่อถือ แต่เป็นหลักฐานว่า dependency path ไม่เหมาะกับ critical scoring path
   ในสภาวะที่รอ response ไม่ได้
2. ThreatFox ถูกทดสอบตรงด้วย key ที่ configured แล้ว 5 call ใน session เดียวกัน:
   HTTP 200 ครบทุก call, ไม่มี timeout/exception, latency 487.4-905.5 ms
   (รายละเอียดในตารางด้านล่าง)
3. `sources_checked` ที่ `threat_intel.py:1076` นับจำนวน task ที่พยายามเรียก
   รวม Group B ด้วย ค่าเดิมจึงเหมาะเป็น informational count แต่ไม่ควรใช้เป็น
   denominator ของ scoring coverage หลังจากแยก reliability group แล้ว

ข้อสรุป: ThreatFox ยังคงอยู่ใน Group A ตาม operational evidence ส่วน source ใน
`GROUP_B_EXCLUDE` ถูกกันออกจากสูตรคะแนน/verdict แต่ยังถูกเรียกแบบ optional/
best-effort และ raw result ยังถูกเก็บเพื่อการตรวจสอบและรายงาน

## Design decision

### Reliability-based exclusion

ใช้ reliability ของ dependency path เป็น gating dimension แยกจาก credibility
ของ information:

- Group A: response path มีเสถียรภาพเพียงพอสำหรับ critical scoring path
- Group B: มีหลักฐาน operational เรื่อง auth/rate-limit/timeout จึงไม่เข้า
  weighted score, average, multi-source boost หรือ verdict coverage denominator
- Raw Group B ไม่ถูกลบ เพื่อให้ analyst ตรวจสอบ evidence เดิมได้

ใน `calculate_source_coverage()` จึงเก็บ `coverage["group_a"]` และ
`coverage["group_b"]` แยกกัน ขณะที่ historical top-level coverage fields ถูก
ตั้งให้สะท้อน Group A เพื่อให้ `determine_verdict()` ใช้ denominator ที่ถูกต้อง
โดยไม่สูญเสียความโปร่งใสของข้อมูล Group B

### Circuit-breaker principle

แนวคิดนี้สอดคล้องกับ Circuit Breaker Pattern: dependency ที่ไม่น่าเชื่อถือใน
เชิงระบบไม่ควรอยู่บนเส้นทางตัดสินใจหลัก เพราะ failure หรือการค้างของ dependency
อาจทำให้ resource ถูกใช้ต่อเนื่องและทำให้ระบบหลักเปราะบาง แต่ยังสามารถเรียกแบบ
best-effort เพื่อเก็บข้อมูลเสริมได้

เอกสารนี้ใช้คำว่า “circuit-breaker principle” อย่างระมัดระวัง: การเปลี่ยนแปลง
ในขั้นนี้คือ scoring exclusion และการแยก coverage; ไม่ได้อ้างว่าได้เพิ่ม stateful
open/half-open circuit breaker ใหม่ในรอบ documentation นี้

## Empirical evidence

ตัวเลขด้านล่างมาจากการทดสอบจริงใน session นี้ ไม่ใช่ synthetic benchmark
และไม่ควรตีความเป็น SLA ระยะยาว

| Source | IOC ที่ทดสอบ | เวลา/ผลที่สังเกต | ผลต่อ design |
|---|---|---:|---|
| ThreatFox | IPv4 `8.8.8.8` | 905.5 ms, HTTP 200, Not listed | คงไว้ Group A |
| ThreatFox | Domain `example.com` | 492.7 ms, HTTP 200, No exact match | คงไว้ Group A |
| ThreatFox | URL `https://example.com/` | 644.9 ms, HTTP 200, Not listed | คงไว้ Group A |
| ThreatFox | MD5 `44d88612fea8...` | 502.8 ms, HTTP 200, Not listed | คงไว้ Group A |
| ThreatFox | SHA256 `0123456789ab...` | 487.4 ms, HTTP 200, Not listed | คงไว้ Group A |
| ThreatFox | ทั้ง 5 calls | average 606.7 ms, median 502.8 ms, range 487.4-905.5 ms | ไม่มี timeout/error ใน sample |
| AlienVault OTX | integration path เดิม | observe timeout ที่ 15 s | ไม่เข้า critical scoring path |

หมายเหตุ: AlienVault row เป็นหลักฐาน timeout ที่ observe ได้ ไม่ใช่ค่าเฉลี่ยจาก
sample 5 ครั้งที่วัดคู่ขนานกับ ThreatFox จึงไม่ควรสรุปว่าเป็น comparative SLA
โดยตรง

## Citations and methodological basis

1. **NATO / Admiralty System** — FM 2-22.3 (Human Intelligence Collector
   Operations) เป็นฐานอ้างอิงของการแยก source reliability ออกจาก information
   credibility ใน taxonomy ที่ใช้ต่อมาใน MISP:
   [FM 2-22.3 PDF](https://rdl.train.army.mil/catalog-ws/view/100.ATSC/820FF809-6358-4C86-AC30-82CAE5ED6786-1743454720095/FM2_22x3.pdf)
2. **MISP Admiralty-scale taxonomy** — MISP อธิบาย Admiralty/NATO Scale ว่าใช้
   จัดอันดับทั้ง reliability ของ source และ credibility ของ information:
   [MISP training taxonomy refresher](https://www.misp-project.org/misp-training/misp-training.pdf)
   และ [MISP compliance overview](https://misp-project.org/compliance/iso-iec-27010/)
3. **Circuit Breaker** — Michael T. Nygard, *Release It!*, March 2007,
   chapter/pattern 5.2 Circuit Breaker:
   [O'Reilly book page](https://www.oreilly.com/library/view/release-it/9781680500264/f_0043.xhtml)
   และ [Martin Fowler's CircuitBreaker summary](https://martinfowler.com/bliki/CircuitBreaker.html)
4. **MISP scoring methodology** — Mokaddem, Wagener, Dulaunoy และ Iklody,
   “Taxonomy driven indicator scoring in MISP threat intelligence platforms,”
   arXiv:1902.03914 ใช้เป็น methodological support สำหรับการนำ taxonomy และ
   source-related weights ไปประกอบ indicator scoring:
   [arXiv:1902.03914](https://arxiv.org/abs/1902.03914)

## Scope and audit notes

- `GROUP_B_EXCLUDE` เป็น reliability gate ไม่ใช่คำตัดสินว่า content ของ Group B
  เป็นเท็จหรือไม่มีประโยชน์
- `sources_checked` ยังคงเป็นจำนวน source ที่พยายามเรียกทั้งหมดเพื่อความโปร่งใส
- `coverage.group_a` ใช้เป็น authoritative coverage สำหรับ verdict
- `coverage.group_b` ใช้แสดง availability/flagged/clean/stale/unavailable ของ
  dependency ที่ถูก exclude
- ไม่มีการแก้ `src/mcp_servers/**`, `mcp_client.py`, `src/web/websocket.py`,
  `config.yaml` และไม่มีการ commit

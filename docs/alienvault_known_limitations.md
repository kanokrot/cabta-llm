# AlienVault OTX Known Limitation

AlienVault OTX ให้ score สูง (มักเต็ม 100) กับบาง popular/legit domain ที่ถูกอ้างอิงใน pulse จำนวนมาก
(พบใน dzen.ru, hicloudcam.com) เพราะ unique_attribution_count สูงจนชนค่า cap
ไม่ใช่ bug ในโค้ดเรา — เป็นข้อจำกัดของข้อมูลต้นทาง ยืนยันแล้วว่าไม่มี CLEAN domain อื่นในชุดทดสอบ 85 ตัว
ที่มีปัญหาแบบเดียวกัน (เช็คแล้ว 2026-09-13)

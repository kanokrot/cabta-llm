"""
แยกออกมาจาก llm_analyzer.py เพื่อแก้ปัญหา verdict mismatch:
- Scoring engine (deterministic) กับ LLM analysis เคยให้ verdict ไม่ตรงกัน
  เช่น threat_score=42 (ควรเป็น SUSPICIOUS ตาม README) แต่ LLM ตอบ MALICIOUS
- โมดูลนี้บังคับให้ scoring engine เป็น single source of truth เสมอ
  LLM มีหน้าที่แค่ "อธิบาย" ไม่ใช่ "ตัดสิน"
"""

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

SCORE_THRESHOLDS = [
    (70, "MALICIOUS"),
    (40, "SUSPICIOUS"),
    (1, "CLEAN"),
]


def compute_authoritative_verdict(threat_score: int) -> str:
    """
    คำนวณ verdict ตัวจริงจาก threat_score โดยตรง (deterministic) ไม่ให้ LLM คำนวณเอง

    Args:
        threat_score: คะแนน 0-100 จาก scoring engine

    Returns:
        "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "UNKNOWN"
    """
    for min_score, verdict in SCORE_THRESHOLDS:
        if threat_score >= min_score:
            return verdict
    return "UNKNOWN"


def enforce_verdict_consistency(
    llm_result: Dict,
    authoritative_verdict: str,
) -> Dict:
    """
    บังคับให้ verdict ของ LLM output ตรงกับ scoring engine เสมอ
    (defense-in-depth ชั้นที่ 2 เผื่อ LLM ไม่เชื่อฟัง prompt-level rule)

    Args:
        llm_result: JSON response ที่ parse แล้วจาก LLM (มี key 'verdict')
        authoritative_verdict: verdict จริงที่คำนวณจาก threat_score

    Returns:
        llm_result ที่ verdict ถูก override ให้ตรงกับ scoring engine แล้ว
        พร้อม note เตือนถ้ามีการ override เกิดขึ้น
    """
    if not llm_result or not authoritative_verdict:
        return llm_result

    llm_claimed_verdict = llm_result.get("verdict")

    if llm_claimed_verdict and llm_claimed_verdict != authoritative_verdict:
        logger.warning(
            f"[Verdict Guardrail] Mismatch detected: LLM said '{llm_claimed_verdict}' "
            f"but scoring engine says '{authoritative_verdict}' — overriding to scoring engine result"
        )
        llm_result["verdict_override_note"] = (
            f"⚠️ LLM originally suggested '{llm_claimed_verdict}', "
            f"corrected to '{authoritative_verdict}' to match the deterministic scoring engine. "
            f"This mismatch has been logged for review."
        )

    # scoring engine เป็น source of truth เสมอ ไม่ว่า LLM จะตอบว่าอะไรมา
    llm_result["verdict"] = authoritative_verdict

    return llm_result


def check_source_hallucination(
    llm_result: Dict,
    valid_sources: set,
    all_known_sources: list,
) -> Dict:
    """
    เช็คว่า LLM พูดถึง source ที่ไม่ได้อยู่ใน verified findings หรือไม่
    (ของเดิมจาก _validate_llm_analysis ย้ายมาไว้ตรงนี้เพื่อรวม guardrail logic ไว้ที่เดียว)

    Args:
        llm_result: JSON response จาก LLM
        valid_sources: source names ที่ยืนยันแล้วจริง (status == '✓')
        all_known_sources: source names ทั้งหมดที่ CABTA รู้จัก

    Returns:
        llm_result พร้อม 'hallucination_warning' ถ้าเจอ source แปลกปลอม
    """
    if not llm_result or "analysis" not in llm_result:
        return llm_result

    analysis_text = llm_result.get("analysis", "").lower()

    suspicious_mentions = [
        source_name for source_name in all_known_sources
        if source_name in analysis_text and source_name not in valid_sources
    ]

    if suspicious_mentions:
        logger.warning(
            f"[Verdict Guardrail] Possible hallucination detected: LLM analysis "
            f"mentioned {suspicious_mentions} which were NOT in verified "
            f"findings {valid_sources or '(none)'}"
        )
        llm_result["hallucination_warning"] = (
            f"⚠️ Analyst Note: This AI-generated analysis references source(s) "
            f"{suspicious_mentions} that were not part of the verified findings. "
            f"Please cross-check manually before acting on this summary."
        )

    return llm_result


def validate_llm_analysis(
    llm_result: Dict,
    context: Dict,
    threat_score: Optional[int] = None,
    all_known_sources: Optional[list] = None,
) -> Dict:
    """
    Entry point เดียวที่ llm_analyzer.py เรียกใช้
    รวม guardrail ทั้งหมด: verdict consistency + hallucination check

    Args:
        llm_result: JSON response จาก LLM
        context: context dict ที่ส่งเข้า LLM (มี 'key_findings')
        threat_score: คะแนนจาก scoring engine (ถ้ามี จะเช็ค verdict consistency ด้วย)
        all_known_sources: list ของ source names ทั้งหมด (ถ้าไม่ส่งมา จะข้ามการเช็ค hallucination)

    Returns:
        llm_result ที่ผ่านการ validate ครบทุกชั้นแล้ว
    """
    if not llm_result:
        return llm_result

    # ชั้น 1: บังคับ verdict ให้ตรงกับ scoring engine
    if threat_score is not None:
        authoritative_verdict = compute_authoritative_verdict(threat_score)
        llm_result = enforce_verdict_consistency(llm_result, authoritative_verdict)

    # ชั้น 2: เช็ค hallucination ของ source names
    if all_known_sources:
        valid_sources = {f["source"] for f in context.get("key_findings", [])}
        llm_result = check_source_hallucination(llm_result, valid_sources, all_known_sources)

    return llm_result
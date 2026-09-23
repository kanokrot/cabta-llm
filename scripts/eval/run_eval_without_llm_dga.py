#!/usr/bin/env python3
"""Run eval_benchmark.py with the optional LLM-DGA enrichment disabled.

The current production enrichment path calls llm_dga_judge independently of
analysis.enable_llm.  This wrapper keeps the requested eval command's behavior
while disabling only that non-scoring enrichment at runtime; no src/** file is
modified.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.utils import llm_dga_judge


async def disabled_llm_dga_judge(domain, config):
    return {
        "domain": domain,
        "llm_verdict": "uncertain",
        "llm_reasoning": "disabled for benchmark evaluation",
        "error": "disabled_for_eval",
    }


llm_dga_judge.judge_domain = disabled_llm_dga_judge
sys.argv[0] = str(REPO_ROOT / "scripts" / "eval" / "eval_benchmark.py")
runpy.run_path(str(REPO_ROOT / "scripts" / "eval" / "eval_benchmark.py"), run_name="__main__")

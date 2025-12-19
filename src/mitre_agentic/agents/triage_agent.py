from __future__ import annotations

import json
from typing import Any, Dict, List

from openai import AsyncOpenAI
from pydantic import BaseModel, Field, ValidationError

from mitre_agentic.schemas import TriageInput, TriageOutput, TriagePlanStep


class _TriageLLMOut(BaseModel):
    summary: str = Field(max_length=600)
    suspected_behaviors: List[str] = Field(default_factory=list, max_length=12)
    candidate_platforms: List[str] = Field(default_factory=list, max_length=5)

    # technique_id -> evidence phrases
    technique_evidence: Dict[str, List[str]] = Field(default_factory=dict)

    # optional “keywords” for human readability only
    keywords: List[str] = Field(default_factory=list, max_length=20)


def _safe_get(d: Any, *path: str, default: Any = None) -> Any:
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _dedupe_str_list(xs: List[str], max_items: int) -> List[str]:
    out: List[str] = []
    seen = set()
    for x in xs:
        s = (x or "").strip()
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
        if len(out) >= max_items:
            break
    return out


def _dedupe_technique_evidence(m: Dict[str, List[str]], max_evidence_per_tech: int = 6) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for tid, ev in (m or {}).items():
        if not tid or not isinstance(ev, list):
            continue
        out[str(tid).strip()] = _dedupe_str_list([str(x) for x in ev], max_evidence_per_tech)
    return out


async def triage_incident(
    payload: TriageInput,
    *,
    model: str = "gpt-4.1-mini",
) -> TriageOutput:
    """
    Agent 1 (Triage, LLM):
    - Extract candidate MITRE technique IDs + evidence phrases from raw incident text.
    - Produce a plan for subsequent agents.
    """
    text = payload.incident_text.strip()
    client = AsyncOpenAI()

    system = (
        "You are a SOC triage analyst specialized in mapping EDR alerts to MITRE ATT&CK. "
        "Identify all attack patterns and extract ATT&CK technique IDs *when confident* (Txxxx or Txxxx.xxx). "
        "For each technique, provide short evidence phrases copied/paraphrased from the incident text "
        "(e.g., process names, flags like -EncodedCommand, scheduled task creation, rundll32). "
        "Return ONLY valid JSON."
    )

    user = {
        "incident_text": text,
        "output_contract": {
            "summary": "string (<=600 chars)",
            "suspected_behaviors": ["string"],
            "candidate_platforms": ["Windows|Linux|macOS|Cloud|Network|Other"],
            "technique_evidence": {
                "Txxxx or Txxxx.xxx": ["evidence phrase 1", "evidence phrase 2"]
            },
            "keywords": ["optional short tokens for display only"],
        },
        "rules": [
            "Only include technique IDs that look valid: start with 'T' followed by digits; optional .xxx subtechnique.",
            "Evidence phrases must be short and concrete (<=80 chars each).",
            "Include up to ~10 techniques, that map to the identified patterns, ordered by likelihood.",
        ],
    }

    resp = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user)},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )

    raw = resp.choices[0].message.content or "{}"

    try:
        parsed = _TriageLLMOut.model_validate_json(raw)
    except ValidationError:
        # Safe fallback
        parsed = _TriageLLMOut(
            summary="LLM triage parsing failed; falling back to minimal triage.",
            suspected_behaviors=[],
            candidate_platforms=["Windows"],
            technique_evidence={},
            keywords=[],
        )

    technique_evidence = _dedupe_technique_evidence(parsed.technique_evidence, max_evidence_per_tech=6)
    keywords = _dedupe_str_list(parsed.keywords, 20)
    suspected = _dedupe_str_list(parsed.suspected_behaviors, 12)
    platforms = _dedupe_str_list(parsed.candidate_platforms, 5) or ["Windows"]

    plan = [
        TriagePlanStep(
            step=1,
            actor="mapping_agent",
            intent="Confirm technique details and tactics for top-K candidate techniques.",
            suggested_tools=["get_technique_by_id", "get_technique_tactics"],
            notes="Use top-K technique IDs from triage technique_evidence; confirm with MCP.",
        ),
        TriagePlanStep(
            step=2,
            actor="intel_agent",
            intent="Find threat groups and software associated with confirmed techniques.",
            suggested_tools=["get_groups_using_technique", "get_software_using_technique"],
            notes="Reverse lookups using technique STIX IDs.",
        ),
        TriagePlanStep(
            step=3,
            actor="detection_agent",
            intent="Pull STIX data components (if present) and then LLM fallback when missing.",
            suggested_tools=["get_datacomponents_detecting_technique"],
            notes="Router decides if Agent 5 runs for missing detection mappings.",
        ),
    ]

    return TriageOutput(
        summary=parsed.summary,
        suspected_behaviors=suspected,
        keywords=keywords,
        candidate_platforms=platforms,
        plan=plan,
        technique_evidence=technique_evidence,
    )

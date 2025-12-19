from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

import httpx
from dotenv import load_dotenv

from mitre_agentic.schemas import IncidentExecutiveReport

load_dotenv()

# (gpt-4.1-mini, gpt-4o-mini, etc.)
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")


def _safe(obj: Any, *path: str, default=None):
    cur = obj
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _extract_json_text(raw: str) -> str:
    """
    Returns a JSON string suitable for pydantic .model_validate_json().

    Handles common LLM wrappers:
      - ```json ... ```
      - ``` ... ```
      - Leading/trailing commentary around a JSON object
    """
    if not raw:
        return raw

    s = raw.strip()

    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", s, flags=re.DOTALL | re.IGNORECASE)
    if fence:
        s = fence.group(1).strip()

    obj_start = s.find("{")
    arr_start = s.find("[")
    if obj_start == -1 and arr_start == -1:
        return s

    start = min([i for i in [obj_start, arr_start] if i != -1])
    candidate = s[start:].strip()

    try:
        json.loads(candidate)
        return candidate
    except Exception:
        last_obj = candidate.rfind("}")
        last_arr = candidate.rfind("]")
        end = max(last_obj, last_arr)
        if end != -1:
            return candidate[: end + 1].strip()
        return candidate


def _compact_techniques(confirmed: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for t in confirmed or []:
        tid = t.get("id", "")
        name = t.get("name", "")
        tactics = t.get("tactics", [])

        tactic_names: List[str] = []
        if isinstance(tactics, list):
            for x in tactics:
                if isinstance(x, dict) and x.get("tactic"):
                    tactic_names.append(str(x["tactic"]))

        tactic_str = ", ".join(sorted(set(tactic_names))) if tactic_names else "Unknown"
        out.append(f"{tid} {name} ({tactic_str})".strip())

    return out[:20]


def _compact_intel(intel: Dict[str, Any], max_items: int = 12) -> List[str]:
    """
    Compact intel agent data into readable lines for LLM context.
    Returns lines like:
      "T1055 Process Injection: Groups=APT28, FIN7 | Software=Cobalt Strike, Empire"
    """
    lines: List[str] = []
    intel_items = (intel or {}).get("intel", [])
    if not isinstance(intel_items, list):
        return lines

    for item in intel_items[:max_items]:
        if not isinstance(item, dict):
            continue

        tech = item.get("technique", {})
        if not isinstance(tech, dict):
            continue

        tid = str(tech.get("id", "") or "")
        tname = str(tech.get("name", "") or "")

        groups = item.get("groups_using_technique", [])
        gnames: List[str] = []
        if isinstance(groups, list):
            for g in groups:
                if isinstance(g, dict) and isinstance(g.get("name"), str):
                    gnames.append(g["name"])

        software = item.get("software_using_technique", [])
        snames: List[str] = []
        if isinstance(software, list):
            for s in software:
                if isinstance(s, dict) and isinstance(s.get("name"), str):
                    snames.append(s["name"])

        if gnames or snames:
            groups_str = ", ".join(gnames[:5]) if gnames else "—"
            software_str = ", ".join(snames[:5]) if snames else "—"
            lines.append(f"{tid} {tname}: Groups={groups_str} | Software={software_str}")

    return lines


def _compact_detections(
    detections: Dict[str, Any],
    reasoning: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Provide both STIX-backed detections and LLM fallback hypotheses (if present)
    as context to the report writer.
    """
    stix_rows: List[Dict[str, Any]] = []
    for item in (detections or {}).get("detections", []):
        tech = item.get("technique", {}) if isinstance(item, dict) else {}
        det = item.get("detection", {}) if isinstance(item, dict) else {}

        stix_rows.append(
            {
                "technique_id": tech.get("id"),
                "technique_name": tech.get("name"),
                "stix_total_datacomponents": det.get("total_datacomponents", 0),
                "stix_top_datacomponents": det.get("top_datacomponents", []),
                "note": det.get("message") or "",
            }
        )

    llm_rows: List[Any] = []
    if isinstance(reasoning, dict):
        if "llm_detections" in reasoning:
            llm_rows = reasoning.get("llm_detections") or []
        elif "hypotheses" in reasoning:
            llm_rows = reasoning.get("hypotheses") or []

    return {"stix": stix_rows, "llm": llm_rows}


def _compact_mitigations(mitigations_ctx: Dict[str, Any], max_per_technique: int = 6) -> Dict[str, Any]:
    """
    mitigation_agent output (expected):
      {"domain": "...", "mitigations": [{"technique": {...}, "mitigations":[...], "count":..., "formatted":...}, ...]}

    We give the LLM:
      - structured lines per technique (names/ids)
      - and the raw 'formatted' block as fallback reference (but clipped)
    """
    items = (mitigations_ctx or {}).get("mitigations", [])
    if not isinstance(items, list):
        items = []

    structured: List[Dict[str, Any]] = []
    formatted_by_tech: List[Dict[str, str]] = []

    for it in items:
        if not isinstance(it, dict):
            continue

        tech = it.get("technique", {})
        if not isinstance(tech, dict):
            tech = {}

        tech_id = str(tech.get("id") or "")
        tech_name = str(tech.get("name") or "")

        mit_list = it.get("mitigations", [])
        if not isinstance(mit_list, list):
            mit_list = []

        top = []
        for m in mit_list[:max_per_technique]:
            if isinstance(m, dict):
                top.append(
                    {
                        "attack_id": m.get("attack_id"),
                        "name": m.get("name"),
                        "stix_id": m.get("stix_id"),
                    }
                )

        structured.append(
            {
                "technique_id": tech_id,
                "technique_name": tech_name,
                "count": int(it.get("count") or len(mit_list)),
                "top_mitigations": top,
            }
        )

        fmt = it.get("formatted") or ""
        if isinstance(fmt, str) and fmt.strip():
            formatted_by_tech.append(
                {
                    "technique_id": tech_id,
                    "formatted": fmt[:2000],  # bounded
                }
            )

    return {"structured": structured, "formatted": formatted_by_tech}


async def write_executive_report_llm(
    *,
    incident_text: str,
    triage_summary: str,
    confirmed_techniques: List[Dict[str, Any]],
    intel: Dict[str, Any],
    detections: Dict[str, Any],
    mitigations: Optional[Dict[str, Any]] = None,
    detection_reasoning: Optional[Dict[str, Any]] = None,
    navigator_layer_path: Optional[str] = None,
    model: str = DEFAULT_MODEL,
) -> Dict[str, Any]:
    """
    Agent (Reporting):
    LLM writes a full executive report as JSON (validated by IncidentExecutiveReport),
    then returns {"report": <validated dict>}.
    """
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set. Add it to .env")

    context = {
        "incident_text": incident_text,
        "triage_summary": triage_summary,
        "mapped_techniques": _compact_techniques(confirmed_techniques),
        "intel_summary": _compact_intel(intel),
        "detection_context": _compact_detections(detections, detection_reasoning),
        "mitigations_context": _compact_mitigations(mitigations or {}),
        "navigator_layer_path": navigator_layer_path,
    }

    system = (
        "You are a senior Incident Response lead writing an executive report.\n"
        "Use ONLY the provided structured context.\n"
        "Return ONLY valid JSON (no code fences) matching the required schema.\n"
        "Be specific and actionable. Do NOT invent facts.\n"
        "If something is unknown, write 'unknown'."
    )

    user = (
        "Write an executive incident report from this context.\n\n"
        "Schema fields (must include all):\n"
        "- title (<=140)\n"
        "- executive_summary (<=900)\n"
        "- likely_attack_flow (3-12 bullet lines)\n"
        "- mapped_techniques (1-20 lines)\n"
        "- notable_groups_software (0-30 lines)\n"
        "- detection_recommendations (3-20 lines)\n"
        "- immediate_actions (3-15 lines)\n"
        "- iocs: { suspected_artifacts[], suspicious_processes[], suspicious_network[] }\n"
        "- navigator_layer_path (string or null)\n"
        "- markdown (full report in Markdown, <=12000)\n\n"
        f"CONTEXT JSON:\n{json.dumps(context, indent=2)}"
    )

    async with httpx.AsyncClient(timeout=90) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": 0.2,
            },
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]

    content = _extract_json_text(content)

    report = IncidentExecutiveReport.model_validate_json(content)
    return {"report": report.model_dump()}

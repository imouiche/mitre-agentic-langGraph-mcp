from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from openai import AsyncOpenAI
from pydantic import ValidationError

from mitre_agentic.schemas import DetectionLLMOutput


# Helpers

def _safe_get(d: Any, *path: str, default: Any = None) -> Any:
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _truncate_list(x: Any, n: int) -> List[Any]:
    return x[:n] if isinstance(x, list) else []


def _clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def _truncate_str(s: Any, max_len: int) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= max_len else (s[: max_len - 1] + "…")


def _extract_json_object(text: str) -> str:
    """
    Best-effort: if the model returns extra text, try to extract the first JSON object.
    """
    if not text:
        return "{}"
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return "{}"


def _sanitize_llm_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enforce schema constraints BEFORE Pydantic validation to prevent crashes:
      - technique_id/name <= 140
      - hypotheses length 1..5
      - title <= 140
      - telemetry list length 2..8, each item <= 140
      - rationale <= 400
      - confidence in {low, medium, high}
    """
    out: Dict[str, Any] = {}

    out["technique_id"] = _truncate_str(payload.get("technique_id", ""), 140)
    out["technique_name"] = _truncate_str(payload.get("technique_name", ""), 140)

    raw_h = payload.get("hypotheses", [])
    if not isinstance(raw_h, list):
        raw_h = []

    raw_h = raw_h[:5]  # max 5
    cleaned_h: List[Dict[str, Any]] = []

    for h in raw_h:
        if not isinstance(h, dict):
            continue

        title = _truncate_str(h.get("title", ""), 140)

        telemetry = h.get("telemetry", [])
        if not isinstance(telemetry, list):
            telemetry = []
        telemetry = [ _truncate_str(x, 140) for x in telemetry if x is not None ]
        telemetry = telemetry[:8]  # max 8

        # Ensure at least 2 telemetry items (schema expects 2..8)
        if len(telemetry) < 2:
            # Sensible defaults if model gave too little
            if len(telemetry) == 0:
                telemetry = ["Endpoint process telemetry (EDR/Sysmon)", "Network telemetry (DNS/Proxy/Firewall)"]
            else:
                telemetry.append("Endpoint process telemetry (EDR/Sysmon)")

        rationale = _truncate_str(h.get("rationale", ""), 400)

        conf = str(h.get("confidence", "medium")).lower().strip()
        if conf not in {"low", "medium", "high"}:
            conf = "medium"

        cleaned_h.append(
            {
                "title": title,
                "telemetry": telemetry,
                "rationale": rationale,
                "confidence": conf,
            }
        )

    # Ensure at least 1 hypothesis
    if not cleaned_h:
        cleaned_h = [
            {
                "title": "Correlate endpoint execution chain with network activity",
                "telemetry": ["Endpoint process telemetry (EDR/Sysmon)", "Network telemetry (DNS/Proxy/Firewall)"],
                "rationale": "When vendor mappings are missing, correlating process lineage with outbound traffic often surfaces suspicious behaviors.",
                "confidence": "medium",
            }
        ]

    out["hypotheses"] = cleaned_h
    return out


# LLM Interaction

async def _llm_generate_detection_hypotheses(
    *,
    client: AsyncOpenAI,
    technique_id: str,
    technique_name: str,
    technique_description: str,
    incident_text: str,
    model: str,
) -> DetectionLLMOutput:
    """
    Ask the LLM for detection hypotheses in a strict schema.
    We sanitize/truncate before Pydantic validation so the app never crashes
    on "string_too_long" errors.
    """
    # Thanks to ed donner LLM course for prompt pattern
    system = (
        "You are a senior detection engineer. "
        "Return detection ideas that are practical, log-source oriented, and defensible. "
        "Avoid vague advice. Focus on telemetry sources (EDR/Sysmon/Windows Event Logs/Proxy/DNS/etc). "
        "Output MUST be valid JSON matching the provided schema."
    )

    user = {
        "task": "Generate detection hypotheses for a MITRE ATT&CK technique when STIX detection mappings are missing.",
        "technique": {
            "id": technique_id,
            "name": technique_name,
            "description": technique_description,
        },
        "incident_context": incident_text,
        "constraints": {
            "num_hypotheses": "1 to 5",
            "telemetry_items_per_hypothesis": "2 to 8",
            "title_max_len": 140,
            "telemetry_item_max_len": 140,
            "rationale_max_len": 400,
            "confidence_values": ["low", "medium", "high"],
        },
        "schema": {
            "technique_id": "string<=140",
            "technique_name": "string<=140",
            "hypotheses": [
                {
                    "title": "string<=140",
                    "telemetry": ["string<=140", "... (2..8)"],
                    "rationale": "string<=400",
                    "confidence": "low|medium|high",
                }
            ],
        },
        "output_instructions": "Return ONLY JSON. No markdown, no extra keys.",
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

    raw_text = resp.choices[0].message.content or "{}"
    raw_text = _extract_json_object(raw_text)

    try:
        parsed = json.loads(raw_text)
    except Exception:
        parsed = {}

    # Some models wrap/unwrap the payload -> FTSE
    if isinstance(parsed, dict):
        for k in ("result", "output", "data"):
            if isinstance(parsed.get(k), dict):
                parsed = parsed[k]
                break

    if not isinstance(parsed, dict):
        parsed = {}

    # Enforce length + shape constraints BEFORE Pydantic validation
    sanitized = _sanitize_llm_payload(parsed)

    # Validate + coerce into our schema (now safe)
    return DetectionLLMOutput.model_validate(sanitized)


# ----------------------------
# Agent wrapper (STIX -> else LLM)

# LiteLLM would be better in terms of cost/speed? feel free ...

async def reason_detection_with_llm_fallback(
    *,
    confirmed_techniques: List[Dict[str, Any]],
    stix_detection_output: Dict[str, Any],
    incident_text: str,
    model: str = "gpt-4.1-mini",
    max_hypotheses_per_technique: int = 3, # do not overwelm the analyst
) -> Dict[str, Any]:
    """
    Agent (Detection Reasoning, LLM fallback):
    - If STIX provides data components, keep them.
    - If STIX provides none, ask LLM for structured detection hypotheses.
    """
    openai_client = AsyncOpenAI()

    detections = _safe_get(stix_detection_output, "detections", default=[])
    stix_by_id: Dict[str, Dict[str, Any]] = {}

    for item in detections:
        tech = item.get("technique", {}) if isinstance(item, dict) else {}
        det = item.get("detection", {}) if isinstance(item, dict) else {}
        tid = tech.get("id")
        if tid:
            stix_by_id[str(tid)] = {"technique": tech, "detection": det}

    out: List[Dict[str, Any]] = []

    for t in confirmed_techniques:
        tid = str(t.get("id") or "")
        tname = str(t.get("name") or "")
        tdesc = str(t.get("description") or "")

        stix_item = stix_by_id.get(tid, {})
        stix_det = stix_item.get("detection", {}) if stix_item else {}

        total = int(stix_det.get("total_datacomponents", 0) or 0)
        top_components = stix_det.get("top_datacomponents", []) or []
        top_components = _truncate_list(top_components, 10)

        if total > 0:
            out.append(
                {
                    "technique": {"id": tid, "name": tname, "stix_id": t.get("stix_id")},
                    "mode": "stix_datacomponents",
                    "stix": {"total": total, "top_datacomponents": top_components},
                    "llm": None,
                }
            )
            continue

        # LLM fallback (safe + truncated)
        llm_structured = await _llm_generate_detection_hypotheses(
            client=openai_client,
            technique_id=_truncate_str(tid, 140),
            technique_name=_truncate_str(tname, 140),
            technique_description=str(tdesc or ""),
            incident_text=str(incident_text or ""),
            model=model,
        )

        llm_structured.hypotheses = llm_structured.hypotheses[:max_hypotheses_per_technique]

        out.append(
            {
                "technique": {"id": tid, "name": tname, "stix_id": t.get("stix_id")},
                "mode": "llm_fallback",
                "stix": {"total": 0, "top_datacomponents": []},
                "llm": llm_structured.model_dump(),
                "note": (
                    "STIX returned 0 data components for this technique in this release; "
                    "LLM generated detection hypotheses using incident context."
                ),
            }
        )

    return {"detection_reasoning": out}

# data components / detection mapping agent
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from mitre_agentic.mcp_client import MitreMcpClient


def _safe_get(d: Any, *path: str, default: Any = None) -> Any:
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _extract_component_names(datacomponents_payload: Any, max_items: int) -> Tuple[List[str], int]:
    """
    mitreattack-python commonly returns RelationshipEntry[DataComponent]-like dicts:
      [
        { "object": { "name": "Process Creation", ... }, "relationships": [...] },
        ...
      ]
    We extract readable names safely.
    """
    if not isinstance(datacomponents_payload, list):
        return ([], 0)

    names: List[str] = []
    for item in datacomponents_payload:
        if not isinstance(item, dict):
            continue

        obj = item.get("object")
        if isinstance(obj, dict):
            name = obj.get("name")
            if name:
                names.append(str(name))
        else:
            # fallback shape (rare): the item itself may be the object
            name = item.get("name")
            if name:
                names.append(str(name))

    total = len(names)
    return (names[:max_items], total)


def _compact_detection_text(text: Optional[str], max_chars: int = 280) -> str:
    """
    Make ATT&CK detection guidance readable in terminal.
    """
    if not text:
        return ""
    s = " ".join(text.strip().split())
    return s[:max_chars] + ("..." if len(s) > max_chars else "")


async def _fallback_detection_from_technique_object(
    client: MitreMcpClient,
    technique_stix_id: str,
    domain: str,
) -> Dict[str, Any]:
    """
    Fallback when the structured datacomponent mapping returns 0.
    We fetch the technique object and use its built-in fields:
      - x_mitre_data_sources (list[str])
      - x_mitre_detection (str)
    This is often *more understandable* for humans anyway.
    """
    obj_resp = await client.call_tool(
        "get_object_by_stix_id",
        {"stix_id": technique_stix_id, "domain": domain},
    )

    # Depending on your server wrapper, technique may be under result/object.
    technique_obj = (
        _safe_get(obj_resp, "result", "object", default=None)
        or _safe_get(obj_resp, "result", default=None)
        or obj_resp
    )

    if not isinstance(technique_obj, dict):
        return {
            "fallback_used": True,
            "data_sources": [],
            "detection_text": "",
            "note": "Technique object could not be parsed for detection guidance.",
        }

    data_sources = technique_obj.get("x_mitre_data_sources") or []
    if not isinstance(data_sources, list):
        data_sources = []

    detection_text = technique_obj.get("x_mitre_detection") or ""
    if not isinstance(detection_text, str):
        detection_text = ""

    return {
        "fallback_used": True,
        "data_sources": [str(x) for x in data_sources][:12],  # keep demo readable
        "detection_text": _compact_detection_text(detection_text),
        "note": "Structured data components were empty; used ATT&CK technique detection guidance instead.",
    }


async def recommend_detection_telemetry(
    client: MitreMcpClient,
    *,
    confirmed_techniques: List[Dict[str, Any]],
    domain: str = "enterprise",
    max_items: int = 8,
) -> Dict[str, Any]:
    """
    Agent 4 (Detection):
    1) Try structured "data components detecting technique"
    2) If tool returns 0, fallback to technique's built-in detection guidance
       via get_object_by_stix_id (x_mitre_detection + x_mitre_data_sources).
    """
    out: List[Dict[str, Any]] = []

    for t in confirmed_techniques:
        stix_id = t.get("stix_id")
        if not stix_id:
            continue

        # --- Primary: structured data components ---
        resp = await client.call_tool(
            "get_datacomponents_detecting_technique",
            {"technique_stix_id": stix_id, "domain": domain},
        )

        payload = _safe_get(resp, "result", default=None) or resp
        count = 0
        datacomponents = []

        if isinstance(payload, dict):
            count = int(payload.get("count") or 0)
            datacomponents = payload.get("datacomponents") or []

        top_names, total = _extract_component_names(datacomponents, max_items=max_items)

        detection_block: Dict[str, Any] = {
            "mode": "datacomponents",
            "total_datacomponents": total,
            "top_datacomponents": top_names,
        }

        # --- Fallback if empty ---
        if count == 0 or total == 0:
            fallback = await _fallback_detection_from_technique_object(
                client, technique_stix_id=stix_id, domain=domain
            )
            detection_block = {
                "mode": "fallback_technique_detection",
                **fallback,
            }

        out.append(
            {
                "technique": {
                    "id": t.get("id"),
                    "name": t.get("name"),
                    "stix_id": stix_id,
                },
                "detection": detection_block,
            }
        )

    return {"domain": domain, "detections": out}

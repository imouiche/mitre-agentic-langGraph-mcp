from __future__ import annotations

from typing import Any, Dict, List

from mitre_agentic.mcp_client import MitreMcpClient


def _safe_get(d: Any, *path: str, default: Any = None) -> Any:
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


async def enrich_with_groups_and_software(
    client: MitreMcpClient,
    *,
    confirmed_techniques: List[Dict[str, Any]],
    domain: str = "enterprise",
    max_items: int = 8,
) -> Dict[str, Any]:
    """
    Agent 3 (Intel):
    For each confirmed technique, pull:
      - groups that use it
      - software that uses it
    """
    enriched: List[Dict[str, Any]] = []

    for t in confirmed_techniques:
        stix_id = t.get("stix_id")
        if not stix_id:
            continue

        groups_resp = await client.call_tool(
            "get_groups_using_technique",
            {"technique_stix_id": stix_id, "domain": domain},
        )
        software_resp = await client.call_tool(
            "get_software_using_technique",
            {"technique_stix_id": stix_id, "domain": domain},
        )

        # groups = _safe_get(groups_resp, "groups", default=[])
        # software = _safe_get(software_resp, "software", default=[])

        #let's handles schema variations without crashes--
        groups = (
            _safe_get(groups_resp, "result", "groups", default=None)
            or _safe_get(groups_resp, "groups", default=[])
        )

        software = (
            _safe_get(software_resp, "result", "software", default=None)
            or _safe_get(software_resp, "software", default=[])
)


        # Keep demo readable
        groups = groups[:max_items] if isinstance(groups, list) else []
        software = software[:max_items] if isinstance(software, list) else []

        enriched.append(
            {
                "technique": {
                    "id": t.get("id"),
                    "name": t.get("name"),
                    "stix_id": stix_id,
                },
                "groups_using_technique": groups,
                "software_using_technique": software,
            }
        )

    return {"domain": domain, "intel": enriched}


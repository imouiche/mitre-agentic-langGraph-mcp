from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from mitre_agentic.mcp_client import MitreMcpClient


def _safe_get(d: Any, *path: str, default: Any = None) -> Any:
    """Safely navigate nested dict structure."""
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


async def _fetch_mitigations_for_technique(
    client: MitreMcpClient,
    *,
    technique: Dict[str, Any],
    domain: str,
    include_description: bool,
) -> Optional[Dict[str, Any]]:
    """
    Fetch all mitigations for a single technique.
    
    Returns None if technique has no STIX ID or request fails.
    """
    stix_id = technique.get("stix_id")
    if not stix_id:
        return None

    resp = await client.call_tool(
        "get_mitigations_mitigating_technique",
        {
            "technique_stix_id": stix_id,
            "domain": domain,
            "include_description": include_description,
        },
    )

    payload = _safe_get(resp, "result", default=resp)
    if not isinstance(payload, dict):
        return None

    # Extract mitigations list
    raw_list = payload.get("mitigations", [])
    if not isinstance(raw_list, list):
        raw_list = []

    # Normalize mitigation data
    mitigations: List[Dict[str, Any]] = []
    for item in raw_list:
        # Handle both dict and object formats
        if isinstance(item, dict):
            mitigations.append({
                "attack_id": item.get("attack_id"),
                "name": item.get("name"),
                "stix_id": item.get("stix_id") or item.get("id"),
                "description": item.get("description") if include_description else None,
            })
        else:
            # Object with attributes
            mitigations.append({
                "attack_id": getattr(item, "attack_id", None),
                "name": getattr(item, "name", None),
                "stix_id": getattr(item, "stix_id", None) or getattr(item, "id", None),
                "description": getattr(item, "description", None) if include_description else None,
            })

    return {
        "technique": {
            "id": technique.get("id"),
            "name": technique.get("name"),
            "stix_id": stix_id,
        },
        "found": bool(payload.get("found")),
        "count": int(payload.get("count", len(mitigations))),
        "mitigations": mitigations,
        "formatted": payload.get("formatted", ""),
        "message": payload.get("message", ""),
    }


async def enrich_with_mitigations(
    client: MitreMcpClient,
    *,
    confirmed_techniques: List[Dict[str, Any]],
    domain: str = "enterprise",
    include_description: bool = False,
    concurrency: int = 10,
) -> Dict[str, Any]:
    """
    Agent: Mitigation Enrichment
    
    Fetch defensive controls (mitigations) for ALL confirmed techniques.
    
    Args:
        client: MCP client instance
        confirmed_techniques: List of confirmed techniques from mapping agent
        domain: ATT&CK domain
        include_description: Whether to include mitigation descriptions
        concurrency: Max parallel requests
    
    Returns:
        {
            "domain": str,
            "mitigations": [
                {
                    "technique": {"id": "T1059.001", "name": "PowerShell", ...},
                    "count": 3,
                    "mitigations": [
                        {
                            "attack_id": "M1042",
                            "name": "Disable or Remove Feature or Program",
                            "stix_id": "course-of-action--...",
                            "description": "..."
                        },
                        ...
                    ]
                },
                ...
            ],
            "errors": ["error1", ...],
            "summary": {"total_techniques": 5, "with_mitigations": 4, "total_mitigations": 12}
        }
    """
    if not confirmed_techniques:
        return {
            "domain": domain,
            "mitigations": [],
            "errors": [],
            "summary": {"total_techniques": 0, "with_mitigations": 0, "total_mitigations": 0},
        }

    # Use semaphore to limit concurrency
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _fetch_with_limit(t: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Fetch mitigations with concurrency limit."""
        async with sem:
            return await _fetch_mitigations_for_technique(
                client,
                technique=t,
                domain=domain,
                include_description=include_description,
            )

    # Fetch all mitigations in parallel
    tasks = [_fetch_with_limit(t) for t in confirmed_techniques]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    out: List[Dict[str, Any]] = []
    errors: List[str] = []

    for result in results:
        # Handle exceptions from gather
        if isinstance(result, BaseException):
            errors.append(str(result))
            continue

        # Handle None results (technique had no STIX ID)
        if result is None:
            continue

        out.append(result)

    # Calculate summary statistics
    total_mitigations = sum(item.get("count", 0) for item in out)
    with_mitigations = sum(1 for item in out if item.get("count", 0) > 0)

    # Log errors if any
    if errors:
        print(f"{len(errors)} errors during mitigation fetching:")
        for err in errors[:3]:  # Show first 3
            print(f"   - {err}")

    return {
        "domain": domain,
        "mitigations": out,
        "errors": errors,
        "summary": {
            "total_techniques": len(confirmed_techniques),
            "with_mitigations": with_mitigations,
            "total_mitigations": total_mitigations,
        },
    }
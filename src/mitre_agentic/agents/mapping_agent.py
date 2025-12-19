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


async def _fetch_technique_details(
    client: MitreMcpClient,
    *,
    technique_id: str,
    domain: str,
    include_description: bool,
) -> Optional[Dict[str, Any]]:
    """
    Fetch full details for a single technique including tactics.
    
    Returns None if technique not found.
    """
    # Get technique details
    detail = await client.call_tool(
        "get_technique_by_id",
        {
            "technique_id": technique_id,
            "domain": domain,
            "include_description": include_description,
        },
    )
    
    payload = _safe_get(detail, "result", default=detail)
    
    if not isinstance(payload, dict) or not payload.get("found"):
        return None
    
    # Extract technique info
    tech = payload.get("technique", {})
    if not isinstance(tech, dict):
        return None
    
    t_id = tech.get("id") or technique_id
    t_name = tech.get("name") or ""
    t_stix = tech.get("stix_id")
    t_desc = tech.get("description") if include_description else None
    
    # Get tactics for this technique
    tactics_resp = await client.call_tool(
        "get_technique_tactics",
        {"technique_id": t_id, "domain": domain},
    )
    
    tactics_payload = _safe_get(tactics_resp, "result", default=tactics_resp)
    tactics = tactics_payload.get("tactics") if isinstance(tactics_payload, dict) else []
    
    if not isinstance(tactics, list):
        tactics = []
    
    return {
        "id": t_id,
        "name": t_name,
        "stix_id": t_stix,
        "description": t_desc,
        "tactics": tactics,
    }


async def map_techniques(
    client: MitreMcpClient,
    *,
    technique_ids: List[str],
    domain: str = "enterprise",
    include_description: bool = True,
    concurrency: int = 10, # Max parallel requests
) -> Dict[str, Any]:
    """
    Agent 2 (Mapping):
    Confirm and enrich ALL technique IDs from triage.
    
    Fetches:
    - Technique details (name, STIX ID, description)
    - Associated tactics
    
    Args:
        client: MCP client instance
        technique_ids: List of technique IDs from triage (e.g., ["T1059.001", "T1053.005"])
        domain: ATT&CK domain (enterprise, mobile, ics)
        include_description: Whether to fetch full descriptions
        concurrency: Max parallel requests
    
    Returns:
        {
            "domain": str,
            "confirmed_techniques": [
                {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "stix_id": "attack-pattern--...",
                    "description": "...",
                    "tactics": [
                        {"tactic": "execution", "tactic_id": "TA0002"},
                        ...
                    ]
                },
                ...
            ],
            "not_found": ["T9999"],  # Techniques that don't exist
        }
    """
    if not technique_ids:
        return {
            "domain": domain,
            "confirmed_techniques": [],
            "not_found": [],
        }
    
    # Use semaphore to limit concurrency
    sem = asyncio.Semaphore(concurrency)
    
    async def _fetch_with_limit(tid: str) -> tuple[str, Optional[Dict[str, Any]]]:
        """Fetch technique with concurrency limit."""
        async with sem:
            result = await _fetch_technique_details(
                client,
                technique_id=tid,
                domain=domain,
                include_description=include_description,
            )
            return tid, result
    
    # Fetch all techniques in parallel
    tasks = [_fetch_with_limit(tid) for tid in technique_ids]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Separate successful from failed
    confirmed: List[Dict[str, Any]] = []
    not_found: List[str] = []
    errors: List[str] = []
    
    for result in results:
        # Handle exceptions from gather
        if isinstance(result, BaseException):  # ← Fixed: Check BaseException first
            errors.append(str(result))
            continue
        
        # Now result as tuple[str, Optional[Dict]]
        tid, technique = result
        
        if technique is None:
            not_found.append(tid)
        else:
            confirmed.append(technique)
    
    # Log errors
    if errors:
        print(f"{len(errors)} errors during technique fetching:")
        for err in errors[:3]:  # Show first 3
            print(f"   - {err}")
    
    return {
        "domain": domain,
        "confirmed_techniques": confirmed,
        "not_found": not_found,
        "errors": errors,
    }


# # Legacy compatibility wrapper
# async def map_techniques_topk(
#     client: MitreMcpClient,
#     *,
#     technique_ids: List[str],
#     domain: str = "enterprise",
#     include_description: bool = True,
#     top_k: int = 5,
# ) -> Dict[str, Any]:
#     """
#     DEPRECATED: Use map_techniques() instead.
    
#     This wrapper exists for backward compatibility but now processes
#     ALL techniques (ignores top_k parameter).
#     """
#     # Just call the new function (ignore top_k)
#     return await map_techniques(
#         client,
#         technique_ids=technique_ids,
#         domain=domain,
#         include_description=include_description,
#     )
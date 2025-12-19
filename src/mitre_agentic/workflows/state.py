
from __future__ import annotations
from typing import Any, Dict, List, Optional, TypedDict
from typing_extensions import Annotated
from langgraph.graph import add_messages

# Custom reducer for merging dicts
def merge_dicts(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two dicts, with right overwriting left."""
    return {**left, **right}

class InvestigationState(TypedDict, total=False):
    """State for the MITRE ATT&CK investigation workflow."""
    
    # ========== Inputs ==========
    incident_text: str
    
    # ========== Shared Resources ==========
    mcp_client: Any  # Shared MCP client instance (not serializable, but works in memory)
    
    # ========== Agent Outputs ==========
    triage_summary: Optional[str]
    technique_candidates: Dict[str, List[str]]
    technique_ids: List[str]
    confirmed_techniques: List[Dict[str, Any]]
    intel: Dict[str, Any]
    detections: Dict[str, Any]
    detection_reasoning: Dict[str, Any]
    mitigations: Dict[str, Any]
    navigator_layer_path: Optional[str]
    navigator_layer: Optional[Dict[str, Any]]
    report: Dict[str, Any]
    report_markdown: Optional[str]
    
    # ========== Metadata ==========
    completed_agents: Annotated[List[str], lambda x, y: x + y]
    errors: Annotated[List[Dict[str, str]], lambda x, y: x + y]
    timings: Annotated[Dict[str, float], merge_dicts]  # ← Merge dicts
    domain: str
    llm_model: str


def create_initial_state(
    incident_text: str,
    domain: str = "enterprise",
    llm_model: str = "gpt-4o-mini",
    mcp_client: Any = None 
) -> InvestigationState:
    """Create initial investigation state with required fields."""
    return InvestigationState(
        incident_text=incident_text,
        domain=domain,
        llm_model=llm_model,
        mcp_client=mcp_client,  # share across agents
        technique_candidates={},
        technique_ids=[],
        confirmed_techniques=[],
        intel={},
        detections={},
        detection_reasoning={},
        mitigations={},
        completed_agents=[],
        errors=[],
        timings={},
    )

# Some utility functions for updating state
def add_error(
    state: InvestigationState,
    agent_name: str,
    error: str
) -> Dict[str, Any]:
    """Add an error to state."""
    return {
        "errors": [{
            "agent": agent_name,
            "error": error,
            "timestamp": __import__("datetime").datetime.now().isoformat()
        }]
    }


def mark_agent_complete(
    state: InvestigationState,
    agent_name: str
) -> Dict[str, Any]:
    """Mark an agent as completed."""
    return {
        "completed_agents": [agent_name]
    }


def add_timing(
    state: InvestigationState,
    agent_name: str,
    duration: float
) -> Dict[str, Any]:
    """Add timing information."""
    timings = state.get("timings", {}).copy()
    timings[agent_name] = duration
    return {"timings": timings}
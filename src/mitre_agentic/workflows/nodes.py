from __future__ import annotations

import time
import asyncio
from typing import Any, Dict

from mitre_agentic.workflows.state import InvestigationState, mark_agent_complete, add_error, add_timing
from mitre_agentic.schemas import TriageInput
from mitre_agentic.agents.triage_agent import triage_incident
from mitre_agentic.agents.mapping_agent import map_techniques
from mitre_agentic.agents.intel_agent import enrich_with_groups_and_software
from mitre_agentic.agents.detection_agent import recommend_detection_telemetry
from mitre_agentic.agents.detection_reasoning_agent import reason_detection_with_llm_fallback
from mitre_agentic.agents.mitigation_agent import enrich_with_mitigations
from mitre_agentic.agents.visualization_agent import build_navigator_layer_from_techniques, save_layer_json
from mitre_agentic.agents.report_agent import write_executive_report_llm
from mitre_agentic.mcp_client import MitreMcpClient


# ========== Helper: Retry Decorator ==========

def retry_async(max_attempts: int = 1, backoff: float = 1.0):
    """Decorator to retry async functions with exponential backoff."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            last_exception: Exception | None = None  # Type hint fix
            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts:
                        wait_time = backoff * (2 ** (attempt - 1))
                        print(f"⚠️  {func.__name__} attempt {attempt} failed: {e}")
                        print(f"   Retrying in {wait_time}s...")
                        await asyncio.sleep(wait_time)
                    else:
                        print(f"❌ {func.__name__} failed after {max_attempts} attempts")
            
            # Raise the last exception (guaranteed to be set here)
            if last_exception is not None:
                raise last_exception
            else:
                raise RuntimeError(f"{func.__name__} failed with no exception captured")
        
        return wrapper
    return decorator


# ========== Helper: Extract Technique IDs ==========

def _extract_technique_ids(triage_out: Any) -> list[str]:
    """Extract technique IDs from triage output (object or dict)."""
    # Object-style
    if hasattr(triage_out, "technique_evidence"):
        te = getattr(triage_out, "technique_evidence")
        if isinstance(te, dict):
            return [str(k) for k in te.keys()]
    
    # Dict-style
    if isinstance(triage_out, dict):
        te = triage_out.get("technique_evidence")
        if isinstance(te, dict):
            return [str(k) for k in te.keys()]
    
    return []


# ========== Node 1: Triage (LLM) ==========

@retry_async(max_attempts=1, backoff=1.0)
async def triage_node(state: InvestigationState) -> Dict[str, Any]:
    """
    Agent 1: Triage (LLM)
    Extract technique candidates from incident text.
    """
    print("\n🔍 [1/8] Running Triage Agent (LLM)...")
    start_time = time.time()
    
    try:
        # Safe access with get()
        incident_text = state.get("incident_text", "")
        if not incident_text:
            raise ValueError("No incident text provided")
        
        triage_input = TriageInput(incident_text=incident_text)
        triage_out = await triage_incident(triage_input)
        
        # Extract technique IDs
        technique_ids = _extract_technique_ids(triage_out)
        
        if not technique_ids:
            raise ValueError("Triage produced no technique candidates")
        
        # Get technique evidence (dict or empty)
        technique_evidence = {}
        if hasattr(triage_out, "technique_evidence"):
            technique_evidence = getattr(triage_out, "technique_evidence") or {}
        elif isinstance(triage_out, dict):
            technique_evidence = triage_out.get("technique_evidence", {})
        
        # Get summary
        summary = None
        if hasattr(triage_out, "summary"):
            summary = getattr(triage_out, "summary")
        elif isinstance(triage_out, dict):
            summary = triage_out.get("summary")
        
        duration = time.time() - start_time
        print(f"✅ Triage complete: {len(technique_ids)} candidates ({duration:.2f}s)")
        
        return {
            "triage_summary": summary,
            "technique_candidates": technique_evidence,
            "technique_ids": technique_ids,
            **mark_agent_complete(state, "triage"),
            **add_timing(state, "triage", duration),
        }
    
    except Exception as e:
        print(f"❌ Triage failed: {e}")
        return add_error(state, "triage", str(e))


# ========== Node 2: Mapping (MCP) ==========

@retry_async(max_attempts=3, backoff=2.0)
async def mapping_node(state: InvestigationState) -> Dict[str, Any]:
    """Agent 2: Mapping (MCP)"""
    print("\n🗺️  [2/8] Running Mapping Agent (MCP)...")
    start_time = time.time()
    
    technique_ids = state.get("technique_ids", [])
    if not technique_ids:
        return add_error(state, "mapping", "No technique IDs from triage")
    
    client = state.get("mcp_client")
    if not client:
        return add_error(state, "mapping", "No MCP client in state")
    
    try:
        mapping = await map_techniques(  # ← Use new function
            client,
            technique_ids=technique_ids,
            domain=state.get("domain", "enterprise"),
            include_description=True,
        )
        
        confirmed = mapping.get("confirmed_techniques", []) or []
        not_found = mapping.get("not_found", []) or []
        
        if not confirmed:
            raise ValueError("No techniques confirmed by mapping agent")
        
        duration = time.time() - start_time
        print(f"✅ Mapping complete: {len(confirmed)} techniques confirmed ({duration:.2f}s)")
        
        if not_found:
            print(f"⚠️  {len(not_found)} techniques not found: {', '.join(not_found)}")
        
        return {
            "confirmed_techniques": confirmed,
            **mark_agent_complete(state, "mapping"),
            **add_timing(state, "mapping", duration),
        }
    
    except Exception as e:
        print(f"❌ Mapping failed: {e}")
        return add_error(state, "mapping", str(e))


# ========== Node 3: Intel (MCP) - Parallel ==========

@retry_async(max_attempts=1, backoff=2.0)
async def intel_node(state: InvestigationState) -> Dict[str, Any]:
    """
    Agent 3: Intel (MCP)
    Enrich with threat actor groups and malware.
    """
    print("\n🕵️  [3a/8] Running Intel Agent (MCP)...")
    start_time = time.time()
    
    confirmed = state.get("confirmed_techniques", [])
    if not confirmed:
        return add_error(state, "intel", "No confirmed techniques")
    
    #client = MitreMcpClient()
    client = state.get("mcp_client")
    if not client:
        return add_error(state, "mapping", "No MCP client in state")
    
    try:
        intel = await enrich_with_groups_and_software(
            client,
            confirmed_techniques=confirmed,
            domain=state.get("domain", "enterprise"),
            max_items=5,
        )
        
        duration = time.time() - start_time
        intel_items = len(intel.get("intel", []))
        print(f"✅ Intel complete: {intel_items} techniques enriched ({duration:.2f}s)")
        
        return {
            "intel": intel,
            **mark_agent_complete(state, "intel"),
            **add_timing(state, "intel", duration),
        }
    
    except Exception as e:
        print(f"❌ Intel failed: {e}")
        return add_error(state, "intel", str(e))
    
    # finally:
    #     await client.close()


# ========== Node 4: Detection (MCP) - Parallel ==========

@retry_async(max_attempts=1, backoff=2.0)
async def detection_node(state: InvestigationState) -> Dict[str, Any]:
    """
    Agent 4: Detection (MCP)
    Get STIX data components for detection.
    """
    print("\n🔬 [3b/8] Running Detection Agent (MCP)...")
    start_time = time.time()
    
    confirmed = state.get("confirmed_techniques", [])
    if not confirmed:
        return add_error(state, "detection", "No confirmed techniques")
    
    # client = MitreMcpClient()
    client = state.get("mcp_client")
    if not client:
        return add_error(state, "mapping", "No MCP client in state")
    
    try:
        detections = await recommend_detection_telemetry(
            client,
            confirmed_techniques=confirmed,
            domain=state.get("domain", "enterprise"),
            max_items=7,
        )
        
        duration = time.time() - start_time
        detection_items = len(detections.get("detections", []))
        print(f"✅ Detection complete: {detection_items} techniques analyzed ({duration:.2f}s)")
        
        return {
            "detections": detections,
            **mark_agent_complete(state, "detection"),
            **add_timing(state, "detection", duration),
        }
    
    except Exception as e:
        print(f"❌ Detection failed: {e}")
        return add_error(state, "detection", str(e))
    
    # finally:
    #     await client.close()


# ========== Node 5: Mitigation (MCP) - Parallel ==========

@retry_async(max_attempts=1, backoff=2.0)
async def mitigation_node(state: InvestigationState) -> Dict[str, Any]:
    """Agent 6: Mitigation (MCP) - Get ALL defensive controls for techniques."""
    print("\n🛡️  [3c/8] Running Mitigation Agent (MCP)...")
    start_time = time.time()
    
    confirmed = state.get("confirmed_techniques", [])
    if not confirmed:
        return add_error(state, "mitigation", "No confirmed techniques")
    
    client = state.get("mcp_client")
    if not client:
        return add_error(state, "mitigation", "No MCP client in state")
    
    try:
        mitigations = await enrich_with_mitigations(
            client,
            confirmed_techniques=confirmed,
            domain=state.get("domain", "enterprise"),
            include_description=False,
        )
        
        duration = time.time() - start_time
        
        # Extract summary stats
        summary = mitigations.get("summary", {})
        total_mits = summary.get("total_mitigations", 0)
        with_mits = summary.get("with_mitigations", 0)
        total_techs = summary.get("total_techniques", len(confirmed))
        
        print(f"✅ Mitigation complete: {total_mits} controls for {with_mits}/{total_techs} techniques ({duration:.2f}s)")
        
        # Log errors if any
        errors = mitigations.get("errors", [])
        if errors:
            print(f"⚠️  {len(errors)} errors during mitigation fetching")
        
        return {
            "mitigations": mitigations,
            **mark_agent_complete(state, "mitigation"),
            **add_timing(state, "mitigation", duration),
        }
    
    except Exception as e:
        print(f"❌ Mitigation failed: {e}")
        return add_error(state, "mitigation", str(e))
    
    # finally:
    #     await client.close()


# ========== Node 6: Detection Reasoning (LLM) - Conditional ==========

@retry_async(max_attempts=1, backoff=1.0)
async def detection_reasoning_node(state: InvestigationState) -> Dict[str, Any]:
    """
    Agent 5: Detection Reasoning (LLM)
    LLM fallback for techniques with 0 STIX data components.
    """
    print("\n🧠 [4/8] Running Detection Reasoning Agent (LLM)...")
    start_time = time.time()
    
    confirmed = state.get("confirmed_techniques", [])
    detections = state.get("detections", {})
    incident_text = state.get("incident_text", "")
    
    if not confirmed or not detections:
        return add_error(state, "detection_reasoning", "Missing prerequisites")
    
    try:
        reasoning = await reason_detection_with_llm_fallback(
            confirmed_techniques=confirmed,
            stix_detection_output=detections,
            incident_text=incident_text,
            model=state.get("llm_model", "gpt-4o-mini"),
            max_hypotheses_per_technique=3,
        )
        
        duration = time.time() - start_time
        reasoning_items = len(reasoning.get("detection_reasoning", []))
        print(f"✅ Detection Reasoning complete: {reasoning_items} techniques analyzed ({duration:.2f}s)")
        
        return {
            "detection_reasoning": reasoning,
            **mark_agent_complete(state, "detection_reasoning"),
            **add_timing(state, "detection_reasoning", duration),
        }
    
    except Exception as e:
        print(f"⚠️  Detection Reasoning failed (non-critical): {e}")
        # Non-critical failure - return empty result
        return {
            "detection_reasoning": {"detection_reasoning": []},
            **mark_agent_complete(state, "detection_reasoning"),
        }


# ========== Node 7: Visualization (Navigator Layer) ==========

@retry_async(max_attempts=1, backoff=1.0)
async def visualization_node(state: InvestigationState) -> Dict[str, Any]:
    """
    Agent 7: Visualization
    Create ATT&CK Navigator layer.
    """
    print("\n🎨 [5/8] Running Visualization Agent...")
    start_time = time.time()
    
    confirmed = state.get("confirmed_techniques", [])
    incident_text = state.get("incident_text", "")
    
    if not confirmed:
        return add_error(state, "visualization", "No confirmed techniques")
    
    # client = MitreMcpClient()
    client = state.get("mcp_client")
    if not client:
        return add_error(state, "mapping", "No MCP client in state")
    
    try:
        layer = await build_navigator_layer_from_techniques(
            client,
            confirmed_techniques=confirmed,
            domain=state.get("domain", "enterprise"),
            layer_name="Incident Investigation: Technique Coverage",
            description=incident_text[:200],
        )
        
        # Save to disk
        layer_path = save_layer_json(layer, "./out/incident_layer.json")
        
        duration = time.time() - start_time
        print(f"✅ Visualization complete: Layer saved to {layer_path} ({duration:.2f}s)")
        
        return {
            "navigator_layer": layer,
            "navigator_layer_path": str(layer_path),
            **mark_agent_complete(state, "visualization"),
            **add_timing(state, "visualization", duration),
        }
    
    except Exception as e:
        print(f"❌ Visualization failed: {e}")
        return add_error(state, "visualization", str(e))
    
    # finally:
    #     await client.close()


# ========== Node 8: Report (LLM) ==========

@retry_async(max_attempts=1, backoff=2.0)
async def report_node(state: InvestigationState) -> Dict[str, Any]:
    """
    Agent 8: Report (LLM)
    Generate executive markdown report.
    """
    print("\n📄 [6/8] Running Report Agent (LLM)...")
    start_time = time.time()
    
    # Safe access to all required fields
    triage_summary = state.get("triage_summary")
    confirmed = state.get("confirmed_techniques", [])
    intel = state.get("intel", {})
    detections = state.get("detections", {})
    incident_text = state.get("incident_text", "")
    
    # Check prerequisites
    if not triage_summary or not confirmed or not intel or not detections:
        missing = []
        if not triage_summary:
            missing.append("triage_summary")
        if not confirmed:
            missing.append("confirmed_techniques")
        if not intel:
            missing.append("intel")
        if not detections:
            missing.append("detections")
        
        error_msg = f"Missing required data: {', '.join(missing)}"
        print(f"❌ {error_msg}")
        return add_error(state, "report", error_msg)
    
    try:
        report_out = await write_executive_report_llm(
            incident_text=incident_text,
            triage_summary=triage_summary,
            confirmed_techniques=confirmed,
            intel=intel,
            detections=detections,
            detection_reasoning=state.get("detection_reasoning", {}),
            mitigations=state.get("mitigations", {}),
            navigator_layer_path=state.get("navigator_layer_path"),
            model=state.get("llm_model", "gpt-4o-mini"),
        )
        
        # Extract markdown
        report = report_out.get("report", {})
        markdown = report.get("markdown", "")
        
        # Save to disk
        report_path = "./out/incident_report.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(markdown)
        
        duration = time.time() - start_time
        print(f"✅ Report complete: {len(markdown)} chars, saved to {report_path} ({duration:.2f}s)")
        
        return {
            "report": report,
            "report_markdown": markdown,
            **mark_agent_complete(state, "report"),
            **add_timing(state, "report", duration),
        }
    
    except Exception as e:
        print(f"❌ Report failed: {e}")
        return add_error(state, "report", str(e))
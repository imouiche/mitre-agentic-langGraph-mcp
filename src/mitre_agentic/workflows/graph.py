from __future__ import annotations

from typing import Literal, AsyncIterator, Dict, Any, Optional
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.base import BaseCheckpointSaver

from mitre_agentic.workflows.state import InvestigationState
from mitre_agentic.workflows.nodes import (
    triage_node,
    mapping_node,
    intel_node,
    detection_node,
    mitigation_node,
    detection_reasoning_node,
    visualization_node,
    report_node,
)

CompiledGraphType = Any  # This is the return type from workflow.compile()

# ========== Conditional Edge Logic ==========

def should_run_detection_reasoning(state: InvestigationState) -> Literal["detection_reasoning", "visualization"]:
    """
    Decide whether to run detection reasoning based on STIX data availability.
    
    If any technique has 0 data components, run LLM reasoning.
    Otherwise, skip to visualization.
    """
    detections = state.get("detections", {})
    detection_list = detections.get("detections", [])
    
    # Check if any technique has 0 data components
    for item in detection_list:
        detection_data = item.get("detection", {})
        total_components = detection_data.get("total_datacomponents", 0)
        
        if total_components == 0:
            print("Some techniques have 0 data components → Running Detection Reasoning")
            return "detection_reasoning"
    
    print("All techniques have STIX data → Skipping Detection Reasoning")
    return "visualization"


# ========== Graph Construction ==========

def create_investigation_graph(
    checkpointer: Optional[BaseCheckpointSaver] = None
) -> Any:  # ← Fixed return type
    """
    Create the MITRE ATT&CK investigation workflow graph.
    
    Flow:
        START → triage → mapping → [intel, detection, mitigation] (parallel)
              → detection_reasoning (conditional) → visualization → report → END
    
    Args:
        checkpointer: Optional checkpoint saver for persistence.
                     Use MemorySaver() for in-memory checkpoints.
    
    Returns:
        Compiled StateGraph ready for execution.
    """
    
    # Initialize graph
    workflow = StateGraph(InvestigationState)
    
    # ========== Add Nodes ==========
    
    workflow.add_node("triage", triage_node)
    workflow.add_node("mapping", mapping_node)
    workflow.add_node("intel", intel_node)
    workflow.add_node("detection", detection_node)
    workflow.add_node("mitigation", mitigation_node)
    workflow.add_node("detection_reasoning", detection_reasoning_node)
    workflow.add_node("visualization", visualization_node)
    workflow.add_node("report", report_node)
    
    # ========== Define Edges ==========
    
    # Sequential: START → triage → mapping
    workflow.add_edge(START, "triage")
    workflow.add_edge("triage", "mapping")
    
    # Parallel: mapping → [intel, detection, mitigation]
    workflow.add_edge("mapping", "intel")
    workflow.add_edge("mapping", "detection")
    workflow.add_edge("mapping", "mitigation")
    
    # Conditional: detection → detection_reasoning OR visualization
    workflow.add_conditional_edges(
        "detection",
        should_run_detection_reasoning,
        {
            "detection_reasoning": "detection_reasoning",
            "visualization": "visualization",
        },
    )
    
    # Sequential: intel → visualization (synchronization point)
    workflow.add_edge("intel", "visualization")
    
    # Sequential: mitigation → visualization (synchronization point)
    workflow.add_edge("mitigation", "visualization")
    
    # Sequential: detection_reasoning → visualization
    workflow.add_edge("detection_reasoning", "visualization")
    
    # Sequential: visualization → report
    workflow.add_edge("visualization", "report")
    
    # Final: report → END
    workflow.add_edge("report", END)
    
    # ========== Compile Graph ==========
    
    # Compile with optional checkpointing
    if checkpointer is None:
        app = workflow.compile()
    else:
        app = workflow.compile(checkpointer=checkpointer)
    
    return app


# ========== Convenience Functions ==========

def create_graph_with_memory() -> Any:  # ← Fixed return type
    """
    Create investigation graph with in-memory checkpointing.
    
    Enables:
    - Resume from any point if execution fails
    - Inspect intermediate state
    - Time-travel debugging
    
    Usage:
        graph = create_graph_with_memory()
        config = {"configurable": {"thread_id": "investigation-123"}}
        result = await graph.ainvoke(initial_state, config)
    """
    checkpointer = MemorySaver()
    return create_investigation_graph(checkpointer=checkpointer)


def create_graph_no_checkpointing() -> Any:  # ← Fixed return type
    """
    Create investigation graph without checkpointing.
    
    Faster execution, no persistence.
    Use for production runs where checkpoint overhead is unwanted.
    """
    return create_investigation_graph(checkpointer=None)


# ========== Streaming Helpers ==========

async def stream_investigation(
    graph: Any,
    initial_state: InvestigationState,
    config: Optional[Dict[str, Any]] = None  # ← Fixed type hint
) -> AsyncIterator[Dict[str, Any]]:  # ← Fixed return type
    """
    Stream investigation progress with real-time updates.
    
    Args:
        graph: Compiled LangGraph
        initial_state: Starting state
        config: Optional config (e.g., thread_id for checkpointing)
    
    Yields:
        Dict with node name and updated state after each step
    
    Usage:
        graph = create_graph_with_memory()
        initial = create_initial_state("EDR alert: ...")
        config = {"configurable": {"thread_id": "inv-123"}}
        
        async for update in stream_investigation(graph, initial, config):
            node = update["node"]
            state = update["state"]
            print(f"Completed: {node}")
    """
    if config is None:
        config = {}
    
    async for event in graph.astream(initial_state, config, stream_mode="updates"):
        for node_name, node_state in event.items():
            yield {
                "node": node_name,
                "state": node_state,
                "completed_agents": node_state.get("completed_agents", []),
                "errors": node_state.get("errors", []),
            }


async def run_investigation(
    graph: Any,
    initial_state: InvestigationState,
    config: Optional[Dict[str, Any]] = None  # ← Fixed type hint
) -> InvestigationState:
    """
    Run complete investigation and return final state.
    
    Args:
        graph: Compiled LangGraph
        initial_state: Starting state
        config: Optional config (e.g., thread_id for checkpointing)
    
    Returns:
        Final investigation state
    
    Usage:
        graph = create_graph_with_memory()
        initial = create_initial_state("EDR alert: ...")
        final = await run_investigation(graph, initial)
        
        print(final["report_markdown"])
    """
    if config is None:
        config = {}
    
    final_state = await graph.ainvoke(initial_state, config)
    return final_state


# ========== Checkpoint Utilities ==========

async def get_checkpoint_state(
    graph: Any,
    thread_id: str,
    checkpoint_id: Optional[str] = None  # ← Fixed type hint
) -> InvestigationState:
    """
    Retrieve state from a specific checkpoint.
    
    Args:
        graph: Compiled graph with checkpointing
        thread_id: Thread ID used during execution
        checkpoint_id: Optional specific checkpoint (default: latest)
    
    Returns:
        State at that checkpoint
    
    Usage:
        state = await get_checkpoint_state(graph, "inv-123")
        print(state["completed_agents"])
    """
    config: Dict[str, Any] = {"configurable": {"thread_id": thread_id}}
    
    if checkpoint_id:
        config["configurable"]["checkpoint_id"] = checkpoint_id
    
    state = await graph.aget_state(config)
    return state.values


async def resume_from_checkpoint(
    graph: Any,
    thread_id: str,
    checkpoint_id: Optional[str] = None,  # ← Fixed type hint
    updates: Optional[Dict[str, Any]] = None  # ← Fixed type hint
) -> InvestigationState:
    """
    Resume execution from a checkpoint with optional state updates.
    
    Args:
        graph: Compiled graph with checkpointing
        thread_id: Thread ID of the saved run
        checkpoint_id: Optional specific checkpoint (default: latest)
        updates: Optional state updates to apply before resuming
    
    Returns:
        Final state after resuming
    
    Usage:
        # Resume from last checkpoint
        final = await resume_from_checkpoint(graph, "inv-123")
        
        # Resume and override some state
        final = await resume_from_checkpoint(
            graph, 
            "inv-123",
            updates={"llm_model": "gpt-4o"}
        )
    """
    config: Dict[str, Any] = {"configurable": {"thread_id": thread_id}}
    
    if checkpoint_id:
        config["configurable"]["checkpoint_id"] = checkpoint_id
    
    if updates:
        # Apply updates to the checkpoint state
        await graph.aupdate_state(config, updates)
    
    # Resume execution
    final_state = await graph.ainvoke(None, config)
    return final_state


# ========== Visualization ==========


def visualize_graph(
    graph: Any,
    output_path: str = "./out/workflow_graph.png"
) -> None:
    """
    Generate a visual representation of the workflow graph.
    
    Requires: pip install pygraphviz 
    
    Args:
        graph: Compiled LangGraph
        output_path: Where to save the image
    
    Usage:
        graph = create_graph_with_memory()
        visualize_graph(graph, "./workflow.png")
    """
    try:
        # Get mermaid diagram
        mermaid_code = graph.get_graph().draw_mermaid()
        
        print("\n" + "="*80)
        print("WORKFLOW GRAPH (Mermaid)")
        print("="*80)
        print(mermaid_code)
        print("="*80 + "\n")
        
        # Try to render PNG if graphviz available
        try:
            png_data = graph.get_graph().draw_mermaid_png()
            with open(output_path, "wb") as f:
                f.write(png_data)
            print(f"Graph PNG saved to {output_path}")
        except Exception as e:
            print(f"Could not render PNG: {e}")
            print("   Install pygraphviz: pip install pygraphviz")
            
            # Save mermaid code as fallback
            mermaid_path = output_path.replace(".png", ".mmd")
            with open(mermaid_path, "w") as f:
                f.write(mermaid_code)
            print(f"Mermaid code saved to {mermaid_path}")
            print("Visualize at: https://mermaid.live/")
    
    except Exception as e:
        print(f" Visualization failed: {e}")

# ========== Debug Utilities ==========

def print_graph_structure(graph: Any) -> None:
    """Print the graph structure for debugging."""
    print("\n" + "="*80)
    print("WORKFLOW GRAPH STRUCTURE")
    print("="*80)
    
    print("\nNodes:")
    for node in graph.get_graph().nodes:
        print(f"  - {node}")
    
    print("\nEdges:")
    for edge in graph.get_graph().edges:
        print(f"  {edge[0]} → {edge[1]}")
    
    print("\n" + "="*80 + "\n")

"""
Visualize the LangGraph workflow structure.
"""

from mitre_agentic.workflows.graph import create_graph_no_checkpointing


def main():
    """Generate and display the workflow graph."""
    print("\n" + "="*80)
    print("MITRE ATT&CK Investigation Workflow - Graph Visualization")
    print("="*80 + "\n")
    
    # Create graph
    graph = create_graph_no_checkpointing()
    
    # Get graph structure
    print("Workflow Graph Structure:\n")
    
    # Print nodes
    nodes = list(graph.get_graph().nodes)
    print(f"Nodes ({len(nodes)}):")
    for i, node in enumerate(nodes, 1):
        if node == "__start__":
            print(f"  {i}. START")
        elif node == "__end__":
            print(f"  {i}. END")
        else:
            print(f"  {i}. {node}")
    
    # Print edges (handle different edge formats)
    edges = list(graph.get_graph().edges)
    print(f"\nEdges ({len(edges)}):")
    for edge in edges:
        # Edge can be tuple of (source, target) or (source, target, data)
        if isinstance(edge, tuple):
            source = edge[0]
            target = edge[1] if len(edge) > 1 else "?"
            
            # Clean up names
            if source == "__start__":
                source = "START"
            if target == "__end__":
                target = "END"
            
            # Check if it's a conditional edge
            if len(edge) > 2 and isinstance(edge[2], dict):
                edge_data = edge[2]
                if "data" in edge_data:
                    print(f"  {source} → {target} [conditional]")
                else:
                    print(f"  {source} → {target}")
            else:
                print(f"  {source} → {target}")
        else:
            print(f"  {edge}")
    
    # Generate Mermaid diagram
    print("\n" + "="*80)
    print("Mermaid Diagram (paste into https://mermaid.live/):")
    print("="*80 + "\n")
    
    try:
        mermaid = graph.get_graph().draw_mermaid()
        print(mermaid)
        
        # Save to file
        with open("./out/workflow_graph.mmd", "w") as f:
            f.write(mermaid)
        print("\n Mermaid diagram saved to: out/workflow_graph.mmd")
        
    except Exception as e:
        print(f"Could not generate Mermaid: {e}")
    
    # ASCII diagram
    print("\n" + "="*80)
    print("ASCII Workflow Diagram:")
    print("="*80 + "\n")
    
    
    print("="*80)
    print("Graph Statistics:")
    print("="*80)
    print(f"  Total nodes: {len(nodes)}")
    print(f"  Total edges: {len(edges)}")
    print(f"  Parallel nodes: 3 (intel, detection, mitigation)")
    print(f"  Conditional nodes: 1 (detection_reasoning)")
    print(f"  LLM nodes: 3 (triage, detection_reasoning, report)")
    print(f"  MCP nodes: 5 (mapping, intel, detection, mitigation, visualization)")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
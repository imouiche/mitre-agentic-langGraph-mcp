import asyncio
from pathlib import Path
import logging, os

from dotenv import load_dotenv

from mitre_agentic.mcp_client import MitreMcpClient
from mitre_agentic.workflows.state import create_initial_state
from mitre_agentic.workflows.graph import (
    create_graph_no_checkpointing,
    run_investigation,
)

import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

load_dotenv()

def quiet_mcp_logs():
    logging.getLogger().setLevel(logging.WARNING)

    # clean MCP + AnyIO noise
    for name in [
        "mcp",
        "mcp.server",
        "mcp.client",
        "anyio",
        "asyncio",
        "httpx",
    ]:
        logging.getLogger(name).setLevel(logging.WARNING)

    os.environ.setdefault("MCP_LOG_LEVEL", "WARNING")

# load_dotenv()

DEFAULT_INCIDENT = (
    "EDR alert: WINWORD.EXE spawned powershell.exe with an encoded command. "
    "Shortly after, rundll32.exe executed with a suspicious DLL entrypoint and "
    "a scheduled task was created for persistence. Network connections to an "
    "unfamiliar external IP followed."
)


async def main():
    """Run a basic investigation workflow."""
    quiet_mcp_logs()
    print("\n" + "="*80)
    print("MITRE ATT&CK Investigation Workflow - Basic Execution")
    print("="*80 + "\n")
    
    # Create shared MCP client
    print("🔌 Connecting to MCP server...")
    client = MitreMcpClient()
    
    try:
        # Create graph
        print("Building workflow graph...")
        graph = create_graph_no_checkpointing()
        
        print("Creating initial state...")
        initial_state = create_initial_state(
            incident_text=DEFAULT_INCIDENT,
            domain="enterprise",
            llm_model="gpt-4o-mini",
            mcp_client=client
        )
        
        # Run investigation
        print("🚀 Starting investigation...\n")
        final_state = await run_investigation(graph, initial_state)
        
        # Print results
        print("\n" + "="*80)
        print("INVESTIGATION COMPLETE")
        print("="*80)
        
        completed = final_state.get("completed_agents", [])
        print(f"\nCompleted agents ({len(completed)}/8):")
        for agent in completed:
            print(f"   - {agent}")
        
        errors = final_state.get("errors", [])
        if errors:
            print(f"\n Errors encountered ({len(errors)}):")
            for error in errors:
                print(f" - {error.get('agent')}: {error.get('error')}")
        
        timings = final_state.get("timings", {})
        if timings:
            total_time = sum(timings.values())
            print(f"\n Total time: {total_time:.2f}s")
            print("\n  Agent timings:")
            for agent, duration in sorted(timings.items(), key=lambda x: x[1], reverse=True):
                percentage = (duration / total_time * 100) if total_time > 0 else 0
                print(f"   {agent:25s}: {duration:6.2f}s ({percentage:5.1f}%)")
        
        print("\nResults:")
        print(f"Confirmed techniques: {len(final_state.get('confirmed_techniques', []))}")
        print(f"Intel items: {len(final_state.get('intel', {}).get('intel', []))}")
        print(f"Detection items: {len(final_state.get('detections', {}).get('detections', []))}")
        print(f"Mitigation items: {len(final_state.get('mitigations', {}).get('mitigations', []))}")
        
        layer_path = final_state.get("navigator_layer_path")
        if layer_path:
            print(f"\nOutput files:")
            print(f"Navigator layer: {layer_path}")
            print(f"Report: ./out/incident_report.md")
        
        print("\n" + "="*80 + "\n")
        
        return final_state
        
    except Exception as e:
        print(f"\n Investigation failed: {e}")
        import traceback
        traceback.print_exc()
        return None
    
    finally:
        print("Investigation complete, exiting...")
        try:
            print("Closing MCP connection...")
            await client.close()
        except RuntimeError as e:
            # Suppress "cancel scope in different task"
            if "cancel scope" not in str(e):
                raise
            pass


if __name__ == "__main__":
    asyncio.run(main())
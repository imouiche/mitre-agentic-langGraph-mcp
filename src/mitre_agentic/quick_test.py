# Quick test script
import asyncio
from mitre_agentic.mcp_client import MitreMcpClient

async def test():
    client = MitreMcpClient()
    try:
        resp = await client.call_tool(
            "get_mitigations_mitigating_technique",
            {
                "technique_stix_id": "attack-pattern--457c7820-d331-465a-915e-42f85500ccc4",
                "domain": "enterprise",
                "include_description": False,
            }
        )
        
        mitigations = resp.get("result", {}).get("mitigations", [])
        print(f"Found {len(mitigations)} mitigations")
        if mitigations:
            first = mitigations[0]
            second = mitigations[1]
            print(f"First: {first}")
            print(f"Second: {second}")
            if first.get("name"):
                print("Fixed!")
            else:
                print("Still broken - server not restarted")
    finally:
        await client.close()

asyncio.run(test())
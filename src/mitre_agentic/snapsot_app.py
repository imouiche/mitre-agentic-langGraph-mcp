import asyncio

from dotenv import load_dotenv
from mitre_agentic.mcp_client import MitreMcpClient

load_dotenv()


async def main() -> None:
    print("mitre-agentic demo: scaffold ok")
    client = MitreMcpClient()

    # out = await client.run(
    #     tool_calls=[
    #         {"type": "list_tools"},
    #         {"type": "call_tool", "name": "get_data_stats", "args": {}},
    #         {
    #             "type": "call_tool",
    #             "name": "get_technique_by_id",
    #             "args": {"technique_id": "T1055", "domain": "enterprise", "include_description": True},
    #         },
    #     ]
    # )

    # tools = out.get("tools", [])
    # print(f"\nTools discovered: {len(tools)}")
    # for t in tools[:15]:
    #     print(" -", t["name"])
    # if len(tools) > 15:
    #     print(f" ... (+{len(tools) - 15} more)")

    # print("\nMITRE ATT&CK Stats:\n", out.get("get_data_stats"))

    # print("\nTechnique T1055:\n", out.get("get_technique_by_id"))


   
    # Example using Process Injection from your output
    technique_stix_id = "attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d"

    print("\nFetching groups and software for technique T1055...")
    groups = await client.call_tool("get_groups_using_technique", {
        "technique_stix_id": technique_stix_id,
        "domain": "enterprise"
    })

    software = await client.call_tool("get_software_using_technique", {
        "technique_stix_id": technique_stix_id,
        "domain": "enterprise"
    })

    print("\n Groups for technique T1055:")
    print(groups)
    
    print("\n Software for technique T1055:")
    print(software)



# from mitre_agentic.schemas import TriageInput
# from mitre_agentic.agents.triage_agent import triage_incident

# load_dotenv()


# DEFAULT_INCIDENT_TEXT = (
#     "EDR alert: WINWORD.EXE spawned powershell.exe with an encoded command. "
#     "Shortly after, rundll32.exe executed with a suspicious DLL entrypoint and "
#     "a scheduled task was created for persistence. Network connections to an "
#     "unfamiliar external IP followed."
# )


# async def main() -> None:
#     print("mitre-agentic demo: Agent 1 (Triage)")

#     triage_input = TriageInput(incident_text=DEFAULT_INCIDENT_TEXT)
#     triage_out = triage_incident(triage_input)

#     print("\n=== TRIAGE SUMMARY ===")
#     print(triage_out.summary)

#     print("\n=== SUSPECTED BEHAVIORS ===")
#     for b in triage_out.suspected_behaviors:
#         print(f" - {b}")

#     print("\n=== KEYWORDS (for MITRE mapping next) ===")
#     for k in triage_out.keywords:
#         print(f" - {k}")

#     print("\n=== CANDIDATE PLATFORMS ===")
#     for p in triage_out.candidate_platforms:
#         print(f" - {p}")

#     print("\n=== NEXT STEPS PLAN ===")
#     for step in triage_out.plan:
#         tools = ", ".join(step.suggested_tools) if step.suggested_tools else "(none)"
#         print(f"{step.step}. {step.actor}: {step.intent}")
#         print(f"   tools: {tools}")
#         if step.notes:
#             print(f"   notes: {step.notes}")



if __name__ == "__main__":
    asyncio.run(main())

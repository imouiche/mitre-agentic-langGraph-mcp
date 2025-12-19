import asyncio

from dotenv import load_dotenv
import os

from mitre_agentic.schemas import TriageInput
from mitre_agentic.agents.triage_agent import triage_incident

from mitre_agentic.mcp_client import MitreMcpClient
from mitre_agentic.agents.mapping_agent import map_techniques
from mitre_agentic.agents.intel_agent import enrich_with_groups_and_software
from mitre_agentic.agents.detection_agent import recommend_detection_telemetry
from mitre_agentic.agents.detection_reasoning_agent import reason_detection_with_llm_fallback
from mitre_agentic.agents.visualization_agent import build_navigator_layer_from_techniques, save_layer_json
from mitre_agentic.agents.report_agent import write_executive_report_llm
from mitre_agentic.agents.mitigation_agent import enrich_with_mitigations
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


load_dotenv()

print("APP sees OPENAI_API_KEY:", bool(os.getenv("OPENAI_API_KEY")))

DEFAULT_INCIDENT_TEXT = (
    "EDR alert: WINWORD.EXE spawned powershell.exe with an encoded command. "
    "Shortly after, rundll32.exe executed with a suspicious DLL entrypoint and "
    "a scheduled task was created for persistence. Network connections to an "
    "unfamiliar external IP followed."
)


def _extract_technique_ids_from_triage(triage_out) -> list[str]:
    """
    Extract technique IDs from Agent 1 output.

    Supported shapes:
      - triage_out.technique_evidence: dict[str, list[str]]
      - triage_out["technique_evidence"]: dict[str, list[str]]
      - (legacy) technique_candidates / technique_ids if present
    """
    # Object-style: technique_evidence
    if hasattr(triage_out, "technique_evidence"):
        te = getattr(triage_out, "technique_evidence")
        if isinstance(te, dict):
            return [str(k) for k in te.keys()]

    # Dict-style: technique_evidence
    if isinstance(triage_out, dict):
        te = triage_out.get("technique_evidence")
        if isinstance(te, dict):
            return [str(k) for k in te.keys()]

    # Legacy support (optional)
    if hasattr(triage_out, "technique_candidates"):
        tc = getattr(triage_out, "technique_candidates")
        if isinstance(tc, dict):
            return [str(k) for k in tc.keys()]

    if isinstance(triage_out, dict):
        tc = triage_out.get("technique_candidates")
        if isinstance(tc, dict):
            return [str(k) for k in tc.keys()]

    if hasattr(triage_out, "technique_ids"):
        tids = getattr(triage_out, "technique_ids")
        if isinstance(tids, list):
            return [str(x) for x in tids]

    if isinstance(triage_out, dict):
        tids = triage_out.get("technique_ids")
        if isinstance(tids, list):
            return [str(x) for x in tids]

    return []



def _safe_str(x, max_len: int) -> str:
    s = (str(x) if x is not None else "").strip()
    if len(s) > max_len:
        return s[: max_len - 1] + "…"
    return s


async def main() -> None:
    print("mitre-agentic demo: Agent 1 (LLM Triage) -> Agents 2-5 (MCP + LLM fallback)")

    # --- Agent 1: Triage (LLM) ---
    triage_input = TriageInput(incident_text=DEFAULT_INCIDENT_TEXT)
    triage_out = await triage_incident(triage_input)

    # Print triage summary if any
    summary = getattr(triage_out, "summary", None) if not isinstance(triage_out, dict) else triage_out.get("summary")
    if summary:
        print("\n=== TRIAGE SUMMARY ===")
        print(summary)

    technique_ids = _extract_technique_ids_from_triage(triage_out)
    if not technique_ids:
        raise RuntimeError(
            "Triage produced no technique IDs. Ensure triage_agent returns technique_candidates or technique_ids."
        )

    print("\n=== TRIAGE TECHNIQUE CANDIDATES (LLM) ===")

    te = getattr(triage_out, "technique_evidence", None) if not isinstance(triage_out, dict) else triage_out.get("technique_evidence")
    if isinstance(te, dict) and te:
        for tid, evidence in te.items():
            print(f"- {tid}: {evidence}")
    else:
        for tid in technique_ids:
            print(f"- {tid}")


    # --- MCP Client (shared across agents) ---
    client = MitreMcpClient()

    try:
        # --- Agent 2: Mapping (confirm top-K via MCP) ---
        print("\n=== MAPPING (MCP confirm top-K) ===")
        mapping = await map_techniques(
            client,
            technique_ids=technique_ids,
            domain="enterprise",
            include_description=True,
        )

        confirmed = mapping.get("confirmed_techniques", []) or []
        print(f"\nConfirmed techniques: {len(confirmed)}")
        for t in confirmed:
            print("\n---")
            print(f"{t.get('id')} - {t.get('name')}")
            print(f"Tactics: {t.get('tactics')}")
            desc = _safe_str(t.get("description"), 260).replace("\n", " ")
            if desc:
                print(f"Description: {desc}")

        # --- Agent 3: Intel (groups + software) ---
        print("\n=== INTEL: groups/software associated with confirmed techniques ===")
        intel = await enrich_with_groups_and_software(
            client,
            confirmed_techniques=confirmed,
            domain="enterprise",
            max_items=5,
        )

        for item in intel.get("intel", []) or []:
            tech = item.get("technique", {}) or {}
            print("\n---")
            print(f"{tech.get('id')} - {tech.get('name')}")

            groups = item.get("groups_using_technique", []) or []
            software = item.get("software_using_technique", []) or []

            group_names = [g.get("name", "<?>") for g in groups if isinstance(g, dict)]
            software_names = [s.get("name", "<?>") for s in software if isinstance(s, dict)]

            print(f"Groups (top {len(group_names)}): {group_names}")
            print(f"Software (top {len(software_names)}): {software_names}")

        # --- Agent 4: Detection (STIX data components or technique detection fallback) ---
        print("\n=== DETECTION: telemetry/data components to detect confirmed techniques ===")
        detections = await recommend_detection_telemetry(
            client,
            confirmed_techniques=confirmed,
            domain="enterprise",
            max_items=7,
        )

        for item in detections.get("detections", []) or []:
            tech = item.get("technique", {}) or {}
            det = item.get("detection", {}) or {}

            print("\n---")
            print(f"{tech.get('id')} - {tech.get('name')}")

            mode = det.get("mode", "datacomponents")

            if mode == "datacomponents" and det.get("top_datacomponents"):
                total = det.get("total_datacomponents", 0)
                comps = det.get("top_datacomponents", []) or []
                print(f"Data components (top {len(comps)} of {total}):")
                for c in comps:
                    print(f"  - {c}")
            else:
                # Fallback: technique detection guidance (x_mitre_data_sources/x_mitre_detection)
                print("Detection guidance (fallback):")

                data_sources = det.get("data_sources", []) or []
                if data_sources:
                    print("  Data sources to collect:")
                    for ds in data_sources:
                        print(f"   - {ds}")

                detection_text = _safe_str(det.get("detection_text"), 700)
                if detection_text:
                    print("  What to look for:")
                    print(f"   {detection_text}")
                else:
                    print("  (No detection guidance text available in this ATT&CK release.)")

                note = _safe_str(det.get("note"), 220)
                if note:
                    print(f"  Note: {note}")

        # --- Agent 5: Detection Reasoning (LLM fallback when STIX has 0) ---
        print("\n=== DETECTION REASONING (LLM fallback when STIX has 0) ===")
        try:
            reasoning = await reason_detection_with_llm_fallback(
                confirmed_techniques=confirmed,
                stix_detection_output=detections,   # <-- must pass Agent 4 output
                incident_text=DEFAULT_INCIDENT_TEXT,
                model="gpt-4.1-mini",
                max_hypotheses_per_technique=3,
            )
        except Exception as e:
            print(f"Detection reasoning agent failed: {e}")
            reasoning = {"detection_reasoning": []}

        items = reasoning.get("detection_reasoning", []) if isinstance(reasoning, dict) else []
        print(f"Detection reasoning items: {len(items)}")

        for item in items:
            tech = item.get("technique", {}) or {}
            mode = item.get("mode", "<?>")

            print("\n---")
            print(f"{tech.get('id')} - {tech.get('name')}  (mode: {mode})")

            if mode == "stix_datacomponents":
                stix = item.get("stix", {}) or {}
                total = stix.get("total", 0)
                comps = stix.get("top_datacomponents", []) or []
                print(f"STIX data components (top {len(comps)} of {total}):")
                for c in comps:
                    print(f"  - {c}")
            else:
                llm = item.get("llm", {}) or {}
                hyps = llm.get("hypotheses", []) or []
                print(f"LLM hypotheses (showing up to {min(5, len(hyps))}):")
                for h in hyps[:5]:
                    title = _safe_str(h.get("title"), 140)
                    rationale = _safe_str(h.get("rationale"), 400)  # extra safety
                    print(f"  - {title}: {rationale}")

            # --- MITIGATIONS: defensive controls for confirmed techniques ---
        print("\n=== MITIGATIONS: defensive controls for confirmed techniques ===")
        mit = await enrich_with_mitigations(
            client,
            confirmed_techniques=confirmed,
            domain="enterprise",
            include_description=False,
        )

        for item in mit.get("mitigations", []) or []:
            tech = item.get("technique", {}) or {}
            mitigations = item.get("mitigations", []) or []
            print("\n---")
            print(f"{tech.get('id')} - {tech.get('name')}")
            print(f"Mitigations (top {len(mitigations)} / {item.get('count', len(mitigations))}):")
            for m in mitigations:
                name = (m.get("name") or "").strip() if isinstance(m, dict) else ""
                attack_id = (m.get("attack_id") or "").strip() if isinstance(m, dict) else ""
                if not name and item.get("formatted"):
                    # fallback: at least show formatted text
                    print("(see formatted output below)")
                    break
                print(f" - {attack_id} {name}".strip())
            if item.get("formatted"):
                print("Formatted:")
                print(item["formatted"])

        print("\n=== VIZ: ATT&CK Navigator layer ===")
        layer = await build_navigator_layer_from_techniques(
            client,
            confirmed_techniques=confirmed,
            domain="enterprise",
            layer_name="EDR Incident: Technique Coverage",
            description="WINWORD → PowerShell EncodedCommand → rundll32 DLL → Scheduled Task → External IP",
        )
        

        out_file = save_layer_json(layer, "./out/incident_layer.json")
        print(f"Navigator layer saved to: {out_file}")
        print("Upload it to https://mitre-attack.github.io/attack-navigator/ (Open Layer)")


        print("\n=== REPORT: Executive Markdown ===")
        report_out = await write_executive_report_llm(
            incident_text=DEFAULT_INCIDENT_TEXT,
            triage_summary=triage_out.summary,
            confirmed_techniques=confirmed,
            intel=intel,
            detections=detections,
            detection_reasoning=reasoning,          # optional
            mitigations=mit,                        
            navigator_layer_path=str(out_file),  
        )

        md = report_out["report"]["markdown"]
        print(md[:1200] + ("\n...\n" if len(md) > 1200 else ""))

        with open("./src/mitre_agentic/reporting/incident_report.md", "w", encoding="utf-8") as f:
            f.write(md)
        print("Saved: incident_report.md")

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())

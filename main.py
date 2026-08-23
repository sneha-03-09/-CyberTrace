from core.evidence_loader import EvidenceLoader
from core.event_normalizer import EventNormalizer
from core.correlation_engine import CorrelationEngine
from core.attack_timeline import AttackTimeline
from core.incident_detector import IncidentDetector
from core.agent_tools import AgentTools
from core.attack_graph import AttackGraph

from gemini_agent import GeminiAgent
from incident_report import IncidentReport


# ============================================================
# CYBERTRACE
# ============================================================

print("\n==========================================")
print("        CYBERTRACE STARTING")
print("==========================================\n")


# ============================================================
# 1. LOAD EVIDENCE
# ============================================================

loader = EvidenceLoader("data")

evidence = loader.load_all()

print(
    f"Evidence files loaded: {len(evidence)}"
)


# ============================================================
# 2. NORMALIZE EVENTS
# ============================================================

normalizer = EventNormalizer()

normalized_events = normalizer.normalize_all(
    evidence
)

print(
    f"Normalized events: {len(normalized_events)}"
)


# ============================================================
# 3. CORRELATE EVENTS
# ============================================================

correlator = CorrelationEngine()

relationships = correlator.correlate(
    normalized_events
)

print(
    f"Correlations found: {len(relationships)}"
)


# ============================================================
# 4. BUILD TIMELINE
# ============================================================

timeline = AttackTimeline()

timeline_events = timeline.sort_events(
    normalized_events
)

print(
    f"Timeline events: {len(timeline_events)}"
)


# ============================================================
# 5. BUILD ATTACK GRAPH
# ============================================================

attack_graph = AttackGraph()

attack_graph.build(
    relationships
)

print(
    f"Attack graph nodes: {len(attack_graph.nodes)}"
)

print(
    f"Attack graph edges: {len(attack_graph.edges)}"
)


# ============================================================
# 6. INCIDENT DETECTION
# ============================================================

incident_detector = IncidentDetector()

incident = incident_detector.analyze(
    normalized_events
)

print("\n===== INCIDENT DETECTION =====")

print(
    f"Severity: {incident['severity']}"
)

print(
    f"Risk Score: {incident['score']}"
)

print("\nFindings:")

for finding in incident["findings"]:

    print(
        f"- {finding}"
    )


# ============================================================
# 7. CREATE CYBERTRACE AGENT TOOLS
# ============================================================

tools = AgentTools(
    normalized_events
)


# ============================================================
# 8. GEMINI AI AGENT
# ============================================================

gemini_agent = GeminiAgent(
    tools
)


# ============================================================
# 9. INVESTIGATION QUERY
# ============================================================

query = "powershell.exe"

print(
    "\n===== INVESTIGATION ====="
)

print(
    f"Query: {query}"
)


# ============================================================
# 10. GET DIRECT EVIDENCE
# ============================================================

direct_evidence = tools.search_evidence(
    query
)

print(
    f"Events found: {len(direct_evidence)}"
)


# ============================================================
# 11. INSPECT / FOLLOW RELATED EVENTS
# ============================================================

related_evidence = []

for event in direct_evidence:

    if not isinstance(event, dict):
        continue

    event_id = event.get("id")

    if not event_id:
        continue

    try:

        related = tools.get_related_events(
            event_id
        )

        if related:

            if isinstance(related, list):

                related_evidence.extend(
                    related
                )

            else:

                related_evidence.append(
                    related
                )

    except Exception as error:

        print(
            f"Could not get related events for "
            f"{event_id}: {error}"
        )


print(
    f"Related events found: "
    f"{len(related_evidence)}"
)


# ============================================================
# 12. GET TIMELINE
# ============================================================

try:

    timeline_events_for_report = (
        tools.get_timeline()
    )

except Exception:

    timeline_events_for_report = (
        timeline_events
    )


print(
    f"Timeline events: "
    f"{len(timeline_events_for_report)}"
)


# ============================================================
# 13. GEMINI INVESTIGATION
# ============================================================

print(
    "\n===== GEMINI AGENT TEST =====\n"
)


ai_query = """
Investigate the PowerShell activity.

Determine:

1. What started the PowerShell execution?
2. What process spawned PowerShell?
3. Did PowerShell communicate with an external IP?
4. Was persistence created?
5. Was credential-related activity observed?
6. Reconstruct the complete attack chain.
7. Give a final severity and confidence assessment.

Use CyberTrace evidence and do not invent facts.
"""


ai_result = gemini_agent.investigate(
    ai_query
)


# ============================================================
# 14. DISPLAY GEMINI ANALYSIS
# ============================================================

print(
    "\n===== GEMINI AI ANALYSIS =====\n"
)

print(
    ai_result
)


# ============================================================
# 15. GENERATE INCIDENT REPORT
# ============================================================

report_generator = IncidentReport(

    query=query,

    direct_evidence=direct_evidence,

    related_evidence=related_evidence,

    timeline_events=timeline_events_for_report,

    ai_analysis=ai_result
)


report = report_generator.generate()


# ============================================================
# 16. FINAL REPORT
# ============================================================

print(
    "\n===== FINAL CYBERTRACE INCIDENT REPORT ====="
)

print(
    report
)


# ============================================================
# 17. FINISHED
# ============================================================

print(
    "\n=========================================="
)

print(
    "       CYBERTRACE INVESTIGATION DONE"
)

print(
    "==========================================\n"
)
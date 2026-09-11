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
# CYBERTRACE START
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
# 7. AGENT TOOLS
# ============================================================

tools = AgentTools(
    normalized_events
)


# ============================================================
# 8. GEMINI AGENT
# ============================================================

gemini_agent = GeminiAgent(
    tools
)


# ============================================================
# 9. INVESTIGATION QUERY
# ============================================================

query = "powershell.exe"

ai_query = """
Investigate the PowerShell activity.

Determine:

1. What process started PowerShell?
2. What did PowerShell communicate with?
3. Was persistence observed?
4. Was credential-related activity observed?
5. What is the likely attack chain?
6. What evidence supports the conclusion?
7. What evidence is missing?
8. What should the analyst do next?
"""


print(
    "\n===== INVESTIGATION ====="
)

print(
    f"Query: {query}"
)


# ============================================================
# 10. DIRECT EVIDENCE
# ============================================================

direct_evidence = tools.search_evidence(
    query
)

print(
    f"Direct evidence: "
    f"{len(direct_evidence)}"
)


# ============================================================
# 11. RELATED EVIDENCE
# ============================================================

related_evidence = []

seen_related = set()

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

    except Exception as error:

        print(
            f"Related-event error for "
            f"{event_id}: {error}"
        )

        related = []

    if not isinstance(
        related,
        list
    ):
        continue

    for related_event in related:

        if not isinstance(
            related_event,
            dict
        ):
            continue

        related_id = related_event.get(
            "id"
        )

        if not related_id:
            continue

        if related_id in seen_related:
            continue

        seen_related.add(
            related_id
        )

        related_evidence.append(
            related_event
        )


print(
    f"Related evidence: "
    f"{len(related_evidence)}"
)


# ============================================================
# 12. TIMELINE
# ============================================================

try:

    timeline_events_for_report = (
        tools.get_timeline()
    )

except Exception as error:

    print(
        f"Timeline error: {error}"
    )

    timeline_events_for_report = (
        timeline_events
    )


print(
    f"Timeline events: "
    f"{len(timeline_events_for_report)}"
)


# ============================================================
# 13. GEMINI FAST INVESTIGATION
# ============================================================

ai_result = gemini_agent.investigate(
    question=ai_query,
    query=query,
    incident=incident,
    relationships=relationships,
    timeline=timeline_events_for_report
)


# ============================================================
# 14. DISPLAY AI RESULT
# ============================================================

print(
    "\n===== GEMINI AI RESULT =====\n"
)

print(
    f"Summary:\n"
    f"{ai_result.get('summary', 'N/A')}\n"
)

print(
    f"Severity: "
    f"{ai_result.get('severity', incident['severity'])}"
)

print(
    f"Risk Score: "
    f"{ai_result.get('risk_score', incident['score'])}"
)

print(
    f"Confidence: "
    f"{ai_result.get('confidence', 0)}"
)


print("\nEvidence IDs:")

for evidence_id in ai_result.get(
    "evidence_ids",
    []
):

    print(
        f"- {evidence_id}"
    )


print("\nAttack Chain:")

for step in ai_result.get(
    "attack_chain",
    []
):

    print(
        f"- {step}"
    )


print("\nObserved Facts:")

for fact in ai_result.get(
    "observed_facts",
    []
):

    print(
        f"- {fact}"
    )


print("\nInferences:")

for inference in ai_result.get(
    "inferences",
    []
):

    print(
        f"- {inference}"
    )


print("\nEvidence Gaps:")

for gap in ai_result.get(
    "evidence_gaps",
    []
):

    print(
        f"- {gap}"
    )


print("\nRecommended Actions:")

for action in ai_result.get(
    "recommended_actions",
    []
):

    print(
        f"- {action}"
    )


# ============================================================
# 15. INCIDENT REPORT
# ============================================================

report_generator = IncidentReport(

    query=query,

    direct_evidence=direct_evidence,

    related_evidence=related_evidence,

    timeline_events=timeline_events_for_report,

    ai_analysis=ai_result,

    incident=incident,

    relationships=relationships
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
# 17. COMPLETE
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
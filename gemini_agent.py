import os
import json
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types


# ============================================================
# LOAD ENVIRONMENT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE, override=True)


class GeminiAgent:

    def __init__(self, tools):

        self.tools = tools

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise ValueError(
                f"GEMINI_API_KEY not found.\n"
                f"Expected .env at: {ENV_FILE}"
            )

        self.client = genai.Client(
            api_key=api_key
        )

        self.model = os.getenv(
            "GEMINI_MODEL",
            "gemini-3.5-flash-lite"
        )

    # ========================================================
    # LOCAL EVIDENCE COLLECTION
    # ========================================================

    def collect_investigation_context(self, query):

        # ----------------------------------------------------
        # Direct evidence
        # ----------------------------------------------------

        try:
            direct_evidence = self.tools.search_evidence(query)
        except Exception as error:
            print(f"Evidence search error: {error}")
            direct_evidence = []

        if not isinstance(direct_evidence, list):
            direct_evidence = []

        # ----------------------------------------------------
        # Related evidence
        # ----------------------------------------------------

        related_evidence = []
        seen_related_ids = set()

        for event in direct_evidence:

            if not isinstance(event, dict):
                continue

            event_id = event.get("id")

            if not event_id:
                continue

            try:
                related = self.tools.get_related_events(
                    event_id
                )
            except Exception as error:
                print(
                    f"Related-event error for {event_id}: {error}"
                )
                related = []

            if not isinstance(related, list):
                continue

            for related_event in related:

                if not isinstance(related_event, dict):
                    continue

                related_id = related_event.get("id")

                if not related_id:
                    continue

                if related_id == event_id:
                    continue

                if related_id in seen_related_ids:
                    continue

                seen_related_ids.add(related_id)
                related_evidence.append(related_event)

        # ----------------------------------------------------
        # Timeline
        # ----------------------------------------------------

        try:
            timeline = self.tools.get_timeline()
        except Exception as error:
            print(f"Timeline error: {error}")
            timeline = []

        if not isinstance(timeline, list):
            timeline = []

        # ----------------------------------------------------
        # Merge evidence
        # ----------------------------------------------------

        all_evidence = []
        seen_event_ids = set()

        for event in direct_evidence + related_evidence:

            if not isinstance(event, dict):
                continue

            event_id = event.get("id")

            if not event_id:
                continue

            if event_id in seen_event_ids:
                continue

            seen_event_ids.add(event_id)
            all_evidence.append(event)

        return {
            "direct_evidence": direct_evidence,
            "related_evidence": related_evidence,
            "evidence": all_evidence,
            "timeline": timeline
        }

    # ========================================================
    # ONE-CALL GEMINI INVESTIGATION
    # ========================================================

    def investigate(
        self,
        question,
        query=None,
        incident=None,
        relationships=None,
        timeline=None
    ):

        print("\n===== GEMINI FAST INVESTIGATION =====")

        # ----------------------------------------------------
        # Use the actual indicator for evidence retrieval.
        # ----------------------------------------------------

        search_query = query or question

        # ----------------------------------------------------
        # Deterministic CyberTrace results are authoritative.
        # ----------------------------------------------------

        incident = incident or {}
        relationships = relationships or []
        timeline = timeline or []

        authoritative_severity = incident.get(
            "severity",
            "LOW"
        )

        authoritative_risk_score = incident.get(
            "score",
            0
        )

        authoritative_findings = incident.get(
            "findings",
            []
        )

        # ----------------------------------------------------
        # Collect evidence locally.
        # No Gemini call here.
        # ----------------------------------------------------

        context = self.collect_investigation_context(
            search_query
        )

        direct_evidence = context[
            "direct_evidence"
        ]

        related_evidence = context[
            "related_evidence"
        ]

        all_evidence = context[
            "evidence"
        ]

        local_timeline = context[
            "timeline"
        ]

        # Use the existing deterministic timeline if available.
        if not local_timeline:
            local_timeline = timeline

        print(
            f"Search query: {search_query}"
        )

        print(
            f"Local evidence collected: "
            f"{len(all_evidence)}"
        )

        print(
            f"Direct evidence: "
            f"{len(direct_evidence)}"
        )

        print(
            f"Related evidence: "
            f"{len(related_evidence)}"
        )

        print(
            f"Timeline events: "
            f"{len(local_timeline)}"
        )

        print(
            f"Authoritative risk score: "
            f"{authoritative_risk_score}"
        )

        print(
            f"Authoritative severity: "
            f"{authoritative_severity}"
        )

        # ----------------------------------------------------
        # Prompt
        # ----------------------------------------------------

        prompt = f"""
You are CyberTrace, an AI cybersecurity investigation analyst.

The deterministic CyberTrace engine has already:
- loaded evidence
- normalized events
- correlated relationships
- reconstructed the timeline
- calculated the incident risk

Your job is to INVESTIGATE and EXPLAIN the incident.

IMPORTANT:

1. Never invent evidence.
2. Use only the evidence supplied below.
3. Reference evidence IDs.
4. Separate observed facts from inference.
5. Correlation is not absolute proof.
6. Identify evidence gaps.
7. Reconstruct the most likely attack chain.
8. Give an AI confidence score from 0.0 to 1.0.
9. Recommend defensive actions only.
10. Never claim an action was executed.
11. The deterministic severity and risk score are authoritative.
12. DO NOT change the authoritative severity.
13. DO NOT calculate a different risk score.

USER REQUEST:
{question}

AUTHORITATIVE CYBERTRACE INCIDENT:

Severity:
{authoritative_severity}

Risk Score:
{authoritative_risk_score}

Deterministic Findings:
{json.dumps(authoritative_findings, indent=2)}

CORRELATED RELATIONSHIPS:
{json.dumps(relationships, indent=2, default=str)}

DIRECT EVIDENCE:
{json.dumps(direct_evidence, indent=2, default=str)}

RELATED EVIDENCE:
{json.dumps(related_evidence, indent=2, default=str)}

TIMELINE:
{json.dumps(local_timeline, indent=2, default=str)}

Return ONLY valid JSON in exactly this structure:

{{
  "summary": "brief investigation summary",
  "confidence": 0.0,
  "evidence_ids": [],
  "attack_chain": [],
  "observed_facts": [],
  "inferences": [],
  "evidence_gaps": [],
  "recommended_actions": []
}}
"""

        # ----------------------------------------------------
        # ONE Gemini API CALL
        # ----------------------------------------------------

        try:

            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json"
                )
            )

        except Exception as error:

            print(
                f"\nGemini request failed: {error}"
            )

            # ------------------------------------------------
            # Graceful fallback
            # ------------------------------------------------

            return {
                "summary": (
                    "AI investigation is temporarily "
                    "unavailable. Deterministic CyberTrace "
                    "analysis remains available."
                ),
                "severity": authoritative_severity,
                "risk_score": authoritative_risk_score,
                "confidence": 0.0,
                "evidence_ids": [
                    event.get("id")
                    for event in all_evidence
                    if isinstance(event, dict)
                    and event.get("id")
                ],
                "attack_chain": [
                    (
                        f"{item.get('source')} "
                        f"--{item.get('relationship')}--> "
                        f"{item.get('target')}"
                    )
                    for item in relationships
                    if isinstance(item, dict)
                ],
                "observed_facts": authoritative_findings,
                "inferences": [],
                "evidence_gaps": [
                    "Gemini response unavailable"
                ],
                "recommended_actions": [
                    "Review deterministic findings",
                    "Inspect the affected host",
                    "Preserve forensic evidence"
                ],
                "direct_evidence_count": len(
                    direct_evidence
                ),
                "related_evidence_count": len(
                    related_evidence
                ),
                "timeline_count": len(
                    local_timeline
                )
            }

        # ----------------------------------------------------
        # Parse Gemini JSON
        # ----------------------------------------------------

        raw_output = response.text.strip()

        try:

            result = json.loads(raw_output)

        except json.JSONDecodeError:

            cleaned = raw_output

            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]

            elif cleaned.startswith("```"):
                cleaned = cleaned[3:]

            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]

            cleaned = cleaned.strip()

            try:

                result = json.loads(cleaned)

            except json.JSONDecodeError:

                result = {
                    "summary": raw_output,
                    "confidence": 0.0,
                    "evidence_ids": [],
                    "attack_chain": [],
                    "observed_facts": [],
                    "inferences": [],
                    "evidence_gaps": [
                        "AI response was not valid JSON"
                    ],
                    "recommended_actions": []
                }

        # ----------------------------------------------------
        # Ensure fields exist
        # ----------------------------------------------------

        result.setdefault(
            "summary",
            "No summary generated."
        )

        result.setdefault(
            "confidence",
            0.0
        )

        result.setdefault(
            "evidence_ids",
            []
        )

        result.setdefault(
            "attack_chain",
            []
        )

        result.setdefault(
            "observed_facts",
            []
        )

        result.setdefault(
            "inferences",
            []
        )

        result.setdefault(
            "evidence_gaps",
            []
        )

        result.setdefault(
            "recommended_actions",
            []
        )

        # ----------------------------------------------------
        # Deterministic values ALWAYS win
        # ----------------------------------------------------

        result["severity"] = authoritative_severity

        result["risk_score"] = authoritative_risk_score

        result["direct_evidence_count"] = len(
            direct_evidence
        )

        result["related_evidence_count"] = len(
            related_evidence
        )

        result["timeline_count"] = len(
            local_timeline
        )

        print(
            "\n[Gemini completed in one API call]"
        )

        return result
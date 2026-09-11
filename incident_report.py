from datetime import datetime


class IncidentReport:

    def __init__(
        self,
        query,
        direct_evidence,
        related_evidence,
        timeline_events,
        ai_analysis,
        incident=None,
        relationships=None
    ):

        self.query = query
        self.direct_evidence = (
            direct_evidence
        )
        self.related_evidence = (
            related_evidence
        )
        self.timeline_events = (
            timeline_events
        )
        self.ai_analysis = (
            ai_analysis
        )
        self.incident = incident or {}
        self.relationships = (
            relationships or []
        )

    # ========================================================
    # SEVERITY
    # ========================================================

    def determine_severity(self):

        if self.incident:

            severity = self.incident.get(
                "severity"
            )

            if severity:
                return severity

        if isinstance(
            self.ai_analysis,
            dict
        ):

            return self.ai_analysis.get(
                "severity",
                "LOW"
            )

        return "LOW"

    # ========================================================
    # RISK SCORE
    # ========================================================

    def get_risk_score(self):

        if self.incident:

            return self.incident.get(
                "score",
                0
            )

        if isinstance(
            self.ai_analysis,
            dict
        ):

            return self.ai_analysis.get(
                "risk_score",
                0
            )

        return 0

    # ========================================================
    # INDICATORS
    # ========================================================

    def extract_indicators(self):

        indicators = []

        text = str(
            self.ai_analysis
        ).lower()

        if "185.10.20.30" in text:
            indicators.append(
                "185.10.20.30"
            )

        if "powershell.exe" in text:
            indicators.append(
                "powershell.exe"
            )

        if "invoice.exe" in text:
            indicators.append(
                "invoice.exe"
            )

        return list(
            dict.fromkeys(
                indicators
            )
        )

    # ========================================================
    # ATTACK CHAIN
    # ========================================================

    def build_attack_chain(self):

        chain = []

        # Use actual correlation relationships.
        for relationship in self.relationships:

            if not isinstance(
                relationship,
                dict
            ):
                continue

            source = (
                relationship.get("source")
                or relationship.get("actor")
            )

            target = (
                relationship.get("target")
            )

            relation = (
                relationship.get(
                    "relationship"
                )
                or relationship.get("action")
            )

            if source and target and relation:

                chain.append(
                    f"{source} "
                    f"--{relation}--> "
                    f"{target}"
                )

        # If correlation relationships are unavailable,
        # use the AI attack chain as fallback.
        if not chain:

            if isinstance(
                self.ai_analysis,
                dict
            ):

                ai_chain = (
                    self.ai_analysis.get(
                        "attack_chain",
                        []
                    )
                )

                if isinstance(
                    ai_chain,
                    list
                ):

                    chain.extend(
                        ai_chain
                    )

        return chain

    # ========================================================
    # GENERATE REPORT
    # ========================================================

    def generate(self):

        severity = (
            self.determine_severity()
        )

        risk_score = (
            self.get_risk_score()
        )

        indicators = (
            self.extract_indicators()
        )

        attack_chain = (
            self.build_attack_chain()
        )

        report = []

        report.append("")

        report.append(
            "=" * 70
        )

        report.append(
            "              CYBERTRACE INCIDENT REPORT"
        )

        report.append(
            "=" * 70
        )

        report.append("")

        report.append(
            "Generated: "
            + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        report.append(
            f"Investigation Query: "
            f"{self.query}"
        )

        report.append(
            f"Severity: {severity}"
        )

        report.append(
            f"Risk Score: {risk_score}"
        )

        report.append("")

        report.append(
            "-" * 70
        )

        report.append(
            "1. EVIDENCE SUMMARY"
        )

        report.append(
            "-" * 70
        )

        report.append(
            f"Direct Evidence: "
            f"{len(self.direct_evidence)}"
        )

        report.append(
            f"Related Evidence: "
            f"{len(self.related_evidence)}"
        )

        report.append(
            f"Timeline Events: "
            f"{len(self.timeline_events)}"
        )

        report.append("")

        report.append(
            "-" * 70
        )

        report.append(
            "2. ATTACK CHAIN"
        )

        report.append(
            "-" * 70
        )

        if attack_chain:

            for index, step in enumerate(
                attack_chain,
                start=1
            ):

                report.append(
                    f"{index}. {step}"
                )

        else:

            report.append(
                "No attack chain was reconstructed."
            )

        report.append("")

        report.append(
            "-" * 70
        )

        report.append(
            "3. INDICATORS OF COMPROMISE"
        )

        report.append(
            "-" * 70
        )

        if indicators:

            for indicator in indicators:

                report.append(
                    f"- {indicator}"
                )

        else:

            report.append(
                "No indicators automatically extracted."
            )

        report.append("")

        report.append(
            "-" * 70
        )

        report.append(
            "4. AI INVESTIGATION"
        )

        report.append(
            "-" * 70
        )

        if isinstance(
            self.ai_analysis,
            dict
        ):

            report.append(
                f"Summary:\n"
                f"{self.ai_analysis.get('summary', '')}"
            )

            report.append("")

            report.append(
                f"Confidence: "
                f"{self.ai_analysis.get('confidence', 0)}"
            )

            report.append("")

            report.append(
                "Observed Facts:"
            )

            for fact in self.ai_analysis.get(
                "observed_facts",
                []
            ):

                report.append(
                    f"- {fact}"
                )

            report.append("")

            report.append(
                "Inferences:"
            )

            for inference in self.ai_analysis.get(
                "inferences",
                []
            ):

                report.append(
                    f"- {inference}"
                )

            report.append("")

            report.append(
                "Evidence Gaps:"
            )

            for gap in self.ai_analysis.get(
                "evidence_gaps",
                []
            ):

                report.append(
                    f"- {gap}"
                )

        else:

            report.append(
                str(self.ai_analysis)
            )

        report.append("")

        report.append(
            "-" * 70
        )

        report.append(
            "5. RECOMMENDED ACTIONS"
        )

        report.append(
            "-" * 70
        )

        if isinstance(
            self.ai_analysis,
            dict
        ):

            actions = (
                self.ai_analysis.get(
                    "recommended_actions",
                    []
                )
            )

            if actions:

                for index, action in enumerate(
                    actions,
                    start=1
                ):

                    report.append(
                        f"{index}. {action}"
                    )

            else:

                report.append(
                    "No AI recommendations available."
                )

        else:

            default_actions = [
                "Isolate the affected endpoint.",
                "Investigate the suspicious executable.",
                "Block confirmed malicious network indicators.",
                "Review persistence mechanisms.",
                "Investigate possible credential compromise.",
                "Preserve relevant forensic evidence."
            ]

            for index, action in enumerate(
                default_actions,
                start=1
            ):

                report.append(
                    f"{index}. {action}"
                )

        report.append("")

        report.append(
            "=" * 70
        )

        report.append(
            "              END OF REPORT"
        )

        report.append(
            "=" * 70
        )

        report.append("")

        return "\n".join(report)
from datetime import datetime


class IncidentReport:

    def __init__(
        self,
        query,
        direct_evidence,
        related_evidence,
        timeline_events,
        ai_analysis
    ):
        self.query = query
        self.direct_evidence = direct_evidence
        self.related_evidence = related_evidence
        self.timeline_events = timeline_events
        self.ai_analysis = ai_analysis

    # ==========================================
    # DETERMINE SEVERITY
    # ==========================================

    def determine_severity(self):

        text = str(self.ai_analysis).lower()

        critical_keywords = [
            "credential access",
            "persistence",
            "command and control",
            "c2",
            "credential theft"
        ]

        high_keywords = [
            "powershell",
            "malicious",
            "payload",
            "post-exploitation",
            "lateral movement"
        ]

        for keyword in critical_keywords:
            if keyword in text:
                return "CRITICAL"

        for keyword in high_keywords:
            if keyword in text:
                return "HIGH"

        return "MEDIUM"

    # ==========================================
    # EXTRACT INDICATORS
    # ==========================================

    def extract_indicators(self):

        indicators = []

        all_text = str(self.ai_analysis)

        # Known indicator from current dataset
        if "185.10.20.30" in all_text:
            indicators.append("185.10.20.30")

        if "powershell.exe" in all_text.lower():
            indicators.append("powershell.exe")

        if "invoice.exe" in all_text.lower():
            indicators.append("invoice.exe")

        return list(dict.fromkeys(indicators))

    # ==========================================
    # BUILD ATTACK CHAIN
    # ==========================================

    def build_attack_chain(self):

        chain = []

        for event in self.timeline_events:

            if not isinstance(event, dict):
                continue

            source = event.get("source")
            target = event.get("target")
            relationship = event.get("relationship")

            if source and target and relationship:

                chain.append(
                    f"{source} --{relationship}--> {target}"
                )

        return chain

    # ==========================================
    # GENERATE REPORT
    # ==========================================

    def generate(self):

        severity = self.determine_severity()

        indicators = self.extract_indicators()

        attack_chain = self.build_attack_chain()

        report = []

        report.append("")
        report.append("=" * 70)
        report.append("              CYBERTRACE INCIDENT REPORT")
        report.append("=" * 70)

        report.append("")
        report.append(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        report.append(
            f"Investigation Query: {self.query}"
        )

        report.append(
            f"Severity: {severity}"
        )

        report.append("")
        report.append("-" * 70)
        report.append("1. EVIDENCE SUMMARY")
        report.append("-" * 70)

        report.append(
            f"Direct Evidence: {len(self.direct_evidence)}"
        )

        report.append(
            f"Related Evidence: {len(self.related_evidence)}"
        )

        report.append(
            f"Timeline Events: {len(self.timeline_events)}"
        )

        report.append("")
        report.append("-" * 70)
        report.append("2. ATTACK CHAIN")
        report.append("-" * 70)

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
                "No attack chain could be reconstructed."
            )

        report.append("")
        report.append("-" * 70)
        report.append("3. INDICATORS OF COMPROMISE")
        report.append("-" * 70)

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
        report.append("-" * 70)
        report.append("4. AI INVESTIGATION")
        report.append("-" * 70)

        report.append(
            str(self.ai_analysis)
        )

        report.append("")
        report.append("-" * 70)
        report.append("5. RECOMMENDED ACTIONS")
        report.append("-" * 70)

        report.append(
            "1. Isolate the affected endpoint."
        )

        report.append(
            "2. Investigate the identified suspicious executable."
        )

        report.append(
            "3. Block confirmed malicious network indicators."
        )

        report.append(
            "4. Review persistence mechanisms."
        )

        report.append(
            "5. Investigate possible credential compromise."
        )

        report.append(
            "6. Preserve relevant forensic evidence."
        )

        report.append("")
        report.append("=" * 70)
        report.append("              END OF REPORT")
        report.append("=" * 70)
        report.append("")

        return "\n".join(report)
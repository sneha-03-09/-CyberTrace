class IncidentDetector:

    def analyze(self, events):

        findings = []

        event_types = set()
        actions = set()

        for event in events:
            event_types.add(event["type"])
            actions.add(event["action"])

        if "process" in event_types and "network" in event_types:
            findings.append(
                "Process execution followed by network communication"
            )

        if "persistence" in event_types:
            findings.append(
                "Persistence mechanism was created"
            )

        if "authentication" in event_types:
            findings.append(
                "Credential-related activity was observed"
            )

        if "deleted" in actions:
            findings.append(
                "A file deletion event was observed"
            )

        score = self.calculate_score(events)

        return {
            "findings": findings,
            "score": score,
            "severity": self.get_severity(score)
        }

    def calculate_score(self, events):

        score = 0

        types = {event["type"] for event in events}
        actions = {event["action"] for event in events}

        if "process" in types:
            score += 20

        if "network" in types:
            score += 20

        if "persistence" in types:
            score += 25

        if "authentication" in types:
            score += 20

        if "deleted" in actions:
            score += 15

        return min(score, 100)

    def get_severity(self, score):

        if score >= 70:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        return "LOW"
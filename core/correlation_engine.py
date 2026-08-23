class CorrelationEngine:

    def correlate(self, events):

        relationships = []

        for event in events:

            if event["action"] == "spawned":

                relationship = {
                    "source_event": event["id"],
                    "source": event["actor"],
                    "relationship": "SPAWNED",
                    "target": event["target"],
                    "evidence": event["source"]
                }

                relationships.append(relationship)

            elif event["action"] == "connected_to":

                relationship = {
                    "source_event": event["id"],
                    "source": event["actor"],
                    "relationship": "CONNECTED_TO",
                    "target": event["target"],
                    "evidence": event["source"]
                }

                relationships.append(relationship)

            elif event["action"] == "created":

                relationship = {
                    "source_event": event["id"],
                    "source": event["actor"],
                    "relationship": "CREATED",
                    "target": event["target"],
                    "evidence": event["source"]
                }

                relationships.append(relationship)

            elif event["action"] == "deleted":

                relationship = {
                    "source_event": event["id"],
                    "source": event["actor"],
                    "relationship": "DELETED",
                    "target": event["target"],
                    "evidence": event["source"]
                }

                relationships.append(relationship)

        return relationships
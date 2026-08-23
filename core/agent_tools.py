class AgentTools:

    def __init__(self, events):
        self.events = events

    def search_evidence(self, query):

        query = query.lower()

        results = []

        for event in self.events:

            if query in str(event).lower():
                results.append(event)

        return results

    def get_event(self, event_id):

        for event in self.events:

            if event["id"] == event_id:
                return event

        return None

    def get_related_events(self, event_id):

        target_event = self.get_event(event_id)

        if target_event is None:
            return []

        actor = target_event["actor"]
        target = target_event["target"]

        related_events = []

        for event in self.events:

            if event["id"] == event_id:
                continue

            if (
                event["actor"] == actor
                or event["actor"] == target
                or event["target"] == actor
                or event["target"] == target
            ):
                related_events.append(event)

        return related_events

    def get_timeline(self):

        return sorted(
            self.events,
            key=lambda event: event["timestamp"]
        )
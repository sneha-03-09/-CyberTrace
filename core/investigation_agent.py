class InvestigationAgent:

    def __init__(self, tools):
        self.tools = tools

    def search(self, query):

        return self.tools.search_evidence(query)

    def inspect_event(self, event_id):

        return self.tools.get_event(event_id)

    def get_related_events(self, event_id):

        return self.tools.get_related_events(event_id)

    def get_timeline(self):

        return self.tools.get_timeline()

    def investigate(self, query):

        print("\n===== AGENT INVESTIGATION =====\n")

        print("Investigation query:", query)

        # Step 1: Search evidence
        search_results = self.search(query)

        print("\n[1] Evidence Search")
        print("Events found:", len(search_results))

        # If nothing is found
        if not search_results:

            print("No matching evidence found.")

            return {
                "query": query,
                "events": [],
                "related_events": [],
                "timeline": self.get_timeline()
            }

        # Step 2: Inspect matching events
        inspected_events = []

        print("\n[2] Inspecting Events")

        for event in search_results:

            inspected = self.inspect_event(event["id"])

            if inspected:
                inspected_events.append(inspected)

                print(
                    event["id"],
                    "|",
                    event["actor"],
                    "-->",
                    event["target"]
                )

        # Step 3: Follow relationships
        related_events = []

        print("\n[3] Following Related Events")

        for event in inspected_events:

            related = self.get_related_events(event["id"])

            for related_event in related:

                if related_event not in related_events:
                    related_events.append(related_event)

        print(
            "Related events found:",
            len(related_events)
        )

        # Step 4: Get complete timeline
        timeline = self.get_timeline()

        print("\n[4] Checking Timeline")

        print(
            "Timeline events:",
            len(timeline)
        )

        # Step 5: Return investigation data
        return {
            "query": query,
            "events": inspected_events,
            "related_events": related_events,
            "timeline": timeline
        }
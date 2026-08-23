from datetime import datetime


class AttackTimeline:

    def sort_events(self, events):

        sorted_events = sorted(
            events,
            key=lambda event: datetime.fromisoformat(event["timestamp"])
        )

        return sorted_events

    def display_timeline(self, events):

        print("\n===== CYBERTRACE ATTACK TIMELINE =====\n")

        for event in events:

            print(
                f"{event['timestamp']} | "
                f"{event['id']} | "
                f"{event['type'].upper()} | "
                f"{event['actor']} "
                f"--{event['action']}--> "
                f"{event['target']}"
            )
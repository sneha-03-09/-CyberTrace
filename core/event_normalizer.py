class EventNormalizer:

    def normalize(self, event):

        event_type = event.get("event_type")

        if event_type == "process_start":
            return {
                "timestamp": event.get("timestamp"),
                "host": event.get("host"),
                "type": "process",
                "actor": event.get("parent_process"),
                "action": "spawned",
                "target": event.get("process"),
                "source": event.get("source"),
                "raw": event
            }

        elif event_type == "file_created":
            return {
                "timestamp": event.get("timestamp"),
                "host": event.get("host"),
                "type": "file",
                "actor": event.get("user"),
                "action": "created",
                "target": event.get("file"),
                "source": event.get("source"),
                "raw": event
            }

        elif event_type == "file_deleted":
            return {
                "timestamp": event.get("timestamp"),
                "host": event.get("host"),
                "type": "file",
                "actor": event.get("user"),
                "action": "deleted",
                "target": event.get("file"),
                "source": event.get("source"),
                "raw": event
            }

        elif event_type == "network_connection":
            return {
                "timestamp": event.get("timestamp"),
                "host": event.get("host"),
                "type": "network",
                "actor": event.get("process"),
                "action": "connected_to",
                "target": event.get("destination_ip"),
                "source": event.get("source"),
                "raw": event
            }

        elif event_type == "authentication":
            return {
                "timestamp": event.get("timestamp"),
                "host": event.get("host"),
                "type": "authentication",
                "actor": event.get("user"),
                "action": event.get("action"),
                "target": event.get("target"),
                "source": event.get("source"),
                "raw": event
            }

        elif event_type == "persistence_created":
            return {
                "timestamp": event.get("timestamp"),
                "host": event.get("host"),
                "type": "persistence",
                "actor": event.get("user"),
                "action": "created",
                "target": event.get("mechanism"),
                "source": event.get("source"),
                "raw": event
            }

        return {
            "timestamp": event.get("timestamp"),
            "host": event.get("host"),
            "type": "unknown",
            "actor": None,
            "action": event_type,
            "target": None,
            "source": event.get("source"),
            "raw": event
        }

    def normalize_all(self, events):

        normalized_events = []

        for index, event in enumerate(events, start=1):

            normalized_event = self.normalize(event)

            normalized_event["id"] = f"E{index:03d}"

            normalized_events.append(normalized_event)

        return normalized_events
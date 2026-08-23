import json
from pathlib import Path


class EvidenceLoader:

    def __init__(self, data_directory):
        self.data_directory = Path(data_directory)

    def load_file(self, filename):
        file_path = self.data_directory / filename

        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)

    def load_all(self):

        evidence = []

        files = [
            "process_events.json",
            "file_events.json",
            "network_events.json",
            "auth_events.json",
            "persistence_events.json"
        ]

        for filename in files:
            events = self.load_file(filename)

            for event in events:
                event["source"] = filename
                evidence.append(event)

        return evidence
class AttackGraph:

    def __init__(self):
        self.nodes = set()
        self.edges = []

    def build(self, relationships):

        for relationship in relationships:

            source = relationship["source"]
            target = relationship["target"]

            self.nodes.add(source)
            self.nodes.add(target)

            edge = {
                "source": source,
                "relationship": relationship["relationship"],
                "target": target,
                "evidence": relationship["source_event"]
            }

            self.edges.append(edge)

        return self

    def display(self):

        print("\n===== CYBERTRACE ATTACK GRAPH =====\n")

        for edge in self.edges:

            print(
                f"{edge['source']} "
                f"--[{edge['relationship']}]--> "
                f"{edge['target']} "
                f"(Evidence: {edge['evidence']})"
            )
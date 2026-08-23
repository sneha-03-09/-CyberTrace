import os
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types


# ==========================================
# LOAD .ENV
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE, override=True)


class GeminiAgent:

    def __init__(self, tools):

        self.tools = tools

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise ValueError(
                f"GEMINI_API_KEY not found.\n"
                f"Expected .env at: {ENV_FILE}"
            )

        self.client = genai.Client(
            api_key=api_key
        )

        self.model = "gemini-3.6-flash"

    # ==========================================
    # CYBERTRACE TOOLS
    # ==========================================

    def search_evidence(self, query):
        return self.tools.search_evidence(query)

    def inspect_event(self, event_id):
        return self.tools.get_event(event_id)

    def get_related_events(self, event_id):
        return self.tools.get_related_events(event_id)

    def get_timeline(self):
        return self.tools.get_timeline()

    # ==========================================
    # TOOL DEFINITIONS
    # ==========================================

    def get_tool_declarations(self):

        return [

            types.FunctionDeclaration(
                name="search_evidence",
                description=(
                    "Search CyberTrace evidence for a process, "
                    "IP address, file, user, or other indicator."
                ),
                parameters=types.Schema(
                    type=types.Type.OBJECT,
                    properties={
                        "query": types.Schema(
                            type=types.Type.STRING,
                            description="Keyword or indicator to search for."
                        )
                    },
                    required=["query"]
                )
            ),

            types.FunctionDeclaration(
                name="inspect_event",
                description=(
                    "Inspect a complete CyberTrace evidence event "
                    "using its evidence ID."
                ),
                parameters=types.Schema(
                    type=types.Type.OBJECT,
                    properties={
                        "event_id": types.Schema(
                            type=types.Type.STRING,
                            description="Evidence ID such as E001 or E002."
                        )
                    },
                    required=["event_id"]
                )
            ),

            types.FunctionDeclaration(
                name="get_related_events",
                description=(
                    "Find events related to a specific evidence event "
                    "to follow the attack chain."
                ),
                parameters=types.Schema(
                    type=types.Type.OBJECT,
                    properties={
                        "event_id": types.Schema(
                            type=types.Type.STRING,
                            description="Evidence ID to investigate."
                        )
                    },
                    required=["event_id"]
                )
            ),

            types.FunctionDeclaration(
                name="get_timeline",
                description=(
                    "Return all CyberTrace events in chronological order."
                ),
                parameters=types.Schema(
                    type=types.Type.OBJECT,
                    properties={}
                )
            )
        ]

    # ==========================================
    # EXECUTE TOOL
    # ==========================================

    def execute_tool(self, name, arguments):

        if name == "search_evidence":
            return self.search_evidence(arguments["query"])

        if name == "inspect_event":
            return self.inspect_event(arguments["event_id"])

        if name == "get_related_events":
            return self.get_related_events(arguments["event_id"])

        if name == "get_timeline":
            return self.get_timeline()

        return {
            "error": f"Unknown tool: {name}"
        }

    # ==========================================
    # INVESTIGATION LOOP
    # ==========================================

    def investigate(self, question):

        print("\n===== GEMINI INVESTIGATION =====")

        tool_declarations = self.get_tool_declarations()

        config = types.GenerateContentConfig(
            system_instruction="""
You are CyberTrace, an AI cybersecurity investigation agent.

Your job is to investigate security incidents using
CyberTrace evidence and investigation tools.

RULES:

1. Never invent evidence.
2. Use the available tools when evidence is required.
3. Reference evidence IDs whenever possible.
4. Separate observed facts from inference.
5. Correlation does not automatically prove malicious activity.
6. Follow related events when reconstructing an attack chain.
7. Use the timeline to understand chronology.
8. Give an evidence-backed conclusion.
9. Give a confidence level.
10. Continue investigating until there is enough evidence
    to answer the user's question.
""",
            tools=[
                types.Tool(
                    function_declarations=tool_declarations
                )
            ]
        )

        contents = [
            types.Content(
                role="user",
                parts=[
                    types.Part(
                        text=question
                    )
                ]
            )
        ]

        max_steps = 8

        for step in range(max_steps):

            print(f"\n[Agent step {step + 1}]")

            response = self.client.models.generate_content(
                model=self.model,
                contents=contents,
                config=config
            )

            function_calls = response.function_calls

            # ==========================================
            # GEMINI FINISHED
            # ==========================================

            if not function_calls:

                print("[Agent finished]")

                return response.text

            # ==========================================
            # ADD GEMINI'S RESPONSE
            # ==========================================

            contents.append(
                response.candidates[0].content
            )

            # ==========================================
            # EXECUTE FUNCTION CALLS
            # ==========================================

            function_response_parts = []

            for function_call in function_calls:

                name = function_call.name

                arguments = dict(
                    function_call.args
                )

                print(
                    "[Agent tool]",
                    name,
                    arguments
                )

                result = self.execute_tool(
                    name,
                    arguments
                )

                # ======================================
                # CREATE GEMINI FUNCTION RESPONSE
                # ======================================

                function_response_parts.append(
                    types.Part.from_function_response(
                        name=name,
                        response={
                            "result": result
                        }
                    )
                )

            # ==========================================
            # SEND TOOL RESULTS BACK TO GEMINI
            # ==========================================

            contents.append(
                types.Content(
                    role="user",
                    parts=function_response_parts
                )
            )

        return (
            "Investigation stopped after reaching "
            "the maximum investigation steps."
        )
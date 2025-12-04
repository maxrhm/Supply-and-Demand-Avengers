from anthropic import AnthropicFoundry
from anthropic.types import TextBlock
import json
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Deine Tools AUS dem data Modul
# ---------------------------------------------------------------------------

from data import getDataMarkdown, getSummaryMarkdown


# ---------------------------------------------------------------------------
# Anthropic Azure Client
# ---------------------------------------------------------------------------

endpoint = "https://genai-hackathon-25-resource.openai.azure.com/anthropic"
deployment_name = "claude-sonnet-4-5"
api_key = ""

client = AnthropicFoundry(
    api_key=api_key,
    base_url=endpoint,
)


# ---------------------------------------------------------------------------
# System Prompt & Tool Definitionen
# ---------------------------------------------------------------------------

system_prompt = """
Erstelle eine präzise Zusammenfassung aller Inhalte die für die Slides benötigt werden.
Verwende das Tool GetData so oft wie nötig.
Jede Slide Sektion muss mindestens einen GetData ToolCall enthalten.
Keine Bilder.
Ausgabe soll ausschließlich die fertige Zusammenfassung sein.
""".strip()

tools = [
    {
        "name": "getDataMarkdown",
        "description": "Liefert Markdown Inhalte zu Daten.",
        "input_schema": {
            "type": "object",
            "properties": {
                "mode": {"type": "string"},
                "percent": {"type": "number"},
                "header": {"type": "string"},
                "filename": {"type": "string"},
            },
            "required": ["mode", "percent", "header", "filename"],
        },
    },
    {
        "name": "getSummaryMarkdown",
        "description": "Gibt die finale Markdown Zusammenfassung zurück.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
]


# ---------------------------------------------------------------------------
# Originaler Report Payload kommt hier rein
# ---------------------------------------------------------------------------

REPORT_PAYLOAD = {
  "report": [
    ...
  ]
}


# ---------------------------------------------------------------------------
# Tool Router → nutzt 1:1 deine importierten Funktionen
# ---------------------------------------------------------------------------

def process_tool(name: str, tool_input: Dict[str, Any]) -> str:
    if name == "getDataMarkdown":
        return getDataMarkdown(
            mode=tool_input["mode"],
            percent=tool_input["percent"],
            header=tool_input["header"],
            filename=tool_input["filename"]
        )

    if name == "getSummaryMarkdown":
        return getSummaryMarkdown()

    return f"Unbekanntes Tool: {name}"


# ---------------------------------------------------------------------------
# Hauptfunktion: verarbeitet den Report mit Claude Tool Use
# ---------------------------------------------------------------------------

def create_slide_summary_from_report(report_payload: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:

    messages = [{"role": "user", "content": json.dumps(report_payload, ensure_ascii=False)}]
    tool_log: List[Dict[str, Any]] = []

    response = client.messages.create(
        model=deployment_name,
        max_tokens=4096,
        system=[{"type": "text", "text": system_prompt}],
        tools=tools,
        tool_choice="auto",
        messages=messages,
    )

    # Tool Use Loop
    while getattr(response, "stop_reason", None) == "tool_use":

        tool_uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
        if not tool_uses:
            break

        messages.append({"role": "assistant", "content": response.content})

        tool_result_blocks = []

        for tool_use in tool_uses:
            tool_name = tool_use.name
            tool_input = tool_use.input

            result = process_tool(tool_name, tool_input)

            tool_log.append({
                "tool": tool_name,
                "input": tool_input,
                "output_preview": result[:200],
            })

            tool_result_blocks.append({
                "type": "tool_result",
                "tool_use_id": tool_use.id,
                "content": result,
            })

        messages.append({"role": "user", "content": tool_result_blocks})

        response = client.messages.create(
            model=deployment_name,
            max_tokens=4096,
            system=[{"type": "text", "text": system_prompt}],
            tools=tools,
            tool_choice="auto",
            messages=messages,
        )

    # Finale Antwort extrahieren
    final_text_parts: List[str] = []
    for block in response.content:
        if isinstance(block, TextBlock):
            final_text_parts.append(block.text)
        elif getattr(block, "type", None) == "text":
            final_text_parts.append(block.text)

    final_summary = "".join(final_text_parts).strip()
    return final_summary, tool_log


# ---------------------------------------------------------------------------
# Direkt ausführbar
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    summary_markdown, tool_log = create_slide_summary_from_report(REPORT_PAYLOAD)

    print("===== FINALE MARKDOWN ZUSAMMENFASSUNG =====\n")
    print(summary_markdown)

    print("\n\n===== TOOL LOG =====\n")
    print(json.dumps(tool_log, indent=2, ensure_ascii=False))

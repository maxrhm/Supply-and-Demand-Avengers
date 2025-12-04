from anthropic import AnthropicFoundry
import json

# Azure Anthropic Endpoint
endpoint = "https://genai-hackathon-25-resource.openai.azure.com/anthropic"
deployment_name = "claude-sonnet-4-5"
api_key = ""

client = AnthropicFoundry(
    api_key=api_key,
    base_url=endpoint,
)

def _extract_json(raw: str) -> str:
    """
    Versucht aus der Modellantwort den reinen JSON Block herauszuschneiden.
    Entfernt Codefences und beliebigen Text vor oder nach dem JSON Objekt.
    """
    raw = raw.strip()

    # Fall 1: Antwort ist in ```...``` verpackt
    if raw.startswith("```"):
        parts = raw.split("```")
        for part in parts:
            candidate = part.strip()
            if candidate.startswith("{") or candidate.startswith("["):
                return candidate

    # Fall 2: Es gibt davor oder danach noch Text
    first = raw.find("{")
    last = raw.rfind("}")
    if first != -1 and last != -1 and last > first:
        return raw[first:last + 1].strip()

    # Fallback
    return raw


# ---------------------------------------------------------------------------
# Slide Drafting ohne Structured Outputs API, Schema im System Prompt
# ---------------------------------------------------------------------------
def create_slide_deck(summary: str):
    system_prompt = """
You produce structured slide deck JSON outputs.

Return only one JSON object that strictly matches the following JSON Schema.
No explanations, no markdown, no backticks, no surrounding text.
The response content must be valid JSON.

JSON Schema:

{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.com/structured-report.schema.json",
  "title": "Structured Report",
  "type": "object",
  "required": ["report"],
  "properties": {
    "report": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["sectionName", "content"],
        "properties": {
          "sectionName": { "type": "string" },
          "content": {
            "type": "array",
            "items": {
              "type": "object",
              "required": ["type", "description", "value"],
              "properties": {
                "type": { "enum": ["text", "image"] },
                "description": { "type": "string" },
                "value": {
                  "oneOf": [
                    { "type": "string" },
                    {
                      "type": "object",
                      "required": ["link", "description"],
                      "properties": {
                        "link": { "type": "string" },
                        "description": { "type": "string" }
                      }
                    }
                  ]
                }
              }
            }
          }
        }
      }
    }
  },
  "additionalProperties": false
}
""".strip()

    user_prompt = (
        "Create a slide deck structure for this summary:\n\n"
        f"{summary}\n\n"
        "Return only one JSON object that validates against the schema."
    )

    response = client.messages.create(
        model=deployment_name,
        system=system_prompt,
        max_tokens=4096,
        messages=[
            {"role": "user", "content": user_prompt}
        ],
    )

    # Baue die rohe Textantwort zusammen
    raw = "".join(
        getattr(block, "text", "") for block in response.content
    ).strip()

    if not raw:
        raise RuntimeError(
            f"Model response content is empty. Full response object: {response}"
        )

    cleaned = _extract_json(raw)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        # Debughilfe wenn das Modell nicht ganz brav war
        print("Failed to parse JSON")
        print("Raw response:")
        print(raw)
        print("Cleaned candidate:")
        print(cleaned)
        raise e


if __name__ == "__main__":
    summary = "A comprehensive report detailing monthly sales performance, trends, and forecasts."
    result = create_slide_deck(summary)
    print(json.dumps(result, indent=2, ensure_ascii=False))

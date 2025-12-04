## SAP Documentation Generator

This project consists of:
- A general-purpose MCP server that connects to your SAP ABAP system (`sap_mcp.py`).  
  This server exposes SAP ABAP functionality via the MCP protocol and can be reused by any MCP-compatible client, not just the web UI in this repo.
- A Streamlit web client (`web.py`) that uses the MCP server plus an OpenAI-compatible Azure endpoint to generate human-readable documentation.

You start the MCP server first, then the web client. Other MCP-aware tools could also connect to the same SAP MCP server for different use cases (code exploration, analysis, etc.).

---

## Installation

1. Create and activate a virtual environment (recommended):
   - `python -m venv .venv`
   - Linux/macOS: `source .venv/bin/activate`
   - Windows (PowerShell): `.venv\Scripts\Activate.ps1`

2. Install dependencies:
   - `pip install -r reqirements.txt`

---

## Environment configuration (`.env`)

Create a `.env` file in the project root (same folder as `web.py` and `sap_mcp.py`) and define:

### Azure OpenAI / OpenAI Agents
Used by `web.py` (and `main.py`):
- `BASE_URL` – Azure OpenAI endpoint base URL (e.g. `https://your-resource-name.openai.azure.com`)
- `API_KEY` – Azure OpenAI API key
- `DEPLOYMENT` – Chat model deployment name
- `API_VERSION` – Azure OpenAI API version (e.g. `2024-02-15-preview`)

### SAP connection
Used by `sap_mcp.py`:
- `SAP_URL` – Base URL of your SAP system (e.g. `http://hostname:8000`)
- `SAP_USER` – SAP username
- `SAP_PASSWORD` – SAP password
- `SAP_CLIENT` – SAP client (e.g. `100`)
- `SAP_LANGUAGE` – SAP logon language (e.g. `EN`)

Example `.env`:

```env
BASE_URL=https://your-azure-openai-resource.openai.azure.com
API_KEY=your_azure_openai_api_key
DEPLOYMENT=your-chat-deployment-name
API_VERSION=2024-02-15-preview

SAP_URL=http://your-sap-host:8000
SAP_USER=DEVUSER
SAP_PASSWORD=secret
SAP_CLIENT=100
SAP_LANGUAGE=EN
```

---

## Running the MCP server

From the project root:

```bash
python sap_mcp.py
```

Keep this process running; the web client connects to it on `http://localhost:8000/mcp`.  
Because this is a generic MCP server, any other MCP-compatible client can also connect to this endpoint to work with your SAP system.

---

## Running the web client

In a separate terminal, from the project root:

```bash
streamlit run web.py
```

This opens the SAP Documentation Generator in your browser. Make sure the MCP server is running first so the client can use it.

---

## Usage

- Open the Streamlit app.
- In the chat input, enter either:
  - A free-form prompt describing the documentation you want, or
  - An SAP Z-report name.
- The app calls the MCP SAP server, gathers ABAP artifacts, and generates documentation via the Azure/OpenAI agent.
- Use the **clear** button to reset the chat and conversation history.

Note: The web client in this repo is focused specifically on SAP documentation generation; it is just one possible interface on top of the more general SAP MCP server.

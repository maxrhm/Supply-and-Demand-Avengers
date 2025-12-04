import asyncio
import os

import streamlit as st
from dotenv import load_dotenv
from openai import AsyncAzureOpenAI
from openai.types.responses import ResponseTextDeltaEvent

from agents import (
    Agent,
    OpenAIChatCompletionsModel,
    Runner,
    SQLiteSession,
    function_tool,
    set_default_openai_api,
    set_default_openai_client,
    set_tracing_disabled,
)
from agents.mcp import MCPServerStreamableHttp

load_dotenv()

# Read settings
BASE_URL =  os.getenv("BASE_URL")
API_KEY = os.getenv("API_KEY")
deployment = os.getenv("DEPLOYMENT")
instructions = open('instructions.txt', 'r').read()

client = AsyncAzureOpenAI(
    api_key=API_KEY,
    api_version=os.getenv("API_VERSION"),
    azure_ad_token=API_KEY,
    azure_endpoint=BASE_URL,
    azure_deployment=deployment,
    default_headers={
        "Ocp-Apim-Subscription-Key": API_KEY,
    }
)
model = OpenAIChatCompletionsModel(
    model=deployment,
    openai_client=client,
)

set_default_openai_client(client=client, use_for_tracing=False)
set_default_openai_api("chat_completions")
set_tracing_disabled(disabled=True)

# functions from the client
@function_tool
def write_file(filename: str, documentation: str) -> str:
    """write the content into a file"""
    with open(filename, 'wt') as file:
        file.write(documentation)
    return f"file {filename} was written"

# run the agent with streaming
async def run_agent(user_input: str, text_placeholder, tools_placeholder, session: SQLiteSession):
    """Run the agent with SQLite-backed session history and stream into the UI."""
    async with MCPServerStreamableHttp(
        name="Streamable HTTP Python Server",
        params={
            "url": "http://localhost:8000/mcp",
            #"headers": {"Authorization": f"Bearer {token}"},
            "timeout": 10,
            # Avoid terminate-on-close bug that can surface with asyncio.run
            # in environments like Streamlit by not explicitly terminating
            # the remote session when the client context closes.
            "terminate_on_close": False,
        },
        cache_tools_list=True,
        max_retry_attempts=3,
        client_session_timeout_seconds=300,
    ) as server:
        agent = Agent(
            name="Assistant",
            instructions=instructions,
            tools=[write_file],
            mcp_servers=[server],
        )
        streamed = Runner.run_streamed(agent, input=user_input, max_turns=100, session=session)

        full_text = ""
        tool_logs: list[str] = []

        async for event in streamed.stream_events():
            if event.type == "raw_response_event" and isinstance(event.data, ResponseTextDeltaEvent):
                delta = event.data.delta or ""
                full_text += delta
                text_placeholder.markdown(full_text)
            elif event.type == "run_item_stream_event":
                item = event.item
                if getattr(item, "type", None) == "tool_call_item":
                    tool_name = (
                        getattr(item, "tool_name", None)
                        or getattr(getattr(item, "tool", None), "name", None)
                        or getattr(item, "name", None)
                    )
                    # Fallback to the string representation if we still couldn't find a name
                    if not tool_name:
                        tool_name = str(item.raw_item.name)
                    tool_logs.append(f"`{tool_name}`")
                    tools_placeholder.markdown("**Tool activity**:\n" + ",".join(tool_logs))

        return full_text

# web interface
async def main():
    st.logo("image.png", size="large")
    st.title("SAP Documentation Generator")

    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Initialize conversation session for the agent
    if "conversation_session" not in st.session_state:
        st.session_state.conversation_session = SQLiteSession("conversation")

    if st.button("clear"):
        st.session_state.conversation_session = SQLiteSession("conversation")
        st.session_state.messages = []

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if prompt := st.chat_input("Enter prompt or z report name?"):
        # Display user message in chat message container
        with st.chat_message("user"):
            st.markdown(prompt)

        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})

        with st.spinner("Documentating...."):
            # Stream assistant response and tool activity into the UI
            with st.chat_message("assistant"):
                text_placeholder = st.empty()
                tools_placeholder = st.empty()
                response = await run_agent(
                    prompt,
                    text_placeholder,
                    tools_placeholder,
                    st.session_state.conversation_session,
                )

        # Add assistant response to chat history
        st.session_state.messages.append({"role": "assistant", "content": response})

# call main
if __name__ == "__main__":
    asyncio.run(main())

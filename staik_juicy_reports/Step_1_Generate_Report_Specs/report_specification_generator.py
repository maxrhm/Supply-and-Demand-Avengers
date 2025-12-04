from anthropic import AnthropicFoundry
import streamlit as st
import random
import json
import os

endpoint = "https://genai-hackathon-25-resource.services.ai.azure.com/anthropic"
deployment_name = "claude-haiku-4-5"
api_key = ""


# Programme that generates a high level summary of requirements for a report. This summry includes key points such as 
# the target group, time frame (observation period), target audience, and a summary of the desired information and content for the report

# Output JSON Structure: 

# {
#   "reportName": "Monthly Sales Report",
#   "targetAudience": "Sales Managers",
#   "observationPeriod": "Monthly",
#   "summary": "A comprehensive report detailing monthly sales performance, trends, and forecasts....."
# }


# object to store responses in 
report_specification = {
    "reportName": "",
    "targetAudience": "",
    "observationPeriod": "",
    "summary": ""
}


system_prompt = "You are an experienced reporting specialist. \
Your first task is to gather all stakeholder requirements needed to produce their desired report. \
Ask the user targeted questions to collect all necessary details for the report. \
Once all information is gathered, produce a clear, structured summary of the requirements. \
Ask the user to confirm the summary. \
Only proceed to the next step after the user explicitly verifies its accuracy. \
Use the following JSON as the structural reference. \
{\
  'reportName': 'Monthly Sales Report',\
  'targetAudience': 'Sales Managers',\
  'observationPeriod': 'Monthly',\
  'summary': 'A comprehensive report detailing monthly sales performance, trends, and forecasts.....'\
}\
"


# client def.
client = AnthropicFoundry(
    api_key=api_key,
    base_url=endpoint
)

def export_report_specification():
    """
    Export the report_specification object to a JSON file under the /runs directory.
    The file will be named with the current timestamp.
    """
    # Ensure the /runs directory exists
    runs_dir = "runs"
    if not os.path.exists(runs_dir):
        os.makedirs(runs_dir)

    # Generate a unique filename using the current timestamp
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = os.path.join(runs_dir, f"report_specification_{timestamp}.json")

    # Write the report_specification object to the file
    with open(file_path, "w") as json_file:
        json.dump(st.session_state.report_specification, json_file, indent=4)

    st.success(f"Report specification exported to {file_path}")


# -----------------------------
# STREAMLIT UI
# -----------------------------

st.title("StAIk 🥩 -- Juicy Reports")

# Initialize session state for questions and responses
if "current_category" not in st.session_state:
    st.session_state.current_category = None

if "asked_questions" not in st.session_state:
    st.session_state.asked_questions = []

if "report_specification" not in st.session_state:
    st.session_state.report_specification = report_specification

# Initialize session state for question history
if "question_history" not in st.session_state:
    st.session_state.question_history = []

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display previous chat messages
# for message in st.session_state.messages:
#     with st.chat_message(message["role"]):
#         st.markdown(message["content"])

# Display the history of questions and answers above the current question
st.subheader("Question and Answer History")
for entry in st.session_state.question_history:
    st.markdown(f"**Q:** {entry['question']}")
    st.markdown(f"**A:** {entry['answer']}")

def generate_question_for_category(category):
    """
    Generate a question dynamically for the given category using Anthropic.
    """
    prompt = f"""
    Based on the system prompt, generate a targeted question to gather information for the '{category}' category of the report. 
    Respond with a single question as a string. Be very precise an focused.
    """

    # Send the prompt to Anthropic
    response = client.messages.create(
        model=deployment_name,
        system=system_prompt,
        max_tokens=128,
        messages=[{"role": "user", "content": prompt}]
    )

    # Extract the response text from the TextBlock object
    if hasattr(response, "content") and isinstance(response.content, list):
        for block in response.content:
            if hasattr(block, "text"):
                return block.text.strip()

    return "Could not generate a question. Please try again."

# Ensure all necessary session state variables are initialized
if "current_question_index" not in st.session_state:
    st.session_state.current_question_index = 0
if "current_question_asked" not in st.session_state:
    st.session_state.current_question_asked = False
if "categories" not in st.session_state:
    st.session_state.categories = list(report_specification.keys())

# Ensure the question is dynamically generated for the current category
if st.session_state.current_question_index < len(st.session_state.categories):
    current_category = st.session_state.categories[st.session_state.current_question_index]
    question = generate_question_for_category(current_category)
else:
    question = ""  # Default empty string if no question is available

# Iterate through all categories and ask the first question from each
if "current_category" not in st.session_state:
    st.session_state.current_category = None

if "categories" not in st.session_state:
    st.session_state.categories = list(report_specification.keys())

# Initialize session state for current question index
if "current_question_index" not in st.session_state:
    st.session_state.current_question_index = 0

if "question_history" not in st.session_state:
    st.session_state.question_history = []

if st.session_state.current_question_index < len(st.session_state.categories):
    current_category = st.session_state.categories[st.session_state.current_question_index]
    question = generate_question_for_category(current_category)

    if "current_question_asked" not in st.session_state:
        st.session_state.current_question_asked = False

    if not st.session_state.current_question_asked:
        with st.chat_message("assistant"):
            st.markdown(question)
        st.session_state.current_question_asked = True

    if prompt := st.chat_input("..."):
        # Store & display the user message
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Replace the user input in the corresponding category of the report_specification
        st.session_state.report_specification[current_category] = prompt

        # Add the question and answer to the history
        st.session_state.question_history.append({"question": question, "answer": prompt})

        # Move to the next category
        st.session_state.current_question_index += 1
        st.session_state.current_question_asked = False

        # Clear the input box for the next question
        st.rerun()

# Add a section to display the current state of the report_specification JSON
st.subheader("Current Report Specification")
st.json(st.session_state.report_specification)

# Call the export function when all questions are answered
if st.session_state.current_question_index >= len(st.session_state.categories):
    export_report_specification()

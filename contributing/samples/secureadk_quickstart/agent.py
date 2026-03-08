# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from google.adk import Agent


def record_evidence(note: str) -> str:
  """Records a note as evidence for the current session."""
  return f'Recorded evidence: {note}'


root_agent = Agent(
    model='gemini-2.5-flash',
    name='secure_hello_agent',
    description='A minimal SecureADK sample agent with one governed tool.',
    instruction="""
      You are a security-aware assistant.
      Use the record_evidence tool when the user asks you to record or save
      evidence.
      If the user only asks a question, answer directly without using tools.
    """,
    tools=[record_evidence],
)

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

from __future__ import annotations

import asyncio

from google.adk.agents.llm_agent import Agent
from google.adk.apps.app import App
from google.adk.artifacts.in_memory_artifact_service import (
    InMemoryArtifactService,
)
from google.adk.sessions.in_memory_session_service import (
    InMemorySessionService,
)
from google.adk.secure import capability_state_key
from google.adk.secure import CapabilityVault
from google.adk.secure import IdentityRegistry
from google.adk.secure import InMemoryProvenanceLedger
from google.adk.secure import AgentIdentity
from google.adk.secure import PolicyRule
from google.adk.secure import SECURE_METADATA_KEY
from google.adk.secure import SecureRuntimePlugin
from google.adk.secure import SecureRuntimeBuilder
from google.adk.secure import SealedArtifactService
from google.adk.secure import SimplePolicyEngine
from google.adk.secure.signing import HmacKeyring
from google.adk.tools.function_tool import FunctionTool
from google.genai import types

from tests.unittests import testing_utils


def _build_secure_plugin(
    *,
    allow_tool: bool,
) -> tuple[SecureRuntimePlugin, InMemoryProvenanceLedger]:
  ledger = InMemoryProvenanceLedger()
  keyring = HmacKeyring({'judge-key': 'judge-secret'})
  rules = []
  if allow_tool:
    rules.append(
        PolicyRule(
            name='judge-read-only',
            principals=('judge',),
            tools=('sealed_evidence',),
            actions=('sealed_evidence',),
        )
    )
  plugin = SecureRuntimePlugin(
      identity_registry=IdentityRegistry(
          [AgentIdentity(agent_name='judge', key_id='judge-key', roles=('judge',))]
      ),
      capability_vault=CapabilityVault(
          policy_engine=SimplePolicyEngine(rules),
          keyring=keyring,
      ),
      ledger=ledger,
  )
  return plugin, ledger


def _allowed_tool(tool_context):
  token = tool_context.state.get(
      capability_state_key(tool_context.function_call_id)
  )
  return {'capability_present': token is not None}


def _denied_tool() -> dict[str, object]:
  return {'result': 'should-not-run'}


def _named_tool(func) -> FunctionTool:
  tool = FunctionTool(func)
  tool.name = 'sealed_evidence'
  tool.description = 'SecureADK test tool.'
  return tool


def test_secure_runtime_plugin_denies_unauthorized_tool_calls():
  responses = [
      types.Part.from_function_call(name='sealed_evidence', args={}),
      'finished',
  ]
  mock_model = testing_utils.MockModel.create(responses=responses)
  plugin, ledger = _build_secure_plugin(allow_tool=False)
  agent = Agent(
      name='judge',
      model=mock_model,
      tools=[_named_tool(_denied_tool)],
  )

  runner = testing_utils.InMemoryRunner(agent, plugins=[plugin])
  events = runner.run('start trial')

  assert testing_utils.simplify_events(events)[1][1].function_response.response == {
      'status': 'denied',
      'reason': 'Denied by policy engine default effect.',
      'tool': 'sealed_evidence',
      'action': 'sealed_evidence',
      'risk_score': 1.0,
  }

  ledger_entries = asyncio.run(ledger.list_entries())
  assert any(entry.event_type == 'tool_denied' for entry in ledger_entries)


def test_secure_runtime_plugin_issues_capability_and_signs_model_output():
  responses = [
      types.Part.from_function_call(name='sealed_evidence', args={}),
      'verdict issued',
  ]
  mock_model = testing_utils.MockModel.create(responses=responses)
  plugin, ledger = _build_secure_plugin(allow_tool=True)
  agent = Agent(
      name='judge',
      model=mock_model,
      tools=[_named_tool(_allowed_tool)],
  )

  runner = testing_utils.InMemoryRunner(agent, plugins=[plugin])
  events = runner.run('start trial')

  function_response = testing_utils.simplify_events(events)[1][1].function_response
  assert function_response.response == {'capability_present': True}

  final_event = events[-1]
  assert final_event.custom_metadata is not None
  assert SECURE_METADATA_KEY in final_event.custom_metadata

  ledger_entries = asyncio.run(ledger.list_entries())
  assert any(
      entry.event_type == 'capability_issued' for entry in ledger_entries
  )
  assert any(
      entry.event_type == 'tool_executed' for entry in ledger_entries
  )
  assert any(
      entry.event_type == 'model_response_signed' for entry in ledger_entries
  )


def test_secure_runtime_builder_wraps_app_and_services():
  responses = ['verdict issued']
  mock_model = testing_utils.MockModel.create(responses=responses)
  agent = Agent(name='judge', model=mock_model)
  app = App(name='courtroom', root_agent=agent)

  ledger = InMemoryProvenanceLedger()
  keyring = HmacKeyring({
      'judge-key': 'judge-secret',
      'seal-key': 'seal-secret',
  })
  builder = SecureRuntimeBuilder(
      identity_registry=IdentityRegistry(
          [AgentIdentity(agent_name='judge', key_id='judge-key', roles=('judge',))]
      ),
      capability_vault=CapabilityVault(
          policy_engine=SimplePolicyEngine([]),
          keyring=keyring,
      ),
      ledger=ledger,
      artifact_signing_key_id='seal-key',
  )

  session_service = InMemorySessionService()
  artifact_service = InMemoryArtifactService()
  runner = builder.create_runner(
      app=app,
      session_service=session_service,
      artifact_service=artifact_service,
  )

  assert runner.app is not None
  assert any(
      plugin.name == 'secure_runtime' for plugin in runner.app.plugins
  )
  assert isinstance(runner.artifact_service, SealedArtifactService)

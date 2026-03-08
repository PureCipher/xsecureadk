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

from google.adk.secure.capabilities import CapabilityVault
from google.adk.secure.policies import AuthorizationRequest
from google.adk.secure.policies import PolicyRule
from google.adk.secure.policies import SimplePolicyEngine
from google.adk.secure.signing import HmacKeyring


def test_capability_vault_issues_and_consumes_token():
  keyring = HmacKeyring({'judge-key': 'top-secret'})
  engine = SimplePolicyEngine([
      PolicyRule(
          name='judge-may-read-evidence',
          principals=('judge',),
          tools=('sealed_evidence',),
          actions=('read',),
      )
  ])
  vault = CapabilityVault(policy_engine=engine, keyring=keyring)
  request = AuthorizationRequest(
      agent_name='judge',
      key_id='judge-key',
      roles=('judge',),
      tool_name='sealed_evidence',
      action='read',
      app_name='courtroom',
      user_id='user-1',
      session_id='session-1',
      invocation_id='invocation-1',
      function_call_id='fc-1',
      tenant_id='tenant-a',
      context={'tenant_id': 'tenant-a'},
      tool_args={'case_id': 'case-42'},
  )

  token = vault.issue(request)
  validation = vault.validate(token, request)
  assert validation.valid

  consume_result = vault.consume(token, request)
  assert consume_result.valid

  replay_result = vault.validate(token, request)
  assert not replay_result.valid
  assert replay_result.reason == 'Capability token replay detected.'


def test_capability_vault_rejects_requests_without_matching_policy():
  keyring = HmacKeyring({'juror-key': 'top-secret'})
  engine = SimplePolicyEngine([
      PolicyRule(
          name='judge-only',
          principals=('judge',),
          tools=('sealed_evidence',),
          actions=('read',),
      )
  ])
  vault = CapabilityVault(policy_engine=engine, keyring=keyring)
  request = AuthorizationRequest(
      agent_name='juror',
      key_id='juror-key',
      roles=('juror',),
      tool_name='sealed_evidence',
      action='read',
      app_name='courtroom',
      user_id='user-1',
      session_id='session-1',
      invocation_id='invocation-1',
      tenant_id='tenant-a',
      context={'tenant_id': 'tenant-a'},
      tool_args={},
  )

  decision = vault.authorize(request)

  assert not decision.allowed
  assert decision.matched_rule == 'default_deny'

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

from google.adk.secure import AuthorizationRequest
from google.adk.secure import PolicyRule
from google.adk.secure import SimplePolicyEngine


def _request() -> AuthorizationRequest:
  return AuthorizationRequest(
      agent_name='judge',
      key_id='judge-key',
      roles=('judge',),
      tool_name='sealed_evidence',
      action='read',
      app_name='courtroom',
      user_id='alice',
      session_id='session-1',
      invocation_id='invocation-1',
      function_call_id='fc-1',
      tenant_id='tenant-a',
      context={'tenant_id': 'tenant-a', 'case_id': 'case-7'},
      tool_args={'case_id': 'case-7'},
  )


def test_simple_policy_engine_requires_approval_from_risk_threshold() -> None:
  engine = SimplePolicyEngine(
      [
          PolicyRule(
              name='judge-read',
              principals=('judge',),
              tools=('sealed_evidence',),
              actions=('read',),
              risk_score=0.9,
          )
      ],
      approval_risk_score_threshold=0.8,
      default_approval_hint='Human approval required.',
  )

  decision = engine.authorize(_request())

  assert decision.allowed
  assert decision.requires_approval
  assert decision.approval_hint == 'Human approval required.'


def test_simple_policy_engine_explain_reports_matching_and_failing_conditions() -> (
    None
):
  engine = SimplePolicyEngine([
      PolicyRule(
          name='matched',
          principals=('judge',),
          tools=('sealed_evidence',),
          actions=('read',),
          tenant_ids=('tenant-a',),
          required_tool_args={'case_id': 'case-7'},
      ),
      PolicyRule(
          name='wrong-action',
          principals=('judge',),
          tools=('sealed_evidence',),
          actions=('write',),
      ),
  ])

  explanation = engine.explain(_request())

  assert explanation.decision.allowed
  assert explanation.decision.matched_rule == 'matched'
  assert explanation.evaluations[0].matched
  assert not explanation.evaluations[1].matched
  assert any(
      condition.field_name == 'actions' and not condition.matched
      for condition in explanation.evaluations[1].conditions
  )

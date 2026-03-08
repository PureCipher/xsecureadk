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

from google.adk.secure import GatewayRequest
from google.adk.secure import GatewayRule
from google.adk.secure import RuleBasedAccessGateway


def test_rule_based_gateway_denies_mismatched_tenant() -> None:
  gateway = RuleBasedAccessGateway([
      GatewayRule(
          name='tenant-a-only',
          operations=('run',),
          resource_types=('agent',),
          tenant_ids=('tenant-a',),
      )
  ])

  decision = gateway.authorize(
      GatewayRequest(
          operation='run',
          resource_type='agent',
          resource_name='judge',
          app_name='courtroom',
          user_id='alice',
          agent_name='judge',
          tenant_id='tenant-b',
      )
  )

  assert not decision.allowed
  assert decision.matched_rule == 'default_deny'


def test_rule_based_gateway_allows_matching_principal_and_context() -> None:
  gateway = RuleBasedAccessGateway([
      GatewayRule(
          name='judge-tool-gateway',
          operations=('tool',),
          resource_types=('tool',),
          resource_names=('sealed_evidence',),
          principals=('judge',),
          tenant_ids=('tenant-a',),
          required_context={'case_id': 'case-7'},
      )
  ])

  decision = gateway.authorize(
      GatewayRequest(
          operation='tool',
          resource_type='tool',
          resource_name='sealed_evidence',
          app_name='courtroom',
          user_id='alice',
          agent_name='judge',
          roles=('judge',),
          tenant_id='tenant-a',
          case_id='case-7',
          context={'case_id': 'case-7'},
      )
  )

  assert decision.allowed
  assert decision.matched_rule == 'judge-tool-gateway'


def test_rule_based_gateway_requires_approval_from_risk_threshold() -> None:
  gateway = RuleBasedAccessGateway(
      [
          GatewayRule(
              name='approve-sensitive-tool',
              operations=('tool',),
              resource_types=('tool',),
              resource_names=('sealed_evidence',),
              principals=('judge',),
              risk_score=0.9,
          )
      ],
      approval_risk_score_threshold=0.8,
      default_approval_hint='Human approval required.',
  )

  decision = gateway.authorize(
      GatewayRequest(
          operation='tool',
          resource_type='tool',
          resource_name='sealed_evidence',
          app_name='courtroom',
          user_id='alice',
          agent_name='judge',
      )
  )

  assert decision.allowed
  assert decision.requires_approval
  assert decision.approval_hint == 'Human approval required.'


def test_rule_based_gateway_explain_reports_matching_and_failing_conditions():
  gateway = RuleBasedAccessGateway([
      GatewayRule(
          name='matched',
          operations=('tool',),
          resource_types=('tool',),
          resource_names=('sealed_evidence',),
          principals=('judge',),
      ),
      GatewayRule(
          name='wrong-tenant',
          operations=('tool',),
          resource_types=('tool',),
          tenant_ids=('tenant-b',),
      ),
  ])

  explanation = gateway.explain(
      GatewayRequest(
          operation='tool',
          resource_type='tool',
          resource_name='sealed_evidence',
          app_name='courtroom',
          user_id='alice',
          agent_name='judge',
          tenant_id='tenant-a',
      )
  )

  assert explanation.decision.allowed
  assert explanation.decision.matched_rule == 'matched'
  assert explanation.evaluations[0].matched
  assert not explanation.evaluations[1].matched
  assert any(
      condition.field_name == 'tenant_ids' and not condition.matched
      for condition in explanation.evaluations[1].conditions
  )

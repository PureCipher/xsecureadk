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

from google.adk.secure import AuthorizationRequest
from google.adk.secure import GatewayDecision
from google.adk.secure import GatewayRequest
from google.adk.secure import InMemoryPolicyObservationStore
from google.adk.secure import PolicyDecision
from google.adk.secure import PolicyRecommender


def test_policy_recommender_generates_actionable_recommendations() -> None:
  recommender = PolicyRecommender(
      store=InMemoryPolicyObservationStore(),
      minimum_evidence_count=2,
      high_risk_threshold=0.8,
  )

  for suffix in ('1', '2'):
    asyncio.run(
        recommender.record_policy_decision(
            request=AuthorizationRequest(
                agent_name='judge',
                key_id='judge-key',
                tool_name='sealed_evidence',
                action='sealed_evidence',
                app_name='courtroom',
                user_id='alice',
                session_id='session-1',
                invocation_id=f'inv-deny-{suffix}',
            ),
            decision=PolicyDecision(
                allowed=False,
                reason='Denied by policy engine default effect.',
                matched_rule='default_deny',
                risk_score=1.0,
            ),
        )
    )
    asyncio.run(
        recommender.record_policy_decision(
            request=AuthorizationRequest(
                agent_name='judge',
                key_id='judge-key',
                tool_name='issue_verdict',
                action='issue_verdict',
                app_name='courtroom',
                user_id='alice',
                session_id='session-1',
                invocation_id=f'inv-allow-{suffix}',
            ),
            decision=PolicyDecision(
                allowed=True,
                reason='Allowed by policy rule.',
                matched_rule='judge-high-risk',
                risk_score=0.95,
                capability_ttl_seconds=60,
            ),
        )
    )
    asyncio.run(
        recommender.record_gateway_decision(
            request=GatewayRequest(
                operation='run',
                resource_type='agent',
                resource_name='judge',
                app_name='courtroom',
                user_id='alice',
                session_id='session-1',
                invocation_id=f'inv-gateway-{suffix}',
            ),
            decision=GatewayDecision(
                allowed=True,
                reason='Allowed by gateway rule.',
                matched_rule='default_allow',
                risk_score=0.1,
            ),
        )
    )

  report = asyncio.run(recommender.generate_report())

  recommendation_types = {
      recommendation.recommendation_type
      for recommendation in report.recommendations
  }
  assert report.observation_count == 6
  assert 'explicit_rule_candidate' in recommendation_types
  assert 'approval_guard_candidate' in recommendation_types
  assert 'tenant_scope_candidate' in recommendation_types

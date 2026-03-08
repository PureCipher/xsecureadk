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

from google.adk.secure import RuleBasedAnomalyDetector


def test_anomaly_detector_flags_repeated_denials_and_high_risk() -> None:
  detector = RuleBasedAnomalyDetector(
      repeated_denials_threshold=2,
      high_risk_score_threshold=0.7,
      block_severity_threshold=0.9,
  )

  first_alerts = detector.record_tool_decision(
      app_name='courtroom',
      user_id='alice',
      session_id='session-1',
      invocation_id='inv-1',
      agent_name='judge',
      tool_name='sealed_evidence',
      allowed=False,
      risk_score=0.8,
      reason='Denied by policy.',
  )
  second_alerts = detector.record_tool_decision(
      app_name='courtroom',
      user_id='alice',
      session_id='session-1',
      invocation_id='inv-1',
      agent_name='judge',
      tool_name='sealed_evidence',
      allowed=False,
      risk_score=1.0,
      reason='Denied by policy.',
  )

  assert {alert.alert_type for alert in first_alerts} == {
      'high_risk_policy_decision'
  }
  assert {alert.alert_type for alert in second_alerts} == {
      'high_risk_policy_decision',
      'repeated_tool_denials',
  }
  assert detector.should_block(second_alerts)


def test_anomaly_detector_flags_possible_collusion() -> None:
  detector = RuleBasedAnomalyDetector(
      duplicate_response_agents_threshold=2,
  )

  alerts = detector.record_model_response(
      app_name='courtroom',
      user_id='alice',
      session_id='session-1',
      invocation_id='inv-1',
      agent_name='judge',
      response_hash='abc123',
  )
  assert alerts == []

  alerts = detector.record_model_response(
      app_name='courtroom',
      user_id='alice',
      session_id='session-1',
      invocation_id='inv-1',
      agent_name='clerk',
      response_hash='abc123',
  )

  assert len(alerts) == 1
  assert alerts[0].alert_type == 'possible_agent_collusion'
  assert alerts[0].payload['matchingAgents'] == ['clerk', 'judge']

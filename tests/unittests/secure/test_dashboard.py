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

from google.adk.secure import AgentIdentity
from google.adk.secure import AnomalyAlert
from google.adk.secure import AuthorizationRequest
from google.adk.secure import CapabilityVault
from google.adk.secure import IdentityRegistry
from google.adk.secure import InMemoryLineageStore
from google.adk.secure import InMemoryPolicyObservationStore
from google.adk.secure import InMemoryProvenanceLedger
from google.adk.secure import InMemorySecureEventSink
from google.adk.secure import LineageTracker
from google.adk.secure import PolicyDecision
from google.adk.secure import PolicyRecommender
from google.adk.secure import RuleBasedAnomalyDetector
from google.adk.secure import SecureRuntimeBuilder
from google.adk.secure import SimplePolicyEngine
from google.adk.secure import TelemetryRedactor
from google.adk.secure.signing import HmacKeyring


def test_secure_dashboard_snapshot_summarizes_runtime_state() -> None:
  builder = SecureRuntimeBuilder(
      identity_registry=IdentityRegistry([
          AgentIdentity(
              agent_name='judge',
              key_id='judge-key',
              roles=('judge',),
          )
      ]),
      capability_vault=CapabilityVault(
          policy_engine=SimplePolicyEngine([]),
          keyring=HmacKeyring({'judge-key': 'secret'}),
      ),
      ledger=InMemoryProvenanceLedger(),
      lineage_tracker=LineageTracker(store=InMemoryLineageStore()),
      anomaly_detector=RuleBasedAnomalyDetector(),
      secure_event_sink=InMemorySecureEventSink(),
      telemetry_redactor=TelemetryRedactor(),
      policy_recommender=PolicyRecommender(
          store=InMemoryPolicyObservationStore(),
          minimum_evidence_count=1,
      ),
  )

  asyncio.run(
      builder.ledger.append(
          event_type='invocation_started',
          app_name='courtroom',
          user_id='alice',
          session_id='session-1',
          invocation_id='inv-1',
          payload={'email': 'alice@example.com'},
      )
  )
  asyncio.run(
      builder.lineage_tracker.record(
          record_type='prompt',
          entity_id='prompt:inv-1',
          app_name='courtroom',
          user_id='alice',
          session_id='session-1',
          invocation_id='inv-1',
          payload={'phone': '+1 555 555 5555'},
      )
  )
  asyncio.run(
      builder.policy_recommender.record_policy_decision(
          request=AuthorizationRequest(
              agent_name='judge',
              key_id='judge-key',
              tool_name='sealed_evidence',
              action='sealed_evidence',
              app_name='courtroom',
              user_id='alice',
              session_id='session-1',
              invocation_id='inv-1',
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
      builder.anomaly_alert_sink.emit_alerts([
          AnomalyAlert(
              alert_type='possible_agent_collusion',
              severity=1.0,
              reason='Matching responses observed.',
              app_name='courtroom',
              user_id='alice',
              session_id='session-1',
              invocation_id='inv-1',
              agent_name='judge',
          )
      ])
  )

  snapshot = asyncio.run(
      builder.build_dashboard_snapshot(
          app_name='courtroom',
          limit=5,
      )
  )

  assert snapshot.app_name == 'courtroom'
  assert snapshot.ledger_summary.total_count == 1
  assert snapshot.lineage_summary.total_count == 1
  assert snapshot.anomaly_summary.counts_by_type == {
      'possible_agent_collusion': 1
  }
  assert snapshot.recommendation_report.recommendation_count >= 1
  assert snapshot.observability_sinks == ['InMemorySecureEventSink']
  assert snapshot.privacy_mode == 'redact'
  assert snapshot.recent_ledger_events[0]['payload']['email'] == '<redacted>'

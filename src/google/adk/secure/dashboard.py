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

from collections import Counter

from google.adk.platform import time as platform_time
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from .alert_sinks import InMemoryAnomalyAlertSink
from .recommendations import PolicyRecommendation
from .recommendations import PolicyRecommendationReport
from .trust import TrustScore
from .trust import TrustScoreReport


class DashboardSectionSummary(BaseModel):
  """Compact summary for one SecureADK dashboard section."""

  model_config = ConfigDict(
      extra='forbid',
  )

  total_count: int = 0
  counts_by_type: dict[str, int] = Field(default_factory=dict)


class SecureDashboardSnapshot(BaseModel):
  """Structured SecureADK dashboard response for CLI and web UIs."""

  model_config = ConfigDict(
      extra='forbid',
  )

  generated_at: float
  app_name: str | None = None
  secure_runtime_enabled: bool = True
  ledger_chain_valid: bool | None = None
  privacy_mode: str | None = None
  observability_sinks: list[str] = Field(default_factory=list)
  deployment_attestation_present: bool = False
  deployment_attestation_verified: bool | None = None
  ledger_summary: DashboardSectionSummary = Field(
      default_factory=DashboardSectionSummary
  )
  lineage_summary: DashboardSectionSummary = Field(
      default_factory=DashboardSectionSummary
  )
  anomaly_summary: DashboardSectionSummary = Field(
      default_factory=DashboardSectionSummary
  )
  trust_summary: DashboardSectionSummary = Field(
      default_factory=DashboardSectionSummary
  )
  recommendation_report: PolicyRecommendationReport = Field(
      default_factory=lambda: PolicyRecommendationReport(
          generated_at=platform_time.get_time(),
          observation_count=0,
          recommendation_count=0,
      )
  )
  trust_report: TrustScoreReport = Field(
      default_factory=lambda: TrustScoreReport(
          generated_at=platform_time.get_time(),
          score_count=0,
          event_count=0,
      )
  )
  recent_ledger_events: list[dict[str, object]] = Field(default_factory=list)
  recent_lineage_records: list[dict[str, object]] = Field(default_factory=list)
  recent_anomaly_alerts: list[dict[str, object]] = Field(default_factory=list)
  top_recommendations: list[PolicyRecommendation] = Field(default_factory=list)
  lowest_trust_subjects: list[TrustScore] = Field(default_factory=list)


async def build_secure_dashboard_snapshot(
    *,
    builder,
    app_name: str | None = None,
    limit: int = 10,
) -> SecureDashboardSnapshot:
  """Builds a SecureADK dashboard snapshot from an initialized builder."""
  ledger_entries = (
      await builder.ledger.list_entries() if builder.ledger is not None else []
  )
  lineage_records = (
      await builder.lineage_tracker.list_records()
      if builder.lineage_tracker is not None
      else []
  )
  anomaly_alerts = (
      builder.anomaly_alert_archive.alerts
      if isinstance(builder.anomaly_alert_archive, InMemoryAnomalyAlertSink)
      else []
  )
  recommendation_report = (
      await builder.policy_recommender.generate_report()
      if builder.policy_recommender is not None
      else PolicyRecommendationReport(
          generated_at=platform_time.get_time(),
          observation_count=0,
          recommendation_count=0,
      )
  )
  trust_report = (
      await builder.trust_scorer.generate_report()
      if builder.trust_scorer is not None
      else TrustScoreReport(
          generated_at=platform_time.get_time(),
          score_count=0,
          event_count=0,
      )
  )
  deployment_attestation_verified = None
  if (
      builder.deployment_attestation is not None
      and builder.deployment_attestor is not None
  ):
    deployment_attestation_verified = (
        builder.deployment_attestor.verify_attestation(
            builder.deployment_attestation
        ).valid
    )
  return SecureDashboardSnapshot(
      generated_at=platform_time.get_time(),
      app_name=app_name,
      secure_runtime_enabled=True,
      ledger_chain_valid=(
          await builder.ledger.verify_chain()
          if builder.ledger is not None
          else None
      ),
      privacy_mode=(
          builder.telemetry_redactor.mode
          if builder.telemetry_redactor is not None
          else None
      ),
      observability_sinks=builder.observability_sink_names,
      deployment_attestation_present=builder.deployment_attestation is not None,
      deployment_attestation_verified=deployment_attestation_verified,
      ledger_summary=_summary_by_type(
          [entry.event_type for entry in ledger_entries]
      ),
      lineage_summary=_summary_by_type(
          [record.record_type for record in lineage_records]
      ),
      anomaly_summary=_summary_by_type(
          [alert.alert_type for alert in anomaly_alerts]
      ),
      trust_summary=_summary_by_type(
          [score.subject_type for score in trust_report.scores]
      ),
      recommendation_report=recommendation_report,
      trust_report=trust_report,
      recent_ledger_events=[
          entry.model_dump(by_alias=True, exclude_none=True, mode='json')
          for entry in ledger_entries[-limit:]
      ],
      recent_lineage_records=[
          record.model_dump(by_alias=True, exclude_none=True, mode='json')
          for record in lineage_records[-limit:]
      ],
      recent_anomaly_alerts=[
          alert.model_dump(by_alias=True, exclude_none=True, mode='json')
          for alert in anomaly_alerts[-limit:]
      ],
      top_recommendations=recommendation_report.recommendations[:limit],
      lowest_trust_subjects=trust_report.scores[:limit],
  )


def _summary_by_type(values: list[str]) -> DashboardSectionSummary:
  counts = Counter(values)
  return DashboardSectionSummary(
      total_count=sum(counts.values()),
      counts_by_type=dict(sorted(counts.items())),
  )

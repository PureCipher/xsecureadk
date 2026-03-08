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

import abc
import asyncio
import json
from pathlib import Path
from typing import Any

from google.adk.platform import time as platform_time
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from .anomaly import AnomalyAlert
from .attestation import DeploymentAttestation
from .gateway import GatewayDecision
from .gateway import GatewayRequest
from .policies import AuthorizationRequest
from .policies import PolicyDecision


class TrustScore(BaseModel):
  """Current trust score for an agent, tool, evaluator, or deployment."""

  model_config = ConfigDict(
      extra='forbid',
  )

  subject_type: str
  subject_id: str
  tenant_id: str | None = None
  score: float = Field(ge=0.0, le=1.0)
  observation_count: int = Field(ge=0)
  last_reason: str | None = None
  last_source: str | None = None
  updated_at: float
  metadata: dict[str, Any] = Field(default_factory=dict)


class TrustEvent(BaseModel):
  """One trust score adjustment event."""

  model_config = ConfigDict(
      extra='forbid',
  )

  timestamp: float
  subject_type: str
  subject_id: str
  tenant_id: str | None = None
  delta: float
  score_after: float = Field(ge=0.0, le=1.0)
  reason: str
  source: str
  metadata: dict[str, Any] = Field(default_factory=dict)


class TrustScoreReport(BaseModel):
  """Report containing current trust scores and recent score changes."""

  model_config = ConfigDict(
      extra='forbid',
  )

  generated_at: float
  score_count: int
  event_count: int
  scores: list[TrustScore] = Field(default_factory=list)
  recent_events: list[TrustEvent] = Field(default_factory=list)


class BaseTrustStore(abc.ABC):
  """Persistence interface for trust scores and score-change events."""

  @abc.abstractmethod
  async def save_score(self, score: TrustScore) -> TrustScore:
    """Persists a score snapshot."""

  @abc.abstractmethod
  async def list_scores(self) -> list[TrustScore]:
    """Returns all known trust scores."""

  @abc.abstractmethod
  async def append_event(self, event: TrustEvent) -> TrustEvent:
    """Persists one trust event."""

  @abc.abstractmethod
  async def list_events(self) -> list[TrustEvent]:
    """Returns all trust events."""


class InMemoryTrustStore(BaseTrustStore):
  """In-memory trust store for tests and dashboards."""

  def __init__(self):
    self._scores_by_subject: dict[tuple[str, str, str | None], TrustScore] = {}
    self._events: list[TrustEvent] = []

  async def save_score(self, score: TrustScore) -> TrustScore:
    self._scores_by_subject[
        (score.subject_type, score.subject_id, score.tenant_id)
    ] = score
    return score

  async def list_scores(self) -> list[TrustScore]:
    return list(self._scores_by_subject.values())

  async def append_event(self, event: TrustEvent) -> TrustEvent:
    self._events.append(event)
    return event

  async def list_events(self) -> list[TrustEvent]:
    return list(self._events)


class FileTrustStore(BaseTrustStore):
  """File-backed trust store that keeps scores and events on disk."""

  def __init__(self, path: str | Path):
    self._root = Path(path)
    self._root.mkdir(parents=True, exist_ok=True)
    self._scores_path = self._root / 'scores.json'
    self._events_path = self._root / 'events.jsonl'
    self._lock = asyncio.Lock()

  async def save_score(self, score: TrustScore) -> TrustScore:
    async with self._lock:
      scores = await self.list_scores()
      scores_by_subject = {
          (item.subject_type, item.subject_id, item.tenant_id): item
          for item in scores
      }
      scores_by_subject[
          (score.subject_type, score.subject_id, score.tenant_id)
      ] = score
      self._scores_path.write_text(
          json.dumps(
              [
                  item.model_dump(
                      by_alias=True,
                      exclude_none=True,
                      mode='json',
                  )
                  for item in scores_by_subject.values()
              ],
              ensure_ascii=True,
              indent=2,
          ),
          encoding='utf-8',
      )
    return score

  async def list_scores(self) -> list[TrustScore]:
    if not self._scores_path.exists():
      return []
    return [
        TrustScore.model_validate(item)
        for item in json.loads(self._scores_path.read_text(encoding='utf-8'))
    ]

  async def append_event(self, event: TrustEvent) -> TrustEvent:
    async with self._lock:
      with self._events_path.open('a', encoding='utf-8') as handle:
        handle.write(
            event.model_dump_json(
                by_alias=True,
                exclude_none=True,
            )
        )
        handle.write('\n')
    return event

  async def list_events(self) -> list[TrustEvent]:
    if not self._events_path.exists():
      return []
    with self._events_path.open('r', encoding='utf-8') as handle:
      return [
          TrustEvent.model_validate_json(line)
          for line in handle
          if line.strip()
      ]


class TrustScorer:
  """Maintains trust scores from runtime decisions, anomalies, and signatures."""

  def __init__(
      self,
      *,
      store: BaseTrustStore,
      base_score: float = 0.75,
      min_score: float = 0.0,
      max_score: float = 1.0,
  ):
    self._store = store
    self._base_score = base_score
    self._min_score = min_score
    self._max_score = max_score

  async def record_policy_decision(
      self,
      *,
      request: AuthorizationRequest,
      decision: PolicyDecision,
  ) -> None:
    delta = 0.01 if decision.allowed else -0.04
    delta -= min(0.06, decision.risk_score * 0.05)
    if decision.requires_approval:
      delta -= 0.02
    reason = decision.reason
    await self._apply_delta(
        subject_type='agent',
        subject_id=request.agent_name,
        tenant_id=request.tenant_id,
        delta=delta,
        reason=reason,
        source='policy',
        metadata={'matchedRule': decision.matched_rule},
    )
    await self._apply_delta(
        subject_type='tool',
        subject_id=request.tool_name,
        tenant_id=request.tenant_id,
        delta=delta,
        reason=reason,
        source='policy',
        metadata={
            'action': request.action,
            'matchedRule': decision.matched_rule,
        },
    )

  async def record_gateway_decision(
      self,
      *,
      request: GatewayRequest,
      decision: GatewayDecision,
  ) -> None:
    delta = 0.01 if decision.allowed else -0.05
    delta -= min(0.05, decision.risk_score * 0.05)
    if decision.requires_approval:
      delta -= 0.02
    subject_id = (
        request.agent_name or request.resource_name or request.resource_type
    )
    await self._apply_delta(
        subject_type='agent',
        subject_id=subject_id,
        tenant_id=request.tenant_id,
        delta=delta,
        reason=decision.reason,
        source='gateway',
        metadata={'matchedRule': decision.matched_rule},
    )

  async def record_anomaly_alert(self, alert: AnomalyAlert) -> None:
    delta = -min(0.3, max(0.02, alert.severity * 0.2))
    if alert.agent_name is not None:
      await self._apply_delta(
          subject_type='agent',
          subject_id=alert.agent_name,
          tenant_id=None,
          delta=delta,
          reason=alert.reason,
          source='anomaly',
          metadata={'alertType': alert.alert_type},
      )
    if alert.tool_name is not None:
      await self._apply_delta(
          subject_type='tool',
          subject_id=alert.tool_name,
          tenant_id=None,
          delta=delta,
          reason=alert.reason,
          source='anomaly',
          metadata={'alertType': alert.alert_type},
      )

  async def record_signature_verification(
      self,
      *,
      subject_type: str,
      subject_id: str,
      valid: bool,
      reason: str,
      tenant_id: str | None = None,
  ) -> None:
    await self._apply_delta(
        subject_type=subject_type,
        subject_id=subject_id,
        tenant_id=tenant_id,
        delta=0.03 if valid else -0.2,
        reason=reason,
        source='signature_verification',
    )

  async def record_deployment_attestation(
      self,
      *,
      attestation: DeploymentAttestation,
      verified: bool,
  ) -> None:
    await self._apply_delta(
        subject_type='deployment',
        subject_id=attestation.app_name,
        tenant_id=attestation.tenant_id,
        delta=0.05 if verified else -0.25,
        reason=(
            'Deployment attestation verified.'
            if verified
            else 'Deployment attestation failed verification.'
        ),
        source='deployment_attestation',
        metadata={'deploymentTarget': attestation.deployment_target},
    )

  async def list_scores(self) -> list[TrustScore]:
    return await self._store.list_scores()

  async def list_events(self) -> list[TrustEvent]:
    return await self._store.list_events()

  async def generate_report(self, *, limit: int = 20) -> TrustScoreReport:
    scores = sorted(
        await self._store.list_scores(),
        key=lambda score: (score.score, score.subject_type, score.subject_id),
    )
    events = await self._store.list_events()
    return TrustScoreReport(
        generated_at=platform_time.get_time(),
        score_count=len(scores),
        event_count=len(events),
        scores=scores[:limit],
        recent_events=events[-limit:],
    )

  async def _apply_delta(
      self,
      *,
      subject_type: str,
      subject_id: str,
      tenant_id: str | None,
      delta: float,
      reason: str,
      source: str,
      metadata: dict[str, Any] | None = None,
  ) -> None:
    score = await self._get_or_create_score(
        subject_type=subject_type,
        subject_id=subject_id,
        tenant_id=tenant_id,
    )
    score_value = min(
        self._max_score,
        max(self._min_score, score.score + delta),
    )
    updated_score = score.model_copy(
        update={
            'score': score_value,
            'observation_count': score.observation_count + 1,
            'last_reason': reason,
            'last_source': source,
            'updated_at': platform_time.get_time(),
            'metadata': {
                **score.metadata,
                **dict(metadata or {}),
            },
        }
    )
    await self._store.save_score(updated_score)
    await self._store.append_event(
        TrustEvent(
            timestamp=platform_time.get_time(),
            subject_type=subject_type,
            subject_id=subject_id,
            tenant_id=tenant_id,
            delta=delta,
            score_after=score_value,
            reason=reason,
            source=source,
            metadata=dict(metadata or {}),
        )
    )

  async def _get_or_create_score(
      self,
      *,
      subject_type: str,
      subject_id: str,
      tenant_id: str | None,
  ) -> TrustScore:
    for score in await self._store.list_scores():
      if (
          score.subject_type == subject_type
          and score.subject_id == subject_id
          and score.tenant_id == tenant_id
      ):
        return score
    return TrustScore(
        subject_type=subject_type,
        subject_id=subject_id,
        tenant_id=tenant_id,
        score=self._base_score,
        observation_count=0,
        updated_at=platform_time.get_time(),
    )

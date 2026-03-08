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
from google.adk.platform import uuid as platform_uuid
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from .gateway import GatewayDecision
from .gateway import GatewayRequest
from .policies import AuthorizationRequest
from .policies import PolicyDecision


class PolicyObservation(BaseModel):
  """Recorded policy or gateway decision used for recommendation analysis."""

  model_config = ConfigDict(
      extra='forbid',
  )

  observation_id: str
  timestamp: float
  source: str
  allowed: bool
  requires_approval: bool = False
  matched_rule: str | None = None
  reason: str
  risk_score: float = 0.0
  app_name: str
  user_id: str | None = None
  session_id: str | None = None
  invocation_id: str | None = None
  agent_name: str | None = None
  roles: tuple[str, ...] = ()
  operation: str
  resource_type: str
  resource_name: str | None = None
  tenant_id: str | None = None
  case_id: str | None = None
  context: dict[str, Any] = Field(default_factory=dict)


class PolicyRecommendation(BaseModel):
  """Actionable recommendation derived from runtime policy observations."""

  model_config = ConfigDict(
      extra='forbid',
  )

  recommendation_id: str
  recommendation_type: str
  priority: int = Field(ge=1, le=5)
  confidence: float = Field(ge=0.0, le=1.0)
  title: str
  message: str
  evidence_count: int = Field(ge=1)
  source: str
  proposed_rule: dict[str, Any] = Field(default_factory=dict)
  supporting_observation_ids: list[str] = Field(default_factory=list)


class PolicyRecommendationReport(BaseModel):
  """Summary report for SecureADK policy recommendations."""

  model_config = ConfigDict(
      extra='forbid',
  )

  generated_at: float
  observation_count: int
  recommendation_count: int
  recommendations: list[PolicyRecommendation] = Field(default_factory=list)


class BasePolicyObservationStore(abc.ABC):
  """Base store for policy observations."""

  @abc.abstractmethod
  async def append(self, observation: PolicyObservation) -> PolicyObservation:
    """Appends one observation."""

  @abc.abstractmethod
  async def list_observations(self) -> list[PolicyObservation]:
    """Returns all observations."""


class InMemoryPolicyObservationStore(BasePolicyObservationStore):
  """In-memory observation store for tests and dashboards."""

  def __init__(self):
    self._observations: list[PolicyObservation] = []

  async def append(self, observation: PolicyObservation) -> PolicyObservation:
    self._observations.append(observation)
    return observation

  async def list_observations(self) -> list[PolicyObservation]:
    return list(self._observations)


class FilePolicyObservationStore(BasePolicyObservationStore):
  """JSONL-backed policy observation store."""

  def __init__(self, path: str | Path):
    self._path = Path(path)
    self._path.parent.mkdir(parents=True, exist_ok=True)
    self._lock = asyncio.Lock()

  async def append(self, observation: PolicyObservation) -> PolicyObservation:
    async with self._lock:
      with self._path.open('a', encoding='utf-8') as handle:
        handle.write(
            observation.model_dump_json(
                by_alias=True,
                exclude_none=True,
            )
        )
        handle.write('\n')
    return observation

  async def list_observations(self) -> list[PolicyObservation]:
    if not self._path.exists():
      return []
    with self._path.open('r', encoding='utf-8') as handle:
      return [
          PolicyObservation.model_validate_json(line)
          for line in handle
          if line.strip()
      ]


class PolicyRecommender:
  """Records runtime observations and generates least-privilege guidance."""

  def __init__(
      self,
      *,
      store: BasePolicyObservationStore,
      minimum_evidence_count: int = 3,
      high_risk_threshold: float = 0.8,
  ):
    self._store = store
    self._minimum_evidence_count = minimum_evidence_count
    self._high_risk_threshold = high_risk_threshold

  async def record_policy_decision(
      self,
      *,
      request: AuthorizationRequest,
      decision: PolicyDecision,
  ) -> PolicyObservation:
    return await self._store.append(
        PolicyObservation(
            observation_id=str(platform_uuid.new_uuid()),
            timestamp=platform_time.get_time(),
            source='policy',
            allowed=decision.allowed,
            requires_approval=decision.requires_approval,
            matched_rule=decision.matched_rule,
            reason=decision.reason,
            risk_score=decision.risk_score,
            app_name=request.app_name,
            user_id=request.user_id,
            session_id=request.session_id,
            invocation_id=request.invocation_id,
            agent_name=request.agent_name,
            roles=request.roles,
            operation=request.action,
            resource_type='tool',
            resource_name=request.tool_name,
            tenant_id=request.tenant_id,
            case_id=request.case_id,
            context={
                'toolArgs': request.tool_args,
                **json.loads(json.dumps(request.context, ensure_ascii=True)),
            },
        )
    )

  async def record_gateway_decision(
      self,
      *,
      request: GatewayRequest,
      decision: GatewayDecision,
  ) -> PolicyObservation:
    return await self._store.append(
        PolicyObservation(
            observation_id=str(platform_uuid.new_uuid()),
            timestamp=platform_time.get_time(),
            source='gateway',
            allowed=decision.allowed,
            requires_approval=decision.requires_approval,
            matched_rule=decision.matched_rule,
            reason=decision.reason,
            risk_score=decision.risk_score,
            app_name=request.app_name,
            user_id=request.user_id,
            session_id=request.session_id,
            invocation_id=request.invocation_id,
            agent_name=request.agent_name,
            roles=request.roles,
            operation=request.operation,
            resource_type=request.resource_type,
            resource_name=request.resource_name,
            tenant_id=request.tenant_id,
            case_id=request.case_id,
            context=json.loads(json.dumps(request.context, ensure_ascii=True)),
        )
    )

  async def list_observations(self) -> list[PolicyObservation]:
    return await self._store.list_observations()

  async def generate_report(
      self,
      *,
      minimum_evidence_count: int | None = None,
  ) -> PolicyRecommendationReport:
    observations = await self._store.list_observations()
    threshold = minimum_evidence_count or self._minimum_evidence_count
    recommendations = []
    recommendations.extend(
        self._recommend_explicit_rules(observations, threshold)
    )
    recommendations.extend(
        self._recommend_approval_guards(observations, threshold)
    )
    recommendations.extend(
        self._recommend_tenant_scope(observations, threshold)
    )
    return PolicyRecommendationReport(
        generated_at=platform_time.get_time(),
        observation_count=len(observations),
        recommendation_count=len(recommendations),
        recommendations=sorted(
            recommendations,
            key=lambda recommendation: (
                -recommendation.priority,
                -recommendation.evidence_count,
                recommendation.title,
            ),
        ),
    )

  def _recommend_explicit_rules(
      self,
      observations: list[PolicyObservation],
      minimum_evidence_count: int,
  ) -> list[PolicyRecommendation]:
    groups = self._group_observations(
        observation
        for observation in observations
        if not observation.allowed
        and (
            observation.matched_rule in (None, 'default_deny')
            or observation.reason.endswith('default effect.')
        )
    )
    recommendations = []
    for group in groups.values():
      if len(group) < minimum_evidence_count:
        continue
      sample = group[0]
      recommendations.append(
          PolicyRecommendation(
              recommendation_id=str(platform_uuid.new_uuid()),
              recommendation_type='explicit_rule_candidate',
              priority=4,
              confidence=min(1.0, 0.4 + len(group) * 0.1),
              title=(
                  f'Codify {sample.source} rule for '
                  f'{sample.agent_name or "unknown"} -> '
                  f'{sample.resource_name or sample.resource_type}'
              ),
              message=(
                  'Repeated default denials indicate a stable access pattern '
                  'that should be reviewed and either encoded explicitly or '
                  'blocked intentionally.'
              ),
              evidence_count=len(group),
              source=sample.source,
              proposed_rule=self._proposed_rule(group),
              supporting_observation_ids=[
                  observation.observation_id for observation in group
              ],
          )
      )
    return recommendations

  def _recommend_approval_guards(
      self,
      observations: list[PolicyObservation],
      minimum_evidence_count: int,
  ) -> list[PolicyRecommendation]:
    groups = self._group_observations(
        observation
        for observation in observations
        if observation.allowed
        and not observation.requires_approval
        and observation.risk_score >= self._high_risk_threshold
    )
    recommendations = []
    for group in groups.values():
      if len(group) < minimum_evidence_count:
        continue
      sample = group[0]
      recommendations.append(
          PolicyRecommendation(
              recommendation_id=str(platform_uuid.new_uuid()),
              recommendation_type='approval_guard_candidate',
              priority=5,
              confidence=min(1.0, 0.5 + len(group) * 0.1),
              title=(
                  'Require approval for'
                  f' {sample.resource_name or sample.resource_type}'
              ),
              message=(
                  'High-risk allowed actions are recurring without explicit '
                  'approval. SecureADK should gate this access behind human '
                  'approval or tighter policy thresholds.'
              ),
              evidence_count=len(group),
              source=sample.source,
              proposed_rule={
                  **self._proposed_rule(group),
                  'requires_approval': True,
              },
              supporting_observation_ids=[
                  observation.observation_id for observation in group
              ],
          )
      )
    return recommendations

  def _recommend_tenant_scope(
      self,
      observations: list[PolicyObservation],
      minimum_evidence_count: int,
  ) -> list[PolicyRecommendation]:
    groups = self._group_observations(
        observation
        for observation in observations
        if observation.allowed and observation.tenant_id is None
    )
    recommendations = []
    for group in groups.values():
      if len(group) < minimum_evidence_count:
        continue
      sample = group[0]
      recommendations.append(
          PolicyRecommendation(
              recommendation_id=str(platform_uuid.new_uuid()),
              recommendation_type='tenant_scope_candidate',
              priority=3,
              confidence=min(1.0, 0.3 + len(group) * 0.1),
              title=(
                  'Add tenant scope to'
                  f' {sample.resource_name or sample.resource_type}'
              ),
              message=(
                  'Allowed actions were observed without tenant context. Add '
                  'tenant-scoped rules or bindings to strengthen isolation.'
              ),
              evidence_count=len(group),
              source=sample.source,
              proposed_rule={
                  **self._proposed_rule(group),
                  'tenant_ids': ['<tenant-id>'],
              },
              supporting_observation_ids=[
                  observation.observation_id for observation in group
              ],
          )
      )
    return recommendations

  def _group_observations(
      self,
      observations,
  ) -> dict[tuple[str | None, ...], list[PolicyObservation]]:
    groups: dict[tuple[str | None, ...], list[PolicyObservation]] = {}
    for observation in observations:
      key = (
          observation.source,
          observation.agent_name,
          observation.operation,
          observation.resource_type,
          observation.resource_name,
          observation.tenant_id,
      )
      groups.setdefault(key, []).append(observation)
    return groups

  @staticmethod
  def _proposed_rule(
      group: list[PolicyObservation],
  ) -> dict[str, Any]:
    sample = group[0]
    rule = {
        'name': (
            (
                f'{sample.source}-{sample.agent_name or "anonymous"}-'
                f'{sample.resource_name or sample.resource_type}-{sample.operation}'
            ).replace('*', 'wildcard')
        ),
        'principals': [sample.agent_name] if sample.agent_name else [],
        'app_names': [sample.app_name],
        'tenant_ids': [sample.tenant_id] if sample.tenant_id else [],
    }
    if sample.source == 'policy':
      rule.update({
          'tools': [sample.resource_name] if sample.resource_name else [],
          'actions': [sample.operation],
      })
    else:
      rule.update({
          'operations': [sample.operation],
          'resource_types': [sample.resource_type],
          'resource_names': (
              [sample.resource_name] if sample.resource_name else []
          ),
      })
    return rule

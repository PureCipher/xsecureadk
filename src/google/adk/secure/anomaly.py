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
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Optional

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field


class AnomalyAlert(BaseModel):
  """Alert raised by runtime anomaly or collusion analysis."""

  model_config = ConfigDict(
      extra='forbid',
  )

  alert_type: str
  severity: float = Field(ge=0.0)
  reason: str
  app_name: Optional[str] = None
  user_id: Optional[str] = None
  session_id: Optional[str] = None
  invocation_id: Optional[str] = None
  agent_name: Optional[str] = None
  tool_name: Optional[str] = None
  payload: dict[str, object] = Field(default_factory=dict)


class BaseAnomalyDetector(abc.ABC):
  """Base interface for runtime anomaly detection."""

  @abc.abstractmethod
  def record_tool_decision(
      self,
      *,
      app_name: str,
      user_id: str,
      session_id: str,
      invocation_id: str,
      agent_name: str,
      tool_name: str,
      allowed: bool,
      risk_score: float,
      reason: str,
  ) -> list[AnomalyAlert]:
    """Records a tool authorization decision."""

  @abc.abstractmethod
  def record_model_response(
      self,
      *,
      app_name: str,
      user_id: str,
      session_id: str,
      invocation_id: str,
      agent_name: str,
      response_hash: str,
  ) -> list[AnomalyAlert]:
    """Records a model response for collusion analysis."""

  @abc.abstractmethod
  def finalize_invocation(self, invocation_id: str) -> list[AnomalyAlert]:
    """Clears any per-invocation state and returns final alerts."""

  @abc.abstractmethod
  def should_block(self, alerts: Iterable[AnomalyAlert]) -> bool:
    """Returns whether a set of alerts should block execution."""


@dataclass
class _InvocationState:
  denied_count: int = 0
  capability_count: int = 0
  response_hashes_by_agent: dict[str, str] = None

  def __post_init__(self):
    if self.response_hashes_by_agent is None:
      self.response_hashes_by_agent = {}


class RuleBasedAnomalyDetector(BaseAnomalyDetector):
  """Simple runtime anomaly detector with lightweight collusion heuristics."""

  def __init__(
      self,
      *,
      repeated_denials_threshold: int = 3,
      capability_burst_threshold: int = 10,
      duplicate_response_agents_threshold: int = 2,
      high_risk_score_threshold: float = 0.8,
      block_severity_threshold: Optional[float] = None,
  ):
    self._repeated_denials_threshold = repeated_denials_threshold
    self._capability_burst_threshold = capability_burst_threshold
    self._duplicate_response_agents_threshold = (
        duplicate_response_agents_threshold
    )
    self._high_risk_score_threshold = high_risk_score_threshold
    self._block_severity_threshold = block_severity_threshold
    self._state_by_invocation: dict[str, _InvocationState] = {}

  def record_tool_decision(
      self,
      *,
      app_name: str,
      user_id: str,
      session_id: str,
      invocation_id: str,
      agent_name: str,
      tool_name: str,
      allowed: bool,
      risk_score: float,
      reason: str,
  ) -> list[AnomalyAlert]:
    state = self._state_by_invocation.setdefault(
        invocation_id, _InvocationState()
    )
    alerts = []

    if risk_score >= self._high_risk_score_threshold:
      alerts.append(
          AnomalyAlert(
              alert_type='high_risk_policy_decision',
              severity=risk_score,
              reason=reason,
              app_name=app_name,
              user_id=user_id,
              session_id=session_id,
              invocation_id=invocation_id,
              agent_name=agent_name,
              tool_name=tool_name,
              payload={
                  'allowed': allowed,
                  'riskScore': risk_score,
              },
          )
      )

    if allowed:
      state.capability_count += 1
      if state.capability_count >= self._capability_burst_threshold:
        alerts.append(
            AnomalyAlert(
                alert_type='capability_burst',
                severity=1.0,
                reason='Capability issuance threshold exceeded.',
                app_name=app_name,
                user_id=user_id,
                session_id=session_id,
                invocation_id=invocation_id,
                agent_name=agent_name,
                tool_name=tool_name,
                payload={
                    'capabilityCount': state.capability_count,
                },
            )
        )
    else:
      state.denied_count += 1
      if state.denied_count >= self._repeated_denials_threshold:
        alerts.append(
            AnomalyAlert(
                alert_type='repeated_tool_denials',
                severity=1.0,
                reason='Repeated tool denials observed in one invocation.',
                app_name=app_name,
                user_id=user_id,
                session_id=session_id,
                invocation_id=invocation_id,
                agent_name=agent_name,
                tool_name=tool_name,
                payload={
                    'deniedCount': state.denied_count,
                },
            )
        )

    return alerts

  def record_model_response(
      self,
      *,
      app_name: str,
      user_id: str,
      session_id: str,
      invocation_id: str,
      agent_name: str,
      response_hash: str,
  ) -> list[AnomalyAlert]:
    state = self._state_by_invocation.setdefault(
        invocation_id, _InvocationState()
    )
    state.response_hashes_by_agent[agent_name] = response_hash
    matching_agents = sorted(
        current_agent
        for current_agent, current_hash in (
            state.response_hashes_by_agent.items()
        )
        if current_hash == response_hash
    )
    if len(matching_agents) < self._duplicate_response_agents_threshold:
      return []
    return [
        AnomalyAlert(
            alert_type='possible_agent_collusion',
            severity=1.0,
            reason='Multiple agents produced the same response hash.',
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
            invocation_id=invocation_id,
            agent_name=agent_name,
            payload={
                'matchingAgents': matching_agents,
                'responseHash': response_hash,
            },
        )
    ]

  def finalize_invocation(self, invocation_id: str) -> list[AnomalyAlert]:
    self._state_by_invocation.pop(invocation_id, None)
    return []

  def should_block(self, alerts: Iterable[AnomalyAlert]) -> bool:
    if self._block_severity_threshold is None:
      return False
    return any(
        alert.severity >= self._block_severity_threshold for alert in alerts
    )

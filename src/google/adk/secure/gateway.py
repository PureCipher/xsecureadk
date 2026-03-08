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
import fnmatch
from typing import Any
from typing import Literal
from typing import Optional

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
  if not patterns:
    return True
  return any(fnmatch.fnmatch(value, pattern) for pattern in patterns)


def _matches_optional(value: Optional[str], patterns: tuple[str, ...]) -> bool:
  if not patterns:
    return True
  if value is None:
    return False
  return _matches_any(value, patterns)


def _matches_subset(
    required_values: dict[str, Any],
    actual_values: dict[str, Any],
) -> bool:
  for key, required_value in required_values.items():
    if key not in actual_values:
      return False
    actual_value = actual_values[key]
    if isinstance(required_value, (list, tuple, set, frozenset)):
      if actual_value not in required_value:
        return False
    elif actual_value != required_value:
      return False
  return True


class GatewayRequest(BaseModel):
  """Access gateway request for an invocation or resource operation."""

  model_config = ConfigDict(
      extra='forbid',
  )

  operation: str
  resource_type: str
  resource_name: Optional[str] = None
  app_name: str
  user_id: Optional[str] = None
  session_id: Optional[str] = None
  invocation_id: Optional[str] = None
  agent_name: Optional[str] = None
  roles: tuple[str, ...] = ()
  tenant_id: Optional[str] = None
  case_id: Optional[str] = None
  context: dict[str, Any] = Field(default_factory=dict)


class GatewayDecision(BaseModel):
  """Decision emitted by a SecureADK access gateway."""

  model_config = ConfigDict(
      extra='forbid',
  )

  allowed: bool
  reason: str
  matched_rule: Optional[str] = None
  risk_score: float = 0.0
  requires_approval: bool = False
  approval_hint: Optional[str] = None
  approval_payload: dict[str, Any] = Field(default_factory=dict)


class GatewayRuleEvaluation(BaseModel):
  """Explains whether and why a gateway rule matched."""

  model_config = ConfigDict(
      extra='forbid',
  )

  rule_name: str
  effect: Literal['allow', 'deny']
  matched: bool
  risk_score: float
  requires_approval: bool = False
  conditions: list['RuleConditionResult'] = Field(default_factory=list)


class GatewayExplanation(BaseModel):
  """Dry-run explanation for a gateway authorization request."""

  model_config = ConfigDict(
      extra='forbid',
  )

  request: GatewayRequest
  decision: GatewayDecision
  evaluations: list[GatewayRuleEvaluation] = Field(default_factory=list)


class GatewayRule(BaseModel):
  """A rule describing a gateway allow or deny policy."""

  model_config = ConfigDict(
      extra='forbid',
  )

  name: str
  effect: Literal['allow', 'deny'] = 'allow'
  operations: tuple[str, ...] = ()
  resource_types: tuple[str, ...] = ()
  resource_names: tuple[str, ...] = ()
  app_names: tuple[str, ...] = ()
  users: tuple[str, ...] = ()
  principals: tuple[str, ...] = ()
  roles: tuple[str, ...] = ()
  tenant_ids: tuple[str, ...] = ()
  case_ids: tuple[str, ...] = ()
  required_context: dict[str, Any] = Field(default_factory=dict)
  risk_score: float = Field(default=0.0, ge=0.0)
  requires_approval: bool = False
  approval_hint: Optional[str] = None
  approval_payload: dict[str, Any] = Field(default_factory=dict)

  def matches(self, request: GatewayRequest) -> bool:
    """Returns whether this rule applies to the request."""
    if not _matches_any(request.operation, self.operations):
      return False
    if not _matches_any(request.resource_type, self.resource_types):
      return False
    if not _matches_optional(request.resource_name, self.resource_names):
      return False
    if not _matches_any(request.app_name, self.app_names):
      return False
    if not _matches_optional(request.user_id, self.users):
      return False
    if not _matches_optional(request.agent_name, self.principals):
      return False
    if self.roles and not set(self.roles).intersection(request.roles):
      return False
    if not _matches_optional(request.tenant_id, self.tenant_ids):
      return False
    if not _matches_optional(request.case_id, self.case_ids):
      return False
    if not _matches_subset(self.required_context, request.context):
      return False
    return True


class BaseAccessGateway(abc.ABC):
  """Base interface for a dedicated SecureADK access gateway."""

  @abc.abstractmethod
  def authorize(self, request: GatewayRequest) -> GatewayDecision:
    """Returns whether the request may cross the gateway boundary."""

  @abc.abstractmethod
  def explain(self, request: GatewayRequest) -> GatewayExplanation:
    """Returns a dry-run explanation for a gateway request."""


class AllowAllAccessGateway(BaseAccessGateway):
  """Gateway that allows all requests."""

  def authorize(self, request: GatewayRequest) -> GatewayDecision:
    del request
    return GatewayDecision(
        allowed=True,
        reason='Allowed by AllowAllAccessGateway.',
        matched_rule='allow_all',
    )

  def explain(self, request: GatewayRequest) -> GatewayExplanation:
    from .policies import RuleConditionResult

    return GatewayExplanation(
        request=request,
        decision=self.authorize(request),
        evaluations=[
            GatewayRuleEvaluation(
                rule_name='allow_all',
                effect='allow',
                matched=True,
                risk_score=0.0,
                conditions=[
                    RuleConditionResult(
                        field_name='*',
                        matched=True,
                        message='AllowAllAccessGateway matches every request.',
                    )
                ],
            )
        ],
    )


class RuleBasedAccessGateway(BaseAccessGateway):
  """Rule-based gateway with deny precedence."""

  def __init__(
      self,
      rules: list[GatewayRule],
      *,
      default_effect: Literal['allow', 'deny'] = 'deny',
      approval_risk_score_threshold: float | None = None,
      default_approval_hint: str | None = None,
  ):
    self._rules = list(rules)
    self._default_effect = default_effect
    self._approval_risk_score_threshold = approval_risk_score_threshold
    self._default_approval_hint = default_approval_hint

  def authorize(self, request: GatewayRequest) -> GatewayDecision:
    matching_rules = [rule for rule in self._rules if rule.matches(request)]
    deny_rule = next(
        (rule for rule in matching_rules if rule.effect == 'deny'),
        None,
    )
    if deny_rule is not None:
      return GatewayDecision(
          allowed=False,
          reason=f'Denied by gateway rule {deny_rule.name!r}.',
          matched_rule=deny_rule.name,
          risk_score=max(deny_rule.risk_score, 1.0),
      )

    allow_rule = next(
        (rule for rule in matching_rules if rule.effect == 'allow'),
        None,
    )
    if allow_rule is not None:
      requires_approval = self._requires_approval(allow_rule)
      return GatewayDecision(
          allowed=True,
          reason=f'Allowed by gateway rule {allow_rule.name!r}.',
          matched_rule=allow_rule.name,
          risk_score=allow_rule.risk_score,
          requires_approval=requires_approval,
          approval_hint=(
              allow_rule.approval_hint or self._default_approval_hint
              if requires_approval
              else None
          ),
          approval_payload=(
              dict(allow_rule.approval_payload) if requires_approval else {}
          ),
      )

    if self._default_effect == 'allow':
      return GatewayDecision(
          allowed=True,
          reason='Allowed by gateway default effect.',
          matched_rule='default_allow',
      )

    return GatewayDecision(
        allowed=False,
        reason='Denied by gateway default effect.',
        matched_rule='default_deny',
        risk_score=1.0,
    )

  def explain(self, request: GatewayRequest) -> GatewayExplanation:
    return GatewayExplanation(
        request=request,
        decision=self.authorize(request),
        evaluations=[
            self._evaluate_rule(rule, request) for rule in self._rules
        ],
    )

  def _requires_approval(self, rule: GatewayRule) -> bool:
    if rule.requires_approval:
      return True
    if self._approval_risk_score_threshold is None:
      return False
    return rule.risk_score >= self._approval_risk_score_threshold

  def _evaluate_rule(
      self, rule: GatewayRule, request: GatewayRequest
  ) -> GatewayRuleEvaluation:
    from .policies import RuleConditionResult

    conditions = [
        RuleConditionResult(
            field_name='operations',
            matched=_matches_any(request.operation, rule.operations),
            expected=list(rule.operations),
            actual=request.operation,
            message=(
                'Operation matched.'
                if _matches_any(request.operation, rule.operations)
                else 'Operation did not match.'
            ),
        ),
        RuleConditionResult(
            field_name='resource_types',
            matched=_matches_any(request.resource_type, rule.resource_types),
            expected=list(rule.resource_types),
            actual=request.resource_type,
            message=(
                'Resource type matched.'
                if _matches_any(request.resource_type, rule.resource_types)
                else 'Resource type did not match.'
            ),
        ),
        RuleConditionResult(
            field_name='resource_names',
            matched=_matches_optional(
                request.resource_name, rule.resource_names
            ),
            expected=list(rule.resource_names),
            actual=request.resource_name,
            message=(
                'Resource name matched.'
                if _matches_optional(request.resource_name, rule.resource_names)
                else 'Resource name did not match.'
            ),
        ),
        RuleConditionResult(
            field_name='app_names',
            matched=_matches_any(request.app_name, rule.app_names),
            expected=list(rule.app_names),
            actual=request.app_name,
            message=(
                'App matched.'
                if _matches_any(request.app_name, rule.app_names)
                else 'App did not match.'
            ),
        ),
        RuleConditionResult(
            field_name='users',
            matched=_matches_optional(request.user_id, rule.users),
            expected=list(rule.users),
            actual=request.user_id,
            message=(
                'User matched.'
                if _matches_optional(request.user_id, rule.users)
                else 'User did not match.'
            ),
        ),
        RuleConditionResult(
            field_name='principals',
            matched=_matches_optional(request.agent_name, rule.principals),
            expected=list(rule.principals),
            actual=request.agent_name,
            message=(
                'Principal matched.'
                if _matches_optional(request.agent_name, rule.principals)
                else 'Principal did not match.'
            ),
        ),
        RuleConditionResult(
            field_name='roles',
            matched=(
                not rule.roles
                or bool(set(rule.roles).intersection(request.roles))
            ),
            expected=list(rule.roles),
            actual=list(request.roles),
            message=(
                'Role requirement matched.'
                if (
                    not rule.roles
                    or bool(set(rule.roles).intersection(request.roles))
                )
                else 'Role requirement did not match.'
            ),
        ),
        RuleConditionResult(
            field_name='tenant_ids',
            matched=_matches_optional(request.tenant_id, rule.tenant_ids),
            expected=list(rule.tenant_ids),
            actual=request.tenant_id,
            message=(
                'Tenant matched.'
                if _matches_optional(request.tenant_id, rule.tenant_ids)
                else 'Tenant did not match.'
            ),
        ),
        RuleConditionResult(
            field_name='case_ids',
            matched=_matches_optional(request.case_id, rule.case_ids),
            expected=list(rule.case_ids),
            actual=request.case_id,
            message=(
                'Case matched.'
                if _matches_optional(request.case_id, rule.case_ids)
                else 'Case did not match.'
            ),
        ),
        RuleConditionResult(
            field_name='required_context',
            matched=_matches_subset(rule.required_context, request.context),
            expected=rule.required_context,
            actual=request.context,
            message=(
                'Required context matched.'
                if _matches_subset(rule.required_context, request.context)
                else 'Required context did not match.'
            ),
        ),
    ]
    return GatewayRuleEvaluation(
        rule_name=rule.name,
        effect=rule.effect,
        matched=all(condition.matched for condition in conditions),
        risk_score=rule.risk_score,
        requires_approval=self._requires_approval(rule),
        conditions=conditions,
    )

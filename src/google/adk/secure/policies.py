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


class AuthorizationRequest(BaseModel):
  """Runtime authorization request for a single tool action."""

  model_config = ConfigDict(
      extra='forbid',
  )

  agent_name: str
  key_id: str
  roles: tuple[str, ...] = ()
  tool_name: str
  action: str
  app_name: str
  user_id: str
  session_id: str
  invocation_id: str
  function_call_id: Optional[str] = None
  tenant_id: Optional[str] = None
  case_id: Optional[str] = None
  context: dict[str, Any] = Field(default_factory=dict)
  tool_args: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
  """Result of evaluating a runtime authorization request."""

  model_config = ConfigDict(
      extra='forbid',
  )

  allowed: bool
  reason: str
  matched_rule: Optional[str] = None
  risk_score: float = 0.0
  capability_ttl_seconds: Optional[int] = None
  requires_approval: bool = False
  approval_hint: Optional[str] = None
  approval_payload: dict[str, Any] = Field(default_factory=dict)


class RuleConditionResult(BaseModel):
  """Condition-level explanation for a policy or gateway rule."""

  model_config = ConfigDict(
      extra='forbid',
  )

  field_name: str
  matched: bool
  expected: Any = None
  actual: Any = None
  message: str


class PolicyRuleEvaluation(BaseModel):
  """Explains whether and why a policy rule matched."""

  model_config = ConfigDict(
      extra='forbid',
  )

  rule_name: str
  effect: Literal['allow', 'deny']
  matched: bool
  risk_score: float
  requires_approval: bool = False
  conditions: list[RuleConditionResult] = Field(default_factory=list)


class PolicyExplanation(BaseModel):
  """Dry-run explanation for a policy authorization request."""

  model_config = ConfigDict(
      extra='forbid',
  )

  request: AuthorizationRequest
  decision: PolicyDecision
  evaluations: list[PolicyRuleEvaluation] = Field(default_factory=list)


class PolicyRule(BaseModel):
  """A simple RBAC/ABAC policy rule."""

  model_config = ConfigDict(
      extra='forbid',
  )

  name: str
  effect: Literal['allow', 'deny'] = 'allow'
  principals: tuple[str, ...] = ()
  roles: tuple[str, ...] = ()
  tools: tuple[str, ...] = ()
  actions: tuple[str, ...] = ()
  app_names: tuple[str, ...] = ()
  tenant_ids: tuple[str, ...] = ()
  required_context: dict[str, Any] = Field(default_factory=dict)
  required_tool_args: dict[str, Any] = Field(default_factory=dict)
  max_ttl_seconds: Optional[int] = Field(default=None, ge=1)
  risk_score: float = Field(default=0.0, ge=0.0)
  requires_approval: bool = False
  approval_hint: Optional[str] = None
  approval_payload: dict[str, Any] = Field(default_factory=dict)

  def matches(self, request: AuthorizationRequest) -> bool:
    """Returns whether the rule applies to a request."""
    if not _matches_any(request.agent_name, self.principals):
      return False
    if self.roles and not set(self.roles).intersection(request.roles):
      return False
    if not _matches_any(request.tool_name, self.tools):
      return False
    if not _matches_any(request.action, self.actions):
      return False
    if not _matches_any(request.app_name, self.app_names):
      return False
    if not _matches_optional(request.tenant_id, self.tenant_ids):
      return False
    if not _matches_subset(self.required_context, request.context):
      return False
    if not _matches_subset(self.required_tool_args, request.tool_args):
      return False
    return True


class BasePolicyEngine(abc.ABC):
  """Base interface for runtime policy evaluation."""

  @abc.abstractmethod
  def authorize(self, request: AuthorizationRequest) -> PolicyDecision:
    """Returns the authorization decision for a request."""

  @abc.abstractmethod
  def explain(self, request: AuthorizationRequest) -> PolicyExplanation:
    """Returns a dry-run explanation for a request."""


class AllowAllPolicyEngine(BasePolicyEngine):
  """Policy engine that allows all tool actions."""

  def __init__(self, *, capability_ttl_seconds: int = 300):
    self._capability_ttl_seconds = capability_ttl_seconds

  def authorize(self, request: AuthorizationRequest) -> PolicyDecision:
    del request
    return PolicyDecision(
        allowed=True,
        reason='Allowed by AllowAllPolicyEngine.',
        matched_rule='allow_all',
        capability_ttl_seconds=self._capability_ttl_seconds,
    )

  def explain(self, request: AuthorizationRequest) -> PolicyExplanation:
    return PolicyExplanation(
        request=request,
        decision=self.authorize(request),
        evaluations=[
            PolicyRuleEvaluation(
                rule_name='allow_all',
                effect='allow',
                matched=True,
                risk_score=0.0,
                conditions=[
                    RuleConditionResult(
                        field_name='*',
                        matched=True,
                        message='AllowAllPolicyEngine matches every request.',
                    )
                ],
            )
        ],
    )


class SimplePolicyEngine(BasePolicyEngine):
  """Rule-based zero-trust policy engine with deny-by-default semantics."""

  def __init__(
      self,
      rules: list[PolicyRule],
      *,
      default_effect: Literal['allow', 'deny'] = 'deny',
      default_capability_ttl_seconds: int = 300,
      approval_risk_score_threshold: float | None = None,
      default_approval_hint: str | None = None,
  ):
    self._rules = list(rules)
    self._default_effect = default_effect
    self._default_capability_ttl_seconds = default_capability_ttl_seconds
    self._approval_risk_score_threshold = approval_risk_score_threshold
    self._default_approval_hint = default_approval_hint

  def authorize(self, request: AuthorizationRequest) -> PolicyDecision:
    matching_rules = [rule for rule in self._rules if rule.matches(request)]
    deny_rule = next(
        (rule for rule in matching_rules if rule.effect == 'deny'),
        None,
    )
    if deny_rule is not None:
      return PolicyDecision(
          allowed=False,
          reason=f'Denied by policy rule {deny_rule.name!r}.',
          matched_rule=deny_rule.name,
          risk_score=max(deny_rule.risk_score, 1.0),
      )

    allow_rule = next(
        (rule for rule in matching_rules if rule.effect == 'allow'),
        None,
    )
    if allow_rule is not None:
      requires_approval = self._requires_approval(allow_rule)
      return PolicyDecision(
          allowed=True,
          reason=f'Allowed by policy rule {allow_rule.name!r}.',
          matched_rule=allow_rule.name,
          risk_score=allow_rule.risk_score,
          capability_ttl_seconds=(
              allow_rule.max_ttl_seconds or self._default_capability_ttl_seconds
          ),
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
      return PolicyDecision(
          allowed=True,
          reason='Allowed by policy engine default effect.',
          matched_rule='default_allow',
          capability_ttl_seconds=self._default_capability_ttl_seconds,
      )

    return PolicyDecision(
        allowed=False,
        reason='Denied by policy engine default effect.',
        matched_rule='default_deny',
        risk_score=1.0,
    )

  def explain(self, request: AuthorizationRequest) -> PolicyExplanation:
    return PolicyExplanation(
        request=request,
        decision=self.authorize(request),
        evaluations=[
            self._evaluate_rule(rule, request) for rule in self._rules
        ],
    )

  def _requires_approval(self, rule: PolicyRule) -> bool:
    if rule.requires_approval:
      return True
    if self._approval_risk_score_threshold is None:
      return False
    return rule.risk_score >= self._approval_risk_score_threshold

  def _evaluate_rule(
      self, rule: PolicyRule, request: AuthorizationRequest
  ) -> PolicyRuleEvaluation:
    conditions = [
        self._condition_result(
            field_name='principals',
            matched=_matches_any(request.agent_name, rule.principals),
            expected=list(rule.principals),
            actual=request.agent_name,
            positive_message='Agent principal matched.',
            negative_message='Agent principal did not match.',
        ),
        self._condition_result(
            field_name='roles',
            matched=(
                not rule.roles
                or bool(set(rule.roles).intersection(request.roles))
            ),
            expected=list(rule.roles),
            actual=list(request.roles),
            positive_message='Role requirement matched.',
            negative_message='Role requirement did not match.',
        ),
        self._condition_result(
            field_name='tools',
            matched=_matches_any(request.tool_name, rule.tools),
            expected=list(rule.tools),
            actual=request.tool_name,
            positive_message='Tool matched.',
            negative_message='Tool did not match.',
        ),
        self._condition_result(
            field_name='actions',
            matched=_matches_any(request.action, rule.actions),
            expected=list(rule.actions),
            actual=request.action,
            positive_message='Action matched.',
            negative_message='Action did not match.',
        ),
        self._condition_result(
            field_name='app_names',
            matched=_matches_any(request.app_name, rule.app_names),
            expected=list(rule.app_names),
            actual=request.app_name,
            positive_message='App matched.',
            negative_message='App did not match.',
        ),
        self._condition_result(
            field_name='tenant_ids',
            matched=_matches_optional(request.tenant_id, rule.tenant_ids),
            expected=list(rule.tenant_ids),
            actual=request.tenant_id,
            positive_message='Tenant matched.',
            negative_message='Tenant did not match.',
        ),
        self._condition_result(
            field_name='required_context',
            matched=_matches_subset(rule.required_context, request.context),
            expected=rule.required_context,
            actual=request.context,
            positive_message='Required context matched.',
            negative_message='Required context did not match.',
        ),
        self._condition_result(
            field_name='required_tool_args',
            matched=_matches_subset(rule.required_tool_args, request.tool_args),
            expected=rule.required_tool_args,
            actual=request.tool_args,
            positive_message='Required tool args matched.',
            negative_message='Required tool args did not match.',
        ),
    ]
    return PolicyRuleEvaluation(
        rule_name=rule.name,
        effect=rule.effect,
        matched=all(condition.matched for condition in conditions),
        risk_score=rule.risk_score,
        requires_approval=self._requires_approval(rule),
        conditions=conditions,
    )

  @staticmethod
  def _condition_result(
      *,
      field_name: str,
      matched: bool,
      expected: Any,
      actual: Any,
      positive_message: str,
      negative_message: str,
  ) -> RuleConditionResult:
    return RuleConditionResult(
        field_name=field_name,
        matched=matched,
        expected=expected,
        actual=actual,
        message=positive_message if matched else negative_message,
    )

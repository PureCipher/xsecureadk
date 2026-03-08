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


class SimplePolicyEngine(BasePolicyEngine):
  """Rule-based zero-trust policy engine with deny-by-default semantics."""

  def __init__(
      self,
      rules: list[PolicyRule],
      *,
      default_effect: Literal['allow', 'deny'] = 'deny',
      default_capability_ttl_seconds: int = 300,
  ):
    self._rules = list(rules)
    self._default_effect = default_effect
    self._default_capability_ttl_seconds = default_capability_ttl_seconds

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
      return PolicyDecision(
          allowed=True,
          reason=f'Allowed by policy rule {allow_rule.name!r}.',
          matched_rule=allow_rule.name,
          risk_score=allow_rule.risk_score,
          capability_ttl_seconds=(
              allow_rule.max_ttl_seconds
              or self._default_capability_ttl_seconds
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

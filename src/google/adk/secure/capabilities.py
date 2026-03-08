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

from typing import Optional

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from ..agents.context import Context
from ..platform import time as platform_time
from ..platform import uuid as platform_uuid
from ..sessions.state import State
from .policies import AuthorizationRequest
from .policies import BasePolicyEngine
from .policies import PolicyDecision
from .signing import HmacKeyring
from .signing import payload_hash
from .tenant_crypto import TenantCryptoManager

_CAPABILITY_STATE_PREFIX = f'{State.TEMP_PREFIX}secureadk:capability:'


class CapabilityToken(BaseModel):
  """Short-lived authorization token for a single tool action."""

  model_config = ConfigDict(
      extra='forbid',
  )

  token_id: str
  nonce: str
  key_id: str
  agent_name: str
  tool_name: str
  action: str
  app_name: str
  session_id: str
  invocation_id: str
  function_call_id: Optional[str] = None
  tenant_id: Optional[str] = None
  case_id: Optional[str] = None
  context: dict[str, object] = Field(default_factory=dict)
  issued_at: float
  expires_at: float
  signature: str


class CapabilityValidationResult(BaseModel):
  """Result of validating a capability token."""

  model_config = ConfigDict(
      extra='forbid',
  )

  valid: bool
  reason: str


def capability_state_key(function_call_id: str) -> str:
  """Returns the temp-state key used to expose a capability token."""
  return f'{_CAPABILITY_STATE_PREFIX}{function_call_id}'


def get_current_capability(tool_context: Context) -> Optional[CapabilityToken]:
  """Retrieves the current SecureADK capability from tool context state."""
  if not tool_context.function_call_id:
    return None
  token_data = tool_context.state.get(
      capability_state_key(tool_context.function_call_id)
  )
  if token_data is None:
    return None
  return CapabilityToken.model_validate(token_data)


class CapabilityVault:
  """Issues and validates short-lived capability tokens."""

  def __init__(
      self,
      *,
      policy_engine: BasePolicyEngine,
      keyring: HmacKeyring,
      default_ttl_seconds: int = 300,
      tenant_crypto_manager: TenantCryptoManager | None = None,
  ):
    self.policy_engine = policy_engine
    self.keyring = keyring
    self.default_ttl_seconds = default_ttl_seconds
    self.tenant_crypto_manager = tenant_crypto_manager
    self._consumed_token_ids: set[str] = set()

  def authorize(self, request: AuthorizationRequest) -> PolicyDecision:
    return self.policy_engine.authorize(request)

  def issue(
      self,
      request: AuthorizationRequest,
      *,
      decision: Optional[PolicyDecision] = None,
  ) -> CapabilityToken:
    """Issues a capability token after policy approval."""
    decision = decision or self.authorize(request)
    if not decision.allowed:
      raise PermissionError(decision.reason)

    issued_at = platform_time.get_time()
    ttl_seconds = decision.capability_ttl_seconds or self.default_ttl_seconds
    token = CapabilityToken(
        token_id=str(platform_uuid.new_uuid()),
        nonce=str(platform_uuid.new_uuid()),
        key_id=request.key_id,
        agent_name=request.agent_name,
        tool_name=request.tool_name,
        action=request.action,
        app_name=request.app_name,
        session_id=request.session_id,
        invocation_id=request.invocation_id,
        function_call_id=request.function_call_id,
        tenant_id=request.tenant_id,
        case_id=request.case_id,
        context=dict(request.context),
        issued_at=issued_at,
        expires_at=issued_at + ttl_seconds,
        signature='',
    )
    if self.tenant_crypto_manager is None:
      token.signature = self.keyring.sign_value(
          self._token_payload(token),
          key_id=token.key_id,
      ).signature
    else:
      token.signature = self.tenant_crypto_manager.sign_value(
          keyring=self.keyring,
          value=self._token_payload(token),
          key_id=token.key_id,
          tenant_id=token.tenant_id,
      ).signature
    return token

  def validate(
      self,
      token: CapabilityToken,
      request: AuthorizationRequest,
      *,
      allow_reuse: bool = False,
  ) -> CapabilityValidationResult:
    """Validates token integrity, scope, and replay constraints."""
    valid_signature = (
        self.keyring.verify_value(
            self._token_payload(token),
            key_id=token.key_id,
            signature=token.signature,
            signed_at=token.issued_at,
        )
        if self.tenant_crypto_manager is None
        else self.tenant_crypto_manager.verify_value(
            keyring=self.keyring,
            value=self._token_payload(token),
            key_id=token.key_id,
            signature=token.signature,
            signed_at=token.issued_at,
            tenant_id=token.tenant_id,
        )
    )
    if not valid_signature:
      return CapabilityValidationResult(
          valid=False,
          reason='Capability signature verification failed.',
      )

    now = platform_time.get_time()
    if token.expires_at < now:
      return CapabilityValidationResult(
          valid=False,
          reason='Capability token has expired.',
      )

    if not allow_reuse and token.token_id in self._consumed_token_ids:
      return CapabilityValidationResult(
          valid=False,
          reason='Capability token replay detected.',
      )

    if token.agent_name != request.agent_name:
      return CapabilityValidationResult(
          valid=False,
          reason='Capability subject mismatch.',
      )
    if token.tool_name != request.tool_name or token.action != request.action:
      return CapabilityValidationResult(
          valid=False,
          reason='Capability scope mismatch.',
      )
    if token.app_name != request.app_name:
      return CapabilityValidationResult(
          valid=False,
          reason='Capability app mismatch.',
      )
    if token.session_id != request.session_id:
      return CapabilityValidationResult(
          valid=False,
          reason='Capability session mismatch.',
      )
    if token.invocation_id != request.invocation_id:
      return CapabilityValidationResult(
          valid=False,
          reason='Capability invocation mismatch.',
      )
    if token.function_call_id != request.function_call_id:
      return CapabilityValidationResult(
          valid=False,
          reason='Capability function call mismatch.',
      )
    if token.tenant_id != request.tenant_id:
      return CapabilityValidationResult(
          valid=False,
          reason='Capability tenant mismatch.',
      )
    return CapabilityValidationResult(
        valid=True,
        reason='Capability token is valid.',
    )

  def consume(
      self,
      token: CapabilityToken,
      request: AuthorizationRequest,
  ) -> CapabilityValidationResult:
    """Validates and marks a token as used."""
    result = self.validate(token, request, allow_reuse=False)
    if result.valid:
      self._consumed_token_ids.add(token.token_id)
    return result

  @staticmethod
  def token_hash(token: CapabilityToken) -> str:
    return payload_hash(
        token.model_dump(by_alias=True, exclude_none=True, mode='json')
    )

  @staticmethod
  def _token_payload(token: CapabilityToken) -> dict[str, object]:
    return token.model_dump(
        by_alias=True,
        exclude_none=True,
        mode='json',
        exclude={'signature'},
    )

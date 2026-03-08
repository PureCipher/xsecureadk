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

import copy
from typing import Any
from typing import Optional

from google.genai import types

from ..agents.base_agent import BaseAgent
from ..agents.callback_context import CallbackContext
from ..models.llm_request import LlmRequest
from ..models.llm_response import LlmResponse
from ..plugins.base_plugin import BasePlugin
from ..tools.base_tool import BaseTool
from ..tools.tool_context import ToolContext
from .capabilities import capability_state_key
from .capabilities import CapabilityToken
from .capabilities import CapabilityVault
from .identities import AgentIdentity
from .identities import IdentityRegistry
from .policies import AuthorizationRequest
from .provenance import BaseProvenanceLedger
from .signing import HmacKeyring
from .signing import payload_hash

SECURE_METADATA_KEY = 'secureadk'


class SecureRuntimePlugin(BasePlugin):
  """SecureADK runtime plugin for identity, policy, and provenance."""

  def __init__(
      self,
      *,
      identity_registry: IdentityRegistry,
      capability_vault: CapabilityVault,
      response_keyring: Optional[HmacKeyring] = None,
      ledger: Optional[BaseProvenanceLedger] = None,
      name: str = 'secure_runtime',
      tenant_state_key: str = 'tenant_id',
      case_state_key: str = 'case_id',
      enforce_agent_identity: bool = True,
      sign_model_responses: bool = True,
      sign_partial_responses: bool = False,
  ):
    super().__init__(name=name)
    self._identity_registry = identity_registry
    self._capability_vault = capability_vault
    self._response_keyring = response_keyring or capability_vault.keyring
    self._ledger = ledger
    self._tenant_state_key = tenant_state_key
    self._case_state_key = case_state_key
    self._enforce_agent_identity = enforce_agent_identity
    self._sign_model_responses = sign_model_responses
    self._sign_partial_responses = sign_partial_responses
    self._issued_capabilities: dict[tuple[str, str], CapabilityToken] = {}

  async def before_run_callback(
      self, *, invocation_context
  ) -> Optional[types.Content]:
    identity = self._resolve_identity(invocation_context.agent.name)
    if self._ledger is not None:
      await self._ledger.append(
          event_type='invocation_started',
          actor=identity.subject if identity is not None else None,
          app_name=invocation_context.session.app_name,
          user_id=invocation_context.user_id,
          session_id=invocation_context.session.id,
          invocation_id=invocation_context.invocation_id,
          payload={
              'userContentHash': (
                  payload_hash(
                      invocation_context.user_content.model_dump(
                          by_alias=True,
                          exclude_none=True,
                          mode='json',
                      )
                  )
                  if invocation_context.user_content is not None
                  else None
              ),
          },
      )
    return None

  async def before_agent_callback(
      self,
      *,
      agent: BaseAgent,
      callback_context: CallbackContext,
  ) -> Optional[types.Content]:
    identity = self._resolve_identity(agent.name)
    if self._ledger is not None:
      await self._ledger.append(
          event_type='agent_bound',
          actor=identity.subject if identity is not None else None,
          app_name=callback_context.session.app_name,
          user_id=callback_context.user_id,
          session_id=callback_context.session.id,
          invocation_id=callback_context.invocation_id,
          payload={
              'roles': list(identity.roles) if identity is not None else [],
              'tenantId': self._tenant_id(callback_context, identity),
          },
      )
    return None

  async def before_model_callback(
      self, *, callback_context: CallbackContext, llm_request: LlmRequest
  ) -> Optional[LlmResponse]:
    del callback_context, llm_request
    return None

  async def after_model_callback(
      self,
      *,
      callback_context: CallbackContext,
      llm_response: LlmResponse,
  ) -> Optional[LlmResponse]:
    if not self._sign_model_responses:
      return None
    if llm_response.partial and not self._sign_partial_responses:
      return None
    if not llm_response.content and not llm_response.error_code:
      return None

    identity = self._resolve_identity(callback_context.agent_name)
    if identity is None:
      return None

    previous_event_hash = (
        payload_hash(
            callback_context.session.events[-1].model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            )
        )
        if callback_context.session.events
        else None
    )
    signed_payload = {
        'actor': identity.subject,
        'appName': callback_context.session.app_name,
        'sessionId': callback_context.session.id,
        'invocationId': callback_context.invocation_id,
        'previousEventHash': previous_event_hash,
        'response': llm_response.model_dump(
            by_alias=True,
            exclude_none=True,
            mode='json',
        ),
    }
    envelope = self._response_keyring.sign_value(
        signed_payload,
        key_id=identity.key_id,
    )
    secure_metadata = {
        'actor': identity.subject,
        'keyId': identity.key_id,
        'payloadHash': envelope.payload_hash,
        'previousEventHash': previous_event_hash,
        'signature': envelope.signature,
        'signedAt': envelope.signed_at,
    }
    llm_response.custom_metadata = {
        **(llm_response.custom_metadata or {}),
        SECURE_METADATA_KEY: secure_metadata,
    }
    if self._ledger is not None:
      await self._ledger.append(
          event_type='model_response_signed',
          actor=identity.subject,
          app_name=callback_context.session.app_name,
          user_id=callback_context.user_id,
          session_id=callback_context.session.id,
          invocation_id=callback_context.invocation_id,
          payload=copy.deepcopy(secure_metadata),
      )
    return None

  async def before_tool_callback(
      self,
      *,
      tool: BaseTool,
      tool_args: dict[str, Any],
      tool_context: ToolContext,
  ) -> Optional[dict]:
    identity = self._resolve_identity(tool_context.agent_name)
    request = self._build_authorization_request(
        identity=identity,
        tool=tool,
        tool_args=tool_args,
        tool_context=tool_context,
    )
    decision = self._capability_vault.authorize(request)
    if not decision.allowed:
      tool_context.actions.skip_summarization = True
      if self._ledger is not None:
        await self._ledger.append(
            event_type='tool_denied',
            actor=identity.subject if identity is not None else None,
            app_name=tool_context.session.app_name,
            user_id=tool_context.user_id,
            session_id=tool_context.session.id,
            invocation_id=tool_context.invocation_id,
            payload={
                'tool': tool.name,
                'action': request.action,
                'reason': decision.reason,
                'riskScore': decision.risk_score,
                'toolArgKeys': sorted(tool_args),
                'toolArgsHash': payload_hash(tool_args),
            },
        )
      return {
          'status': 'denied',
          'reason': decision.reason,
          'tool': tool.name,
          'action': request.action,
          'risk_score': decision.risk_score,
      }

    token = self._capability_vault.issue(request, decision=decision)
    cache_key = self._capability_key(tool_context)
    self._issued_capabilities[cache_key] = token
    if tool_context.function_call_id:
      tool_context.state[
          capability_state_key(tool_context.function_call_id)
      ] = token.model_dump(by_alias=True, exclude_none=True, mode='json')
    if self._ledger is not None:
      await self._ledger.append(
          event_type='capability_issued',
          actor=identity.subject if identity is not None else None,
          app_name=tool_context.session.app_name,
          user_id=tool_context.user_id,
          session_id=tool_context.session.id,
          invocation_id=tool_context.invocation_id,
          payload={
              'tool': tool.name,
              'action': request.action,
              'tokenHash': self._capability_vault.token_hash(token),
              'expiresAt': token.expires_at,
          },
      )
    return None

  async def after_tool_callback(
      self,
      *,
      tool: BaseTool,
      tool_args: dict[str, Any],
      tool_context: ToolContext,
      result: dict,
  ) -> Optional[dict]:
    cache_key = self._capability_key(tool_context)
    token = self._issued_capabilities.pop(cache_key, None)
    if token is None:
      return None

    identity = self._resolve_identity(tool_context.agent_name)
    request = self._build_authorization_request(
        identity=identity,
        tool=tool,
        tool_args=tool_args,
        tool_context=tool_context,
    )
    validation = self._capability_vault.consume(token, request)
    if self._ledger is not None:
      await self._ledger.append(
          event_type='tool_executed',
          actor=identity.subject if identity is not None else None,
          app_name=tool_context.session.app_name,
          user_id=tool_context.user_id,
          session_id=tool_context.session.id,
          invocation_id=tool_context.invocation_id,
          payload={
              'tool': tool.name,
              'action': request.action,
              'validCapability': validation.valid,
              'validationReason': validation.reason,
              'resultHash': payload_hash(result),
              'tokenHash': self._capability_vault.token_hash(token),
          },
      )
    return None

  async def after_run_callback(self, *, invocation_context) -> None:
    stale_keys = [
        cache_key
        for cache_key in self._issued_capabilities
        if cache_key[0] == invocation_context.invocation_id
    ]
    for cache_key in stale_keys:
      token = self._issued_capabilities.pop(cache_key)
      if self._ledger is not None:
        await self._ledger.append(
            event_type='capability_abandoned',
            actor=invocation_context.agent.name,
            app_name=invocation_context.session.app_name,
            user_id=invocation_context.user_id,
            session_id=invocation_context.session.id,
            invocation_id=invocation_context.invocation_id,
            payload={
                'tokenHash': self._capability_vault.token_hash(token),
                'functionCallId': token.function_call_id,
            },
        )
    if self._ledger is not None:
      await self._ledger.append(
          event_type='invocation_finished',
          actor=invocation_context.agent.name,
          app_name=invocation_context.session.app_name,
          user_id=invocation_context.user_id,
          session_id=invocation_context.session.id,
          invocation_id=invocation_context.invocation_id,
          payload={},
      )

  def _resolve_identity(self, agent_name: str) -> Optional[AgentIdentity]:
    identity = self._identity_registry.get_identity(agent_name)
    if identity is None and self._enforce_agent_identity:
      raise ValueError(
          f'SecureADK identity enforcement failed for agent {agent_name!r}.'
      )
    return identity

  def _build_authorization_request(
      self,
      *,
      identity: Optional[AgentIdentity],
      tool: BaseTool,
      tool_args: dict[str, Any],
      tool_context: ToolContext,
  ) -> AuthorizationRequest:
    action = self._tool_action(tool)
    tenant_id = self._tenant_id(tool_context, identity)
    case_id = tool_context.state.get(self._case_state_key)
    context = {
        'tenant_id': tenant_id,
        'case_id': case_id,
        'tool_name': tool.name,
        'user_id': tool_context.user_id,
    }
    if identity is not None:
      context.update(identity.attributes)
    return AuthorizationRequest(
        agent_name=tool_context.agent_name,
        key_id=identity.key_id if identity is not None else 'anonymous',
        roles=identity.roles if identity is not None else (),
        tool_name=tool.name,
        action=action,
        app_name=tool_context.session.app_name,
        user_id=tool_context.user_id,
        session_id=tool_context.session.id,
        invocation_id=tool_context.invocation_id,
        function_call_id=tool_context.function_call_id,
        tenant_id=tenant_id,
        case_id=case_id,
        context=context,
        tool_args=copy.deepcopy(tool_args),
    )

  def _tenant_id(
      self,
      context: CallbackContext | ToolContext,
      identity: Optional[AgentIdentity],
  ) -> Optional[str]:
    tenant_id = context.state.get(self._tenant_state_key)
    if tenant_id is not None:
      return tenant_id
    if identity is not None:
      return identity.tenant_id
    return None

  @staticmethod
  def _tool_action(tool: BaseTool) -> str:
    if tool.custom_metadata:
      secure_action = tool.custom_metadata.get('secure_action')
      if isinstance(secure_action, str) and secure_action:
        return secure_action
    return tool.name

  @staticmethod
  def _capability_key(tool_context: ToolContext) -> tuple[str, str]:
    return (
        tool_context.invocation_id,
        tool_context.function_call_id or '',
    )

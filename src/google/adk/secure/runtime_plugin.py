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
from .alert_sinks import BaseAnomalyAlertSink
from .anomaly import AnomalyAlert
from .anomaly import BaseAnomalyDetector
from .attestation import DeploymentAttestation
from .attestation import DeploymentAttestor
from .capabilities import capability_state_key
from .capabilities import CapabilityToken
from .capabilities import CapabilityVault
from .gateway import BaseAccessGateway
from .gateway import GatewayRequest
from .identities import AgentIdentity
from .identities import IdentityRegistry
from .isolation import TenantIsolationManager
from .lineage import LineageTracker
from .policies import AuthorizationRequest
from .provenance import BaseProvenanceLedger
from .recommendations import PolicyRecommender
from .signing import HmacKeyring
from .signing import payload_hash
from .tenant_crypto import TenantCryptoManager
from .trust import TrustScorer

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
      gateway: BaseAccessGateway | None = None,
      anomaly_detector: BaseAnomalyDetector | None = None,
      anomaly_alert_sink: BaseAnomalyAlertSink | None = None,
      lineage_tracker: LineageTracker | None = None,
      tenant_isolation_manager: TenantIsolationManager | None = None,
      policy_recommender: PolicyRecommender | None = None,
      deployment_attestation: DeploymentAttestation | None = None,
      deployment_attestor: DeploymentAttestor | None = None,
      trust_scorer: TrustScorer | None = None,
      tenant_crypto_manager: TenantCryptoManager | None = None,
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
    self._gateway = gateway
    self._anomaly_detector = anomaly_detector
    self._anomaly_alert_sink = anomaly_alert_sink
    self._lineage_tracker = lineage_tracker
    self._tenant_isolation_manager = tenant_isolation_manager
    self._policy_recommender = policy_recommender
    self._deployment_attestation = deployment_attestation
    self._deployment_attestor = deployment_attestor
    self._trust_scorer = trust_scorer
    self._tenant_crypto_manager = tenant_crypto_manager
    self._issued_capabilities: dict[tuple[str, str], CapabilityToken] = {}

  async def before_run_callback(
      self, *, invocation_context
  ) -> Optional[types.Content]:
    identity = self._resolve_identity(invocation_context.agent.name)
    tenant_id = self._state_tenant_id(
        invocation_context.session.state,
        identity,
    )
    case_id = invocation_context.session.state.get(self._case_state_key)
    self._validate_session_tenant(
        app_name=invocation_context.session.app_name,
        user_id=invocation_context.user_id,
        session=invocation_context.session,
        identity=identity,
    )
    if self._gateway is not None:
      request = self._build_gateway_request(
          operation='run',
          resource_type='agent',
          resource_name=invocation_context.agent.name,
          app_name=invocation_context.session.app_name,
          user_id=invocation_context.user_id,
          session_id=invocation_context.session.id,
          invocation_id=invocation_context.invocation_id,
          identity=identity,
          state=invocation_context.session.state,
      )
      decision = self._gateway.authorize(request)
      await self._record_gateway_decision(
          request=request,
          decision=decision,
          actor=identity.subject if identity is not None else None,
          app_name=invocation_context.session.app_name,
          user_id=invocation_context.user_id,
          session_id=invocation_context.session.id,
          invocation_id=invocation_context.invocation_id,
          operation='run',
          resource_name=invocation_context.agent.name,
      )
      if not decision.allowed:
        raise PermissionError(decision.reason)
    if self._deployment_attestation is not None:
      verification = self._verify_deployment_attestation()
      if self._deployment_attestor is not None:
        await self._deployment_attestor.record_attestation(
            self._deployment_attestation,
            verified=verification.valid,
        )
      if self._trust_scorer is not None:
        await self._trust_scorer.record_deployment_attestation(
            attestation=self._deployment_attestation,
            verified=verification.valid,
        )
      if not verification.valid:
        raise PermissionError(verification.reason)
    if self._ledger is not None:
      await self._ledger.append(
          event_type='invocation_started',
          actor=identity.subject if identity is not None else None,
          app_name=invocation_context.session.app_name,
          user_id=invocation_context.user_id,
          session_id=invocation_context.session.id,
          invocation_id=invocation_context.invocation_id,
          payload={
              'userContentHash': self._content_hash(
                  invocation_context.user_content
              ),
              'tenantId': tenant_id,
              'caseId': case_id,
          },
      )
    if self._lineage_tracker is not None:
      await self._lineage_tracker.record(
          record_type='prompt',
          entity_id=self._prompt_entity(invocation_context.invocation_id),
          app_name=invocation_context.session.app_name,
          user_id=invocation_context.user_id,
          session_id=invocation_context.session.id,
          invocation_id=invocation_context.invocation_id,
          payload={
              'userContentHash': self._content_hash(
                  invocation_context.user_content
              ),
              'tenantId': tenant_id,
              'caseId': case_id,
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
    tenant_id = self._tenant_id(callback_context, identity)
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
              'tenantId': tenant_id,
          },
      )
    if self._lineage_tracker is not None:
      await self._lineage_tracker.record(
          record_type='agent_binding',
          entity_id=self._agent_binding_entity(
              callback_context.invocation_id, agent.name
          ),
          app_name=callback_context.session.app_name,
          user_id=callback_context.user_id,
          session_id=callback_context.session.id,
          invocation_id=callback_context.invocation_id,
          parent_entities=(
              self._prompt_entity(callback_context.invocation_id),
          ),
          payload={
              'agentName': agent.name,
              'roles': list(identity.roles) if identity is not None else [],
              'tenantId': tenant_id,
          },
      )
    return None

  async def before_model_callback(
      self, *, callback_context: CallbackContext, llm_request: LlmRequest
  ) -> Optional[LlmResponse]:
    if self._lineage_tracker is not None:
      await self._lineage_tracker.record(
          record_type='model_request',
          entity_id=self._model_request_entity(
              callback_context.invocation_id,
              callback_context.agent_name,
          ),
          app_name=callback_context.session.app_name,
          user_id=callback_context.user_id,
          session_id=callback_context.session.id,
          invocation_id=callback_context.invocation_id,
          parent_entities=(
              self._prompt_entity(callback_context.invocation_id),
              self._agent_binding_entity(
                  callback_context.invocation_id,
                  callback_context.agent_name,
              ),
          ),
          payload=self._model_request_payload(llm_request),
      )
    return None

  async def after_model_callback(
      self,
      *,
      callback_context: CallbackContext,
      llm_response: LlmResponse,
  ) -> Optional[LlmResponse]:
    secure_metadata = None
    if self._sign_model_responses:
      if llm_response.partial and not self._sign_partial_responses:
        return None
      if llm_response.content or llm_response.error_code:
        identity = self._resolve_identity(callback_context.agent_name)
        if identity is not None:
          tenant_id = self._tenant_id(callback_context, identity)
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
              'tenantId': tenant_id,
              'previousEventHash': previous_event_hash,
              'response': llm_response.model_dump(
                  by_alias=True,
                  exclude_none=True,
                  mode='json',
              ),
          }
          envelope = (
              self._response_keyring.sign_value(
                  signed_payload,
                  key_id=identity.key_id,
              )
              if self._tenant_crypto_manager is None
              else self._tenant_crypto_manager.sign_value(
                  keyring=self._response_keyring,
                  value=signed_payload,
                  key_id=identity.key_id,
                  tenant_id=tenant_id,
              )
          )
          secure_metadata = {
              'actor': identity.subject,
              'keyId': identity.key_id,
              'keyEpoch': envelope.key_epoch,
              'keyScope': envelope.key_scope,
              'tenantId': envelope.tenant_id,
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

    response_hash = payload_hash(
        llm_response.model_dump(
            by_alias=True,
            exclude_none=True,
            mode='json',
        )
    )
    if self._lineage_tracker is not None:
      await self._lineage_tracker.record(
          record_type='model_response',
          entity_id=self._model_response_entity(
              callback_context.invocation_id,
              callback_context.agent_name,
          ),
          app_name=callback_context.session.app_name,
          user_id=callback_context.user_id,
          session_id=callback_context.session.id,
          invocation_id=callback_context.invocation_id,
          parent_entities=(
              self._model_request_entity(
                  callback_context.invocation_id,
                  callback_context.agent_name,
              ),
          ),
          payload={
              'responseHash': response_hash,
              'partial': llm_response.partial,
              'turnComplete': llm_response.turn_complete,
              'secureMetadata': secure_metadata,
          },
      )
    if self._anomaly_detector is not None and not llm_response.partial:
      alerts = self._anomaly_detector.record_model_response(
          app_name=callback_context.session.app_name,
          user_id=callback_context.user_id,
          session_id=callback_context.session.id,
          invocation_id=callback_context.invocation_id,
          agent_name=callback_context.agent_name,
          response_hash=response_hash,
      )
      await self._emit_alerts(alerts)
    return None

  async def before_tool_callback(
      self,
      *,
      tool: BaseTool,
      tool_args: dict[str, Any],
      tool_context: ToolContext,
  ) -> Optional[dict]:
    identity = self._resolve_identity(tool_context.agent_name)
    self._validate_session_tenant(
        app_name=tool_context.session.app_name,
        user_id=tool_context.user_id,
        session=tool_context.session,
        identity=identity,
    )
    action = self._tool_action(tool)

    if self._gateway is not None:
      gateway_request = self._build_gateway_request(
          operation='tool',
          resource_type='tool',
          resource_name=tool.name,
          app_name=tool_context.session.app_name,
          user_id=tool_context.user_id,
          session_id=tool_context.session.id,
          invocation_id=tool_context.invocation_id,
          identity=identity,
          state=tool_context.state,
          extra_context={
              'action': action,
              'toolArgsHash': payload_hash(tool_args),
          },
      )
      gateway_decision = self._gateway.authorize(gateway_request)
      await self._record_gateway_decision(
          request=gateway_request,
          decision=gateway_decision,
          actor=identity.subject if identity is not None else None,
          app_name=tool_context.session.app_name,
          user_id=tool_context.user_id,
          session_id=tool_context.session.id,
          invocation_id=tool_context.invocation_id,
          operation='tool',
          resource_name=tool.name,
      )
      if gateway_decision.requires_approval:
        approval_response = await self._handle_tool_approval_requirement(
            tool_name=tool.name,
            action=action,
            risk_score=gateway_decision.risk_score,
            source='gateway',
            reason=gateway_decision.reason,
            matched_rule=gateway_decision.matched_rule,
            approval_hint=gateway_decision.approval_hint,
            approval_payload=gateway_decision.approval_payload,
            tool_context=tool_context,
        )
        if approval_response is not None:
          return approval_response
      if not gateway_decision.allowed:
        return await self._deny_tool_call(
            reason=gateway_decision.reason,
            tool_name=tool.name,
            action=action,
            risk_score=gateway_decision.risk_score,
            source='gateway',
            tool_context=tool_context,
        )

    request = self._build_authorization_request(
        identity=identity,
        tool=tool,
        tool_args=tool_args,
        tool_context=tool_context,
    )
    decision = self._capability_vault.authorize(request)
    await self._record_policy_decision(
        request=request,
        decision=decision,
    )
    alerts = self._record_tool_alerts(
        request=request,
        decision_allowed=decision.allowed,
        risk_score=decision.risk_score,
        reason=decision.reason,
    )
    await self._emit_alerts(alerts)
    if (
        self._anomaly_detector is not None
        and self._anomaly_detector.should_block(alerts)
    ):
      return await self._deny_tool_call(
          reason='Blocked by anomaly detector.',
          tool_name=tool.name,
          action=request.action,
          risk_score=max(alert.severity for alert in alerts),
          source='anomaly_detector',
          tool_context=tool_context,
      )
    if decision.requires_approval:
      approval_response = await self._handle_tool_approval_requirement(
          tool_name=tool.name,
          action=request.action,
          risk_score=decision.risk_score,
          source='policy',
          reason=decision.reason,
          matched_rule=decision.matched_rule,
          approval_hint=decision.approval_hint,
          approval_payload=decision.approval_payload,
          tool_context=tool_context,
      )
      if approval_response is not None:
        return approval_response
    if not decision.allowed:
      await self._record_tool_authorization_lineage(
          request=request,
          allowed=False,
          risk_score=decision.risk_score,
          reason=decision.reason,
          token_hash=None,
      )
      return await self._deny_tool_call(
          reason=decision.reason,
          tool_name=tool.name,
          action=request.action,
          risk_score=decision.risk_score,
          source='policy',
          tool_context=tool_context,
      )

    token = self._capability_vault.issue(request, decision=decision)
    cache_key = self._capability_key(tool_context)
    self._issued_capabilities[cache_key] = token
    if tool_context.function_call_id:
      tool_context.state[
          capability_state_key(tool_context.function_call_id)
      ] = token.model_dump(by_alias=True, exclude_none=True, mode='json')
    token_hash = self._capability_vault.token_hash(token)
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
              'tokenHash': token_hash,
              'expiresAt': token.expires_at,
          },
      )
    await self._record_tool_authorization_lineage(
        request=request,
        allowed=True,
        risk_score=decision.risk_score,
        reason=decision.reason,
        token_hash=token_hash,
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
    result_hash = payload_hash(result)
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
              'resultHash': result_hash,
              'tokenHash': self._capability_vault.token_hash(token),
          },
      )
    if self._lineage_tracker is not None:
      await self._lineage_tracker.record(
          record_type='tool_execution',
          entity_id=self._tool_execution_entity(
              tool_context.invocation_id,
              tool_context.function_call_id,
              tool.name,
          ),
          app_name=tool_context.session.app_name,
          user_id=tool_context.user_id,
          session_id=tool_context.session.id,
          invocation_id=tool_context.invocation_id,
          parent_entities=(
              self._tool_authorization_entity(
                  tool_context.invocation_id,
                  tool_context.function_call_id,
                  tool.name,
              ),
          ),
          payload={
              'tool': tool.name,
              'action': request.action,
              'resultHash': result_hash,
              'validCapability': validation.valid,
              'validationReason': validation.reason,
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
    if self._anomaly_detector is not None:
      await self._emit_alerts(
          self._anomaly_detector.finalize_invocation(
              invocation_context.invocation_id
          )
      )
    if self._lineage_tracker is not None:
      await self._lineage_tracker.record(
          record_type='invocation_complete',
          entity_id=self._invocation_entity(invocation_context.invocation_id),
          app_name=invocation_context.session.app_name,
          user_id=invocation_context.user_id,
          session_id=invocation_context.session.id,
          invocation_id=invocation_context.invocation_id,
          parent_entities=(
              self._prompt_entity(invocation_context.invocation_id),
          ),
          payload={},
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
    state_values = self._state_dict(tool_context.state)
    case_id = state_values.get(self._case_state_key)
    context = {
        'tenant_id': tenant_id,
        'case_id': case_id,
        'tool_name': tool.name,
        'user_id': tool_context.user_id,
        **copy.deepcopy(state_values),
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

  def _build_gateway_request(
      self,
      *,
      operation: str,
      resource_type: str,
      resource_name: str,
      app_name: str,
      user_id: str,
      session_id: str,
      invocation_id: str,
      identity: AgentIdentity | None,
      state: Any,
      extra_context: dict[str, Any] | None = None,
  ) -> GatewayRequest:
    state_values = self._state_dict(state)
    tenant_id = state_values.get(self._tenant_state_key)
    if tenant_id is None and identity is not None:
      tenant_id = identity.tenant_id
    context = {
        'tenant_id': tenant_id,
        'case_id': state_values.get(self._case_state_key),
        **copy.deepcopy(state_values),
    }
    if identity is not None:
      context.update(identity.attributes)
    if extra_context:
      context.update(extra_context)
    return GatewayRequest(
        operation=operation,
        resource_type=resource_type,
        resource_name=resource_name,
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
        invocation_id=invocation_id,
        agent_name=identity.subject if identity is not None else None,
        roles=identity.roles if identity is not None else (),
        tenant_id=tenant_id,
        case_id=state_values.get(self._case_state_key),
        context=context,
    )

  def _tenant_id(
      self,
      context: CallbackContext | ToolContext,
      identity: Optional[AgentIdentity],
  ) -> Optional[str]:
    return self._state_tenant_id(context.state, identity)

  def _state_tenant_id(
      self,
      state: Any,
      identity: Optional[AgentIdentity],
  ) -> Optional[str]:
    tenant_id = self._state_dict(state).get(self._tenant_state_key)
    if tenant_id is not None:
      return tenant_id
    if identity is not None:
      return identity.tenant_id
    return None

  @staticmethod
  def _state_dict(state: Any) -> dict[str, Any]:
    if hasattr(state, 'to_dict'):
      return state.to_dict()
    if isinstance(state, dict):
      return state
    return dict(state)

  def _validate_session_tenant(
      self,
      *,
      app_name: str,
      user_id: str,
      session,
      identity: AgentIdentity | None,
  ) -> None:
    if self._tenant_isolation_manager is None:
      return
    self._tenant_isolation_manager.validate_session(
        app_name=app_name,
        user_id=user_id,
        session=session,
        identity_tenant_id=(
            identity.tenant_id if identity is not None else None
        ),
    )

  async def _record_gateway_decision(
      self,
      *,
      request: GatewayRequest,
      decision,
      actor: str | None,
      app_name: str,
      user_id: str,
      session_id: str,
      invocation_id: str,
      operation: str,
      resource_name: str,
  ) -> None:
    event_type = 'gateway_allowed' if decision.allowed else 'gateway_denied'
    payload = {
        'operation': operation,
        'resourceName': resource_name,
        'reason': decision.reason,
        'matchedRule': decision.matched_rule,
        'riskScore': decision.risk_score,
    }
    if self._ledger is not None:
      await self._ledger.append(
          event_type=event_type,
          actor=actor,
          app_name=app_name,
          user_id=user_id,
          session_id=session_id,
          invocation_id=invocation_id,
          payload=payload,
      )
    if self._lineage_tracker is not None:
      await self._lineage_tracker.record(
          record_type=event_type,
          entity_id=(
              f'invocation:{invocation_id}:gateway:{operation}:{resource_name}'
          ),
          app_name=app_name,
          user_id=user_id,
          session_id=session_id,
          invocation_id=invocation_id,
          payload=payload,
      )
    if self._policy_recommender is not None:
      await self._policy_recommender.record_gateway_decision(
          request=request,
          decision=decision,
      )
    if self._trust_scorer is not None:
      await self._trust_scorer.record_gateway_decision(
          request=request,
          decision=decision,
      )

  async def _record_policy_decision(
      self,
      *,
      request: AuthorizationRequest,
      decision,
  ) -> None:
    if self._policy_recommender is None:
      if self._trust_scorer is None:
        return
    if self._policy_recommender is not None:
      await self._policy_recommender.record_policy_decision(
          request=request,
          decision=decision,
      )
    if self._trust_scorer is not None:
      await self._trust_scorer.record_policy_decision(
          request=request,
          decision=decision,
      )

  async def _record_tool_authorization_lineage(
      self,
      *,
      request: AuthorizationRequest,
      allowed: bool,
      risk_score: float,
      reason: str,
      token_hash: str | None,
  ) -> None:
    if self._lineage_tracker is None:
      return
    await self._lineage_tracker.record(
        record_type='tool_authorization',
        entity_id=self._tool_authorization_entity(
            request.invocation_id,
            request.function_call_id,
            request.tool_name,
        ),
        app_name=request.app_name,
        user_id=request.user_id,
        session_id=request.session_id,
        invocation_id=request.invocation_id,
        parent_entities=(
            self._model_request_entity(
                request.invocation_id,
                request.agent_name,
            ),
        ),
        payload={
            'tool': request.tool_name,
            'action': request.action,
            'allowed': allowed,
            'riskScore': risk_score,
            'reason': reason,
            'toolArgsHash': payload_hash(request.tool_args),
            'tokenHash': token_hash,
        },
    )

  def _record_tool_alerts(
      self,
      *,
      request: AuthorizationRequest,
      decision_allowed: bool,
      risk_score: float,
      reason: str,
  ) -> list[AnomalyAlert]:
    if self._anomaly_detector is None:
      return []
    return self._anomaly_detector.record_tool_decision(
        app_name=request.app_name,
        user_id=request.user_id,
        session_id=request.session_id,
        invocation_id=request.invocation_id,
        agent_name=request.agent_name,
        tool_name=request.tool_name,
        allowed=decision_allowed,
        risk_score=risk_score,
        reason=reason,
    )

  async def _emit_alerts(self, alerts: list[AnomalyAlert]) -> None:
    if not alerts:
      return
    for alert in alerts:
      if self._trust_scorer is not None:
        await self._trust_scorer.record_anomaly_alert(alert)
      if self._ledger is not None:
        await self._ledger.append(
            event_type='anomaly_detected',
            actor=alert.agent_name,
            app_name=alert.app_name,
            user_id=alert.user_id,
            session_id=alert.session_id,
            invocation_id=alert.invocation_id,
            payload=alert.model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            ),
        )
      if self._lineage_tracker is not None:
        await self._lineage_tracker.record(
            record_type='anomaly_alert',
            entity_id=(
                f'invocation:{alert.invocation_id}:anomaly:{alert.alert_type}:'
                f'{payload_hash(alert.payload)[:16]}'
            ),
            app_name=alert.app_name,
            user_id=alert.user_id,
            session_id=alert.session_id,
            invocation_id=alert.invocation_id,
            payload=alert.model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            ),
        )
    if self._anomaly_alert_sink is not None:
      await self._anomaly_alert_sink.emit_alerts(alerts)

  def _verify_deployment_attestation(self):
    if (
        self._deployment_attestation is None
        or self._deployment_attestor is None
    ):
      raise ValueError('Deployment attestation is not configured.')
    return self._deployment_attestor.verify_attestation(
        self._deployment_attestation
    )

  async def _handle_tool_approval_requirement(
      self,
      *,
      tool_name: str,
      action: str,
      risk_score: float,
      source: str,
      reason: str,
      matched_rule: str | None,
      approval_hint: str | None,
      approval_payload: dict[str, Any],
      tool_context: ToolContext,
  ) -> dict | None:
    confirmation = tool_context.tool_confirmation
    approval_payload_dict = {
        'tool': tool_name,
        'action': action,
        'source': source,
        'reason': reason,
        'riskScore': risk_score,
        'matchedRule': matched_rule,
        **approval_payload,
    }
    if confirmation is None:
      tool_context.request_confirmation(
          hint=(
              approval_hint
              or f'Approve SecureADK action {action!r} for tool {tool_name!r}.'
          ),
          payload=approval_payload_dict,
      )
      await self._record_approval_event(
          event_type='approval_requested',
          tool_name=tool_name,
          action=action,
          risk_score=risk_score,
          source=source,
          reason=reason,
          matched_rule=matched_rule,
          tool_context=tool_context,
          payload=approval_payload_dict,
      )
      tool_context.actions.skip_summarization = True
      return {
          'status': 'requires_approval',
          'reason': reason,
          'tool': tool_name,
          'action': action,
          'risk_score': risk_score,
      }
    if not confirmation.confirmed:
      await self._record_approval_event(
          event_type='approval_rejected',
          tool_name=tool_name,
          action=action,
          risk_score=risk_score,
          source=source,
          reason=reason,
          matched_rule=matched_rule,
          tool_context=tool_context,
          payload={
              **approval_payload_dict,
              'confirmationPayload': confirmation.payload,
          },
      )
      return await self._deny_tool_call(
          reason='Rejected by human approval workflow.',
          tool_name=tool_name,
          action=action,
          risk_score=risk_score,
          source='approval',
          tool_context=tool_context,
      )
    await self._record_approval_event(
        event_type='approval_granted',
        tool_name=tool_name,
        action=action,
        risk_score=risk_score,
        source=source,
        reason=reason,
        matched_rule=matched_rule,
        tool_context=tool_context,
        payload={
            **approval_payload_dict,
            'confirmationPayload': confirmation.payload,
        },
    )
    return None

  async def _record_approval_event(
      self,
      *,
      event_type: str,
      tool_name: str,
      action: str,
      risk_score: float,
      source: str,
      reason: str,
      matched_rule: str | None,
      tool_context: ToolContext,
      payload: dict[str, Any],
  ) -> None:
    event_payload = {
        'tool': tool_name,
        'action': action,
        'riskScore': risk_score,
        'source': source,
        'reason': reason,
        'matchedRule': matched_rule,
        **payload,
    }
    if self._ledger is not None:
      await self._ledger.append(
          event_type=event_type,
          actor=tool_context.agent_name,
          app_name=tool_context.session.app_name,
          user_id=tool_context.user_id,
          session_id=tool_context.session.id,
          invocation_id=tool_context.invocation_id,
          payload=event_payload,
      )
    if self._lineage_tracker is not None:
      await self._lineage_tracker.record(
          record_type=event_type,
          entity_id=(
              f'invocation:{tool_context.invocation_id}:approval:'
              f'{tool_name}:{action}:{source}'
          ),
          app_name=tool_context.session.app_name,
          user_id=tool_context.user_id,
          session_id=tool_context.session.id,
          invocation_id=tool_context.invocation_id,
          payload=event_payload,
      )

  async def _deny_tool_call(
      self,
      *,
      reason: str,
      tool_name: str,
      action: str,
      risk_score: float,
      source: str,
      tool_context: ToolContext,
  ) -> dict:
    tool_context.actions.skip_summarization = True
    if self._ledger is not None:
      await self._ledger.append(
          event_type='tool_denied',
          actor=tool_context.agent_name,
          app_name=tool_context.session.app_name,
          user_id=tool_context.user_id,
          session_id=tool_context.session.id,
          invocation_id=tool_context.invocation_id,
          payload={
              'tool': tool_name,
              'action': action,
              'reason': reason,
              'riskScore': risk_score,
              'source': source,
          },
      )
    return {
        'status': 'denied',
        'reason': reason,
        'tool': tool_name,
        'action': action,
        'risk_score': risk_score,
    }

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

  @staticmethod
  def _content_hash(content: types.Content | None) -> str | None:
    if content is None:
      return None
    return payload_hash(
        content.model_dump(by_alias=True, exclude_none=True, mode='json')
    )

  @staticmethod
  def _model_request_payload(llm_request: LlmRequest) -> dict[str, Any]:
    return {
        'model': llm_request.model,
        'contentsHash': payload_hash([
            content.model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            )
            for content in llm_request.contents
        ]),
        'systemInstructionHash': payload_hash(
            llm_request.config.system_instruction
        ),
        'toolNames': sorted(llm_request.tools_dict),
        'cacheConfigEnabled': llm_request.cache_config is not None,
    }

  @staticmethod
  def _invocation_entity(invocation_id: str) -> str:
    return f'invocation:{invocation_id}'

  @staticmethod
  def _prompt_entity(invocation_id: str) -> str:
    return f'invocation:{invocation_id}:prompt'

  @staticmethod
  def _agent_binding_entity(invocation_id: str, agent_name: str) -> str:
    return f'invocation:{invocation_id}:agent:{agent_name}'

  @staticmethod
  def _model_request_entity(invocation_id: str, agent_name: str) -> str:
    return f'invocation:{invocation_id}:model_request:{agent_name}'

  @staticmethod
  def _model_response_entity(invocation_id: str, agent_name: str) -> str:
    return f'invocation:{invocation_id}:model_response:{agent_name}'

  @staticmethod
  def _tool_authorization_entity(
      invocation_id: str,
      function_call_id: str | None,
      tool_name: str,
  ) -> str:
    suffix = function_call_id or tool_name
    return f'invocation:{invocation_id}:tool_authorization:{suffix}'

  @staticmethod
  def _tool_execution_entity(
      invocation_id: str,
      function_call_id: str | None,
      tool_name: str,
  ) -> str:
    suffix = function_call_id or tool_name
    return f'invocation:{invocation_id}:tool_execution:{suffix}'

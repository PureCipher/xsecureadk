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

from dataclasses import dataclass
from typing import Optional

from ..agents.base_agent import BaseAgent
from ..apps.app import App
from ..artifacts.base_artifact_service import BaseArtifactService
from ..auth.credential_service.base_credential_service import BaseCredentialService
from ..memory.base_memory_service import BaseMemoryService
from ..runners import Runner
from ..sessions.base_session_service import BaseSessionService
from .alert_sinks import BaseAnomalyAlertSink
from .anomaly import BaseAnomalyDetector
from .artifact_sealing import SealedArtifactService
from .capabilities import CapabilityVault
from .gateway import BaseAccessGateway
from .identities import IdentityRegistry
from .isolation import TenantIsolatedArtifactService
from .isolation import TenantIsolatedSessionService
from .isolation import TenantIsolationManager
from .lineage import LineageTracker
from .provenance import BaseProvenanceLedger
from .runtime_plugin import SecureRuntimePlugin
from .signing import HmacKeyring
from .trusted_evaluators import TrustedEvaluatorService


@dataclass(frozen=True)
class SecureRuntimeApplication:
  """SecureADK application bundle returned by config/application helpers."""

  app: App
  artifact_service: BaseArtifactService | None
  session_service: BaseSessionService | None
  builder: 'SecureRuntimeBuilder | None'


class SecureRuntimeBuilder:
  """Wires SecureADK into the existing App/Runner construction path.

  This helper keeps the standard ADK runtime intact. It adds the secure runtime
  as an application plugin and optionally wraps the artifact service with
  sealing so callers can keep using the normal ``App`` and ``Runner`` setup.
  """

  def __init__(
      self,
      *,
      identity_registry: IdentityRegistry,
      capability_vault: CapabilityVault,
      ledger: BaseProvenanceLedger | None = None,
      response_keyring: Optional[HmacKeyring] = None,
      plugin_name: str = 'secure_runtime',
      tenant_state_key: str = 'tenant_id',
      case_state_key: str = 'case_id',
      enforce_agent_identity: bool = True,
      sign_model_responses: bool = True,
      sign_partial_responses: bool = False,
      artifact_signing_key_id: str | None = None,
      artifact_keyring: Optional[HmacKeyring] = None,
      artifact_actor: str = 'omniseal-adapter',
      gateway: BaseAccessGateway | None = None,
      anomaly_detector: BaseAnomalyDetector | None = None,
      anomaly_alert_sink: BaseAnomalyAlertSink | None = None,
      lineage_tracker: LineageTracker | None = None,
      trusted_evaluator_service: TrustedEvaluatorService | None = None,
      tenant_isolation_manager: TenantIsolationManager | None = None,
  ):
    self._identity_registry = identity_registry
    self._capability_vault = capability_vault
    self._ledger = ledger
    self._response_keyring = response_keyring
    self._plugin_name = plugin_name
    self._tenant_state_key = tenant_state_key
    self._case_state_key = case_state_key
    self._enforce_agent_identity = enforce_agent_identity
    self._sign_model_responses = sign_model_responses
    self._sign_partial_responses = sign_partial_responses
    self._artifact_signing_key_id = artifact_signing_key_id
    self._artifact_keyring = artifact_keyring
    self._artifact_actor = artifact_actor
    self._gateway = gateway
    self._anomaly_detector = anomaly_detector
    self._anomaly_alert_sink = anomaly_alert_sink
    self._lineage_tracker = lineage_tracker
    self._trusted_evaluator_service = trusted_evaluator_service
    self._tenant_isolation_manager = tenant_isolation_manager

  @property
  def ledger(self) -> BaseProvenanceLedger | None:
    return self._ledger

  @property
  def gateway(self) -> BaseAccessGateway | None:
    return self._gateway

  @property
  def keyring(self) -> HmacKeyring:
    return self._capability_vault.keyring

  @property
  def lineage_tracker(self) -> LineageTracker | None:
    return self._lineage_tracker

  @property
  def policy_engine(self):
    return self._capability_vault.policy_engine

  @property
  def trusted_evaluator_service(
      self,
  ) -> TrustedEvaluatorService | None:
    return self._trusted_evaluator_service

  @property
  def anomaly_alert_sink(self) -> BaseAnomalyAlertSink | None:
    return self._anomaly_alert_sink

  @property
  def tenant_isolation_manager(
      self,
  ) -> TenantIsolationManager | None:
    return self._tenant_isolation_manager

  def build_plugin(self) -> SecureRuntimePlugin:
    """Builds a SecureADK runtime plugin instance."""
    return SecureRuntimePlugin(
        identity_registry=self._identity_registry,
        capability_vault=self._capability_vault,
        response_keyring=self._response_keyring,
        ledger=self._ledger,
        name=self._plugin_name,
        tenant_state_key=self._tenant_state_key,
        case_state_key=self._case_state_key,
        enforce_agent_identity=self._enforce_agent_identity,
        sign_model_responses=self._sign_model_responses,
        sign_partial_responses=self._sign_partial_responses,
        gateway=self._gateway,
        anomaly_detector=self._anomaly_detector,
        anomaly_alert_sink=self._anomaly_alert_sink,
        lineage_tracker=self._lineage_tracker,
        tenant_isolation_manager=self._tenant_isolation_manager,
    )

  def apply_to_app(self, app: App) -> App:
    """Returns an ``App`` with the SecureADK runtime plugin appended."""
    if any(plugin.name == self._plugin_name for plugin in app.plugins):
      raise ValueError(
          'App already contains a plugin named '
          f'{self._plugin_name!r}; refusing to add SecureADK twice.'
      )
    return app.model_copy(
        update={'plugins': [*app.plugins, self.build_plugin()]}
    )

  def wrap_session_service(
      self,
      session_service: BaseSessionService | None,
  ) -> BaseSessionService | None:
    """Wraps a session service with tenant isolation when configured."""
    if session_service is None or self._tenant_isolation_manager is None:
      return session_service
    return TenantIsolatedSessionService(
        delegate=session_service,
        isolation_manager=self._tenant_isolation_manager,
    )

  def wrap_artifact_service(
      self,
      artifact_service: BaseArtifactService | None,
      *,
      session_service: BaseSessionService | None = None,
  ) -> BaseArtifactService | None:
    """Wraps an artifact service with sealing when configured."""
    if artifact_service is None:
      return artifact_service

    wrapped_service = artifact_service
    if self._tenant_isolation_manager is not None:
      if session_service is None:
        raise ValueError(
            'SecureADK tenant isolation requires a session service when'
            ' wrapping the artifact service.'
        )
      wrapped_service = TenantIsolatedArtifactService(
          delegate=wrapped_service,
          session_service=session_service,
          isolation_manager=self._tenant_isolation_manager,
      )

    if self._artifact_signing_key_id is None:
      return wrapped_service
    return SealedArtifactService(
        delegate=wrapped_service,
        keyring=self._artifact_keyring or self._capability_vault.keyring,
        signing_key_id=self._artifact_signing_key_id,
        actor=self._artifact_actor,
        ledger=self._ledger,
        lineage_tracker=self._lineage_tracker,
    )

  def create_runner(
      self,
      *,
      session_service: BaseSessionService,
      app: App | None = None,
      agent: BaseAgent | None = None,
      app_name: str | None = None,
      artifact_service: BaseArtifactService | None = None,
      memory_service: Optional[BaseMemoryService] = None,
      credential_service: Optional[BaseCredentialService] = None,
      plugin_close_timeout: float = 5.0,
      auto_create_session: bool = False,
  ) -> Runner:
    """Creates a standard ADK ``Runner`` with SecureADK attached.

    Callers can provide either an existing ``App`` or the normal ``app_name`` +
    ``agent`` pair. The returned runner still executes through the standard
    ADK path; the only difference is the secure plugin and optional artifact
    sealing wrapper.
    """
    if app is None:
      if app_name is None or agent is None:
        raise ValueError(
            'Either app or both app_name and agent must be provided.'
        )
      app = App(name=app_name, root_agent=agent)
    secure_app = self.apply_to_app(app)
    secure_session_service = self.wrap_session_service(session_service)
    secure_artifact_service = self.wrap_artifact_service(
        artifact_service,
        session_service=secure_session_service,
    )
    return Runner(
        app=secure_app,
        app_name=app_name,
        artifact_service=secure_artifact_service,
        session_service=secure_session_service,
        memory_service=memory_service,
        credential_service=credential_service,
        plugin_close_timeout=plugin_close_timeout,
        auto_create_session=auto_create_session,
    )

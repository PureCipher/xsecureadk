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

from ..agents.base_agent import BaseAgent
from ..apps.app import App
from ..artifacts.base_artifact_service import BaseArtifactService
from ..auth.credential_service.base_credential_service import (
    BaseCredentialService,
)
from ..memory.base_memory_service import BaseMemoryService
from ..runners import Runner
from ..sessions.base_session_service import BaseSessionService
from .artifact_sealing import SealedArtifactService
from .capabilities import CapabilityVault
from .identities import IdentityRegistry
from .provenance import BaseProvenanceLedger
from .runtime_plugin import SecureRuntimePlugin
from .signing import HmacKeyring


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
    )

  def apply_to_app(self, app: App) -> App:
    """Returns an ``App`` with the SecureADK runtime plugin appended."""
    if any(plugin.name == self._plugin_name for plugin in app.plugins):
      raise ValueError(
          'App already contains a plugin named '
          f'{self._plugin_name!r}; refusing to add SecureADK twice.'
      )
    return app.model_copy(update={'plugins': [*app.plugins, self.build_plugin()]})

  def wrap_artifact_service(
      self,
      artifact_service: BaseArtifactService | None,
  ) -> BaseArtifactService | None:
    """Wraps an artifact service with sealing when configured."""
    if artifact_service is None or self._artifact_signing_key_id is None:
      return artifact_service
    return SealedArtifactService(
        delegate=artifact_service,
        keyring=self._artifact_keyring or self._capability_vault.keyring,
        signing_key_id=self._artifact_signing_key_id,
        actor=self._artifact_actor,
        ledger=self._ledger,
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
    secure_artifact_service = self.wrap_artifact_service(artifact_service)
    return Runner(
        app=secure_app,
        app_name=app_name,
        artifact_service=secure_artifact_service,
        session_service=session_service,
        memory_service=memory_service,
        credential_service=credential_service,
        plugin_close_timeout=plugin_close_timeout,
        auto_create_session=auto_create_session,
    )

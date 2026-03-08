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

from typing import Any

from ..sessions.base_session_service import BaseSessionService
from .isolation import TenantIsolationManager
from .signing import HmacKeyring
from .signing import SignatureEnvelope


class TenantCryptoManager:
  """Enables per-tenant signing scopes on top of the shared keyring."""

  def __init__(
      self,
      *,
      enabled: bool = False,
      tenant_state_key: str = 'tenant_id',
      require_tenant: bool = False,
      isolation_manager: TenantIsolationManager | None = None,
      session_service: BaseSessionService | None = None,
  ):
    self._enabled = enabled
    self._tenant_state_key = tenant_state_key
    self._require_tenant = require_tenant
    self._isolation_manager = isolation_manager
    self._session_service = session_service

  @property
  def enabled(self) -> bool:
    return self._enabled

  @property
  def session_service(self) -> BaseSessionService | None:
    return self._session_service

  def with_session_service(
      self, session_service: BaseSessionService | None
  ) -> TenantCryptoManager:
    """Returns a copy that can resolve tenants from sessions."""
    return TenantCryptoManager(
        enabled=self._enabled,
        tenant_state_key=self._tenant_state_key,
        require_tenant=self._require_tenant,
        isolation_manager=self._isolation_manager,
        session_service=session_service,
    )

  def scoped_tenant_id(self, tenant_id: str | None) -> str | None:
    """Returns the tenant id only when tenant crypto is enabled."""
    if not self._enabled:
      return None
    if tenant_id is None and self._require_tenant:
      raise PermissionError(
          'SecureADK per-tenant crypto requires a tenant id for signing.'
      )
    return tenant_id

  def resolve_local_tenant_id(
      self,
      *,
      app_name: str | None = None,
      user_id: str | None = None,
      state: Any | None = None,
      fallback_tenant_id: str | None = None,
  ) -> str | None:
    """Resolves tenant id without consulting persisted session state."""
    if not self._enabled:
      return None
    if fallback_tenant_id is not None:
      return fallback_tenant_id
    state_dict = self._state_dict(state)
    if self._tenant_state_key in state_dict:
      return state_dict[self._tenant_state_key]
    if app_name is not None and self._isolation_manager is not None:
      tenant_from_app_name = self._isolation_manager.tenant_from_app_name(
          app_name
      )
      if tenant_from_app_name is not None:
        return tenant_from_app_name
    if user_id is not None and self._isolation_manager is not None:
      bound_tenant = self._isolation_manager.resolve_user_tenant(user_id)
      if bound_tenant is not None:
        return bound_tenant
    return None

  def sign_value(
      self,
      *,
      keyring: HmacKeyring,
      value: Any,
      key_id: str,
      tenant_id: str | None = None,
  ) -> SignatureEnvelope:
    """Signs a payload in either global or tenant scope."""
    return keyring.sign_value(
        value,
        key_id=key_id,
        tenant_id=self.scoped_tenant_id(tenant_id),
    )

  def verify_value(
      self,
      *,
      keyring: HmacKeyring,
      value: Any,
      key_id: str,
      signature: str,
      signed_at: float | None = None,
      tenant_id: str | None = None,
  ) -> bool:
    """Verifies a payload in either global or tenant scope."""
    return keyring.verify_value(
        value,
        key_id=key_id,
        signature=signature,
        signed_at=signed_at,
        tenant_id=self.scoped_tenant_id(tenant_id),
    )

  async def resolve_tenant_id(
      self,
      *,
      app_name: str | None = None,
      user_id: str | None = None,
      session_id: str | None = None,
      state: Any | None = None,
      fallback_tenant_id: str | None = None,
  ) -> str | None:
    """Resolves tenant id from runtime state, session state, or namespacing."""
    tenant_id = self.resolve_local_tenant_id(
        app_name=app_name,
        user_id=user_id,
        state=state,
        fallback_tenant_id=fallback_tenant_id,
    )
    if tenant_id is not None or not self._enabled:
      return self.scoped_tenant_id(tenant_id)
    if (
        self._session_service is not None
        and app_name is not None
        and user_id is not None
        and session_id is not None
    ):
      session = await self._session_service.get_session(
          app_name=app_name,
          user_id=user_id,
          session_id=session_id,
      )
      if session is not None:
        return self.scoped_tenant_id(
            self._state_dict(session.state).get(self._tenant_state_key)
        )
    if self._require_tenant:
      raise PermissionError(
          'SecureADK per-tenant crypto could not resolve a tenant id.'
      )
    return None

  def envelope_metadata(
      self,
      *,
      envelope: SignatureEnvelope,
      metadata: dict[str, Any] | None = None,
  ) -> dict[str, Any]:
    """Adds tenant crypto metadata to a secure metadata payload."""
    metadata = dict(metadata or {})
    metadata.update({
        'keyScope': envelope.key_scope,
    })
    if envelope.tenant_id is not None:
      metadata['tenantId'] = envelope.tenant_id
    return metadata

  @staticmethod
  def _state_dict(state: Any | None) -> dict[str, Any]:
    if state is None:
      return {}
    if hasattr(state, 'to_dict'):
      return state.to_dict()
    if isinstance(state, dict):
      return state
    return dict(state)

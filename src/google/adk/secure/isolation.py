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
from typing import Optional
from typing import Union

from google.genai import types
from pydantic import BaseModel
from pydantic import ConfigDict
from typing_extensions import override

from ..artifacts.base_artifact_service import ArtifactVersion
from ..artifacts.base_artifact_service import BaseArtifactService
from ..sessions.base_session_service import BaseSessionService
from ..sessions.base_session_service import GetSessionConfig
from ..sessions.base_session_service import ListSessionsResponse
from ..sessions.session import Session

_TENANT_APP_MARKER = '::secureadk_tenant::'


class TenantIsolationBinding(BaseModel):
  """Static mapping between a user and a tenant."""

  model_config = ConfigDict(
      extra='forbid',
  )

  user_id: str
  tenant_id: str


class TenantIsolationManager:
  """Resolves and validates tenant boundaries for sessions and artifacts."""

  def __init__(
      self,
      *,
      bindings: list[TenantIsolationBinding],
      tenant_state_key: str = 'tenant_id',
      require_tenant: bool = True,
      enforce_identity_tenant_match: bool = True,
      require_session_scoped_artifacts: bool = True,
  ):
    self._binding_by_user = {binding.user_id: binding for binding in bindings}
    self._tenant_state_key = tenant_state_key
    self._require_tenant = require_tenant
    self._enforce_identity_tenant_match = enforce_identity_tenant_match
    self._require_session_scoped_artifacts = require_session_scoped_artifacts

  @property
  def tenant_state_key(self) -> str:
    return self._tenant_state_key

  def resolve_user_tenant(self, user_id: str) -> Optional[str]:
    binding = self._binding_by_user.get(user_id)
    return binding.tenant_id if binding is not None else None

  def validate_session_state(
      self,
      *,
      app_name: str,
      user_id: str,
      state: dict[str, Any],
      identity_tenant_id: Optional[str] = None,
  ) -> str:
    """Validates tenant affinity for a session state."""
    tenant_id = state.get(self._tenant_state_key)
    bound_tenant = self.resolve_user_tenant(user_id)
    if tenant_id is None:
      tenant_id = bound_tenant
      if tenant_id is not None:
        state[self._tenant_state_key] = tenant_id
    if tenant_id is None and self._require_tenant:
      raise PermissionError(
          f'SecureADK tenant isolation requires {self._tenant_state_key!r} in'
          f' session state for app {app_name!r}.'
      )
    if (
        bound_tenant is not None
        and tenant_id is not None
        and bound_tenant != tenant_id
    ):
      raise PermissionError(
          f'User {user_id!r} is bound to tenant {bound_tenant!r}, not'
          f' {tenant_id!r}.'
      )
    if (
        self._enforce_identity_tenant_match
        and identity_tenant_id is not None
        and tenant_id is not None
        and identity_tenant_id != tenant_id
    ):
      raise PermissionError(
          f'Agent identity tenant {identity_tenant_id!r} does not match'
          f' session tenant {tenant_id!r}.'
      )
    assert tenant_id is not None
    return tenant_id

  def validate_session(
      self,
      *,
      app_name: str,
      user_id: str,
      session: Session,
      identity_tenant_id: Optional[str] = None,
  ) -> str:
    """Validates an already-loaded session."""
    if session.app_name != app_name:
      raise PermissionError(
          f'Session app mismatch: expected {app_name!r}, found'
          f' {session.app_name!r}.'
      )
    return self.validate_session_state(
        app_name=app_name,
        user_id=user_id,
        state=session.state,
        identity_tenant_id=identity_tenant_id,
    )

  def require_artifact_session_scope(self, session_id: Optional[str]) -> None:
    if session_id is None and self._require_session_scoped_artifacts:
      raise PermissionError(
          'SecureADK tenant isolation requires session-scoped artifacts.'
      )

  @staticmethod
  def namespace_app_name(app_name: str, tenant_id: str) -> str:
    return f'{app_name}{_TENANT_APP_MARKER}{tenant_id}'

  @staticmethod
  def public_app_name(app_name: str) -> str:
    if _TENANT_APP_MARKER not in app_name:
      return app_name
    return app_name.split(_TENANT_APP_MARKER, maxsplit=1)[0]

  @staticmethod
  def tenant_from_app_name(app_name: str) -> Optional[str]:
    if _TENANT_APP_MARKER not in app_name:
      return None
    return app_name.split(_TENANT_APP_MARKER, maxsplit=1)[1]


class TenantIsolatedSessionService(BaseSessionService):
  """Session service wrapper that namespaces storage by tenant."""

  def __init__(
      self,
      *,
      delegate: BaseSessionService,
      isolation_manager: TenantIsolationManager,
  ):
    self._delegate = delegate
    self._isolation_manager = isolation_manager

  @override
  async def create_session(
      self,
      *,
      app_name: str,
      user_id: str,
      state: Optional[dict[str, Any]] = None,
      session_id: Optional[str] = None,
  ) -> Session:
    state = dict(state or {})
    tenant_id = self._isolation_manager.validate_session_state(
        app_name=app_name,
        user_id=user_id,
        state=state,
    )
    session = await self._delegate.create_session(
        app_name=self._isolation_manager.namespace_app_name(
            app_name, tenant_id
        ),
        user_id=user_id,
        state=state,
        session_id=session_id,
    )
    return session.model_copy(update={'app_name': app_name})

  @override
  async def get_session(
      self,
      *,
      app_name: str,
      user_id: str,
      session_id: str,
      config: Optional[GetSessionConfig] = None,
  ) -> Optional[Session]:
    tenant_id = self._isolation_manager.resolve_user_tenant(user_id)
    if tenant_id is None:
      raise PermissionError(f'No tenant binding found for user {user_id!r}.')
    session = await self._delegate.get_session(
        app_name=self._isolation_manager.namespace_app_name(
            app_name, tenant_id
        ),
        user_id=user_id,
        session_id=session_id,
        config=config,
    )
    if session is None:
      return None
    self._isolation_manager.validate_session(
        app_name=app_name,
        user_id=user_id,
        session=session.model_copy(update={'app_name': app_name}),
    )
    return session.model_copy(update={'app_name': app_name})

  @override
  async def list_sessions(
      self, *, app_name: str, user_id: Optional[str] = None
  ) -> ListSessionsResponse:
    if user_id is None:
      raise PermissionError(
          'Tenant-isolated session listing requires a user_id.'
      )
    tenant_id = self._isolation_manager.resolve_user_tenant(user_id)
    if tenant_id is None:
      raise PermissionError(f'No tenant binding found for user {user_id!r}.')
    response = await self._delegate.list_sessions(
        app_name=self._isolation_manager.namespace_app_name(
            app_name, tenant_id
        ),
        user_id=user_id,
    )
    return ListSessionsResponse(
        sessions=[
            session.model_copy(update={'app_name': app_name})
            for session in response.sessions
        ]
    )

  @override
  async def delete_session(
      self, *, app_name: str, user_id: str, session_id: str
  ) -> None:
    tenant_id = self._isolation_manager.resolve_user_tenant(user_id)
    if tenant_id is None:
      raise PermissionError(f'No tenant binding found for user {user_id!r}.')
    await self._delegate.delete_session(
        app_name=self._isolation_manager.namespace_app_name(
            app_name, tenant_id
        ),
        user_id=user_id,
        session_id=session_id,
    )


class TenantIsolatedArtifactService(BaseArtifactService):
  """Artifact service wrapper that enforces tenant-scoped storage."""

  def __init__(
      self,
      *,
      delegate: BaseArtifactService,
      session_service: BaseSessionService,
      isolation_manager: TenantIsolationManager,
  ):
    self._delegate = delegate
    self._session_service = session_service
    self._isolation_manager = isolation_manager

  async def _resolve_namespaced_app_name(
      self,
      *,
      app_name: str,
      user_id: str,
      session_id: Optional[str],
  ) -> str:
    self._isolation_manager.require_artifact_session_scope(session_id)
    tenant_id = self._isolation_manager.resolve_user_tenant(user_id)
    if session_id is not None:
      session = await self._session_service.get_session(
          app_name=app_name,
          user_id=user_id,
          session_id=session_id,
      )
      if session is None:
        raise PermissionError(
            f'Session {session_id!r} not found for artifact access.'
        )
      tenant_id = self._isolation_manager.validate_session(
          app_name=app_name,
          user_id=user_id,
          session=session,
      )
    if tenant_id is None:
      raise PermissionError(f'No tenant binding found for user {user_id!r}.')
    return self._isolation_manager.namespace_app_name(app_name, tenant_id)

  @override
  async def save_artifact(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      artifact: Union[types.Part, dict[str, Any]],
      session_id: Optional[str] = None,
      custom_metadata: Optional[dict[str, Any]] = None,
  ) -> int:
    return await self._delegate.save_artifact(
        app_name=await self._resolve_namespaced_app_name(
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
        ),
        user_id=user_id,
        filename=filename,
        artifact=artifact,
        session_id=session_id,
        custom_metadata=custom_metadata,
    )

  @override
  async def load_artifact(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      session_id: Optional[str] = None,
      version: Optional[int] = None,
  ) -> Optional[types.Part]:
    return await self._delegate.load_artifact(
        app_name=await self._resolve_namespaced_app_name(
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
        ),
        user_id=user_id,
        filename=filename,
        session_id=session_id,
        version=version,
    )

  @override
  async def list_artifact_keys(
      self, *, app_name: str, user_id: str, session_id: Optional[str] = None
  ) -> list[str]:
    return await self._delegate.list_artifact_keys(
        app_name=await self._resolve_namespaced_app_name(
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
        ),
        user_id=user_id,
        session_id=session_id,
    )

  @override
  async def delete_artifact(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      session_id: Optional[str] = None,
  ) -> None:
    await self._delegate.delete_artifact(
        app_name=await self._resolve_namespaced_app_name(
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
        ),
        user_id=user_id,
        filename=filename,
        session_id=session_id,
    )

  @override
  async def list_versions(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      session_id: Optional[str] = None,
  ) -> list[int]:
    return await self._delegate.list_versions(
        app_name=await self._resolve_namespaced_app_name(
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
        ),
        user_id=user_id,
        filename=filename,
        session_id=session_id,
    )

  @override
  async def list_artifact_versions(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      session_id: Optional[str] = None,
  ) -> list[ArtifactVersion]:
    return await self._delegate.list_artifact_versions(
        app_name=await self._resolve_namespaced_app_name(
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
        ),
        user_id=user_id,
        filename=filename,
        session_id=session_id,
    )

  @override
  async def get_artifact_version(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      session_id: Optional[str] = None,
      version: Optional[int] = None,
  ) -> Optional[ArtifactVersion]:
    return await self._delegate.get_artifact_version(
        app_name=await self._resolve_namespaced_app_name(
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
        ),
        user_id=user_id,
        filename=filename,
        session_id=session_id,
        version=version,
    )

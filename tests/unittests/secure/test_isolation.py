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

import asyncio

from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
from google.adk.secure import TenantIsolatedArtifactService
from google.adk.secure import TenantIsolatedSessionService
from google.adk.secure import TenantIsolationBinding
from google.adk.secure import TenantIsolationManager
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.genai import types
import pytest


def _build_manager() -> TenantIsolationManager:
  return TenantIsolationManager(
      bindings=[TenantIsolationBinding(user_id='alice', tenant_id='tenant-a')]
  )


def test_tenant_isolated_session_service_namespaces_storage() -> None:
  delegate = InMemorySessionService()
  session_service = TenantIsolatedSessionService(
      delegate=delegate,
      isolation_manager=_build_manager(),
  )

  session = asyncio.run(
      session_service.create_session(
          app_name='courtroom',
          user_id='alice',
          state={'tenant_id': 'tenant-a'},
      )
  )
  loaded = asyncio.run(
      session_service.get_session(
          app_name='courtroom',
          user_id='alice',
          session_id=session.id,
      )
  )

  assert session.app_name == 'courtroom'
  assert loaded is not None
  assert loaded.app_name == 'courtroom'
  assert list(delegate.sessions) == ['courtroom::secureadk_tenant::tenant-a']


def test_tenant_isolated_artifact_service_requires_session_scope() -> None:
  artifact_service = TenantIsolatedArtifactService(
      delegate=InMemoryArtifactService(),
      session_service=TenantIsolatedSessionService(
          delegate=InMemorySessionService(),
          isolation_manager=_build_manager(),
      ),
      isolation_manager=_build_manager(),
  )

  with pytest.raises(PermissionError):
    asyncio.run(
        artifact_service.save_artifact(
            app_name='courtroom',
            user_id='alice',
            filename='evidence.txt',
            artifact=types.Part(text='sealed'),
        )
    )


def test_tenant_isolated_artifact_service_uses_namespaced_storage() -> None:
  session_delegate = InMemorySessionService()
  artifact_delegate = InMemoryArtifactService()
  isolation_manager = _build_manager()
  session_service = TenantIsolatedSessionService(
      delegate=session_delegate,
      isolation_manager=isolation_manager,
  )
  artifact_service = TenantIsolatedArtifactService(
      delegate=artifact_delegate,
      session_service=session_service,
      isolation_manager=isolation_manager,
  )
  session = asyncio.run(
      session_service.create_session(
          app_name='courtroom',
          user_id='alice',
          state={'tenant_id': 'tenant-a'},
      )
  )

  version = asyncio.run(
      artifact_service.save_artifact(
          app_name='courtroom',
          user_id='alice',
          session_id=session.id,
          filename='evidence.txt',
          artifact=types.Part(text='sealed'),
      )
  )
  artifact = asyncio.run(
      artifact_service.load_artifact(
          app_name='courtroom',
          user_id='alice',
          session_id=session.id,
          filename='evidence.txt',
          version=version,
      )
  )

  assert artifact is not None
  assert artifact.text == 'sealed'
  assert list(artifact_delegate.artifacts) == [
      f'courtroom::secureadk_tenant::tenant-a/alice/{session.id}/evidence.txt'
  ]

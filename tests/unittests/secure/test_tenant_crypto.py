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

from google.adk.secure import TenantCryptoManager
from google.adk.secure import TenantIsolationBinding
from google.adk.secure import TenantIsolationManager
import pytest


def test_tenant_crypto_manager_resolves_tenants_from_state_app_and_user() -> (
    None
):
  isolation_manager = TenantIsolationManager(
      bindings=[TenantIsolationBinding(user_id='alice', tenant_id='tenant-a')],
      require_tenant=True,
  )
  manager = TenantCryptoManager(
      enabled=True,
      require_tenant=True,
      isolation_manager=isolation_manager,
  )

  assert (
      manager.resolve_local_tenant_id(state={'tenant_id': 'tenant-state'})
      == 'tenant-state'
  )
  assert (
      manager.resolve_local_tenant_id(
          app_name=TenantIsolationManager.namespace_app_name(
              'courtroom', 'tenant-app'
          )
      )
      == 'tenant-app'
  )
  assert manager.resolve_local_tenant_id(user_id='alice') == 'tenant-a'
  assert (
      asyncio.run(
          manager.resolve_tenant_id(fallback_tenant_id='tenant-fallback')
      )
      == 'tenant-fallback'
  )


def test_tenant_crypto_manager_requires_tenant_when_enabled() -> None:
  manager = TenantCryptoManager(enabled=True, require_tenant=True)

  with pytest.raises(PermissionError, match='could not resolve a tenant id'):
    asyncio.run(manager.resolve_tenant_id())

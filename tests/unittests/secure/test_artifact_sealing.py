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

from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
from google.adk.secure.artifact_sealing import SEAL_METADATA_KEY
from google.adk.secure.artifact_sealing import SealedArtifactService
from google.adk.secure.provenance import InMemoryProvenanceLedger
from google.adk.secure.signing import HmacKeyring
from google.genai import types
import pytest


@pytest.mark.asyncio
async def test_sealed_artifact_service_persists_and_verifies_seals():
  delegate = InMemoryArtifactService()
  ledger = InMemoryProvenanceLedger()
  service = SealedArtifactService(
      delegate=delegate,
      keyring=HmacKeyring({'seal-key': 'artifact-secret'}),
      signing_key_id='seal-key',
      actor='omniseal-adapter',
      ledger=ledger,
  )

  version = await service.save_artifact(
      app_name='courtroom',
      user_id='clerk',
      session_id='session-1',
      filename='evidence/report.txt',
      artifact=types.Part(text='sealed-evidence'),
  )

  assert version == 0

  version_meta = await service.get_artifact_version(
      app_name='courtroom',
      user_id='clerk',
      session_id='session-1',
      filename='evidence/report.txt',
  )
  assert version_meta is not None
  assert SEAL_METADATA_KEY in version_meta.custom_metadata

  verification = await service.verify_artifact(
      app_name='courtroom',
      user_id='clerk',
      session_id='session-1',
      filename='evidence/report.txt',
  )
  assert verification.valid

  ledger_entries = await ledger.list_entries()
  assert ledger_entries[0].event_type == 'artifact_sealed'

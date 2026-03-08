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
from pathlib import Path

from google.adk.secure import DeploymentAttestor
from google.adk.secure import HmacKeyring
from google.adk.secure import InMemoryLineageStore
from google.adk.secure import InMemoryProvenanceLedger
from google.adk.secure import LineageTracker


def test_deployment_attestor_builds_verifies_and_records_attestations(
    tmp_path: Path,
) -> None:
  source_root = tmp_path / 'agent'
  source_root.mkdir()
  (source_root / 'agent.py').write_text('root_agent = object()\n')

  ledger = InMemoryProvenanceLedger()
  lineage_tracker = LineageTracker(store=InMemoryLineageStore())
  attestor = DeploymentAttestor(
      keyring=HmacKeyring({'deploy-key': 'secret'}),
      signing_key_id='deploy-key',
      ledger=ledger,
      lineage_tracker=lineage_tracker,
  )

  attestation = attestor.build_attestation(
      app_name='courtroom',
      deployment_target='cloud_run',
      source_root=source_root,
      metadata={'adkVersion': '1.0.0'},
  )

  assert attestation.key_id == 'deploy-key'
  assert attestation.component_hashes == {
      'agent.py': attestation.component_hashes['agent.py']
  }
  assert attestor.verify_attestation(
      attestation,
      source_root=source_root,
  ).valid

  output_path = tmp_path / 'attestation.json'
  attestor.write_attestation(attestation, output_path=output_path)
  loaded = attestor.load_attestation(output_path)
  assert loaded.attestation_id == attestation.attestation_id

  asyncio.run(attestor.record_attestation(attestation, verified=True))
  ledger_entries = asyncio.run(ledger.list_entries())
  assert ledger_entries[0].event_type == 'deployment_attested'
  assert ledger_entries[0].payload['verified'] is True
  lineage_records = asyncio.run(lineage_tracker.list_records())
  assert lineage_records[0].record_type == 'deployment_attestation'

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

from google.adk.secure import EvidenceBundle
from google.adk.secure import InMemoryLineageStore
from google.adk.secure import InMemoryProvenanceLedger
from google.adk.secure import LineageTracker
from google.adk.secure import SecureReplayDiffer


def test_secure_replay_differ_detects_invocation_changes() -> None:
  ledger = InMemoryProvenanceLedger()
  lineage = LineageTracker(store=InMemoryLineageStore())
  asyncio.run(
      ledger.append(
          event_type='invocation_started',
          payload={'userContentHash': 'hash-a'},
          invocation_id='left',
      )
  )
  asyncio.run(
      ledger.append(
          event_type='invocation_started',
          payload={'userContentHash': 'hash-b'},
          invocation_id='right',
      )
  )
  asyncio.run(
      lineage.record(
          record_type='model_response',
          entity_id='left-response',
          invocation_id='left',
          payload={'responseHash': 'response-a'},
      )
  )
  asyncio.run(
      lineage.record(
          record_type='model_response',
          entity_id='right-response',
          invocation_id='right',
          payload={'responseHash': 'response-b'},
      )
  )

  differ = SecureReplayDiffer()
  report = differ.diff_invocations(
      left_invocation_id='left',
      right_invocation_id='right',
      left_ledger_entries=[
          entry
          for entry in asyncio.run(ledger.list_entries())
          if entry.invocation_id == 'left'
      ],
      right_ledger_entries=[
          entry
          for entry in asyncio.run(ledger.list_entries())
          if entry.invocation_id == 'right'
      ],
      left_lineage_records=[
          record
          for record in asyncio.run(lineage.list_records())
          if record.invocation_id == 'left'
      ],
      right_lineage_records=[
          record
          for record in asyncio.run(lineage.list_records())
          if record.invocation_id == 'right'
      ],
  )

  assert not report.valid
  assert report.difference_count >= 2


def test_secure_replay_differ_detects_bundle_changes() -> None:
  differ = SecureReplayDiffer()
  left_bundle = EvidenceBundle(
      bundle_id='bundle-left',
      bundle_type='invocation',
      key_id='bundle-key',
      payload_hash='hash-left',
      signature='sig-left',
      signed_at=1.0,
      payload={'responseSignatures': [{'signature': 'a'}]},
  )
  right_bundle = EvidenceBundle(
      bundle_id='bundle-right',
      bundle_type='invocation',
      key_id='bundle-key',
      payload_hash='hash-right',
      signature='sig-right',
      signed_at=2.0,
      payload={'responseSignatures': [{'signature': 'b'}]},
  )

  report = differ.diff_bundles(
      left_bundle=left_bundle,
      right_bundle=right_bundle,
  )

  assert not report.valid
  assert report.differences[0].field_name == 'responseSignatures'

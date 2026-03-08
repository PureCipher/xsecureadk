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

from google.adk.secure import InMemoryLineageStore
from google.adk.secure import LineageTracker


def test_lineage_tracker_links_parent_records() -> None:
  tracker = LineageTracker(store=InMemoryLineageStore())

  prompt_record = asyncio.run(
      tracker.record(
          record_type='prompt',
          entity_id='invocation:1:prompt',
          app_name='courtroom',
          payload={'prompt': 'start trial'},
      )
  )
  response_record = asyncio.run(
      tracker.record(
          record_type='model_response',
          entity_id='invocation:1:model_response:judge',
          app_name='courtroom',
          payload={'response': 'verdict'},
          parent_entities=('invocation:1:prompt',),
      )
  )

  assert response_record.parent_ids == [prompt_record.record_id]
  assert response_record.payload_hash

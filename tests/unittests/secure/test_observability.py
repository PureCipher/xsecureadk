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

from google.adk.secure import BigQuerySecureEventSink
from google.adk.secure import InMemoryProvenanceLedger
from google.adk.secure import InMemorySecureEventSink
from google.adk.secure import SecureEvent
from google.adk.secure import TelemetryRedactor
from google.adk.secure.observability import ObservableProvenanceLedger
from google.adk.secure.observability import RedactingSecureEventSink


def test_observable_provenance_ledger_emits_redacted_secure_events() -> None:
  sink = InMemorySecureEventSink()
  ledger = ObservableProvenanceLedger(
      delegate=InMemoryProvenanceLedger(),
      event_sink=RedactingSecureEventSink(
          delegate=sink,
          redactor=TelemetryRedactor(),
      ),
  )

  asyncio.run(
      ledger.append(
          event_type='invocation_started',
          app_name='courtroom',
          user_id='alice',
          session_id='session-1',
          invocation_id='inv-1',
          payload={
              'email': 'alice@example.com',
              'tenantId': 'tenant-a',
          },
      )
  )

  assert len(sink.events) == 1
  event = sink.events[0]
  assert event.source == 'ledger'
  assert event.payload['email'] == '<redacted>'
  assert event.tenant_id == 'tenant-a'
  assert event.attributes['sequence'] == 1


def test_bigquery_secure_event_sink_inserts_rows() -> None:
  inserted = {}

  class _FakeBigQueryClient:

    def insert_rows_json(self, table_id, rows):
      inserted['table_id'] = table_id
      inserted['rows'] = rows
      return []

  sink = BigQuerySecureEventSink(
      project_id='project-a',
      dataset='secure',
      table='events',
      client=_FakeBigQueryClient(),
  )

  asyncio.run(
      sink.emit_events(
          sink_events := [
              SecureEvent(
                  event_id='event-1',
                  timestamp=1.0,
                  event_type='model_response_signed',
                  source='ledger',
                  app_name='courtroom',
                  payload={'caseId': 'case-1'},
                  attributes={},
              )
          ]
      )
  )

  assert inserted['table_id'] == 'project-a.secure.events'
  assert inserted['rows'][0]['event_type'] == sink_events[0].event_type

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
import json
import logging
from pathlib import Path
import urllib.request

from google.adk.secure import AnomalyAlert
from google.adk.secure import FileAnomalyAlertSink
from google.adk.secure import LoggingAnomalyAlertSink
from google.adk.secure import WebhookAnomalyAlertSink
from google.adk.secure.signing import HmacKeyring


def _sample_alert() -> AnomalyAlert:
  return AnomalyAlert(
      alert_type='possible_agent_collusion',
      severity=1.0,
      reason='Matching response hashes observed.',
      app_name='courtroom',
      user_id='alice',
      session_id='session-1',
      invocation_id='inv-1',
      agent_name='judge',
      payload={'matchingAgents': ['clerk', 'judge']},
  )


def test_logging_anomaly_alert_sink_logs_json(caplog) -> None:
  sink = LoggingAnomalyAlertSink(
      logger_name='google_adk.test.secure.alerts',
      level='WARNING',
  )

  with caplog.at_level(logging.WARNING, logger='google_adk.test.secure.alerts'):
    asyncio.run(sink.emit_alerts([_sample_alert()]))

  assert caplog.records
  assert 'possible_agent_collusion' in caplog.records[0].message


def test_file_anomaly_alert_sink_writes_jsonl(tmp_path: Path) -> None:
  output_path = tmp_path / 'alerts.jsonl'
  sink = FileAnomalyAlertSink(output_path)

  asyncio.run(sink.emit_alerts([_sample_alert()]))

  lines = output_path.read_text(encoding='utf-8').splitlines()
  assert len(lines) == 1
  payload = json.loads(lines[0])
  assert payload['alert_type'] == 'possible_agent_collusion'


def test_webhook_anomaly_alert_sink_posts_signed_payload(monkeypatch) -> None:
  captured = {}

  class _FakeResponse:

    status = 200

    def __enter__(self):
      return self

    def __exit__(self, exc_type, exc_val, exc_tb):
      return False

    def getcode(self) -> int:
      return self.status

  def _fake_urlopen(
      request: urllib.request.Request, timeout: float
  ) -> _FakeResponse:
    captured['url'] = request.full_url
    captured['timeout'] = timeout
    captured['headers'] = dict(request.header_items())
    captured['payload'] = json.loads(request.data.decode('utf-8'))
    return _FakeResponse()

  monkeypatch.setattr(urllib.request, 'urlopen', _fake_urlopen)

  sink = WebhookAnomalyAlertSink(
      url='https://example.test/secureadk/anomalies',
      timeout_seconds=2.0,
      headers={'X-Test-Header': 'ok'},
      keyring=HmacKeyring({'judge-key': 'secret'}),
      signing_key_id='judge-key',
  )

  asyncio.run(sink.emit_alerts([_sample_alert()]))

  assert captured['url'] == 'https://example.test/secureadk/anomalies'
  assert captured['timeout'] == 2.0
  headers_by_lower_name = {
      key.lower(): value for key, value in captured['headers'].items()
  }
  assert headers_by_lower_name['x-test-header'] == 'ok'
  assert headers_by_lower_name['x-secureadk-key-id'] == 'judge-key'
  assert headers_by_lower_name['x-secureadk-signature']
  assert captured['payload']['alerts'][0]['alert_type'] == (
      'possible_agent_collusion'
  )

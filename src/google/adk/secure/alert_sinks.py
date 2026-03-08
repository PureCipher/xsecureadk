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

import abc
import asyncio
from collections.abc import Sequence
import logging
from pathlib import Path
import urllib.request

from .anomaly import AnomalyAlert
from .signing import canonical_json_bytes
from .signing import HmacKeyring

logger = logging.getLogger('google_adk.' + __name__)


class BaseAnomalyAlertSink(abc.ABC):
  """Base interface for operational anomaly alert delivery."""

  @abc.abstractmethod
  async def emit_alerts(self, alerts: Sequence[AnomalyAlert]) -> None:
    """Emits one or more anomaly alerts."""


class InMemoryAnomalyAlertSink(BaseAnomalyAlertSink):
  """Captures alerts in memory for tests and local verification."""

  def __init__(self):
    self._alerts: list[AnomalyAlert] = []

  @property
  def alerts(self) -> list[AnomalyAlert]:
    return list(self._alerts)

  async def emit_alerts(self, alerts: Sequence[AnomalyAlert]) -> None:
    self._alerts.extend(alert.model_copy(deep=True) for alert in alerts)


class LoggingAnomalyAlertSink(BaseAnomalyAlertSink):
  """Writes anomaly alerts to the configured Python logger."""

  def __init__(
      self,
      *,
      logger_name: str = 'google_adk.secure.anomaly_alerts',
      level: str = 'WARNING',
  ):
    self._logger = logging.getLogger(logger_name)
    self._level = logging.getLevelName(level.upper())
    if isinstance(self._level, str):
      raise ValueError(f'Unknown logging level {level!r}.')

  async def emit_alerts(self, alerts: Sequence[AnomalyAlert]) -> None:
    for alert in alerts:
      self._logger.log(
          self._level,
          'SecureADK anomaly alert: %s',
          alert.model_dump_json(
              by_alias=True,
              exclude_none=True,
          ),
      )


class FileAnomalyAlertSink(BaseAnomalyAlertSink):
  """Exports anomaly alerts as JSONL for external processing."""

  def __init__(self, path: str | Path):
    self._path = Path(path)
    self._path.parent.mkdir(parents=True, exist_ok=True)
    self._lock = asyncio.Lock()

  @property
  def path(self) -> Path:
    return self._path

  async def emit_alerts(self, alerts: Sequence[AnomalyAlert]) -> None:
    if not alerts:
      return
    async with self._lock:
      with self._path.open('a', encoding='utf-8') as handle:
        for alert in alerts:
          handle.write(
              alert.model_dump_json(
                  by_alias=True,
                  exclude_none=True,
              )
          )
          handle.write('\n')


class WebhookAnomalyAlertSink(BaseAnomalyAlertSink):
  """Posts anomaly alerts to an external webhook endpoint."""

  def __init__(
      self,
      *,
      url: str,
      timeout_seconds: float = 5.0,
      headers: dict[str, str] | None = None,
      keyring: HmacKeyring | None = None,
      signing_key_id: str | None = None,
  ):
    self._url = url
    self._timeout_seconds = timeout_seconds
    self._headers = dict(headers or {})
    self._keyring = keyring
    self._signing_key_id = signing_key_id
    if bool(self._keyring) != bool(self._signing_key_id):
      raise ValueError(
          'Webhook anomaly sink requires both keyring and signing_key_id, or'
          ' neither.'
      )

  async def emit_alerts(self, alerts: Sequence[AnomalyAlert]) -> None:
    if not alerts:
      return
    payload = {
        'alerts': [
            alert.model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            )
            for alert in alerts
        ]
    }
    headers = {
        'Content-Type': 'application/json',
        **self._headers,
    }
    if self._keyring is not None and self._signing_key_id is not None:
      envelope = self._keyring.sign_value(payload, key_id=self._signing_key_id)
      headers.update({
          'X-SecureADK-Key-Id': self._signing_key_id,
          'X-SecureADK-Payload-Hash': envelope.payload_hash,
          'X-SecureADK-Signature': envelope.signature,
      })
    request = urllib.request.Request(
        self._url,
        data=canonical_json_bytes(payload),
        headers=headers,
        method='POST',
    )
    await asyncio.to_thread(self._send_request, request)

  def _send_request(self, request: urllib.request.Request) -> None:
    with urllib.request.urlopen(
        request,
        timeout=self._timeout_seconds,
    ) as response:
      status_code = getattr(response, 'status', response.getcode())
      if status_code >= 400:
        raise ValueError(
            f'SecureADK webhook anomaly sink failed with status {status_code}.'
        )


class CompositeAnomalyAlertSink(BaseAnomalyAlertSink):
  """Dispatches anomaly alerts to multiple operational sinks."""

  def __init__(
      self,
      sinks: Sequence[BaseAnomalyAlertSink],
      *,
      fail_closed: bool = False,
  ):
    self._sinks = list(sinks)
    self._fail_closed = fail_closed

  async def emit_alerts(self, alerts: Sequence[AnomalyAlert]) -> None:
    if not alerts:
      return
    errors = []
    for sink in self._sinks:
      try:
        await sink.emit_alerts(alerts)
      except Exception as exc:  # pragma: no cover - exercised in tests.
        logger.warning(
            'SecureADK anomaly alert sink %s failed.',
            sink.__class__.__name__,
            exc_info=exc,
        )
        errors.append(exc)
    if errors and self._fail_closed:
      raise errors[0]

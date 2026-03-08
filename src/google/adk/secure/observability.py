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
import logging
from pathlib import Path
from typing import Any
import urllib.request

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from ..platform import time as platform_time
from ..telemetry import tracing
from .alert_sinks import BaseAnomalyAlertSink
from .anomaly import AnomalyAlert
from .lineage import LineageRecord
from .lineage import LineageTracker
from .privacy import TelemetryRedactor
from .provenance import BaseProvenanceLedger
from .provenance import LedgerEntry
from .signing import canonical_json_bytes
from .signing import HmacKeyring

logger = logging.getLogger('google_adk.' + __name__)


class SecureEvent(BaseModel):
  """Normalized SecureADK event for observability and SIEM export."""

  model_config = ConfigDict(
      extra='forbid',
  )

  event_id: str
  timestamp: float
  event_type: str
  source: str
  app_name: str | None = None
  user_id: str | None = None
  session_id: str | None = None
  invocation_id: str | None = None
  actor: str | None = None
  tenant_id: str | None = None
  case_id: str | None = None
  severity: float | None = None
  payload: dict[str, Any] = Field(default_factory=dict)
  attributes: dict[str, Any] = Field(default_factory=dict)


class BaseSecureEventSink(abc.ABC):
  """Base interface for SecureADK observability and SIEM sinks."""

  @abc.abstractmethod
  async def emit_events(self, events: list[SecureEvent]) -> None:
    """Emits one or more secure events."""


class InMemorySecureEventSink(BaseSecureEventSink):
  """Captures secure events in memory for tests and dashboards."""

  def __init__(self):
    self._events: list[SecureEvent] = []

  @property
  def events(self) -> list[SecureEvent]:
    return [event.model_copy(deep=True) for event in self._events]

  async def emit_events(self, events: list[SecureEvent]) -> None:
    self._events.extend(event.model_copy(deep=True) for event in events)


class LoggingSecureEventSink(BaseSecureEventSink):
  """Writes SecureADK events to the configured Python logger."""

  def __init__(
      self,
      *,
      logger_name: str = 'google_adk.secure.events',
      level: str = 'INFO',
  ):
    self._logger = logging.getLogger(logger_name)
    self._level = logging.getLevelName(level.upper())
    if isinstance(self._level, str):
      raise ValueError(f'Unknown logging level {level!r}.')

  async def emit_events(self, events: list[SecureEvent]) -> None:
    for event in events:
      self._logger.log(
          self._level,
          'SecureADK event: %s',
          event.model_dump_json(
              by_alias=True,
              exclude_none=True,
          ),
      )


class FileSecureEventSink(BaseSecureEventSink):
  """Exports SecureADK events as JSONL."""

  def __init__(self, path: str | Path):
    self._path = Path(path)
    self._path.parent.mkdir(parents=True, exist_ok=True)
    self._lock = asyncio.Lock()

  @property
  def path(self) -> Path:
    return self._path

  async def emit_events(self, events: list[SecureEvent]) -> None:
    if not events:
      return
    async with self._lock:
      with self._path.open('a', encoding='utf-8') as handle:
        for event in events:
          handle.write(
              event.model_dump_json(
                  by_alias=True,
                  exclude_none=True,
              )
          )
          handle.write('\n')


class WebhookSecureEventSink(BaseSecureEventSink):
  """Posts SecureADK events to an external webhook endpoint."""

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
          'Webhook secure event sink requires both keyring and signing_key_id,'
          ' or neither.'
      )

  async def emit_events(self, events: list[SecureEvent]) -> None:
    if not events:
      return
    payload = {
        'events': [
            event.model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            )
            for event in events
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
            f'SecureADK webhook sink failed with status {status_code}.'
        )


class OpenTelemetrySecureEventSink(BaseSecureEventSink):
  """Emits SecureADK events as OpenTelemetry span events."""

  def __init__(
      self,
      *,
      event_name_prefix: str = 'secureadk',
      span_name: str = 'secureadk.observe',
  ):
    self._event_name_prefix = event_name_prefix
    self._span_name = span_name

  async def emit_events(self, events: list[SecureEvent]) -> None:
    for event in events:
      current_span = tracing.trace.get_current_span()
      if current_span.get_span_context().is_valid:
        self._add_span_event(current_span, event)
        continue
      with tracing.tracer.start_as_current_span(self._span_name) as span:
        self._add_span_event(span, event)

  def _add_span_event(self, span, event: SecureEvent) -> None:
    span.add_event(
        f'{self._event_name_prefix}.{event.source}.{event.event_type}',
        attributes={
            'secureadk.event_id': event.event_id,
            'secureadk.source': event.source,
            'secureadk.app_name': event.app_name or '',
            'secureadk.user_id': event.user_id or '',
            'secureadk.session_id': event.session_id or '',
            'secureadk.invocation_id': event.invocation_id or '',
            'secureadk.actor': event.actor or '',
            'secureadk.tenant_id': event.tenant_id or '',
            'secureadk.case_id': event.case_id or '',
            'secureadk.severity': (
                event.severity if event.severity is not None else 0.0
            ),
            'secureadk.payload': event.model_dump_json(
                by_alias=True,
                exclude_none=True,
            ),
        },
    )


class SplunkHecSecureEventSink(BaseSecureEventSink):
  """Sends SecureADK events to Splunk HTTP Event Collector."""

  def __init__(
      self,
      *,
      url: str,
      token: str,
      timeout_seconds: float = 5.0,
      source: str = 'secureadk',
      sourcetype: str = '_json',
      host: str | None = None,
  ):
    self._url = url
    self._token = token
    self._timeout_seconds = timeout_seconds
    self._source = source
    self._sourcetype = sourcetype
    self._host = host

  async def emit_events(self, events: list[SecureEvent]) -> None:
    for event in events:
      payload = {
          'time': event.timestamp,
          'event': event.model_dump(
              by_alias=True,
              exclude_none=True,
              mode='json',
          ),
          'source': self._source,
          'sourcetype': self._sourcetype,
      }
      if self._host is not None:
        payload['host'] = self._host
      request = urllib.request.Request(
          self._url,
          data=canonical_json_bytes(payload),
          headers={
              'Authorization': f'Splunk {self._token}',
              'Content-Type': 'application/json',
          },
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
            f'SecureADK Splunk sink failed with status {status_code}.'
        )


class DatadogSecureEventSink(BaseSecureEventSink):
  """Sends SecureADK events to Datadog logs intake."""

  def __init__(
      self,
      *,
      api_key: str,
      url: str = 'https://http-intake.logs.datadoghq.com/api/v2/logs',
      timeout_seconds: float = 5.0,
      service: str = 'adk',
      source: str = 'secureadk',
      tags: tuple[str, ...] = (),
  ):
    self._api_key = api_key
    self._url = url
    self._timeout_seconds = timeout_seconds
    self._service = service
    self._source = source
    self._tags = tags

  async def emit_events(self, events: list[SecureEvent]) -> None:
    if not events:
      return
    payload = [
        {
            'message': event.event_type,
            'service': self._service,
            'ddsource': self._source,
            'ddtags': ','.join(self._tags),
            **event.model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            ),
        }
        for event in events
    ]
    request = urllib.request.Request(
        self._url,
        data=canonical_json_bytes(payload),
        headers={
            'DD-API-KEY': self._api_key,
            'Content-Type': 'application/json',
        },
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
            f'SecureADK Datadog sink failed with status {status_code}.'
        )


class BigQuerySecureEventSink(BaseSecureEventSink):
  """Sends SecureADK events to BigQuery."""

  def __init__(
      self,
      *,
      dataset: str,
      table: str,
      project_id: str | None = None,
      client: Any | None = None,
  ):
    self._dataset = dataset
    self._table = table
    self._project_id = project_id
    self._client = client

  async def emit_events(self, events: list[SecureEvent]) -> None:
    if not events:
      return
    await asyncio.to_thread(self._insert_rows, events)

  def _insert_rows(self, events: list[SecureEvent]) -> None:
    client = self._client
    if client is None:
      from google.cloud import bigquery  # pylint: disable=g-import-not-at-top

      client = bigquery.Client(project=self._project_id)
    table_id = '.'.join(
        value
        for value in (self._project_id, self._dataset, self._table)
        if value
    )
    errors = client.insert_rows_json(
        table_id,
        [
            event.model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            )
            for event in events
        ],
    )
    if errors:
      raise ValueError(f'SecureADK BigQuery sink failed: {errors}')


class CompositeSecureEventSink(BaseSecureEventSink):
  """Dispatches SecureADK events to multiple sinks."""

  def __init__(
      self,
      sinks: list[BaseSecureEventSink],
      *,
      fail_closed: bool = False,
  ):
    self._sinks = list(sinks)
    self._fail_closed = fail_closed

  async def emit_events(self, events: list[SecureEvent]) -> None:
    if not events:
      return
    errors = []
    for sink in self._sinks:
      try:
        await sink.emit_events(events)
      except Exception as exc:  # pragma: no cover
        logger.warning(
            'SecureADK secure event sink %s failed.',
            sink.__class__.__name__,
            exc_info=exc,
        )
        errors.append(exc)
    if errors and self._fail_closed:
      raise errors[0]


class RedactingSecureEventSink(BaseSecureEventSink):
  """Applies privacy-aware redaction before emitting secure events."""

  def __init__(
      self,
      *,
      delegate: BaseSecureEventSink,
      redactor: TelemetryRedactor,
  ):
    self._delegate = delegate
    self._redactor = redactor

  async def emit_events(self, events: list[SecureEvent]) -> None:
    await self._delegate.emit_events([
        event.model_copy(
            update={
                'payload': self._redactor.redact(event.payload),
                'attributes': self._redactor.redact(event.attributes),
            }
        )
        for event in events
    ])


class ObservableProvenanceLedger(BaseProvenanceLedger):
  """Mirrors provenance ledger appends to observability sinks."""

  def __init__(
      self,
      *,
      delegate: BaseProvenanceLedger,
      event_sink: BaseSecureEventSink,
  ):
    self._delegate = delegate
    self._event_sink = event_sink

  async def append(
      self,
      *,
      event_type: str,
      payload: dict[str, Any],
      actor: str | None = None,
      app_name: str | None = None,
      user_id: str | None = None,
      session_id: str | None = None,
      invocation_id: str | None = None,
  ) -> LedgerEntry:
    entry = await self._delegate.append(
        event_type=event_type,
        payload=payload,
        actor=actor,
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
        invocation_id=invocation_id,
    )
    await self._event_sink.emit_events([ledger_entry_to_secure_event(entry)])
    return entry

  async def list_entries(self) -> list[LedgerEntry]:
    return await self._delegate.list_entries()

  async def verify_chain(self) -> bool:
    return await self._delegate.verify_chain()


class ObservableLineageTracker:
  """Mirrors lineage records to observability sinks."""

  def __init__(
      self,
      *,
      delegate: LineageTracker,
      event_sink: BaseSecureEventSink,
  ):
    self._delegate = delegate
    self._event_sink = event_sink

  async def record(
      self,
      *,
      record_type: str,
      entity_id: str,
      payload: dict[str, Any],
      entity_version: str | None = None,
      app_name: str | None = None,
      user_id: str | None = None,
      session_id: str | None = None,
      invocation_id: str | None = None,
      parent_entities: tuple[str, ...] = (),
  ) -> LineageRecord:
    record = await self._delegate.record(
        record_type=record_type,
        entity_id=entity_id,
        payload=payload,
        entity_version=entity_version,
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
        invocation_id=invocation_id,
        parent_entities=parent_entities,
    )
    await self._event_sink.emit_events([lineage_record_to_secure_event(record)])
    return record

  async def list_records(self) -> list[LineageRecord]:
    return await self._delegate.list_records()


class ObservableAnomalyAlertSink(BaseAnomalyAlertSink):
  """Mirrors anomaly alerts to secure observability sinks."""

  def __init__(
      self,
      *,
      event_sink: BaseSecureEventSink,
      delegate: Any | None = None,
  ):
    self._event_sink = event_sink
    self._delegate = delegate

  async def emit_alerts(self, alerts: list[AnomalyAlert]) -> None:
    if alerts:
      await self._event_sink.emit_events(
          [anomaly_alert_to_secure_event(alert) for alert in alerts]
      )
    if self._delegate is not None:
      await self._delegate.emit_alerts(alerts)


def ledger_entry_to_secure_event(entry: LedgerEntry) -> SecureEvent:
  """Builds a secure event from a provenance ledger entry."""
  return SecureEvent(
      event_id=entry.entry_id,
      timestamp=entry.timestamp,
      event_type=entry.event_type,
      source='ledger',
      app_name=entry.app_name,
      user_id=entry.user_id,
      session_id=entry.session_id,
      invocation_id=entry.invocation_id,
      actor=entry.actor,
      tenant_id=_payload_value(entry.payload, 'tenantId', 'tenant_id'),
      case_id=_payload_value(entry.payload, 'caseId', 'case_id'),
      payload=dict(entry.payload),
      attributes={
          'sequence': entry.sequence,
          'entryHash': entry.entry_hash,
          'previousHash': entry.previous_hash,
      },
  )


def lineage_record_to_secure_event(record: LineageRecord) -> SecureEvent:
  """Builds a secure event from a lineage record."""
  return SecureEvent(
      event_id=record.record_id,
      timestamp=record.timestamp,
      event_type=record.record_type,
      source='lineage',
      app_name=record.app_name,
      user_id=record.user_id,
      session_id=record.session_id,
      invocation_id=record.invocation_id,
      tenant_id=_payload_value(record.payload, 'tenantId', 'tenant_id'),
      case_id=_payload_value(record.payload, 'caseId', 'case_id'),
      payload=dict(record.payload),
      attributes={
          'entityId': record.entity_id,
          'entityVersion': record.entity_version,
          'parentIds': list(record.parent_ids),
          'payloadHash': record.payload_hash,
      },
  )


def anomaly_alert_to_secure_event(alert: AnomalyAlert) -> SecureEvent:
  """Builds a secure event from an anomaly alert."""
  return SecureEvent(
      event_id=(
          f'{alert.invocation_id or "global"}:{alert.alert_type}:'
          f'{alert.agent_name or "unknown"}'
      ),
      timestamp=platform_time.get_time(),
      event_type=alert.alert_type,
      source='anomaly',
      app_name=alert.app_name,
      user_id=alert.user_id,
      session_id=alert.session_id,
      invocation_id=alert.invocation_id,
      actor=alert.agent_name,
      severity=alert.severity,
      payload=dict(alert.payload),
      attributes={
          'reason': alert.reason,
          'toolName': alert.tool_name,
      },
  )


def _payload_value(payload: dict[str, Any], *keys: str) -> str | None:
  for key in keys:
    value = payload.get(key)
    if value is not None:
      return str(value)
  return None

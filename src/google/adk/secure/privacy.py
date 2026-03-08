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

import hmac
import re
from typing import Any

from pydantic import BaseModel
from pydantic import ConfigDict

from .alert_sinks import BaseAnomalyAlertSink
from .anomaly import AnomalyAlert
from .lineage import LineageRecord
from .lineage import LineageTracker
from .provenance import BaseProvenanceLedger
from .signing import HmacKeyring

_EMAIL_RE = re.compile(
    r'(?P<value>[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})',
    re.IGNORECASE,
)
_PHONE_RE = re.compile(r'(?P<value>\+?\d[\d\-\s().]{7,}\d)')
_SSN_RE = re.compile(r'(?P<value>\b\d{3}-\d{2}-\d{4}\b)')
_CARD_RE = re.compile(r'(?P<value>\b(?:\d[ -]*?){13,16}\b)')
_DEFAULT_SENSITIVE_FIELDS = frozenset({
    'access_token',
    'account_number',
    'address',
    'api_key',
    'authorization',
    'card_number',
    'credential',
    'credit_card',
    'email',
    'first_name',
    'full_name',
    'last_name',
    'name',
    'password',
    'phone',
    'phone_number',
    'secret',
    'ssn',
    'token',
})


class TelemetryRedactor(BaseModel):
  """Redacts or tokenizes sensitive data in secure telemetry payloads."""

  model_config = ConfigDict(
      extra='forbid',
      arbitrary_types_allowed=True,
  )

  mode: str = 'redact'
  replacement_text: str = '<redacted>'
  field_names: frozenset[str] = _DEFAULT_SENSITIVE_FIELDS
  redact_email: bool = True
  redact_phone: bool = True
  redact_ssn: bool = True
  redact_credit_card: bool = True
  keyring: HmacKeyring | None = None
  tokenization_key_id: str | None = None

  def model_post_init(self, __context: Any) -> None:
    del __context
    if self.mode not in ('redact', 'tokenize'):
      raise ValueError(
          'Telemetry redaction mode must be "redact" or "tokenize".'
      )
    if self.mode == 'tokenize' and (
        self.keyring is None or self.tokenization_key_id is None
    ):
      raise ValueError(
          'Tokenized telemetry redaction requires keyring and'
          ' tokenization_key_id.'
      )

  def redact(self, value: Any, *, field_name: str | None = None) -> Any:
    """Returns a privacy-filtered version of a telemetry payload."""
    if isinstance(value, BaseModel):
      return self.redact(
          value.model_dump(
              by_alias=True,
              exclude_none=True,
              mode='json',
          ),
          field_name=field_name,
      )
    if isinstance(value, dict):
      return {
          key: self.redact(item, field_name=str(key))
          for key, item in value.items()
      }
    if isinstance(value, list):
      return [self.redact(item, field_name=field_name) for item in value]
    if isinstance(value, tuple):
      return tuple(self.redact(item, field_name=field_name) for item in value)
    if isinstance(value, str):
      if field_name is not None and field_name.lower() in self.field_names:
        return self._redact_string(value)
      return self._redact_patterns(value)
    return value

  def _redact_patterns(self, value: str) -> str:
    redacted_value = value
    if self.redact_email:
      redacted_value = _EMAIL_RE.sub(
          lambda match: self._replacement(match.group('value')),
          redacted_value,
      )
    if self.redact_phone:
      redacted_value = _PHONE_RE.sub(
          lambda match: self._replacement(match.group('value')),
          redacted_value,
      )
    if self.redact_ssn:
      redacted_value = _SSN_RE.sub(
          lambda match: self._replacement(match.group('value')),
          redacted_value,
      )
    if self.redact_credit_card:
      redacted_value = _CARD_RE.sub(
          lambda match: self._replacement(match.group('value')),
          redacted_value,
      )
    return redacted_value

  def _redact_string(self, value: str) -> str:
    if not value:
      return value
    return self._replacement(value)

  def _replacement(self, value: str) -> str:
    if self.mode == 'redact':
      return self.replacement_text
    assert self.keyring is not None
    assert self.tokenization_key_id is not None
    key = self.keyring.get_key(self.tokenization_key_id)
    if key is None:
      raise KeyError(
          'Telemetry redaction key '
          f'{self.tokenization_key_id!r} is not available.'
      )
    token = hmac.new(
        key.secret,
        value.encode('utf-8'),
        'sha256',
    ).hexdigest()[:16]
    return f'token:{token}'


class PrivacyAwareProvenanceLedger(BaseProvenanceLedger):
  """Applies telemetry redaction before secure events reach the ledger."""

  def __init__(
      self,
      *,
      delegate: BaseProvenanceLedger,
      redactor: TelemetryRedactor,
  ):
    self._delegate = delegate
    self._redactor = redactor

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
  ):
    return await self._delegate.append(
        event_type=event_type,
        payload=self._redactor.redact(payload),
        actor=actor,
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
        invocation_id=invocation_id,
    )

  async def list_entries(self):
    return await self._delegate.list_entries()

  async def verify_chain(self) -> bool:
    return await self._delegate.verify_chain()


class PrivacyAwareLineageTracker:
  """Applies telemetry redaction before secure lineage is persisted."""

  def __init__(
      self,
      *,
      delegate: LineageTracker,
      redactor: TelemetryRedactor,
  ):
    self._delegate = delegate
    self._redactor = redactor

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
    return await self._delegate.record(
        record_type=record_type,
        entity_id=entity_id,
        payload=self._redactor.redact(payload),
        entity_version=entity_version,
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
        invocation_id=invocation_id,
        parent_entities=parent_entities,
    )

  async def list_records(self) -> list[LineageRecord]:
    return await self._delegate.list_records()


class PrivacyAwareAnomalyAlertSink(BaseAnomalyAlertSink):
  """Applies telemetry redaction before alerts are emitted externally."""

  def __init__(
      self,
      *,
      delegate: BaseAnomalyAlertSink,
      redactor: TelemetryRedactor,
  ):
    self._delegate = delegate
    self._redactor = redactor

  async def emit_alerts(self, alerts):
    redacted_alerts = [
        alert.model_copy(
            update={'payload': self._redactor.redact(alert.payload)}
        )
        for alert in alerts
    ]
    await self._delegate.emit_alerts(redacted_alerts)

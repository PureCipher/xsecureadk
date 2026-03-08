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

import base64
import dataclasses
from enum import Enum
import hashlib
import hmac
import json
from typing import Any

from google.adk.platform import time as platform_time
from pydantic import BaseModel
from pydantic import ConfigDict


def _normalize_for_json(value: Any) -> Any:
  """Normalizes values into a deterministic JSON-friendly structure."""
  if isinstance(value, BaseModel):
    return _normalize_for_json(
        value.model_dump(by_alias=True, exclude_none=True, mode='json')
    )
  if dataclasses.is_dataclass(value):
    return _normalize_for_json(dataclasses.asdict(value))
  if isinstance(value, Enum):
    return _normalize_for_json(value.value)
  if isinstance(value, dict):
    return {
        str(key): _normalize_for_json(item)
        for key, item in sorted(value.items(), key=lambda entry: str(entry[0]))
    }
  if isinstance(value, (list, tuple)):
    return [_normalize_for_json(item) for item in value]
  if isinstance(value, (set, frozenset)):
    return [
        _normalize_for_json(item)
        for item in sorted(value, key=lambda item: repr(item))
    ]
  if isinstance(value, bytes):
    return base64.b64encode(value).decode('ascii')
  if value is None or isinstance(value, (str, int, float, bool)):
    return value
  return repr(value)


def canonical_json_bytes(value: Any) -> bytes:
  """Returns a stable JSON encoding for signing and hashing."""
  normalized_value = _normalize_for_json(value)
  return json.dumps(
      normalized_value,
      sort_keys=True,
      separators=(',', ':'),
      ensure_ascii=True,
  ).encode('utf-8')


def payload_hash(value: Any) -> str:
  """Returns a SHA256 hash for the canonical form of a value."""
  return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class SignatureEnvelope(BaseModel):
  """Represents a cryptographic signature over a structured payload."""

  model_config = ConfigDict(
      extra='forbid',
  )

  algorithm: str = 'hmac-sha256'
  key_id: str
  payload_hash: str
  signature: str
  signed_at: float


class HmacKeyring:
  """Signs and verifies structured payloads with HMAC-SHA256."""

  def __init__(self, secrets_by_key_id: dict[str, str | bytes]):
    if not secrets_by_key_id:
      raise ValueError('At least one signing key must be provided.')
    self._secrets_by_key_id = {
        key_id: (
            secret if isinstance(secret, bytes) else secret.encode('utf-8')
        )
        for key_id, secret in secrets_by_key_id.items()
    }

  def sign_value(self, value: Any, *, key_id: str) -> SignatureEnvelope:
    """Signs a structured value with the requested key."""
    secret = self._secrets_by_key_id.get(key_id)
    if secret is None:
      raise KeyError(f'Unknown signing key: {key_id}')
    payload = canonical_json_bytes(value)
    signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return SignatureEnvelope(
        key_id=key_id,
        payload_hash=hashlib.sha256(payload).hexdigest(),
        signature=signature,
        signed_at=platform_time.get_time(),
    )

  def verify_value(
      self,
      value: Any,
      *,
      key_id: str,
      signature: str,
  ) -> bool:
    """Verifies a signature for a structured value."""
    secret = self._secrets_by_key_id.get(key_id)
    if secret is None:
      return False
    expected_signature = hmac.new(
        secret, canonical_json_bytes(value), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_signature, signature)

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
from typing import Optional

from pydantic import BaseModel
from pydantic import ConfigDict

from ..platform import time as platform_time


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
  key_epoch: Optional[int] = None
  payload_hash: str
  signature: str
  signed_at: float


class SigningKey(BaseModel):
  """Signing key metadata used for rotation and revocation."""

  model_config = ConfigDict(
      extra='forbid',
      arbitrary_types_allowed=True,
  )

  secret: bytes
  epoch: int = 1
  not_before: Optional[float] = None
  not_after: Optional[float] = None
  revoked_at: Optional[float] = None

  @classmethod
  def from_secret(
      cls,
      secret: str | bytes,
      *,
      epoch: int = 1,
      not_before: float | None = None,
      not_after: float | None = None,
      revoked_at: float | None = None,
  ) -> SigningKey:
    """Builds signing key metadata from a raw secret."""
    return cls(
        secret=secret if isinstance(secret, bytes) else secret.encode('utf-8'),
        epoch=epoch,
        not_before=not_before,
        not_after=not_after,
        revoked_at=revoked_at,
    )


class HmacKeyring:
  """Signs and verifies structured payloads with HMAC-SHA256."""

  def __init__(
      self,
      secrets_by_key_id: dict[str, str | bytes | SigningKey],
  ):
    if not secrets_by_key_id:
      raise ValueError('At least one signing key must be provided.')
    self._keys_by_id = {
        key_id: (
            key_value
            if isinstance(key_value, SigningKey)
            else SigningKey.from_secret(key_value)
        )
        for key_id, key_value in secrets_by_key_id.items()
    }

  def sign_value(self, value: Any, *, key_id: str) -> SignatureEnvelope:
    """Signs a structured value with the requested key."""
    key = self._keys_by_id.get(key_id)
    if key is None:
      raise KeyError(f'Unknown signing key: {key_id}')
    self._ensure_key_signable(key_id=key_id, key=key)
    payload = canonical_json_bytes(value)
    signature = hmac.new(key.secret, payload, hashlib.sha256).hexdigest()
    return SignatureEnvelope(
        key_id=key_id,
        key_epoch=key.epoch,
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
      signed_at: float | None = None,
  ) -> bool:
    """Verifies a signature for a structured value."""
    key = self._keys_by_id.get(key_id)
    if key is None:
      return False
    verification_time = (
        signed_at if signed_at is not None else platform_time.get_time()
    )
    if not self._is_signing_time_valid(key=key, signed_at=verification_time):
      return False
    expected_signature = hmac.new(
        key.secret, canonical_json_bytes(value), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_signature, signature)

  def revoke_key(self, key_id: str, *, revoked_at: float | None = None) -> None:
    """Revokes a key for future verification and signing checks."""
    key = self._keys_by_id.get(key_id)
    if key is None:
      raise KeyError(f'Unknown signing key: {key_id}')
    self._keys_by_id[key_id] = key.model_copy(
        update={'revoked_at': revoked_at or platform_time.get_time()}
    )

  def get_key(self, key_id: str) -> SigningKey | None:
    """Returns signing key metadata by key id."""
    return self._keys_by_id.get(key_id)

  def default_signing_key_id(self) -> str:
    """Returns the newest active signing key id."""
    active_keys = [
        (key_id, key)
        for key_id, key in self._keys_by_id.items()
        if self._is_signing_time_valid(
            key=key,
            signed_at=platform_time.get_time(),
            treat_revoked_as_invalid=True,
        )
    ]
    if not active_keys:
      raise ValueError('No active signing keys are available.')
    return max(active_keys, key=lambda item: (item[1].epoch, item[0]))[0]

  def key_ids(self) -> tuple[str, ...]:
    """Returns all known key ids."""
    return tuple(self._keys_by_id)

  def _ensure_key_signable(self, *, key_id: str, key: SigningKey) -> None:
    now = platform_time.get_time()
    if key.not_before is not None and now < key.not_before:
      raise ValueError(
          f'Signing key {key_id!r} is not valid before {key.not_before}.'
      )
    if key.not_after is not None and now > key.not_after:
      raise ValueError(f'Signing key {key_id!r} has expired.')
    if key.revoked_at is not None and now >= key.revoked_at:
      raise ValueError(f'Signing key {key_id!r} has been revoked.')

  @staticmethod
  def _is_signing_time_valid(
      *,
      key: SigningKey,
      signed_at: float,
      treat_revoked_as_invalid: bool = False,
  ) -> bool:
    if key.not_before is not None and signed_at < key.not_before:
      return False
    if key.not_after is not None and signed_at > key.not_after:
      return False
    if key.revoked_at is not None:
      if treat_revoked_as_invalid:
        return signed_at < key.revoked_at
      return signed_at < key.revoked_at
    return True

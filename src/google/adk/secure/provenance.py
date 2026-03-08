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
import json
from pathlib import Path
from typing import Any
from typing import Optional

from google.adk.platform import time as platform_time
from google.adk.platform import uuid as platform_uuid
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from .signing import payload_hash


class LedgerEntry(BaseModel):
  """Append-only provenance record linked by a hash chain."""

  model_config = ConfigDict(
      extra='forbid',
  )

  sequence: int
  entry_id: str
  timestamp: float
  event_type: str
  actor: Optional[str] = None
  app_name: Optional[str] = None
  user_id: Optional[str] = None
  session_id: Optional[str] = None
  invocation_id: Optional[str] = None
  payload: dict[str, Any] = Field(default_factory=dict)
  previous_hash: Optional[str] = None
  entry_hash: str


class BaseProvenanceLedger(abc.ABC):
  """Base interface for immutable provenance sinks."""

  @abc.abstractmethod
  async def append(
      self,
      *,
      event_type: str,
      payload: dict[str, Any],
      actor: Optional[str] = None,
      app_name: Optional[str] = None,
      user_id: Optional[str] = None,
      session_id: Optional[str] = None,
      invocation_id: Optional[str] = None,
  ) -> LedgerEntry:
    """Appends a new record to the ledger."""

  @abc.abstractmethod
  async def list_entries(self) -> list[LedgerEntry]:
    """Returns all records in append order."""

  @abc.abstractmethod
  async def verify_chain(self) -> bool:
    """Verifies the append-only hash chain."""


class InMemoryProvenanceLedger(BaseProvenanceLedger):
  """In-memory provenance ledger for tests and local development."""

  def __init__(self):
    self._entries: list[LedgerEntry] = []

  async def append(
      self,
      *,
      event_type: str,
      payload: dict[str, Any],
      actor: Optional[str] = None,
      app_name: Optional[str] = None,
      user_id: Optional[str] = None,
      session_id: Optional[str] = None,
      invocation_id: Optional[str] = None,
  ) -> LedgerEntry:
    previous_hash = self._entries[-1].entry_hash if self._entries else None
    sequence = len(self._entries) + 1
    entry = LedgerEntry(
        sequence=sequence,
        entry_id=str(platform_uuid.new_uuid()),
        timestamp=platform_time.get_time(),
        event_type=event_type,
        actor=actor,
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
        invocation_id=invocation_id,
        payload=payload,
        previous_hash=previous_hash,
        entry_hash='',
    )
    entry.entry_hash = self._entry_hash(entry)
    self._entries.append(entry)
    return entry

  async def list_entries(self) -> list[LedgerEntry]:
    return list(self._entries)

  async def verify_chain(self) -> bool:
    previous_hash = None
    for expected_sequence, entry in enumerate(self._entries, start=1):
      if entry.sequence != expected_sequence:
        return False
      if entry.previous_hash != previous_hash:
        return False
      if entry.entry_hash != self._entry_hash(entry):
        return False
      previous_hash = entry.entry_hash
    return True

  @staticmethod
  def _entry_hash(entry: LedgerEntry) -> str:
    return payload_hash(
        entry.model_dump(
            by_alias=True,
            exclude_none=True,
            mode='json',
            exclude={'entry_hash'},
        )
    )


class FileProvenanceLedger(BaseProvenanceLedger):
  """Append-only JSONL-backed provenance ledger."""

  def __init__(self, path: str | Path):
    self._path = Path(path)
    self._path.parent.mkdir(parents=True, exist_ok=True)
    self._lock = asyncio.Lock()

  async def append(
      self,
      *,
      event_type: str,
      payload: dict[str, Any],
      actor: Optional[str] = None,
      app_name: Optional[str] = None,
      user_id: Optional[str] = None,
      session_id: Optional[str] = None,
      invocation_id: Optional[str] = None,
  ) -> LedgerEntry:
    async with self._lock:
      entries = await self.list_entries()
      previous_hash = entries[-1].entry_hash if entries else None
      sequence = len(entries) + 1
      entry = LedgerEntry(
          sequence=sequence,
          entry_id=str(platform_uuid.new_uuid()),
          timestamp=platform_time.get_time(),
          event_type=event_type,
          actor=actor,
          app_name=app_name,
          user_id=user_id,
          session_id=session_id,
          invocation_id=invocation_id,
          payload=payload,
          previous_hash=previous_hash,
          entry_hash='',
      )
      entry.entry_hash = payload_hash(
          entry.model_dump(
              by_alias=True,
              exclude_none=True,
              mode='json',
              exclude={'entry_hash'},
          )
      )
      with self._path.open('a', encoding='utf-8') as handle:
        handle.write(
            entry.model_dump_json(
                by_alias=True,
                exclude_none=True,
            )
        )
        handle.write('\n')
      return entry

  async def list_entries(self) -> list[LedgerEntry]:
    if not self._path.exists():
      return []
    with self._path.open('r', encoding='utf-8') as handle:
      return [
          LedgerEntry.model_validate_json(line)
          for line in handle
          if line.strip()
      ]

  async def verify_chain(self) -> bool:
    entries = await self.list_entries()
    previous_hash = None
    for expected_sequence, entry in enumerate(entries, start=1):
      if entry.sequence != expected_sequence:
        return False
      if entry.previous_hash != previous_hash:
        return False
      expected_hash = payload_hash(
          entry.model_dump(
              by_alias=True,
              exclude_none=True,
              mode='json',
              exclude={'entry_hash'},
          )
      )
      if entry.entry_hash != expected_hash:
        return False
      previous_hash = entry.entry_hash
    return True

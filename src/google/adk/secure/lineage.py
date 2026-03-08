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


class LineageRecord(BaseModel):
  """Versioned lineage record linking runtime and evaluation entities."""

  model_config = ConfigDict(
      extra='forbid',
  )

  record_id: str
  timestamp: float
  record_type: str
  entity_id: str
  entity_version: Optional[str] = None
  app_name: Optional[str] = None
  user_id: Optional[str] = None
  session_id: Optional[str] = None
  invocation_id: Optional[str] = None
  parent_ids: list[str] = Field(default_factory=list)
  payload_hash: str
  payload: dict[str, Any] = Field(default_factory=dict)


class BaseLineageStore(abc.ABC):
  """Base store interface for versioned lineage records."""

  @abc.abstractmethod
  async def append(self, record: LineageRecord) -> LineageRecord:
    """Appends a lineage record."""

  @abc.abstractmethod
  async def list_records(self) -> list[LineageRecord]:
    """Returns all lineage records."""


class InMemoryLineageStore(BaseLineageStore):
  """In-memory lineage store for tests and local runs."""

  def __init__(self):
    self._records: list[LineageRecord] = []

  async def append(self, record: LineageRecord) -> LineageRecord:
    self._records.append(record)
    return record

  async def list_records(self) -> list[LineageRecord]:
    return list(self._records)


class FileLineageStore(BaseLineageStore):
  """JSONL-backed lineage store."""

  def __init__(self, path: str | Path):
    self._path = Path(path)
    self._path.parent.mkdir(parents=True, exist_ok=True)
    self._lock = asyncio.Lock()

  async def append(self, record: LineageRecord) -> LineageRecord:
    async with self._lock:
      with self._path.open('a', encoding='utf-8') as handle:
        handle.write(
            record.model_dump_json(
                by_alias=True,
                exclude_none=True,
            )
        )
        handle.write('\n')
    return record

  async def list_records(self) -> list[LineageRecord]:
    if not self._path.exists():
      return []
    with self._path.open('r', encoding='utf-8') as handle:
      return [
          LineageRecord.model_validate_json(line)
          for line in handle
          if line.strip()
      ]


class LineageTracker:
  """Captures versioned lineage for runtime, artifacts, and eval results."""

  def __init__(self, *, store: BaseLineageStore):
    self._store = store
    self._latest_record_id_by_entity: dict[str, str] = {}

  async def record(
      self,
      *,
      record_type: str,
      entity_id: str,
      payload: dict[str, Any],
      entity_version: Optional[str] = None,
      app_name: Optional[str] = None,
      user_id: Optional[str] = None,
      session_id: Optional[str] = None,
      invocation_id: Optional[str] = None,
      parent_entities: tuple[str, ...] = (),
  ) -> LineageRecord:
    """Records a new lineage node and updates entity ancestry state."""
    parent_ids = [
        self._latest_record_id_by_entity[parent_entity]
        for parent_entity in parent_entities
        if parent_entity in self._latest_record_id_by_entity
    ]
    record = LineageRecord(
        record_id=str(platform_uuid.new_uuid()),
        timestamp=platform_time.get_time(),
        record_type=record_type,
        entity_id=entity_id,
        entity_version=entity_version,
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
        invocation_id=invocation_id,
        parent_ids=parent_ids,
        payload_hash=payload_hash(payload),
        payload=payload,
    )
    self._latest_record_id_by_entity[entity_id] = record.record_id
    return await self._store.append(record)

  async def list_records(self) -> list[LineageRecord]:
    return await self._store.list_records()


def default_lineage_payload(value: Any) -> dict[str, Any]:
  """Returns a JSON-friendly lineage payload."""
  if isinstance(value, dict):
    return value
  if isinstance(value, BaseModel):
    return value.model_dump(
        by_alias=True,
        exclude_none=True,
        mode='json',
    )
  return json.loads(json.dumps(value))

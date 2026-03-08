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

from collections import Counter
from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from .evidence_bundle import EvidenceBundle
from .lineage import LineageRecord
from .provenance import LedgerEntry


class ReplayDiffItem(BaseModel):
  """One changed aspect between two replays."""

  model_config = ConfigDict(
      extra='forbid',
  )

  category: str
  field_name: str
  left_value: Any = None
  right_value: Any = None
  message: str


class ReplayDiffReport(BaseModel):
  """Diff report between two invocations or evidence bundles."""

  model_config = ConfigDict(
      extra='forbid',
  )

  valid: bool
  left_subject: str
  right_subject: str
  difference_count: int
  differences: list[ReplayDiffItem] = Field(default_factory=list)


class SecureReplayDiffer:
  """Compares two invocation replays or evidence bundles."""

  def diff_invocations(
      self,
      *,
      left_invocation_id: str,
      right_invocation_id: str,
      left_ledger_entries: Sequence[LedgerEntry],
      right_ledger_entries: Sequence[LedgerEntry],
      left_lineage_records: Sequence[LineageRecord],
      right_lineage_records: Sequence[LineageRecord],
  ) -> ReplayDiffReport:
    """Diffs two invocation histories from ledger and lineage slices."""
    differences = []
    differences.extend(
        self._compare_value(
            category='prompt',
            field_name='userContentHash',
            left_value=self._payload_value(
                left_ledger_entries, 'invocation_started', 'userContentHash'
            ),
            right_value=self._payload_value(
                right_ledger_entries, 'invocation_started', 'userContentHash'
            ),
            message='Prompt hash changed between invocations.',
        )
    )
    differences.extend(
        self._compare_value(
            category='response',
            field_name='responseHash',
            left_value=self._lineage_payloads(
                left_lineage_records, 'model_response', 'responseHash'
            ),
            right_value=self._lineage_payloads(
                right_lineage_records, 'model_response', 'responseHash'
            ),
            message='Model response hashes changed.',
        )
    )
    differences.extend(
        self._compare_value(
            category='tooling',
            field_name='tools',
            left_value=self._event_counter(
                left_ledger_entries, {'capability_issued', 'tool_denied'}
            ),
            right_value=self._event_counter(
                right_ledger_entries, {'capability_issued', 'tool_denied'}
            ),
            message='Tool authorization or denial pattern changed.',
        )
    )
    differences.extend(
        self._compare_value(
            category='policy',
            field_name='policyDecisions',
            left_value=self._lineage_policy_payloads(left_lineage_records),
            right_value=self._lineage_policy_payloads(right_lineage_records),
            message='Policy decision lineage changed.',
        )
    )
    differences.extend(
        self._compare_value(
            category='approval',
            field_name='approvalEvents',
            left_value=self._approval_events(left_ledger_entries),
            right_value=self._approval_events(right_ledger_entries),
            message='Approval workflow changed.',
        )
    )
    differences.extend(
        self._compare_value(
            category='anomaly',
            field_name='anomalies',
            left_value=self._payloads_by_event_type(
                left_ledger_entries, 'anomaly_detected'
            ),
            right_value=self._payloads_by_event_type(
                right_ledger_entries, 'anomaly_detected'
            ),
            message='Anomaly alerts changed.',
        )
    )
    return ReplayDiffReport(
        valid=not differences,
        left_subject=left_invocation_id,
        right_subject=right_invocation_id,
        difference_count=len(differences),
        differences=differences,
    )

  def diff_bundles(
      self,
      *,
      left_bundle: EvidenceBundle,
      right_bundle: EvidenceBundle,
  ) -> ReplayDiffReport:
    """Diffs two persisted evidence bundles."""
    differences = []
    left_payload = left_bundle.payload
    right_payload = right_bundle.payload
    for field_name in (
        'responseSignatures',
        'artifactSeals',
        'anomalyAlerts',
        'approvalEvents',
        'trustedEvaluatorSignatures',
        'deploymentAttestation',
    ):
      differences.extend(
          self._compare_value(
              category='bundle',
              field_name=field_name,
              left_value=left_payload.get(field_name),
              right_value=right_payload.get(field_name),
              message=f'Evidence bundle field {field_name!r} changed.',
          )
      )
    return ReplayDiffReport(
        valid=not differences,
        left_subject=left_bundle.bundle_id,
        right_subject=right_bundle.bundle_id,
        difference_count=len(differences),
        differences=differences,
    )

  def _compare_value(
      self,
      *,
      category: str,
      field_name: str,
      left_value: Any,
      right_value: Any,
      message: str,
  ) -> list[ReplayDiffItem]:
    if left_value == right_value:
      return []
    return [
        ReplayDiffItem(
            category=category,
            field_name=field_name,
            left_value=left_value,
            right_value=right_value,
            message=message,
        )
    ]

  @staticmethod
  def _payload_value(
      entries: Sequence[LedgerEntry],
      event_type: str,
      key: str,
  ) -> Any:
    for entry in entries:
      if entry.event_type == event_type:
        return entry.payload.get(key)
    return None

  @staticmethod
  def _payloads_by_event_type(
      entries: Sequence[LedgerEntry], event_type: str
  ) -> list[dict[str, Any]]:
    return [
        entry.payload for entry in entries if entry.event_type == event_type
    ]

  @staticmethod
  def _approval_events(entries: Sequence[LedgerEntry]) -> list[dict[str, Any]]:
    return [
        {
            'eventType': entry.event_type,
            'payload': entry.payload,
        }
        for entry in entries
        if entry.event_type.startswith('approval_')
    ]

  @staticmethod
  def _lineage_payloads(
      records: Sequence[LineageRecord],
      record_type: str,
      key: str,
  ) -> list[Any]:
    return [
        record.payload.get(key)
        for record in records
        if record.record_type == record_type
    ]

  @staticmethod
  def _lineage_policy_payloads(
      records: Sequence[LineageRecord],
  ) -> list[dict[str, Any]]:
    return [
        record.payload
        for record in records
        if record.record_type
        in (
            'tool_authorization',
            'gateway_allowed',
            'gateway_denied',
        )
    ]

  @staticmethod
  def _event_counter(
      entries: Sequence[LedgerEntry], event_types: set[str]
  ) -> dict[str, int]:
    counter = Counter(
        entry.payload.get('tool', entry.event_type)
        for entry in entries
        if entry.event_type in event_types
    )
    return dict(sorted(counter.items()))

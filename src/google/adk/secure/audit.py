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
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from ..evaluation.base_eval_service import InferenceResult
from ..evaluation.eval_result import EvalCaseResult
from ..evaluation.eval_result import EvalSetResult
from .lineage import FileLineageStore
from .lineage import LineageRecord
from .provenance import FileProvenanceLedger
from .provenance import LedgerEntry
from .signing import payload_hash
from .trust import TrustScorer
from .trusted_evaluators import TRUSTED_EVALUATOR_METADATA_KEY
from .trusted_evaluators import TrustedEvaluatorService


class AuditIssue(BaseModel):
  """Structured issue emitted by SecureADK verification tooling."""

  model_config = ConfigDict(
      extra='forbid',
  )

  code: str
  message: str
  subject: str | None = None
  details: dict[str, Any] = Field(default_factory=dict)


class SignedResultVerification(BaseModel):
  """Verification result for one signed evaluation artifact."""

  model_config = ConfigDict(
      extra='forbid',
  )

  subject: str
  result_type: str
  valid: bool
  metadata: dict[str, Any] = Field(default_factory=dict)
  issues: list[AuditIssue] = Field(default_factory=list)


class EvalAuditReport(BaseModel):
  """Verification report for signed evaluation outputs."""

  model_config = ConfigDict(
      extra='forbid',
  )

  valid: bool
  eval_set_result_id: str | None = None
  verifications: list[SignedResultVerification] = Field(default_factory=list)
  issues: list[AuditIssue] = Field(default_factory=list)


class LineageAuditReport(BaseModel):
  """Verification report for lineage records."""

  model_config = ConfigDict(
      extra='forbid',
  )

  valid: bool
  record_count: int
  entity_count: int
  issues: list[AuditIssue] = Field(default_factory=list)


class LedgerReplayReport(BaseModel):
  """Replay and verification report for ledger entries."""

  model_config = ConfigDict(
      extra='forbid',
  )

  valid: bool
  chain_valid: bool
  total_entry_count: int
  replay_entry_count: int
  first_sequence: int | None = None
  last_sequence: int | None = None
  event_counts: dict[str, int] = Field(default_factory=dict)
  invocation_ids: list[str] = Field(default_factory=list)
  session_ids: list[str] = Field(default_factory=list)
  actors: list[str] = Field(default_factory=list)
  issues: list[AuditIssue] = Field(default_factory=list)
  entries: list[LedgerEntry] = Field(default_factory=list)


def load_eval_set_result_file(path: str | Path) -> EvalSetResult:
  """Loads a persisted eval set result from JSON."""
  return EvalSetResult.model_validate_json(
      Path(path).read_text(encoding='utf-8')
  )


def load_lineage_records_file(path: str | Path) -> list[LineageRecord]:
  """Loads lineage records from a JSONL file."""
  return asyncio.run(FileLineageStore(path).list_records())


def load_ledger_entries_file(path: str | Path) -> list[LedgerEntry]:
  """Loads provenance ledger entries from a JSONL file."""
  return asyncio.run(FileProvenanceLedger(path).list_entries())


class SecureAuditVerifier:
  """Verifies signed evals, lineage history, and ledger replay integrity."""

  def __init__(
      self,
      *,
      trusted_evaluator_service: TrustedEvaluatorService | None = None,
      trust_scorer: TrustScorer | None = None,
  ):
    self._trusted_evaluator_service = trusted_evaluator_service
    self._trust_scorer = trust_scorer

  def verify_inference_result(
      self, inference_result: InferenceResult
  ) -> SignedResultVerification:
    """Verifies a signed inference result."""
    return self._verify_signed_result(
        inference_result,
        result_type='inference_result',
        subject=(
            'inference:'
            f'{inference_result.app_name}:'
            f'{inference_result.eval_set_id}:'
            f'{inference_result.eval_case_id}'
        ),
    )

  def verify_eval_case_result(
      self, eval_case_result: EvalCaseResult
  ) -> SignedResultVerification:
    """Verifies a signed eval case result."""
    return self._verify_signed_result(
        eval_case_result,
        result_type='eval_case_result',
        subject=(
            f'eval_case:{eval_case_result.eval_set_id}:{eval_case_result.eval_id}'
        ),
    )

  def verify_eval_set_result(
      self, eval_set_result: EvalSetResult
  ) -> EvalAuditReport:
    """Verifies signatures attached to an eval set result and its cases."""
    verifications = [
        self.verify_eval_case_result(eval_case_result)
        for eval_case_result in eval_set_result.eval_case_results
    ]
    verifications.append(
        self._verify_signed_result(
            eval_set_result,
            result_type='eval_set_result',
            subject=(
                f'eval_set:{eval_set_result.eval_set_id}:'
                f'{eval_set_result.eval_set_result_id}'
            ),
        )
    )
    issues = [
        issue for verification in verifications for issue in verification.issues
    ]
    return EvalAuditReport(
        valid=all(verification.valid for verification in verifications),
        eval_set_result_id=eval_set_result.eval_set_result_id,
        verifications=verifications,
        issues=issues,
    )

  def verify_lineage_records(
      self, records: Sequence[LineageRecord]
  ) -> LineageAuditReport:
    """Verifies lineage payload hashes and ancestry references."""
    issues = []
    seen_record_ids = set()
    entity_version_pairs = set()
    for record in records:
      if record.record_id in seen_record_ids:
        issues.append(
            AuditIssue(
                code='duplicate_record_id',
                message='Lineage record id was repeated.',
                subject=record.record_id,
            )
        )

      expected_hash = payload_hash(record.payload)
      if expected_hash != record.payload_hash:
        issues.append(
            AuditIssue(
                code='payload_hash_mismatch',
                message='Lineage payload hash did not match its payload.',
                subject=record.record_id,
                details={
                    'expected': expected_hash,
                    'actual': record.payload_hash,
                },
            )
        )

      missing_parents = [
          parent_id
          for parent_id in record.parent_ids
          if parent_id not in seen_record_ids
      ]
      if missing_parents:
        issues.append(
            AuditIssue(
                code='missing_parent_record',
                message='Lineage record referenced parent ids not yet seen.',
                subject=record.record_id,
                details={'missingParentIds': missing_parents},
            )
        )
      seen_record_ids.add(record.record_id)

      if record.entity_version is not None:
        version_key = (record.entity_id, record.entity_version)
        if version_key in entity_version_pairs:
          issues.append(
              AuditIssue(
                  code='duplicate_entity_version',
                  message='Entity version was reused in lineage history.',
                  subject=record.entity_id,
                  details={'entityVersion': record.entity_version},
              )
          )
        entity_version_pairs.add(version_key)

    return LineageAuditReport(
        valid=not issues,
        record_count=len(records),
        entity_count=len({record.entity_id for record in records}),
        issues=issues,
    )

  def replay_ledger_entries(
      self,
      entries: Sequence[LedgerEntry],
      *,
      app_name: str | None = None,
      user_id: str | None = None,
      session_id: str | None = None,
      invocation_id: str | None = None,
      event_type: str | None = None,
      include_entries: bool = False,
  ) -> LedgerReplayReport:
    """Verifies and replays ledger entries, optionally filtering the view."""
    issues = []
    previous_hash = None
    for expected_sequence, entry in enumerate(entries, start=1):
      if entry.sequence != expected_sequence:
        issues.append(
            AuditIssue(
                code='sequence_mismatch',
                message='Ledger sequence numbers were not contiguous.',
                subject=str(entry.sequence),
                details={'expectedSequence': expected_sequence},
            )
        )
      if entry.previous_hash != previous_hash:
        issues.append(
            AuditIssue(
                code='previous_hash_mismatch',
                message='Ledger previous hash did not match replay state.',
                subject=str(entry.sequence),
                details={
                    'expectedPreviousHash': previous_hash,
                    'actualPreviousHash': entry.previous_hash,
                },
            )
        )
      expected_hash = self._ledger_entry_hash(entry)
      if entry.entry_hash != expected_hash:
        issues.append(
            AuditIssue(
                code='entry_hash_mismatch',
                message='Ledger entry hash did not match the signed payload.',
                subject=str(entry.sequence),
                details={
                    'expectedEntryHash': expected_hash,
                    'actualEntryHash': entry.entry_hash,
                },
            )
        )
      previous_hash = entry.entry_hash

    filtered_entries = [
        entry
        for entry in entries
        if (app_name is None or entry.app_name == app_name)
        and (user_id is None or entry.user_id == user_id)
        and (session_id is None or entry.session_id == session_id)
        and (invocation_id is None or entry.invocation_id == invocation_id)
        and (event_type is None or entry.event_type == event_type)
    ]
    event_counts = Counter(entry.event_type for entry in filtered_entries)
    return LedgerReplayReport(
        valid=not issues,
        chain_valid=not issues,
        total_entry_count=len(entries),
        replay_entry_count=len(filtered_entries),
        first_sequence=(
            filtered_entries[0].sequence if filtered_entries else None
        ),
        last_sequence=(
            filtered_entries[-1].sequence if filtered_entries else None
        ),
        event_counts=dict(sorted(event_counts.items())),
        invocation_ids=sorted({
            entry.invocation_id
            for entry in filtered_entries
            if entry.invocation_id is not None
        }),
        session_ids=sorted({
            entry.session_id
            for entry in filtered_entries
            if entry.session_id is not None
        }),
        actors=sorted({
            entry.actor for entry in filtered_entries if entry.actor is not None
        }),
        issues=issues,
        entries=list(filtered_entries) if include_entries else [],
    )

  def _verify_signed_result(
      self,
      value: InferenceResult | EvalCaseResult | EvalSetResult,
      *,
      result_type: str,
      subject: str,
  ) -> SignedResultVerification:
    metadata = value.custom_metadata.get(TRUSTED_EVALUATOR_METADATA_KEY)
    issues = []
    if not isinstance(metadata, dict):
      issues.append(
          AuditIssue(
              code='missing_signature_metadata',
              message='Signed evaluator metadata was not present.',
              subject=subject,
          )
      )
      return SignedResultVerification(
          subject=subject,
          result_type=result_type,
          valid=False,
          issues=issues,
      )
    if self._trusted_evaluator_service is None:
      issues.append(
          AuditIssue(
              code='missing_trusted_evaluator_service',
              message=(
                  'Trusted evaluator verification requires a SecureADK'
                  ' trusted evaluator service.'
              ),
              subject=subject,
          )
      )
      return SignedResultVerification(
          subject=subject,
          result_type=result_type,
          valid=False,
          metadata=metadata,
          issues=issues,
      )
    payload = value.model_dump(
        by_alias=True,
        exclude_none=True,
        mode='json',
        exclude={'custom_metadata'},
    )
    valid = self._trusted_evaluator_service.verify_metadata(metadata, payload)
    if not valid:
      issues.append(
          AuditIssue(
              code='invalid_signature',
              message='Trusted evaluator signature verification failed.',
              subject=subject,
          )
      )
    if self._trust_scorer is not None:
      asyncio.run(
          self._trust_scorer.record_signature_verification(
              subject_type='evaluator',
              subject_id=str(metadata.get('evaluatorName', 'unknown')),
              valid=valid,
              reason=(
                  'Trusted evaluator signature verified.'
                  if valid
                  else 'Trusted evaluator signature verification failed.'
              ),
              tenant_id=metadata.get('tenantId'),
          )
      )
    return SignedResultVerification(
        subject=subject,
        result_type=result_type,
        valid=not issues,
        metadata=metadata,
        issues=issues,
    )

  @staticmethod
  def _ledger_entry_hash(entry: LedgerEntry) -> str:
    return payload_hash(
        entry.model_dump(
            by_alias=True,
            exclude_none=True,
            mode='json',
            exclude={'entry_hash'},
        )
    )

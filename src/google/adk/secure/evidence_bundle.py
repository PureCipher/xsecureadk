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

from collections.abc import Sequence
from pathlib import Path
from typing import Any
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from ..evaluation.eval_result import EvalSetResult
from ..platform import uuid as platform_uuid
from .attestation import DeploymentAttestation
from .audit import SecureAuditVerifier
from .lineage import LineageRecord
from .lineage import LineageTracker
from .provenance import BaseProvenanceLedger
from .provenance import LedgerEntry
from .signing import HmacKeyring
from .signing import payload_hash
from .tenant_crypto import TenantCryptoManager
from .trust import TrustScoreReport
from .trusted_evaluators import TRUSTED_EVALUATOR_METADATA_KEY


class EvidenceBundle(BaseModel):
  """Signed evidence package for an invocation or eval run."""

  model_config = ConfigDict(
      extra='forbid',
  )

  bundle_id: str
  bundle_type: Literal['invocation', 'eval']
  app_name: str | None = None
  session_id: str | None = None
  invocation_id: str | None = None
  eval_set_result_id: str | None = None
  key_id: str
  key_epoch: int | None = None
  key_scope: str = 'global'
  tenant_id: str | None = None
  payload_hash: str
  signature: str
  signed_at: float
  payload: dict[str, Any] = Field(default_factory=dict)


class EvidenceBundleVerification(BaseModel):
  """Verification result for a signed evidence bundle."""

  model_config = ConfigDict(
      extra='forbid',
  )

  valid: bool
  reason: str
  bundle_id: str | None = None


class EvidenceBundleExporter:
  """Exports and verifies SecureADK evidence bundles."""

  def __init__(
      self,
      *,
      keyring: HmacKeyring,
      signing_key_id: str | None = None,
      ledger: BaseProvenanceLedger | None = None,
      lineage_tracker: LineageTracker | None = None,
      audit_verifier: SecureAuditVerifier | None = None,
      deployment_attestation: DeploymentAttestation | None = None,
      trust_report: TrustScoreReport | None = None,
      tenant_crypto_manager: TenantCryptoManager | None = None,
  ):
    self._keyring = keyring
    self._signing_key_id = signing_key_id or keyring.default_signing_key_id()
    self._ledger = ledger
    self._lineage_tracker = lineage_tracker
    self._audit_verifier = audit_verifier
    self._deployment_attestation = deployment_attestation
    self._trust_report = trust_report
    self._tenant_crypto_manager = tenant_crypto_manager

  async def export_invocation_bundle(
      self,
      *,
      invocation_id: str,
      app_name: str | None = None,
      session_id: str | None = None,
  ) -> EvidenceBundle:
    """Exports a signed evidence bundle for a specific invocation."""
    ledger_entries = await self._matching_ledger_entries(
        invocation_id=invocation_id,
        app_name=app_name,
        session_id=session_id,
    )
    lineage_records = await self._matching_lineage_records(
        invocation_id=invocation_id,
        app_name=app_name,
        session_id=session_id,
    )
    payload = {
        'ledgerEntries': self._dump_models(ledger_entries),
        'lineageRecords': self._dump_models(lineage_records),
        'responseSignatures': [
            entry.payload
            for entry in ledger_entries
            if entry.event_type == 'model_response_signed'
        ],
        'artifactSeals': [
            entry.payload
            for entry in ledger_entries
            if entry.event_type == 'artifact_sealed'
        ],
        'anomalyAlerts': [
            entry.payload
            for entry in ledger_entries
            if entry.event_type == 'anomaly_detected'
        ],
        'approvalEvents': [
            {
                'eventType': entry.event_type,
                'payload': entry.payload,
                'timestamp': entry.timestamp,
            }
            for entry in ledger_entries
            if entry.event_type.startswith('approval_')
        ],
        'deploymentAttestation': (
            self._deployment_attestation.model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            )
            if self._deployment_attestation is not None
            else None
        ),
        'trustReport': (
            self._trust_report.model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            )
            if self._trust_report is not None
            else None
        ),
    }
    return self._build_bundle(
        bundle_type='invocation',
        app_name=app_name,
        session_id=session_id,
        invocation_id=invocation_id,
        tenant_id=self._infer_tenant_id(ledger_entries, lineage_records),
        payload=payload,
    )

  async def export_eval_bundle(
      self,
      *,
      eval_set_result: EvalSetResult,
      app_name: str | None = None,
  ) -> EvidenceBundle:
    """Exports a signed evidence bundle for a persisted eval result."""
    audit_report = (
        self._audit_verifier.verify_eval_set_result(eval_set_result)
        if self._audit_verifier is not None
        else None
    )
    ledger_entries = await self._matching_eval_ledger_entries(
        eval_set_id=eval_set_result.eval_set_id,
        app_name=app_name,
    )
    lineage_records = await self._matching_eval_lineage_records(
        eval_set_id=eval_set_result.eval_set_id,
        app_name=app_name,
    )
    payload = {
        'evalSetResult': eval_set_result.model_dump(
            by_alias=True,
            exclude_none=True,
            mode='json',
        ),
        'verificationReport': (
            audit_report.model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            )
            if audit_report is not None
            else None
        ),
        'trustedEvaluatorSignatures': self._collect_eval_signatures(
            eval_set_result
        ),
        'ledgerEntries': self._dump_models(ledger_entries),
        'lineageRecords': self._dump_models(lineage_records),
        'deploymentAttestation': (
            self._deployment_attestation.model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            )
            if self._deployment_attestation is not None
            else None
        ),
        'trustReport': (
            self._trust_report.model_dump(
                by_alias=True,
                exclude_none=True,
                mode='json',
            )
            if self._trust_report is not None
            else None
        ),
    }
    return self._build_bundle(
        bundle_type='eval',
        app_name=app_name,
        eval_set_result_id=eval_set_result.eval_set_result_id,
        tenant_id=self._infer_tenant_id(ledger_entries, lineage_records),
        payload=payload,
    )

  def verify_bundle(self, bundle: EvidenceBundle) -> EvidenceBundleVerification:
    """Verifies the signature and payload hash for an evidence bundle."""
    expected_payload_hash = payload_hash(bundle.payload)
    if expected_payload_hash != bundle.payload_hash:
      return EvidenceBundleVerification(
          valid=False,
          reason='Evidence bundle payload hash mismatch.',
          bundle_id=bundle.bundle_id,
      )
    if not self._keyring.verify_value(
        bundle.payload,
        key_id=bundle.key_id,
        signature=bundle.signature,
        signed_at=bundle.signed_at,
        tenant_id=bundle.tenant_id,
    ):
      return EvidenceBundleVerification(
          valid=False,
          reason='Evidence bundle signature verification failed.',
          bundle_id=bundle.bundle_id,
      )
    return EvidenceBundleVerification(
        valid=True,
        reason='Evidence bundle verified.',
        bundle_id=bundle.bundle_id,
    )

  def write_bundle(
      self,
      bundle: EvidenceBundle,
      *,
      output_path: str | Path,
  ) -> Path:
    """Writes an evidence bundle to disk as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        bundle.model_dump_json(
            by_alias=True,
            exclude_none=True,
            indent=2,
        ),
        encoding='utf-8',
    )
    return path

  async def _matching_ledger_entries(
      self,
      *,
      invocation_id: str | None = None,
      app_name: str | None = None,
      session_id: str | None = None,
  ) -> list[LedgerEntry]:
    if self._ledger is None:
      return []
    return [
        entry
        for entry in await self._ledger.list_entries()
        if (invocation_id is None or entry.invocation_id == invocation_id)
        and (app_name is None or entry.app_name == app_name)
        and (session_id is None or entry.session_id == session_id)
    ]

  async def _matching_eval_ledger_entries(
      self,
      *,
      eval_set_id: str,
      app_name: str | None = None,
  ) -> list[LedgerEntry]:
    if self._ledger is None:
      return []
    return [
        entry
        for entry in await self._ledger.list_entries()
        if (app_name is None or entry.app_name == app_name)
        and entry.event_type == 'trusted_evaluator_signed'
        and entry.payload.get('evalSetId') == eval_set_id
    ]

  async def _matching_lineage_records(
      self,
      *,
      invocation_id: str | None = None,
      app_name: str | None = None,
      session_id: str | None = None,
  ) -> list[LineageRecord]:
    if self._lineage_tracker is None:
      return []
    return [
        record
        for record in await self._lineage_tracker.list_records()
        if (invocation_id is None or record.invocation_id == invocation_id)
        and (app_name is None or record.app_name == app_name)
        and (session_id is None or record.session_id == session_id)
    ]

  async def _matching_eval_lineage_records(
      self,
      *,
      eval_set_id: str,
      app_name: str | None = None,
  ) -> list[LineageRecord]:
    if self._lineage_tracker is None:
      return []
    return [
        record
        for record in await self._lineage_tracker.list_records()
        if (app_name is None or record.app_name == app_name)
        and record.entity_id.startswith('eval:')
        and f':{eval_set_id}:' in record.entity_id
    ]

  def _build_bundle(
      self,
      *,
      bundle_type: Literal['invocation', 'eval'],
      payload: dict[str, Any],
      app_name: str | None = None,
      session_id: str | None = None,
      invocation_id: str | None = None,
      eval_set_result_id: str | None = None,
      tenant_id: str | None = None,
  ) -> EvidenceBundle:
    envelope = (
        self._keyring.sign_value(payload, key_id=self._signing_key_id)
        if self._tenant_crypto_manager is None
        else self._tenant_crypto_manager.sign_value(
            keyring=self._keyring,
            value=payload,
            key_id=self._signing_key_id,
            tenant_id=tenant_id,
        )
    )
    return EvidenceBundle(
        bundle_id=str(platform_uuid.new_uuid()),
        bundle_type=bundle_type,
        app_name=app_name,
        session_id=session_id,
        invocation_id=invocation_id,
        eval_set_result_id=eval_set_result_id,
        key_id=self._signing_key_id,
        key_epoch=envelope.key_epoch,
        key_scope=envelope.key_scope,
        tenant_id=envelope.tenant_id,
        payload_hash=envelope.payload_hash,
        signature=envelope.signature,
        signed_at=envelope.signed_at,
        payload=payload,
    )

  @staticmethod
  def _collect_eval_signatures(
      eval_set_result: EvalSetResult,
  ) -> dict[str, Any]:
    return {
        'evalSet': eval_set_result.custom_metadata.get(
            TRUSTED_EVALUATOR_METADATA_KEY
        ),
        'evalCases': [
            {
                'evalId': eval_case_result.eval_id,
                'metadata': eval_case_result.custom_metadata.get(
                    TRUSTED_EVALUATOR_METADATA_KEY
                ),
            }
            for eval_case_result in eval_set_result.eval_case_results
        ],
    }

  @staticmethod
  def _dump_models(values: Sequence[BaseModel]) -> list[dict[str, Any]]:
    return [
        value.model_dump(
            by_alias=True,
            exclude_none=True,
            mode='json',
        )
        for value in values
    ]

  @staticmethod
  def _infer_tenant_id(
      ledger_entries: Sequence[LedgerEntry],
      lineage_records: Sequence[LineageRecord],
  ) -> str | None:
    for entry in ledger_entries:
      tenant_id = entry.payload.get('tenantId')
      if tenant_id is not None:
        return tenant_id
    for record in lineage_records:
      tenant_id = record.payload.get('tenantId')
      if tenant_id is not None:
        return tenant_id
    return None


def load_evidence_bundle_file(path: str | Path) -> EvidenceBundle:
  """Loads an evidence bundle from a JSON file."""
  return EvidenceBundle.model_validate_json(
      Path(path).read_text(encoding='utf-8')
  )

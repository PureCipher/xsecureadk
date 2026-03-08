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
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from ..secure.audit import EvalAuditReport
from ..secure.audit import LedgerReplayReport
from ..secure.audit import LineageAuditReport
from ..secure.audit import load_eval_set_result_file
from ..secure.audit import load_ledger_entries_file
from ..secure.audit import load_lineage_records_file
from ..secure.audit import SecureAuditVerifier
from ..secure.evidence_bundle import EvidenceBundle
from ..secure.evidence_bundle import EvidenceBundleExporter
from ..secure.evidence_bundle import EvidenceBundleVerification
from ..secure.evidence_bundle import load_evidence_bundle_file
from ..secure.gateway import GatewayExplanation
from ..secure.gateway import GatewayRequest
from ..secure.policies import AuthorizationRequest
from ..secure.policies import PolicyExplanation
from .utils.secure_runtime_config import load_secure_runtime_builder

_ModelT = TypeVar('_ModelT', bound=BaseModel)


def verify_eval_result_file(
    *,
    app_root: str | Path,
    eval_result_path: str | Path,
    secure_config_path: str | Path | None = None,
) -> EvalAuditReport:
  """Verifies a persisted eval result file using SecureADK config."""
  builder = _require_secure_builder(
      app_root=app_root,
      secure_config_path=secure_config_path,
  )
  if builder.trusted_evaluator_service is None:
    raise ValueError(
        'SecureADK trusted evaluator signing is not configured for this app.'
    )
  verifier = SecureAuditVerifier(
      trusted_evaluator_service=builder.trusted_evaluator_service
  )
  return verifier.verify_eval_set_result(
      load_eval_set_result_file(eval_result_path)
  )


def verify_lineage(
    *,
    app_root: str | Path,
    secure_config_path: str | Path | None = None,
    lineage_path: str | Path | None = None,
) -> LineageAuditReport:
  """Verifies lineage records from config-backed storage or an explicit file."""
  verifier = SecureAuditVerifier()
  if lineage_path is not None:
    return verifier.verify_lineage_records(
        load_lineage_records_file(lineage_path)
    )
  builder = _require_secure_builder(
      app_root=app_root,
      secure_config_path=secure_config_path,
  )
  if builder.lineage_tracker is None:
    raise ValueError(
        'SecureADK lineage tracking is not configured for this app.'
    )
  return verifier.verify_lineage_records(
      asyncio.run(builder.lineage_tracker.list_records())
  )


def replay_ledger(
    *,
    app_root: str | Path,
    secure_config_path: str | Path | None = None,
    ledger_path: str | Path | None = None,
    app_name: str | None = None,
    user_id: str | None = None,
    session_id: str | None = None,
    invocation_id: str | None = None,
    event_type: str | None = None,
    include_entries: bool = False,
) -> LedgerReplayReport:
  """Replays SecureADK ledger history with optional filters."""
  verifier = SecureAuditVerifier()
  if ledger_path is not None:
    entries = load_ledger_entries_file(ledger_path)
  else:
    builder = _require_secure_builder(
        app_root=app_root,
        secure_config_path=secure_config_path,
    )
    if builder.ledger is None:
      raise ValueError('SecureADK provenance ledger is not configured.')
    entries = asyncio.run(builder.ledger.list_entries())
  return verifier.replay_ledger_entries(
      entries,
      app_name=app_name,
      user_id=user_id,
      session_id=session_id,
      invocation_id=invocation_id,
      event_type=event_type,
      include_entries=include_entries,
  )


def explain_policy_request(
    *,
    app_root: str | Path,
    request_path: str | Path,
    secure_config_path: str | Path | None = None,
) -> PolicyExplanation:
  """Explains a SecureADK policy decision for a serialized request."""
  builder = _require_secure_builder(
      app_root=app_root,
      secure_config_path=secure_config_path,
  )
  request = _load_model_file(request_path, AuthorizationRequest)
  return builder.policy_engine.explain(request)


def explain_gateway_request(
    *,
    app_root: str | Path,
    request_path: str | Path,
    secure_config_path: str | Path | None = None,
) -> GatewayExplanation:
  """Explains a SecureADK gateway decision for a serialized request."""
  builder = _require_secure_builder(
      app_root=app_root,
      secure_config_path=secure_config_path,
  )
  if builder.gateway is None:
    raise ValueError('SecureADK gateway is not configured for this app.')
  request = _load_model_file(request_path, GatewayRequest)
  return builder.gateway.explain(request)


def export_invocation_bundle(
    *,
    app_root: str | Path,
    invocation_id: str,
    secure_config_path: str | Path | None = None,
    app_name: str | None = None,
    session_id: str | None = None,
    output_path: str | Path | None = None,
) -> EvidenceBundle:
  """Exports a signed evidence bundle for an invocation."""
  builder = _require_secure_builder(
      app_root=app_root,
      secure_config_path=secure_config_path,
  )
  exporter = _build_bundle_exporter(builder)
  bundle = asyncio.run(
      exporter.export_invocation_bundle(
          invocation_id=invocation_id,
          app_name=app_name,
          session_id=session_id,
      )
  )
  if output_path is not None:
    exporter.write_bundle(bundle, output_path=output_path)
  return bundle


def export_eval_bundle(
    *,
    app_root: str | Path,
    eval_result_path: str | Path,
    secure_config_path: str | Path | None = None,
    app_name: str | None = None,
    output_path: str | Path | None = None,
) -> EvidenceBundle:
  """Exports a signed evidence bundle for a persisted eval result."""
  builder = _require_secure_builder(
      app_root=app_root,
      secure_config_path=secure_config_path,
  )
  exporter = _build_bundle_exporter(builder)
  bundle = asyncio.run(
      exporter.export_eval_bundle(
          eval_set_result=load_eval_set_result_file(eval_result_path),
          app_name=app_name,
      )
  )
  if output_path is not None:
    exporter.write_bundle(bundle, output_path=output_path)
  return bundle


def verify_bundle_file(
    *,
    app_root: str | Path,
    bundle_path: str | Path,
    secure_config_path: str | Path | None = None,
) -> EvidenceBundleVerification:
  """Verifies a persisted SecureADK evidence bundle file."""
  builder = _require_secure_builder(
      app_root=app_root,
      secure_config_path=secure_config_path,
  )
  exporter = _build_bundle_exporter(builder)
  return exporter.verify_bundle(load_evidence_bundle_file(bundle_path))


def _build_bundle_exporter(builder) -> EvidenceBundleExporter:
  return EvidenceBundleExporter(
      keyring=builder.keyring,
      ledger=builder.ledger,
      lineage_tracker=builder.lineage_tracker,
      audit_verifier=SecureAuditVerifier(
          trusted_evaluator_service=builder.trusted_evaluator_service
      ),
  )


def _load_model_file(
    path: str | Path,
    model_type: type[_ModelT],
) -> _ModelT:
  return model_type.model_validate_json(Path(path).read_text(encoding='utf-8'))


def _require_secure_builder(
    *,
    app_root: str | Path,
    secure_config_path: str | Path | None,
):
  builder = load_secure_runtime_builder(
      app_root,
      secure_config_path=secure_config_path,
  )
  if builder is None:
    raise ValueError(
        'SecureADK is not configured for this app. Provide a valid'
        ' secure config file or enable SecureADK in the app root.'
    )
  return builder

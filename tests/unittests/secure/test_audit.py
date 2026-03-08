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

from google.adk.evaluation.base_eval_service import InferenceResult
from google.adk.evaluation.base_eval_service import InferenceStatus
from google.adk.evaluation.eval_result import EvalCaseResult
from google.adk.evaluation.eval_result import EvalSetResult
from google.adk.evaluation.evaluator import EvalStatus
from google.adk.secure import InMemoryProvenanceLedger
from google.adk.secure.audit import SecureAuditVerifier
from google.adk.secure.lineage import LineageRecord
from google.adk.secure.signing import HmacKeyring
from google.adk.secure.signing import payload_hash
from google.adk.secure.trusted_evaluators import TrustedEvaluatorIdentity
from google.adk.secure.trusted_evaluators import TrustedEvaluatorRegistry
from google.adk.secure.trusted_evaluators import TrustedEvaluatorService


def _trusted_evaluator_service() -> TrustedEvaluatorService:
  return TrustedEvaluatorService(
      evaluator_name='court-evaluator',
      key_id='eval-key',
      keyring=HmacKeyring({'eval-key': 'secret'}),
      registry=TrustedEvaluatorRegistry([
          TrustedEvaluatorIdentity(
              evaluator_name='court-evaluator',
              key_id='eval-key',
          )
      ]),
  )


def test_secure_audit_verifier_validates_signed_eval_results() -> None:
  service = _trusted_evaluator_service()
  eval_case_result = asyncio.run(
      service.sign_eval_case_result(
          EvalCaseResult(
              eval_set_id='set-1',
              eval_id='case-1',
              final_eval_status=EvalStatus.PASSED,
              overall_eval_metric_results=[],
              eval_metric_result_per_invocation=[],
              session_id='session-1',
          )
      )
  )
  eval_set_result = asyncio.run(
      service.sign_eval_set_result(
          EvalSetResult(
              eval_set_result_id='result-1',
              eval_set_result_name='result-1',
              eval_set_id='set-1',
              eval_case_results=[eval_case_result],
          )
      )
  )

  report = SecureAuditVerifier(
      trusted_evaluator_service=service
  ).verify_eval_set_result(eval_set_result)

  assert report.valid
  assert len(report.verifications) == 2


def test_secure_audit_verifier_detects_invalid_eval_signature() -> None:
  service = _trusted_evaluator_service()
  inference_result = asyncio.run(
      service.sign_inference_result(
          InferenceResult(
              app_name='courtroom',
              eval_set_id='set-1',
              eval_case_id='case-1',
              session_id='session-1',
              status=InferenceStatus.SUCCESS,
          )
      )
  )
  inference_result.status = InferenceStatus.FAILURE

  verification = SecureAuditVerifier(
      trusted_evaluator_service=service
  ).verify_inference_result(inference_result)

  assert not verification.valid
  assert verification.issues[0].code == 'invalid_signature'


def test_secure_audit_verifier_detects_lineage_gaps() -> None:
  record = LineageRecord(
      record_id='record-1',
      timestamp=1.0,
      record_type='model_response',
      entity_id='invocation:1:model_response:judge',
      parent_ids=['missing-parent'],
      payload_hash=payload_hash({'responseHash': 'abc'}),
      payload={'responseHash': 'abc'},
  )

  report = SecureAuditVerifier().verify_lineage_records([record])

  assert not report.valid
  assert report.issues[0].code == 'missing_parent_record'


def test_secure_audit_verifier_replays_and_verifies_ledger() -> None:
  ledger = InMemoryProvenanceLedger()
  asyncio.run(
      ledger.append(
          event_type='invocation_started',
          payload={'tenantId': 'tenant-a'},
          app_name='courtroom',
          user_id='alice',
          session_id='session-1',
          invocation_id='inv-1',
      )
  )
  asyncio.run(
      ledger.append(
          event_type='invocation_finished',
          payload={},
          app_name='courtroom',
          user_id='alice',
          session_id='session-1',
          invocation_id='inv-1',
      )
  )
  entries = asyncio.run(ledger.list_entries())
  tampered_entries = [
      entries[0],
      entries[1].model_copy(update={'entry_hash': 'tampered'}),
  ]

  report = SecureAuditVerifier().replay_ledger_entries(
      tampered_entries,
      invocation_id='inv-1',
      include_entries=True,
  )

  assert not report.valid
  assert report.replay_entry_count == 2
  assert report.event_counts == {
      'invocation_finished': 1,
      'invocation_started': 1,
  }
  assert report.issues[0].code == 'entry_hash_mismatch'

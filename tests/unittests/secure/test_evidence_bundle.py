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

from google.adk.evaluation.eval_metrics import EvalStatus
from google.adk.evaluation.eval_result import EvalCaseResult
from google.adk.evaluation.eval_result import EvalSetResult
from google.adk.secure import DeploymentAttestor
from google.adk.secure import EvidenceBundleExporter
from google.adk.secure import HmacKeyring
from google.adk.secure import InMemoryLineageStore
from google.adk.secure import InMemoryProvenanceLedger
from google.adk.secure import InMemoryTrustStore
from google.adk.secure import LineageTracker
from google.adk.secure import load_evidence_bundle_file
from google.adk.secure import SigningKey
from google.adk.secure import TenantCryptoManager
from google.adk.secure import TrustedEvaluatorIdentity
from google.adk.secure import TrustedEvaluatorRegistry
from google.adk.secure import TrustedEvaluatorService
from google.adk.secure import TrustScorer


def test_evidence_bundle_exporter_exports_and_verifies_invocation_bundle(
    tmp_path,
) -> None:
  ledger = InMemoryProvenanceLedger()
  lineage = LineageTracker(store=InMemoryLineageStore())
  keyring = HmacKeyring(
      {'bundle-key': SigningKey.from_secret('bundle-secret', epoch=2)}
  )
  exporter = EvidenceBundleExporter(
      keyring=keyring,
      signing_key_id='bundle-key',
      ledger=ledger,
      lineage_tracker=lineage,
  )

  asyncio.run(
      ledger.append(
          event_type='model_response_signed',
          actor='judge',
          app_name='courtroom',
          user_id='alice',
          session_id='session-1',
          invocation_id='invocation-1',
          payload={'signature': 'abc'},
      )
  )
  asyncio.run(
      ledger.append(
          event_type='approval_requested',
          actor='judge',
          app_name='courtroom',
          user_id='alice',
          session_id='session-1',
          invocation_id='invocation-1',
          payload={'tool': 'sealed_evidence'},
      )
  )
  asyncio.run(
      lineage.record(
          record_type='tool_authorization',
          entity_id='invocation:invocation-1:tool_authorization:fc-1',
          app_name='courtroom',
          user_id='alice',
          session_id='session-1',
          invocation_id='invocation-1',
          payload={'tool': 'sealed_evidence'},
      )
  )

  bundle = asyncio.run(
      exporter.export_invocation_bundle(
          invocation_id='invocation-1',
          app_name='courtroom',
          session_id='session-1',
      )
  )

  assert bundle.bundle_type == 'invocation'
  assert bundle.key_epoch == 2
  assert exporter.verify_bundle(bundle).valid

  bundle_path = tmp_path / 'invocation-bundle.json'
  exporter.write_bundle(bundle, output_path=bundle_path)
  loaded_bundle = load_evidence_bundle_file(bundle_path)
  assert loaded_bundle.bundle_id == bundle.bundle_id


def test_evidence_bundle_exporter_exports_and_verifies_eval_bundle() -> None:
  ledger = InMemoryProvenanceLedger()
  lineage = LineageTracker(store=InMemoryLineageStore())
  keyring = HmacKeyring({'eval-key': 'eval-secret'})
  trusted_evaluator_service = TrustedEvaluatorService(
      evaluator_name='court-evaluator',
      key_id='eval-key',
      keyring=keyring,
      registry=TrustedEvaluatorRegistry([
          TrustedEvaluatorIdentity(
              evaluator_name='court-evaluator',
              key_id='eval-key',
          )
      ]),
      ledger=ledger,
      lineage_tracker=lineage,
  )
  exporter = EvidenceBundleExporter(
      keyring=keyring,
      signing_key_id='eval-key',
      ledger=ledger,
      lineage_tracker=lineage,
  )

  eval_case_result = asyncio.run(
      trusted_evaluator_service.sign_eval_case_result(
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
      trusted_evaluator_service.sign_eval_set_result(
          EvalSetResult(
              eval_set_result_id='result-1',
              eval_set_id='set-1',
              eval_case_results=[eval_case_result],
              creation_timestamp=1.0,
          )
      )
  )

  bundle = asyncio.run(
      exporter.export_eval_bundle(eval_set_result=eval_set_result)
  )

  assert bundle.bundle_type == 'eval'
  assert bundle.eval_set_result_id == 'result-1'
  assert exporter.verify_bundle(bundle).valid
  assert bundle.payload['trustedEvaluatorSignatures']['evalSet'] is not None


def test_evidence_bundle_exporter_includes_attestation_and_trust_report(
    tmp_path: Path,
) -> None:
  ledger = InMemoryProvenanceLedger()
  lineage = LineageTracker(store=InMemoryLineageStore())
  keyring = HmacKeyring(
      {'bundle-key': SigningKey.from_secret('bundle-secret', epoch=2)}
  )
  trust_scorer = TrustScorer(store=InMemoryTrustStore())
  asyncio.run(
      trust_scorer.record_signature_verification(
          subject_type='deployment',
          subject_id='courtroom',
          tenant_id='tenant-a',
          valid=True,
          reason='Deployment attestation verified.',
      )
  )
  attestation_source = tmp_path / 'agent'
  attestation_source.mkdir()
  (attestation_source / 'agent.py').write_text('root_agent = object()\n')
  deployment_attestation = DeploymentAttestor(
      keyring=keyring,
      signing_key_id='bundle-key',
  ).build_attestation(
      app_name='courtroom',
      deployment_target='cloud_run',
      source_root=attestation_source,
  )
  exporter = EvidenceBundleExporter(
      keyring=keyring,
      signing_key_id='bundle-key',
      ledger=ledger,
      lineage_tracker=lineage,
      deployment_attestation=deployment_attestation,
      trust_report=asyncio.run(trust_scorer.generate_report()),
      tenant_crypto_manager=TenantCryptoManager(enabled=True),
  )

  asyncio.run(
      ledger.append(
          event_type='model_response_signed',
          actor='judge',
          app_name='courtroom',
          invocation_id='invocation-1',
          payload={'signature': 'abc', 'tenantId': 'tenant-a'},
      )
  )

  bundle = asyncio.run(
      exporter.export_invocation_bundle(
          invocation_id='invocation-1',
          app_name='courtroom',
      )
  )

  assert bundle.key_scope == 'tenant'
  assert bundle.tenant_id == 'tenant-a'
  assert bundle.payload['deploymentAttestation'] is not None
  assert bundle.payload['trustReport']['score_count'] == 1
  assert exporter.verify_bundle(bundle).valid

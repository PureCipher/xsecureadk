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

from typing import Any

from pydantic import BaseModel
from pydantic import ConfigDict

from ..evaluation.base_eval_service import InferenceResult
from ..evaluation.eval_result import EvalCaseResult
from ..evaluation.eval_result import EvalSetResult
from .lineage import LineageTracker
from .provenance import BaseProvenanceLedger
from .signing import HmacKeyring
from .signing import payload_hash
from .tenant_crypto import TenantCryptoManager
from .trust import TrustScorer

TRUSTED_EVALUATOR_METADATA_KEY = 'secureadk:trusted_evaluator'


class TrustedEvaluatorIdentity(BaseModel):
  """Trusted evaluator identity metadata."""

  model_config = ConfigDict(
      extra='forbid',
  )

  evaluator_name: str
  key_id: str


class TrustedEvaluatorRegistry:
  """Registry of trusted evaluator identities."""

  def __init__(self, identities: list[TrustedEvaluatorIdentity]):
    self._identity_by_name = {
        identity.evaluator_name: identity for identity in identities
    }

  def get(self, evaluator_name: str) -> TrustedEvaluatorIdentity | None:
    return self._identity_by_name.get(evaluator_name)

  def require(self, evaluator_name: str) -> TrustedEvaluatorIdentity:
    identity = self.get(evaluator_name)
    if identity is None:
      raise ValueError(f'Unknown trusted evaluator {evaluator_name!r}.')
    return identity


class TrustedEvaluatorService:
  """Signs and verifies evaluation outputs from trusted evaluators."""

  def __init__(
      self,
      *,
      evaluator_name: str,
      key_id: str,
      keyring: HmacKeyring,
      registry: TrustedEvaluatorRegistry | None = None,
      ledger: BaseProvenanceLedger | None = None,
      lineage_tracker: LineageTracker | None = None,
      sign_inference_results: bool = True,
      sign_eval_case_results: bool = True,
      sign_eval_set_results: bool = True,
      tenant_crypto_manager: TenantCryptoManager | None = None,
      trust_scorer: TrustScorer | None = None,
  ):
    self._evaluator_name = evaluator_name
    self._key_id = key_id
    self._keyring = keyring
    self._registry = registry
    self._ledger = ledger
    self._lineage_tracker = lineage_tracker
    self._sign_inference_results = sign_inference_results
    self._sign_eval_case_results = sign_eval_case_results
    self._sign_eval_set_results = sign_eval_set_results
    self._tenant_crypto_manager = tenant_crypto_manager
    self._trust_scorer = trust_scorer

  @property
  def evaluator_name(self) -> str:
    return self._evaluator_name

  async def sign_inference_result(
      self,
      inference_result: InferenceResult,
      *,
      tenant_id: str | None = None,
  ) -> InferenceResult:
    """Signs an inference result if this result type is enabled."""
    if not self._sign_inference_results:
      return inference_result
    tenant_id = tenant_id or await self._resolve_tenant_id(
        app_name=inference_result.app_name,
        user_id=None,
        session_id=inference_result.session_id,
    )
    metadata = await self._build_metadata(
        result_type='inference_result',
        payload=self._result_payload(inference_result),
        app_name=inference_result.app_name,
        session_id=inference_result.session_id,
        eval_set_id=inference_result.eval_set_id,
        eval_case_id=inference_result.eval_case_id,
        tenant_id=tenant_id,
    )
    inference_result.custom_metadata[TRUSTED_EVALUATOR_METADATA_KEY] = metadata
    return inference_result

  async def sign_eval_case_result(
      self,
      eval_case_result: EvalCaseResult,
      *,
      app_name: str | None = None,
      tenant_id: str | None = None,
  ) -> EvalCaseResult:
    """Signs an eval case result if this result type is enabled."""
    if not self._sign_eval_case_results:
      return eval_case_result
    tenant_id = tenant_id or await self._resolve_tenant_id(
        app_name=app_name,
        user_id=eval_case_result.user_id,
        session_id=eval_case_result.session_id,
    )
    metadata = await self._build_metadata(
        result_type='eval_case_result',
        payload=self._result_payload(eval_case_result),
        app_name=app_name,
        session_id=eval_case_result.session_id,
        eval_set_id=eval_case_result.eval_set_id,
        eval_case_id=eval_case_result.eval_id,
        tenant_id=tenant_id,
    )
    eval_case_result.custom_metadata[TRUSTED_EVALUATOR_METADATA_KEY] = metadata
    return eval_case_result

  async def sign_eval_set_result(
      self,
      eval_set_result: EvalSetResult,
      *,
      app_name: str | None = None,
      tenant_id: str | None = None,
  ) -> EvalSetResult:
    """Signs an eval set result if this result type is enabled."""
    if not self._sign_eval_set_results:
      return eval_set_result
    if tenant_id is None and eval_set_result.eval_case_results:
      tenant_metadata = eval_set_result.eval_case_results[
          0
      ].custom_metadata.get(TRUSTED_EVALUATOR_METADATA_KEY, {})
      if isinstance(tenant_metadata, dict):
        tenant_id = tenant_metadata.get('tenantId')
    metadata = await self._build_metadata(
        result_type='eval_set_result',
        payload=self._result_payload(eval_set_result),
        app_name=app_name,
        eval_set_id=eval_set_result.eval_set_id,
        eval_case_id=None,
        tenant_id=tenant_id,
    )
    eval_set_result.custom_metadata[TRUSTED_EVALUATOR_METADATA_KEY] = metadata
    return eval_set_result

  def verify_metadata(self, metadata: dict[str, Any], payload: Any) -> bool:
    """Verifies trusted evaluator metadata for a payload."""
    evaluator_name = metadata.get('evaluatorName')
    key_id = metadata.get('keyId')
    signature = metadata.get('signature')
    payload_hash_value = metadata.get('payloadHash')
    if not evaluator_name or not key_id or not signature:
      return False
    if self._registry is not None:
      identity = self._registry.get(evaluator_name)
      if identity is None or identity.key_id != key_id:
        return False
    expected_payload = self._signature_payload(
        result_type=metadata.get('resultType', ''),
        payload=payload,
        eval_set_id=metadata.get('evalSetId'),
        eval_case_id=metadata.get('evalCaseId'),
        session_id=metadata.get('sessionId'),
    )
    if payload_hash(expected_payload) != payload_hash_value:
      return False
    return self._keyring.verify_value(
        expected_payload,
        key_id=key_id,
        signature=signature,
        signed_at=metadata.get('signedAt'),
        tenant_id=metadata.get('tenantId'),
    )

  async def _build_metadata(
      self,
      *,
      result_type: str,
      payload: dict[str, Any],
      app_name: str | None = None,
      session_id: str | None = None,
      eval_set_id: str | None = None,
      eval_case_id: str | None = None,
      tenant_id: str | None = None,
  ) -> dict[str, Any]:
    signature_payload = self._signature_payload(
        result_type=result_type,
        payload=payload,
        eval_set_id=eval_set_id,
        eval_case_id=eval_case_id,
        session_id=session_id,
    )
    envelope = (
        self._keyring.sign_value(signature_payload, key_id=self._key_id)
        if self._tenant_crypto_manager is None
        else self._tenant_crypto_manager.sign_value(
            keyring=self._keyring,
            value=signature_payload,
            key_id=self._key_id,
            tenant_id=tenant_id,
        )
    )
    metadata = {
        'evaluatorName': self._evaluator_name,
        'keyId': self._key_id,
        'keyEpoch': envelope.key_epoch,
        'keyScope': envelope.key_scope,
        'resultType': result_type,
        'evalSetId': eval_set_id,
        'evalCaseId': eval_case_id,
        'sessionId': session_id,
        'payloadHash': envelope.payload_hash,
        'signature': envelope.signature,
        'signedAt': envelope.signed_at,
    }
    if envelope.tenant_id is not None:
      metadata['tenantId'] = envelope.tenant_id
    if self._ledger is not None:
      await self._ledger.append(
          event_type='trusted_evaluator_signed',
          actor=self._evaluator_name,
          app_name=app_name,
          session_id=session_id,
          payload=metadata,
      )
    if self._lineage_tracker is not None:
      entity_id = (
          f'eval:{result_type}:{eval_set_id}:{eval_case_id or "aggregate"}'
      )
      await self._lineage_tracker.record(
          record_type=result_type,
          entity_id=entity_id,
          app_name=app_name,
          session_id=session_id,
          payload={
              **metadata,
              'resultHash': payload_hash(payload),
          },
      )
    if self._trust_scorer is not None:
      await self._trust_scorer.record_signature_verification(
          subject_type='evaluator',
          subject_id=self._evaluator_name,
          valid=True,
          reason='Trusted evaluator output signed.',
          tenant_id=envelope.tenant_id,
      )
    return metadata

  @staticmethod
  def _result_payload(value: BaseModel) -> dict[str, Any]:
    return value.model_dump(
        by_alias=True,
        exclude_none=True,
        mode='json',
        exclude={'custom_metadata'},
    )

  @staticmethod
  def _signature_payload(
      *,
      result_type: str,
      payload: dict[str, Any],
      eval_set_id: str | None,
      eval_case_id: str | None,
      session_id: str | None,
  ) -> dict[str, Any]:
    return {
        'resultType': result_type,
        'evalSetId': eval_set_id,
        'evalCaseId': eval_case_id,
        'sessionId': session_id,
        'payload': payload,
    }

  async def _resolve_tenant_id(
      self,
      *,
      app_name: str | None,
      user_id: str | None,
      session_id: str | None,
  ) -> str | None:
    if self._tenant_crypto_manager is None or app_name is None:
      return None
    return await self._tenant_crypto_manager.resolve_tenant_id(
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
    )

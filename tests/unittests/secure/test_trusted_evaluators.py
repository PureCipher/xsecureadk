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
from google.adk.secure.signing import HmacKeyring
from google.adk.secure.trusted_evaluators import TRUSTED_EVALUATOR_METADATA_KEY
from google.adk.secure.trusted_evaluators import TrustedEvaluatorIdentity
from google.adk.secure.trusted_evaluators import TrustedEvaluatorRegistry
from google.adk.secure.trusted_evaluators import TrustedEvaluatorService


def test_trusted_evaluator_service_signs_and_verifies_inference_result() -> (
    None
):
  service = TrustedEvaluatorService(
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

  metadata = inference_result.custom_metadata[TRUSTED_EVALUATOR_METADATA_KEY]

  assert metadata['evaluatorName'] == 'court-evaluator'
  assert service.verify_metadata(
      metadata,
      inference_result.model_dump(
          by_alias=True,
          exclude_none=True,
          mode='json',
          exclude={'custom_metadata'},
      ),
  )

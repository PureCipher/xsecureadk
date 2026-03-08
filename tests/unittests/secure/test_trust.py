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

from google.adk.secure import InMemoryTrustStore
from google.adk.secure import TrustScorer


def test_trust_scorer_tracks_verification_and_reports_lowest_scores() -> None:
  scorer = TrustScorer(store=InMemoryTrustStore())

  asyncio.run(
      scorer.record_signature_verification(
          subject_type='evaluator',
          subject_id='court-evaluator',
          tenant_id='tenant-a',
          valid=False,
          reason='Signature mismatch',
      )
  )
  asyncio.run(
      scorer.record_signature_verification(
          subject_type='deployment',
          subject_id='courtroom',
          valid=True,
          reason='Deployment attestation verified.',
      )
  )

  report = asyncio.run(scorer.generate_report(limit=10))

  assert report.score_count == 2
  assert report.event_count == 2
  assert report.scores[0].subject_id == 'court-evaluator'
  assert report.scores[0].tenant_id == 'tenant-a'
  assert report.scores[0].score < report.scores[1].score

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
from typing import Optional
from typing import Union

from google.genai import types
from pydantic import BaseModel
from pydantic import ConfigDict

from ..artifacts.base_artifact_service import ArtifactVersion
from ..artifacts.base_artifact_service import BaseArtifactService
from ..artifacts.base_artifact_service import ensure_part
from .lineage import LineageTracker
from .provenance import BaseProvenanceLedger
from .signing import HmacKeyring
from .signing import payload_hash

SEAL_METADATA_KEY = 'secureadk:seal'


class ArtifactSeal(BaseModel):
  """Cryptographic seal attached to an artifact version."""

  model_config = ConfigDict(
      extra='forbid',
  )

  algorithm: str = 'hmac-sha256'
  actor: str
  key_id: str
  key_epoch: Optional[int] = None
  version: int
  digest: str
  previous_digest: Optional[str] = None
  payload_hash: str
  signature: str
  signed_at: float


class ArtifactVerificationResult(BaseModel):
  """Result of verifying an artifact seal."""

  model_config = ConfigDict(
      extra='forbid',
  )

  valid: bool
  reason: str
  seal: Optional[ArtifactSeal] = None


def _artifact_digest(artifact: types.Part) -> str:
  return payload_hash(
      artifact.model_dump(by_alias=True, exclude_none=True, mode='json')
  )


class SealedArtifactService(BaseArtifactService):
  """Artifact service wrapper that seals every saved artifact version."""

  def __init__(
      self,
      *,
      delegate: BaseArtifactService,
      keyring: HmacKeyring,
      signing_key_id: str,
      actor: str = 'secureadk-sealer',
      ledger: Optional[BaseProvenanceLedger] = None,
      lineage_tracker: LineageTracker | None = None,
  ):
    self._delegate = delegate
    self._keyring = keyring
    self._signing_key_id = signing_key_id
    self._actor = actor
    self._ledger = ledger
    self._lineage_tracker = lineage_tracker

  async def save_artifact(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      artifact: Union[types.Part, dict[str, Any]],
      session_id: Optional[str] = None,
      custom_metadata: Optional[dict[str, Any]] = None,
  ) -> int:
    artifact = ensure_part(artifact)
    existing_versions = await self._delegate.list_versions(
        app_name=app_name,
        user_id=user_id,
        filename=filename,
        session_id=session_id,
    )
    version = len(existing_versions)
    previous_seal = None
    if existing_versions:
      latest_meta = await self._delegate.get_artifact_version(
          app_name=app_name,
          user_id=user_id,
          filename=filename,
          session_id=session_id,
      )
      previous_seal = self._extract_seal(latest_meta)

    digest = _artifact_digest(artifact)
    payload = self._seal_payload(
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
        filename=filename,
        version=version,
        digest=digest,
        previous_digest=(
            previous_seal.digest if previous_seal is not None else None
        ),
    )
    envelope = self._keyring.sign_value(
        payload,
        key_id=self._signing_key_id,
    )
    seal = ArtifactSeal(
        actor=self._actor,
        key_id=self._signing_key_id,
        key_epoch=envelope.key_epoch,
        version=version,
        digest=digest,
        previous_digest=(
            previous_seal.digest if previous_seal is not None else None
        ),
        payload_hash=envelope.payload_hash,
        signature=envelope.signature,
        signed_at=envelope.signed_at,
    )
    merged_metadata = dict(custom_metadata or {})
    merged_metadata[SEAL_METADATA_KEY] = seal.model_dump(
        by_alias=True,
        exclude_none=True,
        mode='json',
    )
    saved_version = await self._delegate.save_artifact(
        app_name=app_name,
        user_id=user_id,
        filename=filename,
        artifact=artifact,
        session_id=session_id,
        custom_metadata=merged_metadata,
    )
    if self._ledger is not None:
      await self._ledger.append(
          event_type='artifact_sealed',
          actor=self._actor,
          app_name=app_name,
          user_id=user_id,
          session_id=session_id,
          payload={
              'filename': filename,
              'version': saved_version,
              'digest': digest,
              'previousDigest': seal.previous_digest,
          },
      )
    if self._lineage_tracker is not None:
      await self._lineage_tracker.record(
          record_type='artifact_version',
          entity_id=f'artifact:{app_name}:{session_id}:{filename}',
          entity_version=str(saved_version),
          app_name=app_name,
          user_id=user_id,
          session_id=session_id,
          payload={
              'filename': filename,
              'version': saved_version,
              'digest': digest,
              'previousDigest': seal.previous_digest,
              'payloadHash': seal.payload_hash,
              'signingKeyId': seal.key_id,
          },
      )
    return saved_version

  async def load_artifact(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      session_id: Optional[str] = None,
      version: Optional[int] = None,
  ) -> Optional[types.Part]:
    return await self._delegate.load_artifact(
        app_name=app_name,
        user_id=user_id,
        filename=filename,
        session_id=session_id,
        version=version,
    )

  async def list_artifact_keys(
      self, *, app_name: str, user_id: str, session_id: Optional[str] = None
  ) -> list[str]:
    return await self._delegate.list_artifact_keys(
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
    )

  async def delete_artifact(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      session_id: Optional[str] = None,
  ) -> None:
    await self._delegate.delete_artifact(
        app_name=app_name,
        user_id=user_id,
        filename=filename,
        session_id=session_id,
    )

  async def list_versions(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      session_id: Optional[str] = None,
  ) -> list[int]:
    return await self._delegate.list_versions(
        app_name=app_name,
        user_id=user_id,
        filename=filename,
        session_id=session_id,
    )

  async def list_artifact_versions(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      session_id: Optional[str] = None,
  ) -> list[ArtifactVersion]:
    return await self._delegate.list_artifact_versions(
        app_name=app_name,
        user_id=user_id,
        filename=filename,
        session_id=session_id,
    )

  async def get_artifact_version(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      session_id: Optional[str] = None,
      version: Optional[int] = None,
  ) -> Optional[ArtifactVersion]:
    return await self._delegate.get_artifact_version(
        app_name=app_name,
        user_id=user_id,
        filename=filename,
        session_id=session_id,
        version=version,
    )

  async def verify_artifact(
      self,
      *,
      app_name: str,
      user_id: str,
      filename: str,
      session_id: Optional[str] = None,
      version: Optional[int] = None,
  ) -> ArtifactVerificationResult:
    """Verifies the seal attached to an artifact version."""
    version_meta = await self.get_artifact_version(
        app_name=app_name,
        user_id=user_id,
        filename=filename,
        session_id=session_id,
        version=version,
    )
    seal = self._extract_seal(version_meta)
    if seal is None:
      return ArtifactVerificationResult(
          valid=False,
          reason='Artifact version has no SecureADK seal.',
      )

    artifact = await self.load_artifact(
        app_name=app_name,
        user_id=user_id,
        filename=filename,
        session_id=session_id,
        version=version,
    )
    if artifact is None:
      return ArtifactVerificationResult(
          valid=False,
          reason='Artifact payload could not be loaded.',
          seal=seal,
      )

    digest = _artifact_digest(artifact)
    if digest != seal.digest:
      return ArtifactVerificationResult(
          valid=False,
          reason='Artifact payload digest does not match the stored seal.',
          seal=seal,
      )

    payload = self._seal_payload(
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
        filename=filename,
        version=seal.version,
        digest=seal.digest,
        previous_digest=seal.previous_digest,
    )
    if payload_hash(payload) != seal.payload_hash:
      return ArtifactVerificationResult(
          valid=False,
          reason='Seal payload hash mismatch.',
          seal=seal,
      )
    if not self._keyring.verify_value(
        payload,
        key_id=seal.key_id,
        signature=seal.signature,
        signed_at=seal.signed_at,
    ):
      return ArtifactVerificationResult(
          valid=False,
          reason='Seal signature verification failed.',
          seal=seal,
      )
    return ArtifactVerificationResult(
        valid=True,
        reason='Artifact seal verified.',
        seal=seal,
    )

  @staticmethod
  def _extract_seal(
      version_meta: Optional[ArtifactVersion],
  ) -> Optional[ArtifactSeal]:
    if version_meta is None:
      return None
    seal_data = version_meta.custom_metadata.get(SEAL_METADATA_KEY)
    if not seal_data:
      return None
    return ArtifactSeal.model_validate(seal_data)

  def _seal_payload(
      self,
      *,
      app_name: str,
      user_id: str,
      session_id: Optional[str],
      filename: str,
      version: int,
      digest: str,
      previous_digest: Optional[str],
  ) -> dict[str, object]:
    return {
        'appName': app_name,
        'userId': user_id,
        'sessionId': session_id,
        'filename': filename,
        'version': version,
        'digest': digest,
        'previousDigest': previous_digest,
        'actor': self._actor,
    }

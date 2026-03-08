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

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from ..platform import time as platform_time
from ..platform import uuid as platform_uuid
from .lineage import LineageTracker
from .provenance import BaseProvenanceLedger
from .signing import HmacKeyring
from .signing import payload_hash
from .tenant_crypto import TenantCryptoManager

DEFAULT_ATTESTATION_FILE_NAME = '.secureadk.attestation.json'
_IGNORED_FILE_NAMES = frozenset({
    '.DS_Store',
    DEFAULT_ATTESTATION_FILE_NAME,
})
_IGNORED_SUFFIXES = frozenset({
    '.pyc',
    '.pyo',
})
_IGNORED_PARTS = frozenset({
    '__pycache__',
    '.pytest_cache',
})


class DeploymentAttestation(BaseModel):
  """Signed deployment manifest for a staged or deployed SecureADK app."""

  model_config = ConfigDict(
      extra='forbid',
  )

  attestation_id: str
  app_name: str
  deployment_target: str
  actor: str
  source_root: str | None = None
  metadata: dict[str, Any] = Field(default_factory=dict)
  component_hashes: dict[str, str] = Field(default_factory=dict)
  key_id: str
  key_epoch: int | None = None
  key_scope: str = 'global'
  tenant_id: str | None = None
  payload_hash: str
  signature: str
  signed_at: float


class DeploymentAttestationVerification(BaseModel):
  """Verification result for a deployment attestation."""

  model_config = ConfigDict(
      extra='forbid',
  )

  valid: bool
  reason: str
  attestation_id: str | None = None
  issues: list[str] = Field(default_factory=list)


class DeploymentAttestor:
  """Builds, persists, verifies, and records deployment attestations."""

  def __init__(
      self,
      *,
      keyring: HmacKeyring,
      signing_key_id: str,
      actor: str = 'secureadk-deployer',
      ledger: BaseProvenanceLedger | None = None,
      lineage_tracker: LineageTracker | None = None,
      tenant_crypto_manager: TenantCryptoManager | None = None,
      attestation_file_name: str = DEFAULT_ATTESTATION_FILE_NAME,
  ):
    self._keyring = keyring
    self._signing_key_id = signing_key_id
    self._actor = actor
    self._ledger = ledger
    self._lineage_tracker = lineage_tracker
    self._tenant_crypto_manager = tenant_crypto_manager
    self._attestation_file_name = attestation_file_name

  @property
  def attestation_file_name(self) -> str:
    return self._attestation_file_name

  def build_attestation(
      self,
      *,
      app_name: str,
      deployment_target: str,
      source_root: str | Path,
      metadata: dict[str, Any] | None = None,
      actor: str | None = None,
      explicit_paths: tuple[str | Path, ...] = (),
  ) -> DeploymentAttestation:
    """Builds a signed deployment attestation for a staged source tree."""
    source_root = Path(source_root)
    component_hashes = self._collect_component_hashes(
        source_root=source_root,
        explicit_paths=explicit_paths,
    )
    payload = {
        'appName': app_name,
        'deploymentTarget': deployment_target,
        'actor': actor or self._actor,
        'sourceRoot': str(source_root),
        'metadata': dict(metadata or {}),
        'componentHashes': component_hashes,
    }
    tenant_id = (
        None
        if self._tenant_crypto_manager is None
        else self._tenant_crypto_manager.resolve_local_tenant_id(
            app_name=app_name
        )
    )
    envelope = self._sign(
        payload=payload,
        tenant_id=tenant_id,
    )
    return DeploymentAttestation(
        attestation_id=str(platform_uuid.new_uuid()),
        app_name=app_name,
        deployment_target=deployment_target,
        actor=actor or self._actor,
        source_root=str(source_root),
        metadata=dict(metadata or {}),
        component_hashes=component_hashes,
        key_id=self._signing_key_id,
        key_epoch=envelope.key_epoch,
        key_scope=envelope.key_scope,
        tenant_id=envelope.tenant_id,
        payload_hash=envelope.payload_hash,
        signature=envelope.signature,
        signed_at=envelope.signed_at,
    )

  def verify_attestation(
      self,
      attestation: DeploymentAttestation,
      *,
      source_root: str | Path | None = None,
  ) -> DeploymentAttestationVerification:
    """Verifies the attestation signature and optionally its file hashes."""
    payload = self._payload(attestation)
    issues = []
    if payload_hash(payload) != attestation.payload_hash:
      issues.append('Attestation payload hash mismatch.')
    if not self._verify_signature(attestation=attestation, payload=payload):
      issues.append('Attestation signature verification failed.')
    if source_root is not None:
      expected_hashes = self._collect_component_hashes(
          source_root=Path(source_root),
          explicit_paths=(),
      )
      if expected_hashes != attestation.component_hashes:
        issues.append('Attestation component hashes did not match source tree.')
    return DeploymentAttestationVerification(
        valid=not issues,
        reason='Deployment attestation verified.' if not issues else issues[0],
        attestation_id=attestation.attestation_id,
        issues=issues,
    )

  def load_attestation(self, path: str | Path) -> DeploymentAttestation:
    """Loads a persisted deployment attestation JSON file."""
    return DeploymentAttestation.model_validate_json(
        Path(path).read_text(encoding='utf-8')
    )

  def write_attestation(
      self,
      attestation: DeploymentAttestation,
      *,
      output_path: str | Path,
  ) -> Path:
    """Writes a deployment attestation to disk."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        attestation.model_dump_json(
            by_alias=True,
            exclude_none=True,
            indent=2,
        ),
        encoding='utf-8',
    )
    return output_path

  async def record_attestation(
      self,
      attestation: DeploymentAttestation,
      *,
      verified: bool,
  ) -> None:
    """Records a deployment attestation event into provenance and lineage."""
    payload = {
        'deploymentTarget': attestation.deployment_target,
        'attestationId': attestation.attestation_id,
        'verified': verified,
        'payloadHash': attestation.payload_hash,
        'componentCount': len(attestation.component_hashes),
    }
    if self._ledger is not None:
      await self._ledger.append(
          event_type='deployment_attested',
          actor=attestation.actor,
          app_name=attestation.app_name,
          payload=payload,
      )
    if self._lineage_tracker is not None:
      await self._lineage_tracker.record(
          record_type='deployment_attestation',
          entity_id=(
              f'deployment:{attestation.app_name}:{attestation.attestation_id}'
          ),
          app_name=attestation.app_name,
          payload={
              **payload,
              'metadata': attestation.metadata,
              'componentHashes': attestation.component_hashes,
          },
      )

  def _collect_component_hashes(
      self,
      *,
      source_root: Path,
      explicit_paths: tuple[str | Path, ...],
  ) -> dict[str, str]:
    component_hashes = {}
    candidate_paths = set()
    if source_root.exists():
      candidate_paths.update(self._walk_files(source_root))
    for explicit_path in explicit_paths:
      explicit = Path(explicit_path)
      if explicit.exists():
        if explicit.is_dir():
          candidate_paths.update(self._walk_files(explicit))
        else:
          candidate_paths.add(explicit)
    for path in sorted(candidate_paths):
      relative_path = os.path.relpath(path, source_root)
      component_hashes[relative_path] = payload_hash(path.read_bytes())
    return component_hashes

  def _walk_files(self, root: Path) -> set[Path]:
    files = set()
    for current_root, dir_names, file_names in os.walk(root):
      dir_names[:] = [
          dir_name for dir_name in dir_names if dir_name not in _IGNORED_PARTS
      ]
      for file_name in file_names:
        if file_name in _IGNORED_FILE_NAMES:
          continue
        if Path(file_name).suffix in _IGNORED_SUFFIXES:
          continue
        path = Path(current_root) / file_name
        if any(part in _IGNORED_PARTS for part in path.parts):
          continue
        files.add(path)
    return files

  def _payload(self, attestation: DeploymentAttestation) -> dict[str, Any]:
    return {
        'appName': attestation.app_name,
        'deploymentTarget': attestation.deployment_target,
        'actor': attestation.actor,
        'sourceRoot': attestation.source_root,
        'metadata': attestation.metadata,
        'componentHashes': attestation.component_hashes,
    }

  def _sign(self, *, payload: dict[str, Any], tenant_id: str | None):
    if self._tenant_crypto_manager is None:
      return self._keyring.sign_value(payload, key_id=self._signing_key_id)
    return self._tenant_crypto_manager.sign_value(
        keyring=self._keyring,
        value=payload,
        key_id=self._signing_key_id,
        tenant_id=tenant_id,
    )

  def _verify_signature(
      self,
      *,
      attestation: DeploymentAttestation,
      payload: dict[str, Any],
  ) -> bool:
    if self._tenant_crypto_manager is None:
      return self._keyring.verify_value(
          payload,
          key_id=attestation.key_id,
          signature=attestation.signature,
          signed_at=attestation.signed_at,
      )
    return self._tenant_crypto_manager.verify_value(
        keyring=self._keyring,
        value=payload,
        key_id=attestation.key_id,
        signature=attestation.signature,
        signed_at=attestation.signed_at,
        tenant_id=attestation.tenant_id,
    )


def find_attestation_file(
    app_root: str | Path,
    *,
    file_name: str = DEFAULT_ATTESTATION_FILE_NAME,
) -> Path | None:
  """Returns the default deployment attestation file when present."""
  attestation_path = Path(app_root) / file_name
  if attestation_path.exists():
    return attestation_path
  return None

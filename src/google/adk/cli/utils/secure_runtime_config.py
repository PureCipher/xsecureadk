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

import json
import logging
import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import model_validator
import yaml

from ...agents.base_agent import BaseAgent
from ...apps.app import App
from ...artifacts.base_artifact_service import BaseArtifactService
from ...secure.identities import AgentIdentity
from ...secure.identities import IdentityRegistry
from ...secure.policies import PolicyRule
from ...secure.policies import SimplePolicyEngine
from ...secure.runtime import SecureRuntimeBuilder
from ...secure.capabilities import CapabilityVault
from ...secure.provenance import FileProvenanceLedger
from ...secure.signing import HmacKeyring
from ...utils.env_utils import is_env_enabled

logger = logging.getLogger('google_adk.' + __name__)

SECURE_RUNTIME_CONFIG_ENV = 'ADK_SECURE_CONFIG'
SECURE_RUNTIME_DISABLE_ENV = 'ADK_DISABLE_SECURE_RUNTIME'
_CONFIG_FILE_CANDIDATES = (
    'secureadk.yaml',
    'secureadk.yml',
    'secureadk.json',
)


class _SigningKeyConfig(BaseModel):
  """Config for a signing key reference."""

  model_config = ConfigDict(
      extra='forbid',
  )

  secret: Optional[str] = None
  secret_env: Optional[str] = None

  @model_validator(mode='after')
  def _validate_source(self) -> _SigningKeyConfig:
    if bool(self.secret) == bool(self.secret_env):
      raise ValueError(
          'Exactly one of secret or secret_env must be provided.'
      )
    return self

  def resolve_secret(self) -> str:
    """Returns the secret value from inline config or environment."""
    if self.secret is not None:
      return self.secret
    assert self.secret_env is not None
    secret = os.environ.get(self.secret_env)
    if not secret:
      raise ValueError(
          'Secure runtime key environment variable '
          f'{self.secret_env!r} is not set.'
      )
    return secret


class _SecurePolicyConfig(BaseModel):
  """Policy engine configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  default_effect: str = 'deny'
  default_capability_ttl_seconds: int = Field(default=300, ge=1)
  rules: list[PolicyRule] = Field(default_factory=list)


class _SecureRuntimeOptionsConfig(BaseModel):
  """Runtime plugin behavior configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  plugin_name: str = 'secure_runtime'
  tenant_state_key: str = 'tenant_id'
  case_state_key: str = 'case_id'
  enforce_agent_identity: bool = True
  sign_model_responses: bool = True
  sign_partial_responses: bool = False


class _ArtifactSealingConfig(BaseModel):
  """Artifact sealing configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  signing_key_id: Optional[str] = None
  actor: str = 'omniseal-adapter'

  @model_validator(mode='after')
  def _validate_requirements(self) -> _ArtifactSealingConfig:
    if self.enabled and not self.signing_key_id:
      raise ValueError(
          'artifact_sealing.signing_key_id is required when sealing is enabled.'
      )
    return self


class _LedgerConfig(BaseModel):
  """Provenance ledger configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  path: Optional[str] = None


class SecureRuntimeFileConfig(BaseModel):
  """File-backed SecureADK configuration used by CLI/server entry points."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = True
  signing_keys: dict[str, _SigningKeyConfig]
  identities: list[AgentIdentity]
  policy: _SecurePolicyConfig = Field(default_factory=_SecurePolicyConfig)
  runtime: _SecureRuntimeOptionsConfig = Field(
      default_factory=_SecureRuntimeOptionsConfig
  )
  artifact_sealing: _ArtifactSealingConfig = Field(
      default_factory=_ArtifactSealingConfig
  )
  ledger: _LedgerConfig = Field(default_factory=_LedgerConfig)


def resolve_loaded_app_root(
    agent_or_app: BaseAgent | App,
    *,
    fallback_root: Path | str | None = None,
) -> Optional[Path]:
  """Returns the filesystem root for a loaded agent or app."""
  candidates = []
  if isinstance(agent_or_app, App):
    candidates.append(getattr(agent_or_app, '_adk_origin_path', None))
    candidates.append(getattr(agent_or_app.root_agent, '_adk_origin_path', None))
  else:
    candidates.append(getattr(agent_or_app, '_adk_origin_path', None))

  for candidate in candidates:
    if candidate:
      path = Path(candidate)
      return path if path.is_dir() else path.parent

  if fallback_root is None:
    return None
  fallback_path = Path(fallback_root)
  return fallback_path if fallback_path.is_dir() else fallback_path.parent


def resolve_secure_runtime_config_path(
    app_root: Path | str,
    *,
    secure_config_path: Path | str | None = None,
) -> Optional[Path]:
  """Returns the SecureADK config path, if one is configured."""
  if secure_config_path is not None:
    config_path = Path(secure_config_path).expanduser()
    if not config_path.is_absolute():
      config_path = (Path(app_root) / config_path).resolve()
    if not config_path.exists():
      raise ValueError(
          f'Secure runtime config file not found: {config_path}'
      )
    return config_path

  if is_env_enabled(SECURE_RUNTIME_DISABLE_ENV):
    return None

  app_root = Path(app_root)
  explicit_path = os.environ.get(SECURE_RUNTIME_CONFIG_ENV)
  if explicit_path:
    config_path = Path(explicit_path).expanduser()
    if not config_path.is_absolute():
      config_path = (app_root / config_path).resolve()
    if not config_path.exists():
      raise ValueError(
          f'Secure runtime config file not found: {config_path}'
      )
    return config_path

  for candidate_name in _CONFIG_FILE_CANDIDATES:
    candidate_path = app_root / candidate_name
    if candidate_path.exists():
      return candidate_path

  return None


def load_secure_runtime_builder(
    app_root: Path | str,
    *,
    secure_config_path: Path | str | None = None,
) -> Optional[SecureRuntimeBuilder]:
  """Loads a SecureRuntimeBuilder from app-local config if present."""
  app_root = Path(app_root)
  config_path = resolve_secure_runtime_config_path(
      app_root,
      secure_config_path=secure_config_path,
  )
  if config_path is None:
    return None

  config = SecureRuntimeFileConfig.model_validate(
      _load_config_data(config_path)
  )
  if not config.enabled:
    return None

  keyring = HmacKeyring({
      key_id: key_config.resolve_secret()
      for key_id, key_config in config.signing_keys.items()
  })
  ledger_path = (
      Path(config.ledger.path).expanduser()
      if config.ledger.path
      else app_root / '.adk' / 'secureadk' / 'ledger.jsonl'
  )
  if not ledger_path.is_absolute():
    ledger_path = (app_root / ledger_path).resolve()
  ledger = FileProvenanceLedger(ledger_path)
  return SecureRuntimeBuilder(
      identity_registry=IdentityRegistry(config.identities),
      capability_vault=CapabilityVault(
          policy_engine=SimplePolicyEngine(
              config.policy.rules,
              default_effect=config.policy.default_effect,
              default_capability_ttl_seconds=(
                  config.policy.default_capability_ttl_seconds
              ),
          ),
          keyring=keyring,
      ),
      ledger=ledger,
      response_keyring=keyring,
      plugin_name=config.runtime.plugin_name,
      tenant_state_key=config.runtime.tenant_state_key,
      case_state_key=config.runtime.case_state_key,
      enforce_agent_identity=config.runtime.enforce_agent_identity,
      sign_model_responses=config.runtime.sign_model_responses,
      sign_partial_responses=config.runtime.sign_partial_responses,
      artifact_signing_key_id=config.artifact_sealing.signing_key_id,
      artifact_keyring=keyring,
      artifact_actor=config.artifact_sealing.actor,
  )


def apply_secure_runtime_if_configured(
    *,
    app: App,
    artifact_service: BaseArtifactService | None,
    app_root: Path | str | None,
    secure_config_path: Path | str | None = None,
) -> tuple[App, BaseArtifactService | None]:
  """Wraps an app and artifact service with SecureADK when configured."""
  if app_root is None:
    return app, artifact_service

  builder = load_secure_runtime_builder(
      app_root,
      secure_config_path=secure_config_path,
  )
  if builder is None:
    return app, artifact_service

  logger.info('Enabling SecureADK for app %s from %s', app.name, app_root)
  return builder.apply_to_app(app), builder.wrap_artifact_service(
      artifact_service
  )


def _load_config_data(config_path: Path) -> dict[str, object]:
  """Loads a SecureADK config file from YAML or JSON."""
  text = config_path.read_text(encoding='utf-8')
  suffix = config_path.suffix.lower()
  if suffix == '.json':
    data = json.loads(text)
  else:
    data = yaml.safe_load(text)
  if not isinstance(data, dict):
    raise ValueError(
        f'Secure runtime config must deserialize to an object: {config_path}'
    )
  return data

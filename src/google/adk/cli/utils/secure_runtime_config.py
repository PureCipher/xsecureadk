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
from ...secure.alert_sinks import CompositeAnomalyAlertSink
from ...secure.alert_sinks import FileAnomalyAlertSink
from ...secure.alert_sinks import LoggingAnomalyAlertSink
from ...secure.alert_sinks import WebhookAnomalyAlertSink
from ...secure.anomaly import RuleBasedAnomalyDetector
from ...secure.attestation import DEFAULT_ATTESTATION_FILE_NAME
from ...secure.attestation import DeploymentAttestor
from ...secure.attestation import find_attestation_file
from ...secure.capabilities import CapabilityVault
from ...secure.gateway import GatewayRule
from ...secure.gateway import RuleBasedAccessGateway
from ...secure.identities import AgentIdentity
from ...secure.identities import IdentityRegistry
from ...secure.isolation import TenantIsolationBinding
from ...secure.isolation import TenantIsolationManager
from ...secure.lineage import FileLineageStore
from ...secure.lineage import LineageTracker
from ...secure.observability import BigQuerySecureEventSink
from ...secure.observability import CompositeSecureEventSink
from ...secure.observability import DatadogSecureEventSink
from ...secure.observability import FileSecureEventSink
from ...secure.observability import LoggingSecureEventSink
from ...secure.observability import OpenTelemetrySecureEventSink
from ...secure.observability import SplunkHecSecureEventSink
from ...secure.observability import WebhookSecureEventSink
from ...secure.policies import PolicyRule
from ...secure.policies import SimplePolicyEngine
from ...secure.privacy import TelemetryRedactor
from ...secure.provenance import FileProvenanceLedger
from ...secure.recommendations import FilePolicyObservationStore
from ...secure.recommendations import PolicyRecommender
from ...secure.runtime import SecureRuntimeApplication
from ...secure.runtime import SecureRuntimeBuilder
from ...secure.signing import HmacKeyring
from ...secure.signing import SigningKey
from ...secure.tenant_crypto import TenantCryptoManager
from ...secure.trust import FileTrustStore
from ...secure.trust import TrustScorer
from ...secure.trusted_evaluators import TrustedEvaluatorIdentity
from ...secure.trusted_evaluators import TrustedEvaluatorRegistry
from ...secure.trusted_evaluators import TrustedEvaluatorService
from ...sessions.base_session_service import BaseSessionService
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
  epoch: int = Field(default=1, ge=1)
  not_before: Optional[float] = None
  not_after: Optional[float] = None
  revoked: bool = False
  revoked_at: Optional[float] = None

  @model_validator(mode='after')
  def _validate_source(self) -> _SigningKeyConfig:
    if bool(self.secret) == bool(self.secret_env):
      raise ValueError('Exactly one of secret or secret_env must be provided.')
    if self.revoked and self.revoked_at is None:
      self.revoked_at = 0.0
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

  def build_signing_key(self) -> SigningKey:
    """Builds signing metadata for the configured key."""
    return SigningKey.from_secret(
        self.resolve_secret(),
        epoch=self.epoch,
        not_before=self.not_before,
        not_after=self.not_after,
        revoked_at=self.revoked_at,
    )


class _SecurePolicyConfig(BaseModel):
  """Policy engine configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  default_effect: str = 'deny'
  default_capability_ttl_seconds: int = Field(default=300, ge=1)
  approval_risk_score_threshold: Optional[float] = Field(default=None, ge=0.0)
  default_approval_hint: Optional[str] = None
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


class _GatewayConfig(BaseModel):
  """Dedicated gateway configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  default_effect: str = 'deny'
  approval_risk_score_threshold: Optional[float] = Field(default=None, ge=0.0)
  default_approval_hint: Optional[str] = None
  rules: list[GatewayRule] = Field(default_factory=list)


class _AnomalyLoggingSinkConfig(BaseModel):
  """Logging sink configuration for anomaly alerts."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  logger_name: str = 'google_adk.secure.anomaly_alerts'
  level: str = 'WARNING'


class _AnomalyExportSinkConfig(BaseModel):
  """JSONL export sink configuration for anomaly alerts."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  path: Optional[str] = None


class _AnomalyWebhookSinkConfig(BaseModel):
  """Webhook sink configuration for anomaly alerts."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  url: Optional[str] = None
  timeout_seconds: float = Field(default=5.0, gt=0.0)
  headers: dict[str, str] = Field(default_factory=dict)
  signing_key_id: Optional[str] = None

  @model_validator(mode='after')
  def _validate_requirements(self) -> _AnomalyWebhookSinkConfig:
    if self.enabled and not self.url:
      raise ValueError(
          'anomaly_detection.webhook.url is required when the webhook sink'
          ' is enabled.'
      )
    return self


class _AnomalyConfig(BaseModel):
  """Runtime anomaly detector configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  repeated_denials_threshold: int = Field(default=3, ge=1)
  capability_burst_threshold: int = Field(default=10, ge=1)
  duplicate_response_agents_threshold: int = Field(default=2, ge=2)
  high_risk_score_threshold: float = Field(default=0.8, ge=0.0)
  block_severity_threshold: Optional[float] = Field(default=None, ge=0.0)
  logging: _AnomalyLoggingSinkConfig = Field(
      default_factory=_AnomalyLoggingSinkConfig
  )
  export: _AnomalyExportSinkConfig = Field(
      default_factory=_AnomalyExportSinkConfig
  )
  webhook: _AnomalyWebhookSinkConfig = Field(
      default_factory=_AnomalyWebhookSinkConfig
  )

  @model_validator(mode='after')
  def _validate_sink_enablement(self) -> _AnomalyConfig:
    if self.enabled:
      return self
    if self.logging.enabled or self.export.enabled or self.webhook.enabled:
      raise ValueError(
          'anomaly_detection.enabled must be true when anomaly alert sinks'
          ' are configured.'
      )
    return self


class _LineageConfig(BaseModel):
  """Versioned lineage capture configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  path: Optional[str] = None


class _TrustedEvaluatorsConfig(BaseModel):
  """Trusted evaluator signing configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  evaluator_name: str = 'secureadk-trusted-evaluator'
  signing_key_id: Optional[str] = None
  trusted_evaluators: list[TrustedEvaluatorIdentity] = Field(
      default_factory=list
  )
  sign_inference_results: bool = True
  sign_eval_case_results: bool = True
  sign_eval_set_results: bool = True

  @model_validator(mode='after')
  def _validate_requirements(self) -> _TrustedEvaluatorsConfig:
    if self.enabled and not self.signing_key_id:
      raise ValueError(
          'trusted_evaluators.signing_key_id is required when enabled.'
      )
    return self


class _TelemetryPrivacyConfig(BaseModel):
  """PII-aware telemetry redaction configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  mode: str = 'redact'
  replacement_text: str = '<redacted>'
  field_names: list[str] = Field(default_factory=list)
  redact_email: bool = True
  redact_phone: bool = True
  redact_ssn: bool = True
  redact_credit_card: bool = True
  tokenization_key_id: Optional[str] = None

  @model_validator(mode='after')
  def _validate_mode(self) -> _TelemetryPrivacyConfig:
    if self.mode not in ('redact', 'tokenize'):
      raise ValueError('telemetry_privacy.mode must be "redact" or "tokenize".')
    if (
        self.enabled
        and self.mode == 'tokenize'
        and not self.tokenization_key_id
    ):
      raise ValueError(
          'telemetry_privacy.tokenization_key_id is required for tokenization.'
      )
    return self


class _ObservabilityLoggingConfig(BaseModel):
  """Logging sink configuration for secure events."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  logger_name: str = 'google_adk.secure.events'
  level: str = 'INFO'


class _ObservabilityExportConfig(BaseModel):
  """JSONL export configuration for secure events."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  path: Optional[str] = None


class _ObservabilityWebhookConfig(BaseModel):
  """Webhook configuration for secure event export."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  url: Optional[str] = None
  timeout_seconds: float = Field(default=5.0, gt=0.0)
  headers: dict[str, str] = Field(default_factory=dict)
  signing_key_id: Optional[str] = None

  @model_validator(mode='after')
  def _validate_requirements(self) -> _ObservabilityWebhookConfig:
    if self.enabled and not self.url:
      raise ValueError(
          'observability.webhook.url is required when the webhook sink is'
          ' enabled.'
      )
    return self


class _ObservabilityOpenTelemetryConfig(BaseModel):
  """OpenTelemetry configuration for secure events."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  event_name_prefix: str = 'secureadk'
  span_name: str = 'secureadk.observe'


class _ObservabilitySplunkConfig(BaseModel):
  """Splunk HEC sink configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  url: Optional[str] = None
  token: Optional[str] = None
  token_env: Optional[str] = None
  timeout_seconds: float = Field(default=5.0, gt=0.0)
  source: str = 'secureadk'
  sourcetype: str = '_json'
  host: Optional[str] = None

  @model_validator(mode='after')
  def _validate_requirements(self) -> _ObservabilitySplunkConfig:
    if not self.enabled:
      return self
    if not self.url:
      raise ValueError('observability.splunk.url is required when enabled.')
    if bool(self.token) == bool(self.token_env):
      raise ValueError(
          'Exactly one of observability.splunk.token or token_env must be'
          ' provided.'
      )
    return self

  def resolve_token(self) -> str:
    if self.token is not None:
      return self.token
    assert self.token_env is not None
    token = os.environ.get(self.token_env)
    if not token:
      raise ValueError(
          'Secure runtime observability token environment variable '
          f'{self.token_env!r} is not set.'
      )
    return token


class _ObservabilityDatadogConfig(BaseModel):
  """Datadog log export configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  api_key: Optional[str] = None
  api_key_env: Optional[str] = None
  url: str = 'https://http-intake.logs.datadoghq.com/api/v2/logs'
  timeout_seconds: float = Field(default=5.0, gt=0.0)
  service: str = 'adk'
  source: str = 'secureadk'
  tags: list[str] = Field(default_factory=list)

  @model_validator(mode='after')
  def _validate_requirements(self) -> _ObservabilityDatadogConfig:
    if not self.enabled:
      return self
    if bool(self.api_key) == bool(self.api_key_env):
      raise ValueError(
          'Exactly one of observability.datadog.api_key or api_key_env must be'
          ' provided.'
      )
    return self

  def resolve_api_key(self) -> str:
    if self.api_key is not None:
      return self.api_key
    assert self.api_key_env is not None
    api_key = os.environ.get(self.api_key_env)
    if not api_key:
      raise ValueError(
          'Secure runtime Datadog api key environment variable '
          f'{self.api_key_env!r} is not set.'
      )
    return api_key


class _ObservabilityBigQueryConfig(BaseModel):
  """BigQuery export configuration for secure events."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  project_id: Optional[str] = None
  dataset: Optional[str] = None
  table: str = 'secureadk_events'

  @model_validator(mode='after')
  def _validate_requirements(self) -> _ObservabilityBigQueryConfig:
    if self.enabled and not self.dataset:
      raise ValueError(
          'observability.bigquery.dataset is required when BigQuery export is'
          ' enabled.'
      )
    return self


class _ObservabilityConfig(BaseModel):
  """Observability and SIEM export configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  logging: _ObservabilityLoggingConfig = Field(
      default_factory=_ObservabilityLoggingConfig
  )
  export: _ObservabilityExportConfig = Field(
      default_factory=_ObservabilityExportConfig
  )
  webhook: _ObservabilityWebhookConfig = Field(
      default_factory=_ObservabilityWebhookConfig
  )
  opentelemetry: _ObservabilityOpenTelemetryConfig = Field(
      default_factory=_ObservabilityOpenTelemetryConfig
  )
  splunk: _ObservabilitySplunkConfig = Field(
      default_factory=_ObservabilitySplunkConfig
  )
  datadog: _ObservabilityDatadogConfig = Field(
      default_factory=_ObservabilityDatadogConfig
  )
  bigquery: _ObservabilityBigQueryConfig = Field(
      default_factory=_ObservabilityBigQueryConfig
  )

  @model_validator(mode='after')
  def _validate_enablement(self) -> _ObservabilityConfig:
    if self.enabled:
      return self
    child_enabled = any([
        self.logging.enabled,
        self.export.enabled,
        self.webhook.enabled,
        self.opentelemetry.enabled,
        self.splunk.enabled,
        self.datadog.enabled,
        self.bigquery.enabled,
    ])
    if child_enabled:
      raise ValueError(
          'observability.enabled must be true when secure event sinks are'
          ' configured.'
      )
    return self


class _PolicyRecommendationsConfig(BaseModel):
  """Policy recommendation capture and reporting configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  path: Optional[str] = None
  minimum_evidence_count: int = Field(default=3, ge=1)
  high_risk_threshold: float = Field(default=0.8, ge=0.0)


class _TenantIsolationConfig(BaseModel):
  """Tenant isolation and sandbox separation configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  require_tenant: bool = True
  enforce_identity_tenant_match: bool = True
  require_session_scoped_artifacts: bool = True
  bindings: list[TenantIsolationBinding] = Field(default_factory=list)

  @model_validator(mode='after')
  def _validate_bindings(self) -> _TenantIsolationConfig:
    if self.enabled and not self.bindings:
      raise ValueError(
          'tenant_isolation.bindings is required when isolation is enabled.'
      )
    return self


class _DeploymentAttestationConfig(BaseModel):
  """Deployment attestation configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  signing_key_id: Optional[str] = None
  actor: str = 'secureadk-deployer'
  file_name: str = DEFAULT_ATTESTATION_FILE_NAME

  @model_validator(mode='after')
  def _validate_requirements(self) -> _DeploymentAttestationConfig:
    if self.enabled and not self.signing_key_id:
      raise ValueError(
          'deployment_attestation.signing_key_id is required when enabled.'
      )
    return self


class _TrustScoringConfig(BaseModel):
  """Trust score persistence and scoring configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  path: Optional[str] = None
  base_score: float = Field(default=0.75, ge=0.0, le=1.0)
  min_score: float = Field(default=0.0, ge=0.0, le=1.0)
  max_score: float = Field(default=1.0, ge=0.0, le=1.0)

  @model_validator(mode='after')
  def _validate_bounds(self) -> _TrustScoringConfig:
    if self.min_score > self.max_score:
      raise ValueError(
          'trust_scoring.min_score must be less than or equal to max_score.'
      )
    if not self.min_score <= self.base_score <= self.max_score:
      raise ValueError(
          'trust_scoring.base_score must fall within the configured bounds.'
      )
    return self


class _TenantCryptoConfig(BaseModel):
  """Per-tenant signing scope configuration."""

  model_config = ConfigDict(
      extra='forbid',
  )

  enabled: bool = False
  require_tenant: bool = False


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
  gateway: _GatewayConfig = Field(default_factory=_GatewayConfig)
  anomaly_detection: _AnomalyConfig = Field(default_factory=_AnomalyConfig)
  lineage: _LineageConfig = Field(default_factory=_LineageConfig)
  telemetry_privacy: _TelemetryPrivacyConfig = Field(
      default_factory=_TelemetryPrivacyConfig
  )
  observability: _ObservabilityConfig = Field(
      default_factory=_ObservabilityConfig
  )
  policy_recommendations: _PolicyRecommendationsConfig = Field(
      default_factory=_PolicyRecommendationsConfig
  )
  trusted_evaluators: _TrustedEvaluatorsConfig = Field(
      default_factory=_TrustedEvaluatorsConfig
  )
  tenant_isolation: _TenantIsolationConfig = Field(
      default_factory=_TenantIsolationConfig
  )
  deployment_attestation: _DeploymentAttestationConfig = Field(
      default_factory=_DeploymentAttestationConfig
  )
  trust_scoring: _TrustScoringConfig = Field(
      default_factory=_TrustScoringConfig
  )
  tenant_crypto: _TenantCryptoConfig = Field(
      default_factory=_TenantCryptoConfig
  )


def resolve_loaded_app_root(
    agent_or_app: BaseAgent | App,
    *,
    fallback_root: Path | str | None = None,
) -> Optional[Path]:
  """Returns the filesystem root for a loaded agent or app."""
  candidates = []
  if isinstance(agent_or_app, App):
    candidates.append(getattr(agent_or_app, '_adk_origin_path', None))
    candidates.append(
        getattr(agent_or_app.root_agent, '_adk_origin_path', None)
    )
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
      raise ValueError(f'Secure runtime config file not found: {config_path}')
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
      raise ValueError(f'Secure runtime config file not found: {config_path}')
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
      key_id: key_config.build_signing_key()
      for key_id, key_config in config.signing_keys.items()
  })
  policy_engine = SimplePolicyEngine(
      config.policy.rules,
      default_effect=config.policy.default_effect,
      default_capability_ttl_seconds=(
          config.policy.default_capability_ttl_seconds
      ),
      approval_risk_score_threshold=(
          config.policy.approval_risk_score_threshold
      ),
      default_approval_hint=config.policy.default_approval_hint,
  )
  ledger_path = (
      Path(config.ledger.path).expanduser()
      if config.ledger.path
      else app_root / '.adk' / 'secureadk' / 'ledger.jsonl'
  )
  if not ledger_path.is_absolute():
    ledger_path = (app_root / ledger_path).resolve()
  ledger = FileProvenanceLedger(ledger_path)
  lineage_tracker = None
  if config.lineage.enabled:
    lineage_path = (
        Path(config.lineage.path).expanduser()
        if config.lineage.path
        else app_root / '.adk' / 'secureadk' / 'lineage.jsonl'
    )
    if not lineage_path.is_absolute():
      lineage_path = (app_root / lineage_path).resolve()
    lineage_tracker = LineageTracker(store=FileLineageStore(lineage_path))
  telemetry_redactor = None
  if config.telemetry_privacy.enabled:
    telemetry_redactor_kwargs = dict(
        mode=config.telemetry_privacy.mode,
        replacement_text=config.telemetry_privacy.replacement_text,
        redact_email=config.telemetry_privacy.redact_email,
        redact_phone=config.telemetry_privacy.redact_phone,
        redact_ssn=config.telemetry_privacy.redact_ssn,
        redact_credit_card=config.telemetry_privacy.redact_credit_card,
        keyring=keyring
        if config.telemetry_privacy.mode == 'tokenize'
        else None,
        tokenization_key_id=config.telemetry_privacy.tokenization_key_id,
    )
    if config.telemetry_privacy.field_names:
      telemetry_redactor_kwargs['field_names'] = frozenset(
          config.telemetry_privacy.field_names
      )
    telemetry_redactor = TelemetryRedactor(
        **telemetry_redactor_kwargs,
    )
  secure_event_sink = None
  if config.observability.enabled:
    secure_event_sinks = []
    if config.observability.logging.enabled:
      secure_event_sinks.append(
          LoggingSecureEventSink(
              logger_name=config.observability.logging.logger_name,
              level=config.observability.logging.level,
          )
      )
    if config.observability.export.enabled:
      export_path = (
          Path(config.observability.export.path).expanduser()
          if config.observability.export.path
          else app_root / '.adk' / 'secureadk' / 'secure_events.jsonl'
      )
      if not export_path.is_absolute():
        export_path = (app_root / export_path).resolve()
      secure_event_sinks.append(FileSecureEventSink(export_path))
    if config.observability.webhook.enabled:
      secure_event_sinks.append(
          WebhookSecureEventSink(
              url=config.observability.webhook.url,
              timeout_seconds=config.observability.webhook.timeout_seconds,
              headers=config.observability.webhook.headers,
              keyring=(
                  keyring
                  if config.observability.webhook.signing_key_id
                  else None
              ),
              signing_key_id=config.observability.webhook.signing_key_id,
          )
      )
    if config.observability.opentelemetry.enabled:
      secure_event_sinks.append(
          OpenTelemetrySecureEventSink(
              event_name_prefix=(
                  config.observability.opentelemetry.event_name_prefix
              ),
              span_name=config.observability.opentelemetry.span_name,
          )
      )
    if config.observability.splunk.enabled:
      secure_event_sinks.append(
          SplunkHecSecureEventSink(
              url=config.observability.splunk.url,
              token=config.observability.splunk.resolve_token(),
              timeout_seconds=config.observability.splunk.timeout_seconds,
              source=config.observability.splunk.source,
              sourcetype=config.observability.splunk.sourcetype,
              host=config.observability.splunk.host,
          )
      )
    if config.observability.datadog.enabled:
      secure_event_sinks.append(
          DatadogSecureEventSink(
              api_key=config.observability.datadog.resolve_api_key(),
              url=config.observability.datadog.url,
              timeout_seconds=config.observability.datadog.timeout_seconds,
              service=config.observability.datadog.service,
              source=config.observability.datadog.source,
              tags=tuple(config.observability.datadog.tags),
          )
      )
    if config.observability.bigquery.enabled:
      secure_event_sinks.append(
          BigQuerySecureEventSink(
              project_id=config.observability.bigquery.project_id,
              dataset=config.observability.bigquery.dataset,
              table=config.observability.bigquery.table,
          )
      )
    if secure_event_sinks:
      secure_event_sink = CompositeSecureEventSink(secure_event_sinks)
  gateway = None
  if config.gateway.enabled:
    gateway = RuleBasedAccessGateway(
        config.gateway.rules,
        default_effect=config.gateway.default_effect,
        approval_risk_score_threshold=(
            config.gateway.approval_risk_score_threshold
        ),
        default_approval_hint=config.gateway.default_approval_hint,
    )
  anomaly_detector = None
  anomaly_alert_sink = None
  if config.anomaly_detection.enabled:
    anomaly_detector = RuleBasedAnomalyDetector(
        repeated_denials_threshold=(
            config.anomaly_detection.repeated_denials_threshold
        ),
        capability_burst_threshold=(
            config.anomaly_detection.capability_burst_threshold
        ),
        duplicate_response_agents_threshold=(
            config.anomaly_detection.duplicate_response_agents_threshold
        ),
        high_risk_score_threshold=(
            config.anomaly_detection.high_risk_score_threshold
        ),
        block_severity_threshold=(
            config.anomaly_detection.block_severity_threshold
        ),
    )
    anomaly_alert_sinks = []
    if config.anomaly_detection.logging.enabled:
      anomaly_alert_sinks.append(
          LoggingAnomalyAlertSink(
              logger_name=config.anomaly_detection.logging.logger_name,
              level=config.anomaly_detection.logging.level,
          )
      )
    if config.anomaly_detection.export.enabled:
      alert_export_path = (
          Path(config.anomaly_detection.export.path).expanduser()
          if config.anomaly_detection.export.path
          else app_root / '.adk' / 'secureadk' / 'anomaly_alerts.jsonl'
      )
      if not alert_export_path.is_absolute():
        alert_export_path = (app_root / alert_export_path).resolve()
      anomaly_alert_sinks.append(FileAnomalyAlertSink(alert_export_path))
    if config.anomaly_detection.webhook.enabled:
      anomaly_alert_sinks.append(
          WebhookAnomalyAlertSink(
              url=config.anomaly_detection.webhook.url,
              timeout_seconds=(
                  config.anomaly_detection.webhook.timeout_seconds
              ),
              headers=config.anomaly_detection.webhook.headers,
              keyring=(
                  keyring
                  if config.anomaly_detection.webhook.signing_key_id
                  else None
              ),
              signing_key_id=(config.anomaly_detection.webhook.signing_key_id),
          )
      )
    if anomaly_alert_sinks:
      anomaly_alert_sink = CompositeAnomalyAlertSink(anomaly_alert_sinks)
  policy_recommender = None
  if config.policy_recommendations.enabled:
    observation_path = (
        Path(config.policy_recommendations.path).expanduser()
        if config.policy_recommendations.path
        else app_root / '.adk' / 'secureadk' / 'policy_observations.jsonl'
    )
    if not observation_path.is_absolute():
      observation_path = (app_root / observation_path).resolve()
    policy_recommender = PolicyRecommender(
        store=FilePolicyObservationStore(observation_path),
        minimum_evidence_count=(
            config.policy_recommendations.minimum_evidence_count
        ),
        high_risk_threshold=config.policy_recommendations.high_risk_threshold,
    )
  tenant_isolation_manager = None
  if config.tenant_isolation.enabled:
    tenant_isolation_manager = TenantIsolationManager(
        bindings=config.tenant_isolation.bindings,
        tenant_state_key=config.runtime.tenant_state_key,
        require_tenant=config.tenant_isolation.require_tenant,
        enforce_identity_tenant_match=(
            config.tenant_isolation.enforce_identity_tenant_match
        ),
        require_session_scoped_artifacts=(
            config.tenant_isolation.require_session_scoped_artifacts
        ),
    )
  tenant_crypto_manager = None
  if config.tenant_crypto.enabled:
    tenant_crypto_manager = TenantCryptoManager(
        enabled=True,
        tenant_state_key=config.runtime.tenant_state_key,
        require_tenant=config.tenant_crypto.require_tenant,
        isolation_manager=tenant_isolation_manager,
    )
  trust_scorer = None
  if config.trust_scoring.enabled:
    trust_path = (
        Path(config.trust_scoring.path).expanduser()
        if config.trust_scoring.path
        else app_root / '.adk' / 'secureadk' / 'trust'
    )
    if not trust_path.is_absolute():
      trust_path = (app_root / trust_path).resolve()
    trust_scorer = TrustScorer(
        store=FileTrustStore(trust_path),
        base_score=config.trust_scoring.base_score,
        min_score=config.trust_scoring.min_score,
        max_score=config.trust_scoring.max_score,
    )
  trusted_evaluator_service = None
  if config.trusted_evaluators.enabled:
    registry_identities = list(config.trusted_evaluators.trusted_evaluators)
    if not any(
        identity.evaluator_name == config.trusted_evaluators.evaluator_name
        and identity.key_id == config.trusted_evaluators.signing_key_id
        for identity in registry_identities
    ):
      registry_identities.append(
          TrustedEvaluatorIdentity(
              evaluator_name=config.trusted_evaluators.evaluator_name,
              key_id=config.trusted_evaluators.signing_key_id,
          )
      )
    trusted_evaluator_service = TrustedEvaluatorService(
        evaluator_name=config.trusted_evaluators.evaluator_name,
        key_id=config.trusted_evaluators.signing_key_id,
        keyring=keyring,
        registry=TrustedEvaluatorRegistry(registry_identities),
        ledger=ledger,
        lineage_tracker=lineage_tracker,
        sign_inference_results=(
            config.trusted_evaluators.sign_inference_results
        ),
        sign_eval_case_results=(
            config.trusted_evaluators.sign_eval_case_results
        ),
        sign_eval_set_results=config.trusted_evaluators.sign_eval_set_results,
        tenant_crypto_manager=tenant_crypto_manager,
        trust_scorer=trust_scorer,
    )
  deployment_attestor = None
  deployment_attestation = None
  if config.deployment_attestation.enabled:
    deployment_attestor = DeploymentAttestor(
        keyring=keyring,
        signing_key_id=config.deployment_attestation.signing_key_id,
        actor=config.deployment_attestation.actor,
        ledger=ledger,
        lineage_tracker=lineage_tracker,
        tenant_crypto_manager=tenant_crypto_manager,
        attestation_file_name=config.deployment_attestation.file_name,
    )
    attestation_path = find_attestation_file(
        app_root,
        file_name=config.deployment_attestation.file_name,
    )
    if attestation_path is not None:
      deployment_attestation = deployment_attestor.load_attestation(
          attestation_path
      )
  return SecureRuntimeBuilder(
      identity_registry=IdentityRegistry(config.identities),
      capability_vault=CapabilityVault(
          policy_engine=policy_engine,
          keyring=keyring,
          tenant_crypto_manager=tenant_crypto_manager,
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
      gateway=gateway,
      anomaly_detector=anomaly_detector,
      anomaly_alert_sink=anomaly_alert_sink,
      lineage_tracker=lineage_tracker,
      trusted_evaluator_service=trusted_evaluator_service,
      tenant_isolation_manager=tenant_isolation_manager,
      secure_event_sink=secure_event_sink,
      telemetry_redactor=telemetry_redactor,
      policy_recommender=policy_recommender,
      deployment_attestation=deployment_attestation,
      deployment_attestor=deployment_attestor,
      trust_scorer=trust_scorer,
      tenant_crypto_manager=tenant_crypto_manager,
  )


def apply_secure_runtime_if_configured(
    *,
    app: App,
    artifact_service: BaseArtifactService | None,
    app_root: Path | str | None,
    secure_config_path: Path | str | None = None,
) -> tuple[App, BaseArtifactService | None]:
  """Wraps an app and artifact service with SecureADK when configured."""
  secured = apply_secure_runtime_services_if_configured(
      app=app,
      artifact_service=artifact_service,
      session_service=None,
      app_root=app_root,
      secure_config_path=secure_config_path,
  )
  return secured.app, secured.artifact_service


def apply_secure_runtime_services_if_configured(
    *,
    app: App,
    artifact_service: BaseArtifactService | None,
    session_service: BaseSessionService | None,
    app_root: Path | str | None,
    secure_config_path: Path | str | None = None,
) -> SecureRuntimeApplication:
  """Wraps app, session, and artifact services with SecureADK."""
  if app_root is None:
    return SecureRuntimeApplication(
        app=app,
        artifact_service=artifact_service,
        session_service=session_service,
        builder=None,
    )

  builder = load_secure_runtime_builder(
      app_root,
      secure_config_path=secure_config_path,
  )
  if builder is None:
    return SecureRuntimeApplication(
        app=app,
        artifact_service=artifact_service,
        session_service=session_service,
        builder=None,
    )

  logger.info('Enabling SecureADK for app %s from %s', app.name, app_root)
  secure_session_service = builder.wrap_session_service(session_service)
  secure_artifact_service = builder.wrap_artifact_service(
      artifact_service,
      session_service=secure_session_service,
  )
  return SecureRuntimeApplication(
      app=builder.apply_to_app(app),
      artifact_service=secure_artifact_service,
      session_service=secure_session_service,
      builder=builder,
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

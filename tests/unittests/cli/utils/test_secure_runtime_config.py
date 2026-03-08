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

from pathlib import Path

from google.adk.agents.base_agent import BaseAgent
from google.adk.apps.app import App
from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
from google.adk.cli.utils.secure_runtime_config import apply_secure_runtime_if_configured
from google.adk.cli.utils.secure_runtime_config import load_secure_runtime_builder
from google.adk.secure.artifact_sealing import SealedArtifactService


def test_load_secure_runtime_builder_from_yaml(
    tmp_path: Path,
    monkeypatch,
) -> None:
  app_root = tmp_path / 'courtroom'
  app_root.mkdir()
  (app_root / 'secureadk.yaml').write_text(
      '\n'.join([
          'signing_keys:',
          '  judge-key:',
          '    secret_env: JUDGE_SECRET',
          'identities:',
          '  - agent_name: judge',
          '    key_id: judge-key',
          '    roles: [judge]',
          'policy:',
          '  rules:',
          '    - name: judge-read-only',
          '      principals: [judge]',
          '      tools: [sealed_evidence]',
          '      actions: [sealed_evidence]',
          'artifact_sealing:',
          '  enabled: true',
          '  signing_key_id: judge-key',
      ]),
      encoding='utf-8',
  )
  monkeypatch.setenv('JUDGE_SECRET', 'top-secret')

  builder = load_secure_runtime_builder(app_root)

  assert builder is not None
  app = App(name='courtroom', root_agent=BaseAgent(name='judge'))
  secure_app, secure_artifact_service = apply_secure_runtime_if_configured(
      app=app,
      artifact_service=InMemoryArtifactService(),
      app_root=app_root,
  )

  assert any(plugin.name == 'secure_runtime' for plugin in secure_app.plugins)
  assert isinstance(secure_artifact_service, SealedArtifactService)


def test_load_secure_runtime_builder_from_explicit_config_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
  app_root = tmp_path / 'courtroom'
  app_root.mkdir()
  config_path = tmp_path / 'secure-config.yaml'
  config_path.write_text(
      '\n'.join([
          'signing_keys:',
          '  judge-key:',
          '    secret_env: JUDGE_SECRET',
          'identities:',
          '  - agent_name: judge',
          '    key_id: judge-key',
          '    roles: [judge]',
          'policy:',
          '  rules:',
          '    - name: judge-read-only',
          '      principals: [judge]',
          '      tools: [sealed_evidence]',
          '      actions: [sealed_evidence]',
      ]),
      encoding='utf-8',
  )
  monkeypatch.setenv('JUDGE_SECRET', 'top-secret')

  builder = load_secure_runtime_builder(
      app_root,
      secure_config_path=config_path,
  )

  assert builder is not None
  secure_app, secure_artifact_service = apply_secure_runtime_if_configured(
      app=App(name='courtroom', root_agent=BaseAgent(name='judge')),
      artifact_service=InMemoryArtifactService(),
      app_root=app_root,
      secure_config_path=config_path,
  )

  assert any(plugin.name == 'secure_runtime' for plugin in secure_app.plugins)
  assert secure_artifact_service is not None

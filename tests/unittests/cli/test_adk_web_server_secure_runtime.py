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
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from google.adk.agents.base_agent import BaseAgent
from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
from google.adk.cli.adk_web_server import AdkWebServer
from google.adk.secure.artifact_sealing import SEAL_METADATA_KEY
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.genai import types


class _DummyAgent(BaseAgent):

  def __init__(self) -> None:
    super().__init__(name='judge')
    self.sub_agents = []


class _DummyAgentLoader:

  def __init__(self, app_root: Path):
    self._agent = _DummyAgent()
    setattr(self._agent, '_adk_origin_path', app_root)

  def load_agent(self, app_name: str) -> BaseAgent:
    assert app_name == 'courtroom'
    return self._agent

  def list_agents(self) -> list[str]:
    return ['courtroom']

  def list_agents_detailed(self) -> list[dict[str, object]]:
    return []


def test_save_artifact_uses_secure_artifact_wrapper(
    tmp_path: Path, monkeypatch
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
          "      tools: ['*']",
          "      actions: ['*']",
          'artifact_sealing:',
          '  enabled: true',
          '  signing_key_id: judge-key',
      ]),
      encoding='utf-8',
  )
  monkeypatch.setenv('JUDGE_SECRET', 'top-secret')

  adk_web_server = AdkWebServer(
      agent_loader=_DummyAgentLoader(app_root),
      session_service=InMemorySessionService(),
      memory_service=MagicMock(),
      artifact_service=InMemoryArtifactService(),
      credential_service=MagicMock(),
      eval_sets_manager=MagicMock(),
      eval_set_results_manager=MagicMock(),
      agents_dir=str(tmp_path),
  )
  fast_api_app = adk_web_server.get_fast_api_app(
      setup_observer=lambda _observer, _server: None,
      tear_down_observer=lambda _observer, _server: None,
  )
  client = TestClient(fast_api_app)

  response = client.post(
      '/apps/courtroom/users/user/sessions/session/artifacts',
      json={
          'filename': 'sealed.txt',
          'artifact': (
              types.Part(
                  text='sealed evidence'
              ).model_dump(by_alias=True, exclude_none=True,)
          ),
      },
  )

  assert response.status_code == 200
  data = response.json()
  assert SEAL_METADATA_KEY in data['customMetadata']
  assert (
      adk_web_server.app_artifact_service_dict['courtroom'].__class__.__name__
      == 'SealedArtifactService'
  )

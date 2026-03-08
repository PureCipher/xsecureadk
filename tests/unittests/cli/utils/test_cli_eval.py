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

"""Unit tests for utilities in cli_eval."""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from google.adk.agents.base_agent import BaseAgent
from google.adk.apps.app import App


class _DummyAgent(BaseAgent):

  def __init__(self, name: str) -> None:
    super().__init__(name=name)
    self.sub_agents = []


def test_get_eval_sets_manager_local(monkeypatch):
  mock_local_manager = mock.MagicMock()
  monkeypatch.setattr(
      "google.adk.evaluation.local_eval_sets_manager.LocalEvalSetsManager",
      lambda *a, **k: mock_local_manager,
  )
  from google.adk.cli.cli_eval import get_eval_sets_manager

  manager = get_eval_sets_manager(eval_storage_uri=None, agents_dir="some/dir")
  assert manager == mock_local_manager


def test_get_eval_sets_manager_gcs(monkeypatch):
  mock_gcs_manager = mock.MagicMock()
  mock_create_gcs = mock.MagicMock()
  mock_create_gcs.return_value = SimpleNamespace(
      eval_sets_manager=mock_gcs_manager
  )
  monkeypatch.setattr(
      "google.adk.cli.utils.evals.create_gcs_eval_managers_from_uri",
      mock_create_gcs,
  )
  from google.adk.cli.cli_eval import get_eval_sets_manager

  manager = get_eval_sets_manager(
      eval_storage_uri="gs://bucket", agents_dir="some/dir"
  )
  assert manager == mock_gcs_manager
  mock_create_gcs.assert_called_once_with("gs://bucket")


def test_get_agent_or_app_uses_agent_loader(monkeypatch):
  loaded_agent = _DummyAgent("judge")
  mock_loader = mock.MagicMock()
  mock_loader.load_agent.return_value = loaded_agent
  mock_loader_cls = mock.MagicMock(return_value=mock_loader)
  monkeypatch.setattr(
      "google.adk.cli.cli_eval.AgentLoader",
      mock_loader_cls,
  )
  from google.adk.cli.cli_eval import get_agent_or_app

  loaded = get_agent_or_app("/tmp/courtroom")

  assert loaded is loaded_agent
  mock_loader_cls.assert_called_once_with(agents_dir="/tmp")
  mock_loader.load_agent.assert_called_once_with("courtroom")


def test_get_root_agent_extracts_app_root_agent(monkeypatch):
  root_agent = _DummyAgent("judge")
  loaded_app = App(name="courtroom", root_agent=root_agent)
  monkeypatch.setattr(
      "google.adk.cli.cli_eval.get_agent_or_app",
      lambda *_args, **_kwargs: loaded_app,
  )
  from google.adk.cli.cli_eval import get_root_agent

  assert get_root_agent("/tmp/courtroom") is root_agent

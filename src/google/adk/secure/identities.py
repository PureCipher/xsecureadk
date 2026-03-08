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
from typing import Iterable
from typing import Optional

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field


class AgentIdentity(BaseModel):
  """Identity claims bound to an agent at runtime."""

  model_config = ConfigDict(
      extra='forbid',
  )

  agent_name: str
  key_id: str
  roles: tuple[str, ...] = ()
  tenant_id: Optional[str] = None
  attributes: dict[str, Any] = Field(default_factory=dict)

  @property
  def subject(self) -> str:
    return self.agent_name


class IdentityRegistry:
  """Maps agent names to cryptographic identities."""

  def __init__(self, identities: Iterable[AgentIdentity]):
    self._identity_by_agent: dict[str, AgentIdentity] = {}
    for identity in identities:
      if identity.agent_name in self._identity_by_agent:
        raise ValueError(
            'Duplicate identity registration for agent '
            f'{identity.agent_name!r}.'
        )
      self._identity_by_agent[identity.agent_name] = identity

  def get_identity(self, agent_name: str) -> Optional[AgentIdentity]:
    return self._identity_by_agent.get(agent_name)

  def require_identity(self, agent_name: str) -> AgentIdentity:
    identity = self.get_identity(agent_name)
    if identity is None:
      raise ValueError(
          f'No SecureADK identity registered for agent {agent_name!r}.'
      )
    return identity

  def list_identities(self) -> list[AgentIdentity]:
    return list(self._identity_by_agent.values())

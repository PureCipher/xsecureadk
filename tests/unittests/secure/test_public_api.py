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

from google.adk import SecureRuntimeBuilder
from google.adk.secure import EvidenceBundleExporter
from google.adk.secure import GatewayExplanation
from google.adk.secure import PolicyExplanation
from google.adk.secure import SecureRuntimeBuilder as SecureRuntimeBuilderFromSecure
from google.adk.secure import SigningKey


def test_secure_runtime_builder_is_reexported() -> None:
  assert SecureRuntimeBuilder is SecureRuntimeBuilderFromSecure


def test_secure_package_reexports_new_secure_models() -> None:
  assert EvidenceBundleExporter is not None
  assert GatewayExplanation is not None
  assert PolicyExplanation is not None
  assert SigningKey is not None

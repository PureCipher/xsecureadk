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

from unittest import mock

from google.adk.platform import time as platform_time
from google.adk.secure import HmacKeyring
from google.adk.secure import SigningKey
import pytest


def test_keyring_selects_highest_epoch_active_key() -> None:
  keyring = HmacKeyring({
      'old-key': SigningKey.from_secret(
          'old-secret',
          epoch=1,
          not_before=0.0,
          not_after=10.0,
      ),
      'new-key': SigningKey.from_secret(
          'new-secret',
          epoch=2,
          not_before=5.0,
      ),
  })

  with mock.patch.object(platform_time, 'get_time', return_value=6.0):
    assert keyring.default_signing_key_id() == 'new-key'
    envelope = keyring.sign_value({'verdict': 'approved'}, key_id='new-key')

  assert envelope.key_epoch == 2


def test_keyring_preserves_historical_verification_after_revocation() -> None:
  keyring = HmacKeyring(
      {
          'judge-key': SigningKey.from_secret(
              'judge-secret',
              epoch=3,
          )
      }
  )

  with mock.patch.object(platform_time, 'get_time', return_value=5.0):
    envelope = keyring.sign_value({'response': 'signed'}, key_id='judge-key')

  keyring.revoke_key('judge-key', revoked_at=10.0)

  assert keyring.verify_value(
      {'response': 'signed'},
      key_id='judge-key',
      signature=envelope.signature,
      signed_at=envelope.signed_at,
  )
  assert not keyring.verify_value(
      {'response': 'signed'},
      key_id='judge-key',
      signature=envelope.signature,
      signed_at=12.0,
  )

  with mock.patch.object(platform_time, 'get_time', return_value=12.0):
    with pytest.raises(ValueError, match='has been revoked'):
      keyring.sign_value({'response': 'new'}, key_id='judge-key')


def test_keyring_derives_tenant_scoped_signatures() -> None:
  keyring = HmacKeyring({'judge-key': 'judge-secret'})

  envelope = keyring.sign_value(
      {'response': 'signed'},
      key_id='judge-key',
      tenant_id='tenant-a',
  )

  assert envelope.key_scope == 'tenant'
  assert envelope.tenant_id == 'tenant-a'
  assert keyring.verify_value(
      {'response': 'signed'},
      key_id='judge-key',
      signature=envelope.signature,
      signed_at=envelope.signed_at,
      tenant_id='tenant-a',
  )
  assert not keyring.verify_value(
      {'response': 'signed'},
      key_id='judge-key',
      signature=envelope.signature,
      signed_at=envelope.signed_at,
      tenant_id='tenant-b',
  )

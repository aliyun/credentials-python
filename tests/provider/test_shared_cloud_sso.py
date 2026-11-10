import asyncio
import hashlib
import json
import time

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from alibabacloud_credentials.exceptions import CredentialException
from alibabacloud_credentials.provider.cli_profile import (
    CLIProfileCredentialsProvider, _cloud_sso_session_path,
)
from alibabacloud_credentials.provider.cloud_sso import TeaCore


class SharedCloudSSOTest(TestCase):
    def test_shared_session_refresh(self):
        with TemporaryDirectory() as root:
            self.check_refresh(Path(root))

    def check_refresh(self, tmp_path):
        config_path = tmp_path / "custom.json"
        config = {"current": "dev", "profiles": [{
            "name": "dev", "mode": "CloudSSO", "sso_session": "company",
            "cloud_sso_account_id": "account", "cloud_sso_access_config": "role",
        }]}
        config_path.write_text(json.dumps(config))
        namespace = hashlib.sha256(str(config_path.resolve()).encode("utf-8")).hexdigest()
        session = tmp_path.resolve() / "sso" / namespace / "company.json"
        session.parent.mkdir(parents=True)
        cli = CLIProfileCredentialsProvider(profile_file=str(config_path))
        provider = cli._get_credentials_provider(config, "dev")
        seen = []

        class StopRequest(Exception):
            pass

        def check_request(request, _):
            seen.append(request.headers["Authorization"])
            assert json.loads(request.body) == {"AccountId": "account", "AccessConfigurationId": "role"}
            raise StopRequest

        async def check_request_async(request, options):
            check_request(request, options)

        with patch.object(TeaCore, "do_action", check_request), patch.object(
            TeaCore, "async_do_action", check_request_async
        ):
            for data, message in (
                (None, "unable to read CloudSSO session"),
                ("{", "unable to read CloudSSO session"),
                ('{"name": "wrong"}', "invalid CloudSSO session"),
                (json.dumps({"name": "company", "sign_in_url": "https://example.test",
                             "access_token": "expired", "expires_at": 1}), "expired"),
            ):
                if data is not None:
                    session.write_text(data)
                with self.assertRaisesRegex(CredentialException, message):
                    provider._refresh_credentials()
                with self.assertRaisesRegex(CredentialException, message):
                    asyncio.run(provider._refresh_credentials_async())
            for token in ("first", "second"):
                session.write_text(json.dumps({
                    "name": "company", "sign_in_url": "https://example.test/sign-in",
                    "access_token": token, "expires_at": int(time.time()) + 300,
                }))
                with self.assertRaises(StopRequest):
                    provider._refresh_credentials()
                with self.assertRaises(StopRequest):
                    asyncio.run(provider._refresh_credentials_async())
        self.assertEqual(seen, ["Bearer first", "Bearer first", "Bearer second", "Bearer second"])

    def test_default_session_path_and_invalid_name(self):
        with TemporaryDirectory() as root:
            config = Path(root).resolve() / ".aliyun" / "config.json"
            with patch("alibabacloud_credentials.provider.cli_profile.ac.HOME", root):
                self.assertEqual(Path(_cloud_sso_session_path(str(config), "company")),
                                 config.parent / "sso" / "company.json")
                with self.assertRaisesRegex(CredentialException, "invalid CloudSSO session name"):
                    _cloud_sso_session_path(str(config), "../company")

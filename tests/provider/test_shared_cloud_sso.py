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

    def test_writeback_preserves_shared_sessions_and_unknown_fields(self):
        for mode in ("OAuth", "External"):
            with self.subTest(mode=mode), TemporaryDirectory() as root:
                path = Path(root) / "config.json"
                fixture = {
                    "current": "writer",
                    "future_config": {"empty": {}, "nullable": None, "large": 9007199254740993},
                    "profiles": [
                        {"name": "writer", "mode": mode, "future_writer": {}},
                        {"name": "shared", "mode": "CloudSSO", "sso_session": "company",
                         "future_profile": {"empty": {}}},
                    ],
                }
                provider = CLIProfileCredentialsProvider(profile_file=str(path), profile_name="writer")
                for asynchronous in (False, True):
                    path.write_text(json.dumps(fixture), encoding="utf-8")
                    if mode == "OAuth":
                        args = ("refresh", "access", "new-ak", "secret", "token", 100, 200)
                        if asynchronous:
                            asyncio.run(provider._update_oauth_tokens_async(*args))
                        else:
                            provider._update_oauth_tokens(*args)
                    elif asynchronous:
                        asyncio.run(provider._update_external_credentials_async("new-ak", "secret", "token", 200))
                    else:
                        provider._update_external_credentials("new-ak", "secret", "token", 200)
                    result = json.loads(path.read_text(encoding="utf-8"))
                    self.assertEqual("new-ak", result["profiles"][0]["access_key_id"])
                    self.assertEqual({}, result["profiles"][0]["future_writer"])
                    self.assertEqual(fixture["profiles"][1], result["profiles"][1])
                    self.assertEqual(fixture["future_config"], result["future_config"])

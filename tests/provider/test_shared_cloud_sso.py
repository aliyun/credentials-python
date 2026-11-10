import asyncio
import hashlib
import json
import time

import pytest

from alibabacloud_credentials.exceptions import CredentialException
from alibabacloud_credentials.provider.cli_profile import CLIProfileCredentialsProvider


def test_shared_cloud_sso_refreshes_session(tmp_path, monkeypatch):
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

    from alibabacloud_credentials.provider.cloud_sso import TeaCore

    monkeypatch.setattr(TeaCore, "do_action", check_request)
    monkeypatch.setattr(TeaCore, "async_do_action", check_request_async)

    with pytest.raises(CredentialException, match="unable to read CloudSSO session"):
        provider._refresh_credentials()
    for token in ("first", "second"):
        session.write_text(json.dumps({
            "name": "company", "sign_in_url": "https://example.test/sign-in",
            "access_token": token, "expires_at": int(time.time()) + 300,
        }))
        with pytest.raises(StopRequest):
            provider._refresh_credentials()
        with pytest.raises(StopRequest):
            asyncio.run(provider._refresh_credentials_async())
    assert seen == ["Bearer first", "Bearer first", "Bearer second", "Bearer second"]

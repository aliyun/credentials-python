import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import os
import json
import time
from alibabacloud_credentials.provider.cli_profile import (
    CLIProfileCredentialsProvider,
    CredentialException,
    _load_config_async,
    _load_config
)
from alibabacloud_credentials.provider import (
    StaticAKCredentialsProvider,
    RamRoleArnCredentialsProvider,
    EcsRamRoleCredentialsProvider,
    OIDCRoleArnCredentialsProvider,
    CloudSSOCredentialsProvider,
    OAuthCredentialsProvider
)
from alibabacloud_credentials.utils import auth_constant as ac


class TestCLIProfileCredentialsProvider(unittest.TestCase):

    def setUp(self):
        # 设置时区环境变量以避免调度器初始化问题
        os.environ['TZ'] = 'UTC'
        self.profile_name = "test_profile"
        self.profile_file = os.path.join(ac.HOME, ".aliyun/config.json")
        self.config = {
            "current": "test_profile",
            "profiles": [
                {
                    "name": "test_profile",
                    "mode": "AK",
                    "access_key_id": "test_access_key_id",
                    "access_key_secret": "test_access_key_secret"
                },
                {
                    "name": "sts_token",
                    "mode": "StsToken",
                    "access_key_id": "test_access_key_id",
                    "access_key_secret": "test_access_key_secret",
                    "sts_token": "test_security_token"
                },
                {
                    "name": "ram_role_profile",
                    "mode": "RamRoleArn",
                    "access_key_id": "test_access_key_id",
                    "access_key_secret": "test_access_key_secret",
                    "ram_role_arn": "test_ram_role_arn",
                    "ram_session_name": "test_ram_session_name",
                    "expired_seconds": 7200,
                    "policy": "test_policy",
                    "external_id": "test_external_id",
                    "sts_region": "test_sts_region",
                    "enable_vpc": True
                },
                {
                    "name": "ecs_ram_role_profile",
                    "mode": "EcsRamRole",
                    "ram_role_name": "test_ram_role_name"
                },
                {
                    "name": "oidc_profile",
                    "mode": "OIDC",
                    "ram_role_arn": "test_ram_role_arn",
                    "oidc_provider_arn": "test_oidc_provider_arn",
                    "oidc_token_file": "test_oidc_token_file",
                    "role_session_name": "test_role_session_name",
                    "expired_seconds": 7200,
                    "policy": "test_policy",
                    "sts_region": "test_sts_region",
                    "enable_vpc": True
                },
                {
                    "name": "chainable_ram_role_profile",
                    "mode": "ChainableRamRoleArn",
                    "source_profile": "test_profile",
                    "ram_role_arn": "test_ram_role_arn",
                    "ram_session_name": "test_ram_session_name",
                    "expired_seconds": 7200,
                    "policy": "test_policy",
                    "external_id": "test_external_id",
                    "sts_region": "test_sts_region",
                    "enable_vpc": True
                },
                {
                    "name": "cloud_sso_profile",
                    "mode": "CloudSSO",
                    "cloud_sso_sign_in_url": "https://sso.example.com",
                    "cloud_sso_account_id": "test_account_id",
                    "cloud_sso_access_config": "test_access_config",
                    "access_token": "test_access_token",
                    "cloud_sso_access_token_expire": int(time.mktime(time.localtime())) + 1000
                },
                {
                    "name": "oauth_profile",
                    "mode": "OAuth",
                    "oauth_site_type": "CN",
                    "oauth_refresh_token": "test_refresh_token",
                    "oauth_access_token": "test_oauth_access_token",
                    "oauth_access_token_expire": int(time.mktime(time.localtime())) + 1000
                }
            ]
        }
        self.access_key_id = "test_access_key_id"
        self.access_key_secret = "test_access_key_secret"
        self.security_token = "test_security_token"
        self.expiration = "2023-12-31T23:59:59Z"
        self.response_body = json.dumps({
            "AccessKeyId": self.access_key_id,
            "AccessKeySecret": self.access_key_secret,
            "SecurityToken": self.security_token,
            "Expiration": self.expiration
        })

    def test_init_valid_input(self):
        """
        Test case 1: Valid input, successfully initializes with provided parameters
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_profile_name', self.profile_name):
            provider = CLIProfileCredentialsProvider()

            self.assertEqual(provider._profile_name, self.profile_name)
            self.assertEqual(provider._profile_file, os.path.join(ac.HOME, ".aliyun/config.json"))

    def test_get_credentials_valid_ak(self):
        """
        Test case 2: Valid input, successfully retrieves credentials for AK mode
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config', return_value=self.config):
                        provider = CLIProfileCredentialsProvider(profile_name=self.profile_name)

                        credentials = provider.get_credentials()

                        self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                        self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                        self.assertIsNone(credentials.get_security_token())
                        self.assertEqual(credentials.get_provider_name(), "cli_profile/static_ak")

    def test_get_credentials_valid_sts(self):
        """
        Test case 2: Valid input, successfully retrieves credentials for StsToken mode
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config', return_value=self.config):
                        provider = CLIProfileCredentialsProvider(profile_name='sts_token')

                        credentials = provider.get_credentials()

                        self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                        self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                        self.assertEqual(credentials.get_security_token(), self.security_token)
                        self.assertEqual(credentials.get_provider_name(), "cli_profile/static_sts")

    def test_get_credentials_valid_ram_role_arn(self):
        """
        Test case 3: Valid input, successfully retrieves credentials for RamRoleArn mode
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config', return_value=self.config):
                        provider = CLIProfileCredentialsProvider(profile_name="ram_role_profile")

                        credentials_provider = provider._get_credentials_provider(config=self.config,
                                                                                  profile_name="ram_role_profile")

                        self.assertIsInstance(credentials_provider, RamRoleArnCredentialsProvider)

                        self.assertEqual(
                            credentials_provider._credentials_provider.get_credentials().get_access_key_id(),
                            self.access_key_id)
                        self.assertEqual(
                            credentials_provider._credentials_provider.get_credentials().get_access_key_secret(),
                            self.access_key_secret)
                        self.assertIsNone(
                            credentials_provider._credentials_provider.get_credentials().get_security_token())
                        self.assertEqual(
                            credentials_provider._credentials_provider.get_credentials().get_provider_name(),
                            "static_ak")
                        self.assertEqual(credentials_provider._role_arn, 'test_ram_role_arn')
                        self.assertEqual(credentials_provider._role_session_name, 'test_ram_session_name')
                        self.assertEqual(credentials_provider._duration_seconds, 7200)
                        self.assertEqual(credentials_provider._policy, 'test_policy')
                        self.assertEqual(credentials_provider._external_id, 'test_external_id')
                        self.assertEqual(credentials_provider._sts_endpoint, 'sts-vpc.test_sts_region.aliyuncs.com')

    def test_get_credentials_valid_ecs_ram_role(self):
        """
        Test case 4: Valid input, successfully retrieves credentials for EcsRamRole mode
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', False):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config', return_value=self.config):
                        provider = CLIProfileCredentialsProvider(profile_name="ecs_ram_role_profile")

                        credentials_provider = provider._get_credentials_provider(config=self.config,
                                                                                  profile_name="ecs_ram_role_profile")

                        self.assertIsInstance(credentials_provider, EcsRamRoleCredentialsProvider)

                        self.assertEqual(credentials_provider._role_name, 'test_ram_role_name')

    def test_get_credentials_valid_oidc(self):
        """
        Test case 5: Valid input, successfully retrieves credentials for OIDC mode
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', False):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config', return_value=self.config):
                        provider = CLIProfileCredentialsProvider(profile_name="oidc_profile")

                        credentials_provider = provider._get_credentials_provider(config=self.config,
                                                                                  profile_name="oidc_profile")

                        self.assertIsInstance(credentials_provider, OIDCRoleArnCredentialsProvider)

                        self.assertEqual(credentials_provider._role_arn, 'test_ram_role_arn')
                        self.assertEqual(credentials_provider._oidc_provider_arn, 'test_oidc_provider_arn')
                        self.assertEqual(credentials_provider._role_session_name, 'test_role_session_name')
                        self.assertEqual(credentials_provider._duration_seconds, 7200)
                        self.assertEqual(credentials_provider._policy, 'test_policy')
                        self.assertEqual(credentials_provider._sts_endpoint, 'sts-vpc.test_sts_region.aliyuncs.com')

    def test_get_credentials_valid_chainable_ram_role_arn(self):
        """
        Test case 6: Valid input, successfully retrieves credentials for ChainableRamRoleArn mode
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', False):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config', return_value=self.config):
                        provider = CLIProfileCredentialsProvider(profile_name="chainable_ram_role_profile")

                        credentials_provider = provider._get_credentials_provider(config=self.config,
                                                                                  profile_name="chainable_ram_role_profile")

                        self.assertIsInstance(credentials_provider, RamRoleArnCredentialsProvider)

                        self.assertEqual(
                            credentials_provider._credentials_provider.get_credentials().get_access_key_id(),
                            self.access_key_id)
                        self.assertEqual(
                            credentials_provider._credentials_provider.get_credentials().get_access_key_secret(),
                            self.access_key_secret)
                        self.assertIsNone(
                            credentials_provider._credentials_provider.get_credentials().get_security_token())
                        self.assertEqual(
                            credentials_provider._credentials_provider.get_credentials().get_provider_name(),
                            "static_ak")
                        self.assertEqual(credentials_provider._role_arn, 'test_ram_role_arn')
                        self.assertEqual(credentials_provider._role_session_name, 'test_ram_session_name')
                        self.assertEqual(credentials_provider._duration_seconds, 7200)
                        self.assertEqual(credentials_provider._policy, 'test_policy')
                        self.assertEqual(credentials_provider._external_id, 'test_external_id')
                        self.assertEqual(credentials_provider._sts_endpoint, 'sts-vpc.test_sts_region.aliyuncs.com')

    def test_get_credentials_valid_cloud_sso(self):
        """
        Test case 7: Valid input, successfully retrieves credentials for CloudSSO mode
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', False):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config', return_value=self.config):
                        provider = CLIProfileCredentialsProvider(profile_name="cloud_sso_profile")

                        credentials_provider = provider._get_credentials_provider(config=self.config,
                                                                                  profile_name="cloud_sso_profile")

                        self.assertIsInstance(credentials_provider, CloudSSOCredentialsProvider)

                        self.assertEqual(credentials_provider._sign_in_url, 'https://sso.example.com')
                        self.assertEqual(credentials_provider._account_id, 'test_account_id')
                        self.assertEqual(credentials_provider._access_config, 'test_access_config')
                        self.assertEqual(credentials_provider._access_token, 'test_access_token')
                        self.assertTrue(credentials_provider._access_token_expire > int(time.mktime(time.localtime())))

    def test_get_credentials_valid_oauth(self):
        """
        Test case 8: Valid input, successfully retrieves credentials for OAuth mode
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', False):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config', return_value=self.config):
                        provider = CLIProfileCredentialsProvider(profile_name="oauth_profile")

                        credentials_provider = provider._get_credentials_provider(config=self.config,
                                                                                  profile_name="oauth_profile")

                        self.assertIsInstance(credentials_provider, OAuthCredentialsProvider)

                        self.assertEqual(credentials_provider._client_id, '4038181954557748008')
                        self.assertEqual(credentials_provider._sign_in_url, 'https://oauth.aliyun.com')
                        self.assertEqual(credentials_provider._access_token, 'test_oauth_access_token')
                        self.assertTrue(credentials_provider._access_token_expire > int(time.mktime(time.localtime())))

    def test_get_credentials_cli_profile_disabled(self):
        """
        Test case 9: CLI profile disabled raises CredentialException
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'True'):
            provider = CLIProfileCredentialsProvider(profile_name=self.profile_name)

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn("cli credentials file is disabled", str(context.exception))

    def test_get_credentials_profile_name_not_exists(self):
        """
        Test case 10: Profile file does not exist raises CredentialException
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config', return_value=self.config):
                        provider = CLIProfileCredentialsProvider(profile_name='not_exists')
                        with self.assertRaises(CredentialException) as context:
                            provider.get_credentials()
                            self.assertIn(f"unable to get profile with 'not_exists' form cli credentials file.",
                                          str(context.exception))

    def test_get_credentials_profile_file_not_exists(self):
        """
        Test case 11: Profile file does not exist raises CredentialException
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=False):
                provider = CLIProfileCredentialsProvider(profile_name=self.profile_name)

                with self.assertRaises(CredentialException) as context:
                    provider.get_credentials()

                self.assertIn(f'unable to open credentials file: {self.profile_file}', str(context.exception))

    def test_get_credentials_profile_file_not_file(self):
        """
        Test case 12: Profile file is not a file raises CredentialException
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=False):
                    provider = CLIProfileCredentialsProvider(profile_name=self.profile_name)

                    with self.assertRaises(CredentialException) as context:
                        provider.get_credentials()

                    self.assertIn(f'unable to open credentials file: {self.profile_file}', str(context.exception))

    def test_get_credentials_invalid_json_format(self):
        """
        Test case 13: Invalid JSON format in profile file raises CredentialException
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config',
                               side_effect=json.JSONDecodeError('Invalid JSON', '', 0)):
                        provider = CLIProfileCredentialsProvider(profile_name=self.profile_name)

                        with self.assertRaises(CredentialException) as context:
                            provider.get_credentials()

                        self.assertIn(f'failed to parse credential form cli credentials file: {self.profile_file}',
                                      str(context.exception))

    def test_get_credentials_empty_json(self):
        """
        Test case 14: Empty JSON in profile file raises CredentialException
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config', return_value={}):
                        provider = CLIProfileCredentialsProvider(profile_name=self.profile_name)

                        with self.assertRaises(CredentialException) as context:
                            provider.get_credentials()

                        self.assertIn("unable to get profile with 'test_profile' form cli credentials file.",
                                      str(context.exception))

    def test_get_credentials_missing_profiles(self):
        """
        Test case 15: Missing profiles in JSON raises CredentialException
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config',
                               return_value={"current": "test_profile"}):
                        provider = CLIProfileCredentialsProvider(profile_name=self.profile_name)

                        with self.assertRaises(CredentialException) as context:
                            provider.get_credentials()

                        self.assertIn(f"unable to get profile with 'test_profile' form cli credentials file.",
                                      str(context.exception))

    def test_get_credentials_invalid_profile_mode(self):
        """
        Test case 16: Invalid profile mode raises CredentialException
        """
        invalid_config = {
            "current": "invalid_profile",
            "profiles": [
                {
                    "name": "invalid_profile",
                    "mode": "InvalidMode",
                    "access_key_id": "test_access_key_id",
                    "access_key_secret": "test_access_key_secret"
                }
            ]
        }
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config',
                               return_value=invalid_config):
                        provider = CLIProfileCredentialsProvider(profile_name="invalid_profile")

                        with self.assertRaises(CredentialException) as context:
                            provider.get_credentials()

                        self.assertIn(f"unsupported profile mode 'InvalidMode' form cli credentials file.",
                                      str(context.exception))

    def test_get_credentials_async_valid_ak(self):
        """
        Test case 17: Valid input, successfully retrieves credentials for AK mode
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config_async',
                               AsyncMock(return_value=self.config)):
                        provider = CLIProfileCredentialsProvider(profile_name=self.profile_name)

                        # 使用 asyncio.run() 替代 get_event_loop()
                        async def run_test():
                            return await provider.get_credentials_async()

                        credentials = asyncio.run(run_test())

                        self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                        self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                        self.assertIsNone(credentials.get_security_token())
                        self.assertEqual(credentials.get_provider_name(), "cli_profile/static_ak")

    @patch('builtins.open', new_callable=MagicMock)
    def test_load_config_file_not_found(self, mock_open):
        """
        Test case 18: File not found raises FileNotFoundError
        """
        mock_open.side_effect = FileNotFoundError(f"No such file or directory: '{self.profile_file}'")

        with self.assertRaises(FileNotFoundError) as context:
            _load_config(self.profile_file)

        self.assertIn(f"No such file or directory: '{self.profile_file}'", str(context.exception))

    @patch('builtins.open', new_callable=MagicMock)
    def test_load_config_invalid_json(self, mock_open):
        """
        Test case 19: Invalid JSON format raises json.JSONDecodeError
        """
        invalid_json = "invalid json content"
        mock_open.return_value.__enter__.return_value.read.return_value = invalid_json

        with self.assertRaises(json.JSONDecodeError) as context:
            _load_config(self.profile_file)

        self.assertIn("Expecting value: line 1 column 1", str(context.exception))

    def test_oauth_token_update_callback(self):
        """测试 OAuth 令牌更新回调功能"""
        import tempfile
        import json
        import time

        # 创建临时配置文件
        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "oauth_test",
            "profiles": [
                {
                    "name": "oauth_test",
                    "mode": "OAuth",
                    "oauth_site_type": "CN",
                    "oauth_refresh_token": "initial_refresh_token",
                    "oauth_access_token": "initial_access_token",
                    "oauth_access_token_expire": int(time.time()) + 3600
                }
            ]
        }

        with open(config_path, 'w') as f:
            json.dump(test_config, f, indent=4)

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="oauth_test",
                profile_file=config_path,
                allow_config_force_rewrite=True
            )

            # 更新令牌
            new_refresh_token = "new_refresh_token"
            new_access_token = "new_access_token"
            new_access_key = "new_access_key"
            new_secret = "new_secret"
            new_security_token = "new_security_token"
            new_expire_time = int(time.time()) + 7200
            new_sts_expire = int(time.time()) + 10800

            provider._update_oauth_tokens(new_refresh_token, new_access_token, new_access_key, new_secret,
                                          new_security_token, new_expire_time, new_sts_expire)

            # 验证配置文件已更新
            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            profile = updated_config['profiles'][0]
            self.assertEqual(profile['oauth_refresh_token'], new_refresh_token)
            self.assertEqual(profile['oauth_access_token'], new_access_token)
            self.assertEqual(profile['access_key_id'], new_access_key)
            self.assertEqual(profile['access_key_secret'], new_secret)
            self.assertEqual(profile['sts_token'], new_security_token)
            self.assertEqual(profile['oauth_access_token_expire'], new_expire_time)
            self.assertEqual(profile['sts_expiration'], new_sts_expire)

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_oauth_callback_integration(self):
        """测试 OAuth 回调集成"""
        import tempfile
        import json
        import time

        # 创建临时配置文件
        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "oauth_test",
            "profiles": [
                {
                    "name": "oauth_test",
                    "mode": "OAuth",
                    "oauth_site_type": "CN",
                    "oauth_refresh_token": "initial_refresh_token",
                    "oauth_access_token": "initial_access_token",
                    "oauth_access_token_expire": int(time.time()) + 3600
                }
            ]
        }

        with open(config_path, 'w') as f:
            json.dump(test_config, f, indent=4)

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="oauth_test",
                profile_file=config_path,
                allow_config_force_rewrite=True
            )

            # 获取回调函数
            callback = provider._get_oauth_token_update_callback()

            # 调用回调函数
            new_refresh_token = "callback_refresh_token"
            new_access_token = "callback_access_token"
            new_access_key = "callback_access_key"
            new_secret = "callback_secret"
            new_security_token = "callback_security_token"
            new_expire_time = int(time.time()) + 3600
            new_sts_expire = int(time.time()) + 7200

            callback(new_refresh_token, new_access_token, new_access_key, new_secret, new_security_token,
                     new_expire_time, new_sts_expire)

            # 验证配置文件已更新
            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            profile = updated_config['profiles'][0]
            self.assertEqual(profile['oauth_refresh_token'], new_refresh_token)
            self.assertEqual(profile['oauth_access_token'], new_access_token)
            self.assertEqual(profile['access_key_id'], new_access_key)
            self.assertEqual(profile['access_key_secret'], new_secret)
            self.assertEqual(profile['sts_token'], new_security_token)
            self.assertEqual(profile['oauth_access_token_expire'], new_expire_time)
            self.assertEqual(profile['sts_expiration'], new_sts_expire)

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_concurrent_token_update(self):
        """测试并发令牌更新"""
        import tempfile
        import json
        import time
        import threading

        # 创建临时配置文件
        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "oauth_test",
            "profiles": [
                {
                    "name": "oauth_test",
                    "mode": "OAuth",
                    "oauth_site_type": "CN",
                    "oauth_refresh_token": "initial_refresh_token",
                    "oauth_access_token": "initial_access_token",
                    "oauth_access_token_expire": int(time.time()) + 3600
                }
            ]
        }

        with open(config_path, 'w') as f:
            json.dump(test_config, f, indent=4)

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="oauth_test",
                profile_file=config_path
            )

            results = []
            errors = []

            def update_tokens(index):
                try:
                    refresh_token = f"refresh_token_{index}"
                    access_token = f"access_token_{index}"
                    access_key = f"access_key_{index}"
                    secret = f"secret_{index}"
                    security_token = f"security_token_{index}"
                    expire_time = int(time.time()) + 3600 + index
                    sts_expire = int(time.time()) + 7200 + index

                    provider._update_oauth_tokens(refresh_token, access_token, access_key, secret, security_token,
                                                  expire_time, sts_expire)
                    results.append(index)
                except Exception as e:
                    errors.append(e)

            # 并发更新
            threads = []
            for i in range(10):
                thread = threading.Thread(target=update_tokens, args=(i,))
                threads.append(thread)
                thread.start()

            # 等待所有线程完成
            for thread in threads:
                thread.join()

            # 验证最终配置文件仍然有效
            with open(config_path, 'r') as f:
                final_config = json.load(f)

            self.assertIsNotNone(final_config)
            self.assertIn('profiles', final_config)
            self.assertEqual(len(final_config['profiles']), 1)

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_file_lock_safety(self):
        """测试文件锁安全性"""
        import tempfile
        import json
        import time

        # 创建临时配置文件
        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "oauth_test",
            "profiles": [
                {
                    "name": "oauth_test",
                    "mode": "OAuth",
                    "oauth_site_type": "CN",
                    "oauth_refresh_token": "initial_refresh_token",
                    "oauth_access_token": "initial_access_token",
                    "oauth_access_token_expire": int(time.time()) + 3600
                }
            ]
        }

        with open(config_path, 'w') as f:
            json.dump(test_config, f, indent=4)

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="oauth_test",
                profile_file=config_path,
                allow_config_force_rewrite=True
            )

            # 测试文件锁是否正常工作
            with provider._file_lock:
                # 在锁内执行操作
                provider._update_oauth_tokens("locked_token", "locked_access", "locked_key", "locked_secret",
                                              "locked_sts", int(time.time()) + 3600, int(time.time()) + 7200)

            # 验证操作成功
            with open(config_path, 'r') as f:
                config = json.load(f)

            profile = config['profiles'][0]
            self.assertEqual(profile['oauth_refresh_token'], "locked_token")

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_write_configuration_to_file(self):
        """测试基本文件写入功能"""
        import tempfile
        import json

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "test",
            "profiles": [{"name": "test", "mode": "AK"}]
        }

        try:
            provider = CLIProfileCredentialsProvider()
            provider._write_configuration_to_file(config_path, test_config)

            # 验证文件已写入
            self.assertTrue(os.path.exists(config_path))

            with open(config_path, 'r') as f:
                loaded_config = json.load(f)

            self.assertEqual(loaded_config, test_config)

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_write_configuration_to_file_error(self):
        """测试写入只读目录时的错误处理"""
        import tempfile
        import stat
        import platform

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "readonly", "config.json")

        # 创建只读目录
        readonly_dir = os.path.join(temp_dir, "readonly")
        os.makedirs(readonly_dir)
        
        # Windows和Unix的权限处理不同
        if platform.system() == 'Windows':
            # Windows下使用更严格的权限设置
            try:
                import win32security
                import win32api
                import win32con
                
                # 获取目录的安全描述符
                sd = win32security.GetFileSecurity(readonly_dir, win32security.DACL_SECURITY_INFORMATION)
                dacl = win32security.ACL()
                
                # 创建拒绝所有访问的ACE
                everyone, domain, type = win32security.LookupAccountName("", "Everyone")
                dacl.AddAccessDeniedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, everyone)
                
                # 应用安全描述符
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(readonly_dir, win32security.DACL_SECURITY_INFORMATION, sd)
                
                test_config = {"current": "test"}
                provider = CLIProfileCredentialsProvider(
                    allow_config_force_rewrite=True,
                )
                
                with self.assertRaises(Exception):
                    provider._write_configuration_to_file(config_path, test_config)
                    
            except ImportError:
                # 如果没有pywin32，跳过这个测试
                self.skipTest("pywin32 not available for Windows permission test")
        else:
            # Unix-like系统使用chmod
            os.chmod(readonly_dir, stat.S_IRUSR | stat.S_IXUSR)  # 只读
            test_config = {"current": "test"}
            provider = CLIProfileCredentialsProvider()

            with self.assertRaises(Exception):
                provider._write_configuration_to_file(config_path, test_config)

        try:
            pass  # 测试逻辑在上面
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_write_configuration_to_file_with_lock(self):
        """测试带文件锁的写入功能"""
        import tempfile
        import json

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "test",
            "profiles": [{"name": "test", "mode": "AK"}]
        }

        try:
            # 先创建文件，因为_write_configuration_to_file_with_lock需要文件存在
            with open(config_path, 'w') as f:
                json.dump({}, f)

            provider = CLIProfileCredentialsProvider(
                allow_config_force_rewrite=True,
            )
            provider._write_configuration_to_file_with_lock(config_path, test_config)

            # 验证文件已写入
            self.assertTrue(os.path.exists(config_path))

            with open(config_path, 'r') as f:
                loaded_config = json.load(f)

            self.assertEqual(loaded_config, test_config)

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_write_configuration_to_file_with_lock_error(self):
        """测试带文件锁写入时的错误处理"""
        import tempfile
        import stat
        import platform

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "readonly", "config.json")

        # 创建只读目录
        readonly_dir = os.path.join(temp_dir, "readonly")
        os.makedirs(readonly_dir)
        
        # Windows和Unix的权限处理不同
        if platform.system() == 'Windows':
            # Windows下使用更严格的权限设置
            try:
                import win32security
                import win32api
                import win32con
                
                # 获取目录的安全描述符
                sd = win32security.GetFileSecurity(readonly_dir, win32security.DACL_SECURITY_INFORMATION)
                dacl = win32security.ACL()
                
                # 创建拒绝所有访问的ACE
                everyone, domain, type = win32security.LookupAccountName("", "Everyone")
                dacl.AddAccessDeniedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, everyone)
                
                # 应用安全描述符
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(readonly_dir, win32security.DACL_SECURITY_INFORMATION, sd)
                
                test_config = {"current": "test"}
                provider = CLIProfileCredentialsProvider()
                
                with self.assertRaises(Exception):
                    provider._write_configuration_to_file_with_lock(config_path, test_config)
                    
            except ImportError:
                # 如果没有pywin32，跳过这个测试
                self.skipTest("pywin32 not available for Windows permission test")
        else:
            # Unix-like系统使用chmod
            os.chmod(readonly_dir, stat.S_IRUSR | stat.S_IXUSR)  # 只读
            test_config = {"current": "test"}
            provider = CLIProfileCredentialsProvider()

            with self.assertRaises(Exception):
                provider._write_configuration_to_file_with_lock(config_path, test_config)

        try:
            pass  # 测试逻辑在上面
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_get_oauth_token_update_callback(self):
        """测试获取OAuth令牌更新回调函数"""
        provider = CLIProfileCredentialsProvider()
        callback = provider._get_oauth_token_update_callback()

        self.assertIsNotNone(callback)
        self.assertTrue(callable(callback))

    def test_update_oauth_tokens_error(self):
        """测试更新OAuth令牌时的错误处理"""
        import tempfile
        import json

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        # 创建无效的配置文件
        with open(config_path, 'w') as f:
            f.write("invalid json")

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="test",
                profile_file=config_path
            )

            # 应该抛出CredentialException异常
            with self.assertRaises(CredentialException) as context:
                provider._update_oauth_tokens("token", "access", "key", "secret", "sts", 123, 456)

            self.assertIn("failed to update OAuth tokens in config file", str(context.exception))

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_update_oauth_tokens_profile_not_found(self):
        """测试更新不存在的profile"""
        import tempfile
        import json

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "test",
            "profiles": [{"name": "test", "mode": "AK"}]
        }

        with open(config_path, 'w') as f:
            json.dump(test_config, f, indent=4)

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="nonexistent",
                profile_file=config_path
            )

            # 应该抛出CredentialException异常
            with self.assertRaises(CredentialException) as context:
                provider._update_oauth_tokens("token", "access", "key", "secret", "sts", 123, 456)

            self.assertIn("failed to update OAuth tokens in config file", str(context.exception))

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_get_credentials_with_oauth_profile(self):
        """测试使用OAuth profile获取凭据"""
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config', return_value=self.config):
                        provider = CLIProfileCredentialsProvider(profile_name="oauth_profile")

                        # 模拟OAuth provider的get_credentials方法
                        with patch(
                                'alibabacloud_credentials.provider.oauth.OAuthCredentialsProvider.get_credentials') as mock_get_creds:
                            from alibabacloud_credentials.provider.refreshable import Credentials
                            mock_creds = Credentials(
                                access_key_id="test_ak",
                                access_key_secret="test_sk",
                                security_token="test_token",
                                provider_name="oauth"
                            )
                            mock_get_creds.return_value = mock_creds

                            credentials = provider.get_credentials()

                            self.assertEqual(credentials.get_access_key_id(), "test_ak")
                            self.assertEqual(credentials.get_access_key_secret(), "test_sk")
                            self.assertEqual(credentials.get_security_token(), "test_token")
                            self.assertEqual(credentials.get_provider_name(), "cli_profile/oauth")

    def test_file_lock_concurrent_access(self):
        """测试文件锁的并发访问"""
        import tempfile
        import json
        import threading
        import time

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "oauth_test",
            "profiles": [
                {
                    "name": "oauth_test",
                    "mode": "OAuth",
                    "oauth_site_type": "CN",
                    "oauth_refresh_token": "initial_token",
                    "oauth_access_token": "initial_access",
                    "oauth_access_token_expire": int(time.time()) + 3600
                }
            ]
        }

        with open(config_path, 'w') as f:
            json.dump(test_config, f, indent=4)

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="oauth_test",
                profile_file=config_path
            )

            results = []
            errors = []

            def update_tokens(index):
                try:
                    provider._update_oauth_tokens(
                        f"token_{index}", f"access_{index}", f"key_{index}",
                        f"secret_{index}", f"sts_{index}",
                        int(time.time()) + 3600 + index, int(time.time()) + 7200 + index
                    )
                    results.append(index)
                except Exception as e:
                    errors.append(e)

            # 并发更新
            threads = []
            for i in range(5):
                thread = threading.Thread(target=update_tokens, args=(i,))
                threads.append(thread)
                thread.start()

            # 等待所有线程完成
            for thread in threads:
                thread.join()

            # 验证最终配置文件仍然有效
            with open(config_path, 'r') as f:
                final_config = json.load(f)

            self.assertIsNotNone(final_config)
            self.assertIn('profiles', final_config)
            self.assertEqual(len(final_config['profiles']), 1)

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_edge_cases(self):
        """测试边界情况"""
        import tempfile
        import json

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        # 测试空配置
        empty_config = {"current": "test", "profiles": []}

        with open(config_path, 'w') as f:
            json.dump(empty_config, f, indent=4)

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="test",
                profile_file=config_path
            )

            # 应该抛出CredentialException异常
            with self.assertRaises(CredentialException) as context:
                provider._update_oauth_tokens("token", "access", "key", "secret", "sts", 123, 456)

            self.assertIn("failed to update OAuth tokens in config file", str(context.exception))

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_profile_name_empty(self):
        """测试空profile名称的情况"""
        import tempfile
        import json

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "test",
            "profiles": [
                {
                    "name": "test",
                    "mode": "OAuth",
                    "oauth_site_type": "CN",
                    "oauth_refresh_token": "initial_token",
                    "oauth_access_token": "initial_access",
                    "oauth_access_token_expire": int(time.time()) + 3600
                }
            ]
        }

        with open(config_path, 'w') as f:
            json.dump(test_config, f, indent=4)

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="",  # 空名称
                profile_file=config_path,
                allow_config_force_rewrite=True
            )

            # 应该使用current profile
            provider._update_oauth_tokens("new_token", "new_access", "new_key", "new_secret", "new_sts", 123, 456)

            # 验证配置文件已更新
            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            profile = updated_config['profiles'][0]
            self.assertEqual(profile['oauth_refresh_token'], "new_token")

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_oauth_token_update_callback_async(self):
        """测试异步OAuth令牌更新回调功能"""
        import tempfile
        import json
        import time

        # 创建临时配置文件
        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "oauth_test",
            "profiles": [
                {
                    "name": "oauth_test",
                    "mode": "OAuth",
                    "oauth_site_type": "CN",
                    "oauth_refresh_token": "initial_refresh_token",
                    "oauth_access_token": "initial_access_token",
                    "oauth_access_token_expire": int(time.time()) + 3600
                }
            ]
        }

        with open(config_path, 'w') as f:
            json.dump(test_config, f, indent=4)

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="oauth_test",
                profile_file=config_path,
                allow_config_force_rewrite=True
            )

            # 更新令牌
            new_refresh_token = "new_refresh_token"
            new_access_token = "new_access_token"
            new_access_key = "new_access_key"
            new_secret = "new_secret"
            new_security_token = "new_security_token"
            new_expire_time = int(time.time()) + 7200
            new_sts_expire = int(time.time()) + 10800

            async def run_test():
                await provider._update_oauth_tokens_async(new_refresh_token, new_access_token, new_access_key,
                                                          new_secret, new_security_token, new_expire_time,
                                                          new_sts_expire)

            # 使用 asyncio.run() 替代 get_event_loop()
            asyncio.run(run_test())

            # 验证配置文件已更新
            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            profile = updated_config['profiles'][0]
            self.assertEqual(profile['oauth_refresh_token'], new_refresh_token)
            self.assertEqual(profile['oauth_access_token'], new_access_token)
            self.assertEqual(profile['access_key_id'], new_access_key)
            self.assertEqual(profile['access_key_secret'], new_secret)
            self.assertEqual(profile['sts_token'], new_security_token)
            self.assertEqual(profile['oauth_access_token_expire'], new_expire_time)
            self.assertEqual(profile['sts_expiration'], new_sts_expire)

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_oauth_callback_async_integration(self):
        """测试异步OAuth回调集成"""
        import tempfile
        import json
        import time

        # 创建临时配置文件
        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "oauth_test",
            "profiles": [
                {
                    "name": "oauth_test",
                    "mode": "OAuth",
                    "oauth_site_type": "CN",
                    "oauth_refresh_token": "initial_refresh_token",
                    "oauth_access_token": "initial_access_token",
                    "oauth_access_token_expire": int(time.time()) + 3600
                }
            ]
        }

        with open(config_path, 'w') as f:
            json.dump(test_config, f, indent=4)

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="oauth_test",
                profile_file=config_path,
                allow_config_force_rewrite=True
            )

            # 获取异步回调函数
            callback = provider._get_oauth_token_update_callback_async()

            # 调用异步回调函数
            new_refresh_token = "callback_refresh_token"
            new_access_token = "callback_access_token"
            new_access_key = "callback_access_key"
            new_secret = "callback_secret"
            new_security_token = "callback_security_token"
            new_expire_time = int(time.time()) + 3600
            new_sts_expire = int(time.time()) + 7200

            async def run_test():
                await callback(new_refresh_token, new_access_token, new_access_key, new_secret, new_security_token,
                               new_expire_time, new_sts_expire)

            # 使用 asyncio.run() 替代 get_event_loop()
            asyncio.run(run_test())

            # 验证配置文件已更新
            with open(config_path, 'r') as f:
                updated_config = json.load(f)

            profile = updated_config['profiles'][0]
            self.assertEqual(profile['oauth_refresh_token'], new_refresh_token)
            self.assertEqual(profile['oauth_access_token'], new_access_token)
            self.assertEqual(profile['access_key_id'], new_access_key)
            self.assertEqual(profile['access_key_secret'], new_secret)
            self.assertEqual(profile['sts_token'], new_security_token)
            self.assertEqual(profile['oauth_access_token_expire'], new_expire_time)
            self.assertEqual(profile['sts_expiration'], new_sts_expire)

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_write_configuration_to_file_async(self):
        """测试异步文件写入功能"""
        import tempfile
        import json

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "test",
            "profiles": [{"name": "test", "mode": "AK"}]
        }

        try:
            provider = CLIProfileCredentialsProvider()

            async def run_test():
                await provider._write_configuration_to_file_async(config_path, test_config)

            # 使用 asyncio.run() 替代 get_event_loop()
            asyncio.run(run_test())

            # 验证文件已写入
            self.assertTrue(os.path.exists(config_path))

            with open(config_path, 'r') as f:
                loaded_config = json.load(f)

            self.assertEqual(loaded_config, test_config)

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_write_configuration_to_file_with_lock_async(self):
        """测试异步带文件锁的写入功能"""
        import tempfile
        import json

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "test",
            "profiles": [{"name": "test", "mode": "AK"}]
        }

        try:
            # 先创建文件，因为_write_configuration_to_file_with_lock_async需要文件存在
            with open(config_path, 'w') as f:
                json.dump({}, f)

            provider = CLIProfileCredentialsProvider(
                allow_config_force_rewrite=True,
            )

            async def run_test():
                await provider._write_configuration_to_file_with_lock_async(config_path, test_config)

            # 使用 asyncio.run() 替代 get_event_loop()
            asyncio.run(run_test())

            # 验证文件已写入
            self.assertTrue(os.path.exists(config_path))

            with open(config_path, 'r') as f:
                loaded_config = json.load(f)

            self.assertEqual(loaded_config, test_config)

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_get_oauth_token_update_callback_async(self):
        """测试获取异步OAuth令牌更新回调函数"""
        provider = CLIProfileCredentialsProvider()
        callback = provider._get_oauth_token_update_callback_async()

        self.assertIsNotNone(callback)
        self.assertTrue(callable(callback))

    def test_update_oauth_tokens_async_error(self):
        """测试异步更新OAuth令牌时的错误处理"""
        import tempfile
        import json

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        # 创建无效的配置文件
        with open(config_path, 'w') as f:
            f.write("invalid json")

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="test",
                profile_file=config_path
            )

            async def run_test():
                with self.assertRaises(CredentialException) as context:
                    await provider._update_oauth_tokens_async("token", "access", "key", "secret", "sts", 123, 456)

                self.assertIn("failed to update OAuth tokens in config file", str(context.exception))

            # 使用 asyncio.run() 替代 get_event_loop()
            asyncio.run(run_test())

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_update_oauth_tokens_async_profile_not_found(self):
        """测试异步更新不存在的profile"""
        import tempfile
        import json

        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "config.json")

        test_config = {
            "current": "test",
            "profiles": [{"name": "test", "mode": "AK"}]
        }

        with open(config_path, 'w') as f:
            json.dump(test_config, f, indent=4)

        try:
            provider = CLIProfileCredentialsProvider(
                profile_name="nonexistent",
                profile_file=config_path
            )

            async def run_test():
                with self.assertRaises(CredentialException) as context:
                    await provider._update_oauth_tokens_async("token", "access", "key", "secret", "sts", 123, 456)

                self.assertIn("failed to update OAuth tokens in config file", str(context.exception))

            # 使用 asyncio.run() 替代 get_event_loop()
            asyncio.run(run_test())

        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

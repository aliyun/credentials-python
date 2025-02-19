import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import os
import json
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
    OIDCRoleArnCredentialsProvider
)
from alibabacloud_credentials.utils import auth_constant as ac


class TestCLIProfileCredentialsProvider(unittest.TestCase):

    def setUp(self):
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

    def test_get_credentials_cli_profile_disabled(self):
        """
        Test case 7: CLI profile disabled raises CredentialException
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'True'):
            provider = CLIProfileCredentialsProvider(profile_name=self.profile_name)

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn("cli credentials file is disabled", str(context.exception))

    def test_get_credentials_profile_file_not_exists(self):
        """
        Test case 8: Profile file does not exist raises CredentialException
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=False):
                provider = CLIProfileCredentialsProvider(profile_name=self.profile_name)

                with self.assertRaises(CredentialException) as context:
                    provider.get_credentials()

                self.assertIn(f'unable to open credentials file: {self.profile_file}', str(context.exception))

    def test_get_credentials_profile_file_not_file(self):
        """
        Test case 9: Profile file is not a file raises CredentialException
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
        Test case 10: Invalid JSON format in profile file raises CredentialException
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
        Test case 11: Empty JSON in profile file raises CredentialException
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
        Test case 12: Missing profiles in JSON raises CredentialException
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
        Test case 13: Invalid profile mode raises CredentialException
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
        Test case 14: Valid input, successfully retrieves credentials for AK mode
        """
        with patch('alibabacloud_credentials.provider.cli_profile.au.environment_cli_profile_disabled', 'False'):
            with patch('os.path.exists', return_value=True):
                with patch('os.path.isfile', return_value=True):
                    with patch('alibabacloud_credentials.provider.cli_profile._load_config_async',
                               AsyncMock(return_value=self.config)):
                        provider = CLIProfileCredentialsProvider(profile_name=self.profile_name)

                        loop = asyncio.get_event_loop()
                        task = asyncio.ensure_future(
                            provider.get_credentials_async()
                        )
                        loop.run_until_complete(task)
                        credentials = task.result()

                        self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                        self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                        self.assertIsNone(credentials.get_security_token())
                        self.assertEqual(credentials.get_provider_name(), "cli_profile/static_ak")

    @patch('builtins.open', new_callable=MagicMock)
    def test_load_config_file_not_found(self, mock_open):
        """
        Test case 15: File not found raises FileNotFoundError
        """
        mock_open.side_effect = FileNotFoundError(f"No such file or directory: '{self.profile_file}'")

        with self.assertRaises(FileNotFoundError) as context:
            _load_config(self.profile_file)

        self.assertIn(f"No such file or directory: '{self.profile_file}'", str(context.exception))

    @patch('builtins.open', new_callable=MagicMock)
    def test_load_config_invalid_json(self, mock_open):
        """
        Test case 16: Invalid JSON format raises json.JSONDecodeError
        """
        invalid_json = "invalid json content"
        mock_open.return_value.__enter__.return_value.read.return_value = invalid_json

        with self.assertRaises(json.JSONDecodeError) as context:
            _load_config(self.profile_file)

        self.assertIn("Expecting value: line 1 column 1", str(context.exception))

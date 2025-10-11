import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import os
from alibabacloud_credentials.provider.profile import (
    ProfileCredentialsProvider,
    CredentialException
)
from alibabacloud_credentials.utils import auth_util as au
from alibabacloud_credentials.utils import auth_constant as ac


class TestProfileCredentialsProvider(unittest.TestCase):

    def setUp(self):
        self.profile_name = "default"
        self.profile_file = os.path.join(ac.HOME, ".alibabacloud/credentials.ini")
        self.config = {'default': {
            'type': 'access_key',
            'access_key_id': 'test_access_key_id',
            'access_key_secret': 'test_access_key_secret'
        }, 'ram_role_profile': {
            'type': 'ram_role_arn',
            'access_key_id': 'test_access_key_id',
            'access_key_secret': 'test_access_key_secret',
            'role_arn': 'test_ram_role_arn',
            'role_session_name': 'test_ram_session_name',
            'policy': 'test_policy'
        }, 'oidc_profile': {
            'type': 'oidc_role_arn',
            'role_arn': 'test_ram_role_arn',
            'oidc_provider_arn': 'test_oidc_provider_arn',
            'oidc_token_file_path': 'test_oidc_token_file_path',
            'role_session_name': 'test_role_session_name',
            'policy': 'test_policy'
        }, 'ecs_ram_role_profile': {
            'type': 'ecs_ram_role',
            'role_name': 'test_ram_role_name'
        }, 'rsa_key_pair_profile': {
            'type': 'rsa_key_pair',
            'public_key_id': 'test_public_key_id',
            'private_key_file': 'test_private_key_file'
        }}
        self.access_key_id = "test_access_key_id"
        self.access_key_secret = "test_access_key_secret"
        self.security_token = "test_security_token"
        self.expiration = "2023-12-31T23:59:59Z"
        self.response_body = {
            "AccessKeyId": self.access_key_id,
            "AccessKeySecret": self.access_key_secret,
            "SecurityToken": self.security_token,
            "Expiration": self.expiration
        }

    def test_init_valid_input(self):
        """
        Test case 1: Valid input, successfully initializes with provided parameters
        """
        with patch('alibabacloud_credentials.provider.profile.au.environment_credentials_file', self.profile_file):
            provider = ProfileCredentialsProvider()

            self.assertEqual(provider._profile_file, self.profile_file)
            self.assertEqual(provider._profile_name, au.client_type)

    def test_get_credentials_valid_access_key(self):
        """
        Test case 2: Valid input, successfully retrieves credentials for access_key type
        """
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini', return_value=self.config):
                    provider = ProfileCredentialsProvider(profile_name=self.profile_name)

                    credentials = provider.get_credentials()

                    self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                    self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                    self.assertIsNone(credentials.get_security_token())
                    self.assertEqual(credentials.get_provider_name(), "profile/static_ak")

    def test_get_credentials_valid_ram_role_arn(self):
        """
        Test case 3: Valid input, successfully retrieves credentials for ram_role_arn type
        """
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini', return_value=self.config):
                    provider = ProfileCredentialsProvider(profile_name="ram_role_profile")

                    with self.assertRaises(CredentialException) as context:
                        provider.get_credentials()

                    self.assertIn("error refreshing credentials from ram_role_arn", str(context.exception))

    def test_get_credentials_valid_oidc_role_arn(self):
        """
        Test case 4: Valid input, successfully retrieves credentials for oidc_role_arn type
        """
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini', return_value=self.config):
                    with patch('alibabacloud_credentials.provider.oidc._get_token', return_value='test_token'):
                        provider = ProfileCredentialsProvider(profile_name="oidc_profile")

                        with self.assertRaises(CredentialException) as context:
                            provider.get_credentials()

                        self.assertIn("error refreshing credentials from oidc_role_arn", str(context.exception))

    @patch('Tea.core.TeaCore.do_action')
    def test_get_credentials_valid_ecs_ram_role(self, mock_do_action):
        """
        Test case 5: Valid input, successfully retrieves credentials for ecs_ram_role type
        """
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini', return_value=self.config):
                    mock_response = MagicMock()
                    mock_response.status_code = 400
                    mock_response.body = b'{"error": "Invalid"}'
                    mock_do_action.return_value = mock_response
                    provider = ProfileCredentialsProvider(profile_name="ecs_ram_role_profile")

                    with self.assertRaises(CredentialException) as context:
                        provider.get_credentials()

                    self.assertIn("Failed to get RAM session credentials from ECS metadata service",
                                  str(context.exception))

    def test_get_credentials_valid_rsa_key_pair(self):
        """
        Test case 6: Valid input, successfully retrieves credentials for rsa_key_pair type
        """
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini', return_value=self.config):
                    with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                               return_value='test_content'):
                        provider = ProfileCredentialsProvider(profile_name="rsa_key_pair_profile")
                        with self.assertRaises(CredentialException) as context:
                            provider.get_credentials()

                        self.assertIn("error refreshing credentials from rsa_key_pair", str(context.exception))

    def test_get_credentials_profile_file_not_exists(self):
        """
        Test case 7: Profile file does not exist raises CredentialException
        """
        with patch('os.path.exists', return_value=False):
            provider = ProfileCredentialsProvider(profile_name=self.profile_name)

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn(f'failed to get credential from credentials file: ${self.profile_file}',
                          str(context.exception))

    def test_get_credentials_profile_file_not_file(self):
        """
        Test case 8: Profile file is not a file raises CredentialException
        """
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=False):
                provider = ProfileCredentialsProvider(profile_name=self.profile_name)

                with self.assertRaises(CredentialException) as context:
                    provider.get_credentials()

                self.assertIn(f'failed to get credential from credentials file: ${self.profile_file}',
                              str(context.exception))

    def test_get_credentials_invalid_config_type(self):
        """
        Test case 9: Invalid config type raises CredentialException
        """
        invalid_config = {'default': {
            'type': 'invalid_type',
            'access_key_id': 'test_access_key_id',
            'access_key_secret': 'test_access_key_secret'
        }}
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini', return_value=invalid_config):
                    provider = ProfileCredentialsProvider(profile_name=self.profile_name)

                    with self.assertRaises(CredentialException) as context:
                        provider.get_credentials()

                    self.assertIn(f'unsupported credential type invalid_type from credentials file {self.profile_file}',
                                  str(context.exception))

    def test_get_credentials_missing_access_key_id(self):
        """
        Test case 10: Missing access_key_id raises CredentialException
        """
        missing_access_key_id_config = {'default': {
            'type': 'access_key',
            'access_key_secret': 'test_access_key_secret'
        }}
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini',
                           return_value=missing_access_key_id_config):
                    provider = ProfileCredentialsProvider(profile_name=self.profile_name)

                    with self.assertRaises(ValueError) as context:
                        provider.get_credentials()

                    self.assertIn('the access key id is empty', str(context.exception))

    def test_get_credentials_missing_access_key_secret(self):
        """
        Test case 11: Missing access_key_secret raises CredentialException
        """
        missing_access_key_secret_config = {'default': {
            'type': 'access_key',
            'access_key_id': 'test_access_key_id'
        }}
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini',
                           return_value=missing_access_key_secret_config):
                    provider = ProfileCredentialsProvider(profile_name=self.profile_name)

                    with self.assertRaises(ValueError) as context:
                        provider.get_credentials()

                    self.assertIn('the access key secret is empty',
                                  str(context.exception))

    @patch('alibabacloud_credentials.provider.ram_role_arn.au')
    def test_get_credentials_missing_role_arn(self, mock_au):
        """
        Test case 12: Missing role_arn raises CredentialException
        """
        missing_role_arn_config = {'ram_role_profile': {
            'type': 'ram_role_arn',
            'access_key_id': 'test_access_key_id',
            'access_key_secret': 'test_access_key_secret',
            'role_session_name': 'test_ram_session_name',
            'policy': 'test_policy'
        }}
        mock_au.environment_role_arn = None
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini', return_value=missing_role_arn_config):
                    provider = ProfileCredentialsProvider(profile_name="ram_role_profile")

                    with self.assertRaises(ValueError) as context:
                        provider.get_credentials()

                    self.assertIn('role_arn or environment variable ALIBABA_CLOUD_ROLE_ARN cannot be empty',
                                  str(context.exception))

    @patch('alibabacloud_credentials.provider.oidc.au')
    def test_get_credentials_missing_oidc_provider_arn(self, mock_auth_util):
        """
        Test case 13: Missing oidc_provider_arn raises CredentialException
        """
        missing_oidc_provider_arn_config = {'oidc_profile': {
            'type': 'oidc_role_arn',
            'role_arn': 'test_ram_role_arn',
            'oidc_token_file_path': 'test_oidc_token_file_path',
            'role_session_name': 'test_role_session_name',
            'policy': 'test_policy'
        }}
        mock_auth_util.environment_oidc_provider_arn = None
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini',
                           return_value=missing_oidc_provider_arn_config):
                    provider = ProfileCredentialsProvider(profile_name="oidc_profile")

                    with self.assertRaises(ValueError) as context:
                        provider.get_credentials()

                    self.assertIn(
                        'oidc_provider_arn or environment variable ALIBABA_CLOUD_OIDC_PROVIDER_ARN cannot be empty',
                        str(context.exception))

    @patch('alibabacloud_credentials.provider.oidc.au')
    def test_get_credentials_missing_oidc_token_file_path(self, mock_auth_util):
        """
        Test case 14: Missing oidc_token_file_path raises CredentialException
        """
        missing_oidc_token_file_path_config = {'oidc_profile': {
            'type': 'oidc_role_arn',
            'role_arn': 'test_ram_role_arn',
            'oidc_provider_arn': 'test_oidc_provider_arn',
            'role_session_name': 'test_role_session_name',
            'policy': 'test_policy'
        }}
        mock_auth_util.environment_oidc_token_file = None
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini',
                           return_value=missing_oidc_token_file_path_config):
                    provider = ProfileCredentialsProvider(profile_name="oidc_profile")

                    with self.assertRaises(ValueError) as context:
                        provider.get_credentials()

                    self.assertIn(
                        'oidc_token_file_path or environment variable ALIBABA_CLOUD_OIDC_TOKEN_FILE cannot be empty',
                        str(context.exception))

    @patch('Tea.core.TeaCore.do_action')
    def test_get_credentials_missing_role_name(self, mock_do_action):
        """
        Test case 15: Missing role_name raises CredentialException
        """
        missing_role_name_config = {'ecs_ram_role_profile': {
            'type': 'ecs_ram_role'
        }}
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini',
                           return_value=missing_role_name_config):
                    mock_response = MagicMock()
                    mock_response.status_code = 400
                    mock_response.body = b'{"error": "Invalid"}'
                    mock_do_action.return_value = mock_response
                    provider = ProfileCredentialsProvider(profile_name="ecs_ram_role_profile")

                    with self.assertRaises(CredentialException) as context:
                        provider.get_credentials()

                    self.assertIn('Failed to get RAM session credentials from ECS metadata service',
                                  str(context.exception))

    def test_get_credentials_missing_public_key_id(self):
        """
        Test case 16: Missing public_key_id raises CredentialException
        """
        missing_public_key_id_config = {'rsa_key_pair_profile': {
            'type': 'rsa_key_pair',
            'private_key_file': 'test_private_key_file'
        }}
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini',
                           return_value=missing_public_key_id_config):
                    provider = ProfileCredentialsProvider(profile_name="rsa_key_pair_profile")

                    with self.assertRaises(ValueError) as context:
                        provider.get_credentials()

                    self.assertIn('public_key_id cannot be empty',
                                  str(context.exception))

    def test_get_credentials_missing_private_key_file(self):
        """
        Test case 17: Missing private_key_file raises CredentialException
        """
        missing_private_key_file_config = {'rsa_key_pair_profile': {
            'type': 'rsa_key_pair',
            'public_key_id': 'test_public_key_id'
        }}
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini',
                           return_value=missing_private_key_file_config):
                    provider = ProfileCredentialsProvider(profile_name="rsa_key_pair_profile")

                    with self.assertRaises(ValueError) as context:
                        provider.get_credentials()

                    self.assertIn('private_key_file cannot be empty',
                                  str(context.exception))

    def test_get_credentials_async_valid_access_key(self):
        """
        Test case 18: Valid input, successfully retrieves credentials for access_key type asynchronously
        """
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('alibabacloud_credentials.provider.profile._load_ini_async',
                           AsyncMock(return_value=self.config)):
                    provider = ProfileCredentialsProvider(profile_name=self.profile_name)

                    # 使用 asyncio.run() 替代 get_event_loop()
                    async def run_test():
                        return await provider.get_credentials_async()

                    credentials = asyncio.run(run_test())

                    self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                    self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                    self.assertIsNone(credentials.get_security_token())

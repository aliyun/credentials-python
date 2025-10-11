import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
from alibabacloud_credentials.provider.default import DefaultCredentialsProvider
from alibabacloud_credentials.provider import (
    EnvironmentVariableCredentialsProvider,
    OIDCRoleArnCredentialsProvider,
    CLIProfileCredentialsProvider,
    ProfileCredentialsProvider,
    EcsRamRoleCredentialsProvider,
    URLCredentialsProvider
)
from alibabacloud_credentials.provider.refreshable import Credentials
from alibabacloud_credentials.exceptions import CredentialException


class TestDefaultCredentialsProvider(unittest.TestCase):

    def setUp(self):
        self.access_key_id = "test_access_key_id"
        self.access_key_secret = "test_access_key_secret"
        self.security_token = "test_security_token"
        self.credentials = Credentials(
            access_key_id=self.access_key_id,
            access_key_secret=self.access_key_secret,
            security_token=self.security_token,
            provider_name="test_provider"
        )

    @patch('alibabacloud_credentials.provider.default.au.enable_oidc_credential', False)
    @patch('alibabacloud_credentials.provider.default.au.environment_ecs_metadata_disabled', 'false')
    @patch('alibabacloud_credentials.provider.default.au.environment_credentials_uri', None)
    def test_get_credentials_with_environment_variable_provider(self):
        """
        Test case 1: Successfully retrieves credentials from EnvironmentVariableCredentialsProvider
        """
        env_provider = EnvironmentVariableCredentialsProvider()
        env_provider.get_credentials = MagicMock(return_value=self.credentials)

        with patch('alibabacloud_credentials.provider.default.EnvironmentVariableCredentialsProvider',
                   return_value=env_provider):
            provider = DefaultCredentialsProvider()

            credentials = provider.get_credentials()

            self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
            self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
            self.assertEqual(credentials.get_security_token(), self.security_token)
            self.assertEqual(credentials.get_provider_name(), "default/test_provider")

    @patch('alibabacloud_credentials.provider.default.au.enable_oidc_credential', True)
    @patch('alibabacloud_credentials.provider.oidc.au.environment_role_arn', 'test_role_arn')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_oidc_provider_arn', 'test_oidc_provider_arn')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_oidc_token_file', 'test_token_file')
    @patch('alibabacloud_credentials.provider.default.au.environment_ecs_metadata_disabled', 'false')
    @patch('alibabacloud_credentials.provider.default.au.environment_credentials_uri', None)
    def test_get_credentials_with_oidc_provider(self):
        """
        Test case 2: Successfully retrieves credentials from OIDCRoleArnCredentialsProvider
        """
        env_provider = EnvironmentVariableCredentialsProvider()
        env_provider.get_credentials = MagicMock(
            side_effect=CredentialException("EnvironmentVariableCredentialsProvider failed"))

        oidc_provider = OIDCRoleArnCredentialsProvider()
        oidc_provider.get_credentials = MagicMock(return_value=self.credentials)

        with patch('alibabacloud_credentials.provider.default.EnvironmentVariableCredentialsProvider',
                   return_value=env_provider):
            with patch('alibabacloud_credentials.provider.default.OIDCRoleArnCredentialsProvider',
                       return_value=oidc_provider):
                provider = DefaultCredentialsProvider()

                credentials = provider.get_credentials()

                self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                self.assertEqual(credentials.get_security_token(), self.security_token)
                self.assertEqual(credentials.get_provider_name(), "default/test_provider")

    @patch('alibabacloud_credentials.provider.default.au.enable_oidc_credential', True)
    @patch('alibabacloud_credentials.provider.oidc.au.environment_role_arn', 'test_role_arn')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_oidc_provider_arn', 'test_oidc_provider_arn')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_oidc_token_file', 'test_token_file')
    @patch('alibabacloud_credentials.provider.default.au.environment_ecs_metadata_disabled', 'false')
    @patch('alibabacloud_credentials.provider.default.au.environment_credentials_uri', None)
    def test_get_credentials_with_cli_profile_provider(self):
        """
        Test case 3: Successfully retrieves credentials from CLIProfileCredentialsProvider
        """
        env_provider = EnvironmentVariableCredentialsProvider()
        env_provider.get_credentials = MagicMock(
            side_effect=CredentialException("EnvironmentVariableCredentialsProvider failed"))

        oidc_provider = OIDCRoleArnCredentialsProvider()
        oidc_provider.get_credentials = MagicMock(
            side_effect=CredentialException("OIDCRoleArnCredentialsProvider failed"))

        cli_provider = CLIProfileCredentialsProvider()
        cli_provider.get_credentials = MagicMock(return_value=self.credentials)

        with patch('alibabacloud_credentials.provider.default.EnvironmentVariableCredentialsProvider',
                   return_value=env_provider):
            with patch('alibabacloud_credentials.provider.default.OIDCRoleArnCredentialsProvider',
                       return_value=oidc_provider):
                with patch('alibabacloud_credentials.provider.default.CLIProfileCredentialsProvider',
                           return_value=cli_provider):
                    provider = DefaultCredentialsProvider()

                    credentials = provider.get_credentials()

                    self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                    self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                    self.assertEqual(credentials.get_security_token(), self.security_token)
                    self.assertEqual(credentials.get_provider_name(), "default/test_provider")

    @patch('alibabacloud_credentials.provider.default.au.enable_oidc_credential', True)
    @patch('alibabacloud_credentials.provider.oidc.au.environment_role_arn', 'test_role_arn')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_oidc_provider_arn', 'test_oidc_provider_arn')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_oidc_token_file', 'test_token_file')
    @patch('alibabacloud_credentials.provider.default.au.environment_ecs_metadata_disabled', 'false')
    @patch('alibabacloud_credentials.provider.default.au.environment_credentials_uri', None)
    def test_get_credentials_with_profile_provider(self):
        """
        Test case 4: Successfully retrieves credentials from ProfileCredentialsProvider
        """
        env_provider = EnvironmentVariableCredentialsProvider()
        env_provider.get_credentials = MagicMock(
            side_effect=CredentialException("EnvironmentVariableCredentialsProvider failed"))

        oidc_provider = OIDCRoleArnCredentialsProvider()
        oidc_provider.get_credentials = MagicMock(
            side_effect=CredentialException("OIDCRoleArnCredentialsProvider failed"))

        cli_provider = CLIProfileCredentialsProvider()
        cli_provider.get_credentials = MagicMock(
            side_effect=CredentialException("CLIProfileCredentialsProvider failed"))

        profile_provider = ProfileCredentialsProvider()
        profile_provider.get_credentials = MagicMock(return_value=self.credentials)

        with patch('alibabacloud_credentials.provider.default.EnvironmentVariableCredentialsProvider',
                   return_value=env_provider):
            with patch('alibabacloud_credentials.provider.default.OIDCRoleArnCredentialsProvider',
                       return_value=oidc_provider):
                with patch('alibabacloud_credentials.provider.default.CLIProfileCredentialsProvider',
                           return_value=cli_provider):
                    with patch('alibabacloud_credentials.provider.default.ProfileCredentialsProvider',
                               return_value=profile_provider):
                        provider = DefaultCredentialsProvider()

                        credentials = provider.get_credentials()

                        self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                        self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                        self.assertEqual(credentials.get_security_token(), self.security_token)
                        self.assertEqual(credentials.get_provider_name(), "default/test_provider")

    @patch('alibabacloud_credentials.provider.default.au.enable_oidc_credential', True)
    @patch('alibabacloud_credentials.provider.oidc.au.environment_role_arn', 'test_role_arn')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_oidc_provider_arn', 'test_oidc_provider_arn')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_oidc_token_file', 'test_token_file')
    @patch('alibabacloud_credentials.provider.default.au.environment_ecs_metadata_disabled', 'false')
    @patch('alibabacloud_credentials.provider.default.au.environment_credentials_uri', None)
    def test_get_credentials_with_ecs_ram_role_provider(self):
        """
        Test case 5: Successfully retrieves credentials from EcsRamRoleCredentialsProvider
        """
        env_provider = EnvironmentVariableCredentialsProvider()
        env_provider.get_credentials = MagicMock(
            side_effect=CredentialException("EnvironmentVariableCredentialsProvider failed"))

        oidc_provider = OIDCRoleArnCredentialsProvider()
        oidc_provider.get_credentials = MagicMock(
            side_effect=CredentialException("OIDCRoleArnCredentialsProvider failed"))

        cli_provider = CLIProfileCredentialsProvider()
        cli_provider.get_credentials = MagicMock(
            side_effect=CredentialException("CLIProfileCredentialsProvider failed"))

        profile_provider = ProfileCredentialsProvider()
        profile_provider.get_credentials = MagicMock(
            side_effect=CredentialException("ProfileCredentialsProvider failed"))

        ecs_provider = EcsRamRoleCredentialsProvider()
        ecs_provider.get_credentials = MagicMock(return_value=self.credentials)

        with patch('alibabacloud_credentials.provider.default.EnvironmentVariableCredentialsProvider',
                   return_value=env_provider):
            with patch('alibabacloud_credentials.provider.default.OIDCRoleArnCredentialsProvider',
                       return_value=oidc_provider):
                with patch('alibabacloud_credentials.provider.default.CLIProfileCredentialsProvider',
                           return_value=cli_provider):
                    with patch('alibabacloud_credentials.provider.default.ProfileCredentialsProvider',
                               return_value=profile_provider):
                        with patch('alibabacloud_credentials.provider.default.EcsRamRoleCredentialsProvider',
                                   return_value=ecs_provider):
                            provider = DefaultCredentialsProvider()

                            credentials = provider.get_credentials()

                            self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                            self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                            self.assertEqual(credentials.get_security_token(), self.security_token)
                            self.assertEqual(credentials.get_provider_name(), "default/test_provider")

    @patch('alibabacloud_credentials.provider.default.au.enable_oidc_credential', True)
    @patch('alibabacloud_credentials.provider.oidc.au.environment_role_arn', 'test_role_arn')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_oidc_provider_arn', 'test_oidc_provider_arn')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_oidc_token_file', 'test_token_file')
    @patch('alibabacloud_credentials.provider.default.au.environment_ecs_metadata_disabled', 'false')
    @patch('alibabacloud_credentials.provider.default.au.environment_credentials_uri', "http://example.com/credentials")
    def test_get_credentials_with_url_provider(self):
        """
        Test case 6: Successfully retrieves credentials from URLCredentialsProvider
        """
        env_provider = EnvironmentVariableCredentialsProvider()
        env_provider.get_credentials = MagicMock(
            side_effect=CredentialException("EnvironmentVariableCredentialsProvider failed"))

        oidc_provider = OIDCRoleArnCredentialsProvider()
        oidc_provider.get_credentials = MagicMock(
            side_effect=CredentialException("OIDCRoleArnCredentialsProvider failed"))

        cli_provider = CLIProfileCredentialsProvider()
        cli_provider.get_credentials = MagicMock(
            side_effect=CredentialException("CLIProfileCredentialsProvider failed"))

        profile_provider = ProfileCredentialsProvider()
        profile_provider.get_credentials = MagicMock(
            side_effect=CredentialException("ProfileCredentialsProvider failed"))

        ecs_provider = EcsRamRoleCredentialsProvider()
        ecs_provider.get_credentials = MagicMock(
            side_effect=CredentialException("EcsRamRoleCredentialsProvider failed"))

        url_provider = URLCredentialsProvider()
        url_provider.get_credentials = MagicMock(return_value=self.credentials)

        with patch('alibabacloud_credentials.provider.default.EnvironmentVariableCredentialsProvider',
                   return_value=env_provider):
            with patch('alibabacloud_credentials.provider.default.OIDCRoleArnCredentialsProvider',
                       return_value=oidc_provider):
                with patch('alibabacloud_credentials.provider.default.CLIProfileCredentialsProvider',
                           return_value=cli_provider):
                    with patch('alibabacloud_credentials.provider.default.ProfileCredentialsProvider',
                               return_value=profile_provider):
                        with patch('alibabacloud_credentials.provider.default.EcsRamRoleCredentialsProvider',
                                   return_value=ecs_provider):
                            with patch('alibabacloud_credentials.provider.default.URLCredentialsProvider',
                                       return_value=url_provider):
                                provider = DefaultCredentialsProvider()

                                credentials = provider.get_credentials()

                                self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                                self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                                self.assertEqual(credentials.get_security_token(), self.security_token)
                                self.assertEqual(credentials.get_provider_name(), "default/test_provider")

    @patch('alibabacloud_credentials.provider.default.au.environment_ecs_metadata_disabled', 'false')
    @patch('alibabacloud_credentials.provider.default.au.environment_credentials_uri', "http://example.com/credentials")
    def test_get_credentials_no_valid_provider(self):
        """
        Test case 7: No valid provider raises CredentialException
        """
        env_provider = EnvironmentVariableCredentialsProvider()
        env_provider.get_credentials = MagicMock(
            side_effect=CredentialException("EnvironmentVariableCredentialsProvider failed"))

        oidc_provider = OIDCRoleArnCredentialsProvider(
            role_arn='role_arn',
            oidc_provider_arn='oidc_provider_arn',
            oidc_token_file_path='oidc_token_file_path',
        )
        oidc_provider.get_credentials = MagicMock(
            side_effect=CredentialException("OIDCRoleArnCredentialsProvider failed"))

        cli_provider = CLIProfileCredentialsProvider()
        cli_provider.get_credentials = MagicMock(
            side_effect=CredentialException("CLIProfileCredentialsProvider failed"))

        profile_provider = ProfileCredentialsProvider()
        profile_provider.get_credentials = MagicMock(
            side_effect=CredentialException("ProfileCredentialsProvider failed"))

        ecs_provider = EcsRamRoleCredentialsProvider()
        ecs_provider.get_credentials = MagicMock(
            side_effect=CredentialException("EcsRamRoleCredentialsProvider failed"))

        url_provider = URLCredentialsProvider()
        url_provider.get_credentials = MagicMock(side_effect=CredentialException("URLCredentialsProvider failed"))

        with patch('alibabacloud_credentials.provider.default.EnvironmentVariableCredentialsProvider',
                   return_value=env_provider):
            with patch('alibabacloud_credentials.provider.default.OIDCRoleArnCredentialsProvider',
                       return_value=oidc_provider):
                with patch('alibabacloud_credentials.provider.default.CLIProfileCredentialsProvider',
                           return_value=cli_provider):
                    with patch('alibabacloud_credentials.provider.default.ProfileCredentialsProvider',
                               return_value=profile_provider):
                        with patch('alibabacloud_credentials.provider.default.EcsRamRoleCredentialsProvider',
                                   return_value=ecs_provider):
                            with patch('alibabacloud_credentials.provider.default.URLCredentialsProvider',
                                       return_value=url_provider):
                                provider = DefaultCredentialsProvider()

                                with self.assertRaises(CredentialException) as context:
                                    provider.get_credentials()

                                self.assertIn("unable to load credentials from any of the providers in the chain",
                                              str(context.exception))

    @patch('alibabacloud_credentials.provider.default.au.enable_oidc_credential', False)
    @patch('alibabacloud_credentials.provider.default.au.environment_ecs_metadata_disabled', 'false')
    @patch('alibabacloud_credentials.provider.default.au.environment_credentials_uri', None)
    def test_get_credentials_async_with_environment_variable_provider(self):
        """
        Test case 8: Successfully retrieves credentials asynchronously from EnvironmentVariableCredentialsProvider
        """
        env_provider = EnvironmentVariableCredentialsProvider()
        env_provider.get_credentials_async = AsyncMock(return_value=self.credentials)

        with patch('alibabacloud_credentials.provider.default.EnvironmentVariableCredentialsProvider',
                   return_value=env_provider):
            provider = DefaultCredentialsProvider()

            # 使用 asyncio.run() 替代 get_event_loop()
            async def run_test():
                return await provider.get_credentials_async()

            credentials = asyncio.run(run_test())

            self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
            self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
            self.assertEqual(credentials.get_security_token(), self.security_token)
            self.assertEqual(credentials.get_provider_name(), "default/test_provider")

    @patch('alibabacloud_credentials.provider.default.au.enable_oidc_credential', False)
    @patch('alibabacloud_credentials.provider.default.au.environment_ecs_metadata_disabled', 'false')
    @patch('alibabacloud_credentials.provider.default.au.environment_credentials_uri', None)
    def test_get_credentials_reuse_last_provider_enabled(self):
        """
        Test case 8: Reuse last provider when reuse_last_provider_enabled is True
        """
        env_provider = EnvironmentVariableCredentialsProvider()
        env_provider.get_credentials = MagicMock(
            side_effect=CredentialException("EnvironmentVariableCredentialsProvider failed"))

        cli_provider = CLIProfileCredentialsProvider()
        cli_provider.get_credentials = MagicMock(return_value=self.credentials)

        with patch('alibabacloud_credentials.provider.default.EnvironmentVariableCredentialsProvider',
                   return_value=env_provider):
            with patch('alibabacloud_credentials.provider.default.CLIProfileCredentialsProvider',
                       return_value=cli_provider):
                provider = DefaultCredentialsProvider()

                # First call to get_credentials
                credentials = provider.get_credentials()
                self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                self.assertEqual(credentials.get_security_token(), self.security_token)
                self.assertEqual(credentials.get_provider_name(), "default/test_provider")

                # Second call to get_credentials should reuse the last provider
                credentials = provider.get_credentials()
                self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                self.assertEqual(credentials.get_security_token(), self.security_token)
                self.assertEqual(credentials.get_provider_name(), "default/test_provider")

                # Ensure get_credentials was only called once on the provider
                env_provider.get_credentials.assert_called_once()

    @patch('alibabacloud_credentials.provider.default.au.enable_oidc_credential', False)
    @patch('alibabacloud_credentials.provider.default.au.environment_ecs_metadata_disabled', 'false')
    @patch('alibabacloud_credentials.provider.default.au.environment_credentials_uri', None)
    def test_get_credentials_reuse_last_provider_disabled(self):
        """
        Test case 9: Do not reuse last provider when reuse_last_provider_enabled is False
        """
        env_provider = EnvironmentVariableCredentialsProvider()
        env_provider.get_credentials = MagicMock(
            side_effect=CredentialException("EnvironmentVariableCredentialsProvider failed"))

        cli_provider = CLIProfileCredentialsProvider()
        cli_provider.get_credentials = MagicMock(return_value=self.credentials)

        with patch('alibabacloud_credentials.provider.default.EnvironmentVariableCredentialsProvider',
                   return_value=env_provider):
            with patch('alibabacloud_credentials.provider.default.CLIProfileCredentialsProvider',
                       return_value=cli_provider):
                provider = DefaultCredentialsProvider(reuse_last_provider_enabled=False)

                # First call to get_credentials
                credentials = provider.get_credentials()
                self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                self.assertEqual(credentials.get_security_token(), self.security_token)
                self.assertEqual(credentials.get_provider_name(), "default/test_provider")

                # Second call to get_credentials should not reuse the last provider
                credentials = provider.get_credentials()
                self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                self.assertEqual(credentials.get_security_token(), self.security_token)
                self.assertEqual(credentials.get_provider_name(), "default/test_provider")

                # Ensure get_credentials was called twice on the provider
                self.assertEqual(env_provider.get_credentials.call_count, 2)

    @patch('alibabacloud_credentials.provider.default.au.enable_oidc_credential', False)
    @patch('alibabacloud_credentials.provider.default.au.environment_ecs_metadata_disabled', 'false')
    @patch('alibabacloud_credentials.provider.default.au.environment_credentials_uri', None)
    def test_get_credentials_async_reuse_last_provider_enabled(self):
        """
        Test case 8: Reuse last provider when reuse_last_provider_enabled is True
        """
        env_provider = EnvironmentVariableCredentialsProvider()
        env_provider.get_credentials_async = AsyncMock(
            side_effect=CredentialException("EnvironmentVariableCredentialsProvider failed"))

        cli_provider = CLIProfileCredentialsProvider()
        cli_provider.get_credentials_async = AsyncMock(return_value=self.credentials)

        with patch('alibabacloud_credentials.provider.default.EnvironmentVariableCredentialsProvider',
                   return_value=env_provider):
            with patch('alibabacloud_credentials.provider.default.CLIProfileCredentialsProvider',
                       return_value=cli_provider):
                provider = DefaultCredentialsProvider()

                # First call to get_credentials
                # 使用 asyncio.run() 替代 get_event_loop()
                async def run_test():
                    return await provider.get_credentials_async()

                credentials = asyncio.run(run_test())
                self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                self.assertEqual(credentials.get_security_token(), self.security_token)
                self.assertEqual(credentials.get_provider_name(), "default/test_provider")

                # Second call to get_credentials should reuse the last provider
                async def run_test1():
                    return await provider.get_credentials_async()

                credentials = asyncio.run(run_test1())
                self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                self.assertEqual(credentials.get_security_token(), self.security_token)
                self.assertEqual(credentials.get_provider_name(), "default/test_provider")

                # Ensure get_credentials was only called once on the provider
                env_provider.get_credentials_async.assert_called_once()

    @patch('alibabacloud_credentials.provider.default.au.enable_oidc_credential', False)
    @patch('alibabacloud_credentials.provider.default.au.environment_ecs_metadata_disabled', 'false')
    @patch('alibabacloud_credentials.provider.default.au.environment_credentials_uri', None)
    def test_get_credentials_async_reuse_last_provider_disabled(self):
        """
        Test case 9: Do not reuse last provider when reuse_last_provider_enabled is False
        """
        env_provider = EnvironmentVariableCredentialsProvider()
        env_provider.get_credentials_async = AsyncMock(
            side_effect=CredentialException("EnvironmentVariableCredentialsProvider failed"))

        cli_provider = CLIProfileCredentialsProvider()
        cli_provider.get_credentials_async = AsyncMock(return_value=self.credentials)

        with patch('alibabacloud_credentials.provider.default.EnvironmentVariableCredentialsProvider',
                   return_value=env_provider):
            with patch('alibabacloud_credentials.provider.default.CLIProfileCredentialsProvider',
                       return_value=cli_provider):
                provider = DefaultCredentialsProvider(reuse_last_provider_enabled=False)

                # First call to get_credentials
                # 使用 asyncio.run() 替代 get_event_loop()
                async def run_test():
                    return await provider.get_credentials_async()

                credentials = asyncio.run(run_test())
                self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                self.assertEqual(credentials.get_security_token(), self.security_token)
                self.assertEqual(credentials.get_provider_name(), "default/test_provider")

                # Second call to get_credentials should not reuse the last provider
                async def run_test1():
                    return await provider.get_credentials_async()

                credentials = asyncio.run(run_test1())
                self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
                self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
                self.assertEqual(credentials.get_security_token(), self.security_token)
                self.assertEqual(credentials.get_provider_name(), "default/test_provider")

                # Ensure get_credentials was called twice on the provider
                self.assertEqual(env_provider.get_credentials_async.call_count, 2)

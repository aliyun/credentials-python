import unittest
from unittest.mock import patch, MagicMock
import asyncio
from alibabacloud_credentials.provider import EnvironmentVariableCredentialsProvider
from alibabacloud_credentials.exceptions import CredentialException


class TestEnvironmentVariableCredentialsProvider(unittest.TestCase):

    @patch('alibabacloud_credentials.provider.env.auth_util')
    def test_get_credentials_valid_input(self, mock_auth_util):
        """
        Test case 1: Valid input, successfully retrieves credentials
        """
        # Set mock object return values
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()

        credentials = provider.get_credentials()

        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")
        self.assertEqual(credentials.get_access_key_secret(), "test_access_key_secret")
        self.assertEqual(credentials.get_security_token(), "test_security_token")
        self.assertEqual(credentials.get_provider_name(), "env")

    @patch('alibabacloud_credentials.provider.env.auth_util')
    def test_get_credentials_missing_access_key_id(self, mock_auth_util):
        """
        Test case 2: Missing environment variable accessKeyId raises CredentialException
        """
        mock_auth_util.environment_access_key_id = None
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()

        self.assertIn("Environment variable accessKeyId cannot be empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.env.auth_util')
    def test_get_credentials_empty_access_key_id(self, mock_auth_util):
        """
        Test case 3: Empty environment variable accessKeyId raises CredentialException
        """
        mock_auth_util.environment_access_key_id = ""
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()

        self.assertIn("Environment variable accessKeyId cannot be empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.env.auth_util')
    def test_get_credentials_missing_access_key_secret(self, mock_auth_util):
        """
        Test case 4: Missing environment variable accessKeySecret raises CredentialException
        """
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = None
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()

        self.assertIn("Environment variable accessKeySecret cannot be empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.env.auth_util')
    def test_get_credentials_empty_access_key_secret(self, mock_auth_util):
        """
        Test case 5: Empty environment variable accessKeySecret raises CredentialException
        """
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = ""
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()

        self.assertIn("Environment variable accessKeySecret cannot be empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.env.auth_util')
    def test_get_credentials_async_valid_input(self, mock_auth_util):
        """
        Test case 6: Valid input, successfully retrieves credentials asynchronously
        """
        # Set mock object return values
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()

        # Use asyncio.run to execute the async function
        credentials = asyncio.run(provider.get_credentials_async())

        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")
        self.assertEqual(credentials.get_access_key_secret(), "test_access_key_secret")
        self.assertEqual(credentials.get_security_token(), "test_security_token")
        self.assertEqual(credentials.get_provider_name(), "env")

    @patch('alibabacloud_credentials.provider.env.auth_util')
    def test_get_credentials_async_missing_access_key_id(self, mock_auth_util):
        """
        Test case 7: Missing environment variable accessKeyId raises CredentialException asynchronously
        """
        mock_auth_util.environment_access_key_id = None
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()

        with self.assertRaises(CredentialException) as context:
            asyncio.run(provider.get_credentials_async())

        self.assertIn("Environment variable accessKeyId cannot be empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.env.auth_util')
    def test_get_credentials_async_empty_access_key_id(self, mock_auth_util):
        """
        Test case 8: Empty environment variable accessKeyId raises CredentialException asynchronously
        """
        mock_auth_util.environment_access_key_id = ""
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()

        with self.assertRaises(CredentialException) as context:
            asyncio.run(provider.get_credentials_async())

        self.assertIn("Environment variable accessKeyId cannot be empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.env.auth_util')
    def test_get_credentials_async_missing_access_key_secret(self, mock_auth_util):
        """
        Test case 9: Missing environment variable accessKeySecret raises CredentialException asynchronously
        """
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = None
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()

        with self.assertRaises(CredentialException) as context:
            asyncio.run(provider.get_credentials_async())

        self.assertIn("Environment variable accessKeySecret cannot be empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.env.auth_util')
    def test_get_credentials_async_empty_access_key_secret(self, mock_auth_util):
        """
        Test case 10: Empty environment variable accessKeySecret raises CredentialException asynchronously
        """
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = ""
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()

        with self.assertRaises(CredentialException) as context:
            asyncio.run(provider.get_credentials_async())

        self.assertIn("Environment variable accessKeySecret cannot be empty", str(context.exception))

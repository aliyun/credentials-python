import unittest
from unittest.mock import patch, MagicMock
import asyncio
from alibabacloud_credentials.provider.static_sts import StaticSTSCredentialsProvider
from alibabacloud_credentials.exceptions import CredentialException


class TestStaticSTSCredentialsProvider(unittest.TestCase):

    def test_init_valid_input(self):
        """
        Test case 1: Valid input, successfully initializes with provided access_key_id, access_key_secret, and security_token
        """
        provider = StaticSTSCredentialsProvider(
            access_key_id="test_access_key_id",
            access_key_secret="test_access_key_secret",
            security_token="test_security_token"
        )

        self.assertEqual(provider.access_key_id, "test_access_key_id")
        self.assertEqual(provider.access_key_secret, "test_access_key_secret")
        self.assertEqual(provider.security_token, "test_security_token")

    @patch('alibabacloud_credentials.provider.static_sts.auth_util')
    def test_init_valid_environment_variables(self, mock_auth_util):
        """
        Test case 2: Valid input, successfully initializes with environment variables
        """
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"
        mock_auth_util.environment_security_token = "test_security_token"

        provider = StaticSTSCredentialsProvider()

        self.assertEqual(provider.access_key_id, "test_access_key_id")
        self.assertEqual(provider.access_key_secret, "test_access_key_secret")
        self.assertEqual(provider.security_token, "test_security_token")

    def test_init_missing_access_key_id(self):
        """
        Test case 3: Missing access_key_id raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            StaticSTSCredentialsProvider(
                access_key_secret="test_access_key_secret",
                security_token="test_security_token"
            )

        self.assertIn("the access key id is empty", str(context.exception))

    def test_init_empty_access_key_id(self):
        """
        Test case 4: Empty access_key_id raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            StaticSTSCredentialsProvider(
                access_key_id="",
                access_key_secret="test_access_key_secret",
                security_token="test_security_token"
            )

        self.assertIn("the access key id is empty", str(context.exception))

    def test_init_missing_access_key_secret(self):
        """
        Test case 5: Missing access_key_secret raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            StaticSTSCredentialsProvider(
                access_key_id="test_access_key_id",
                security_token="test_security_token"
            )

        self.assertIn("the access key secret is empty", str(context.exception))

    def test_init_empty_access_key_secret(self):
        """
        Test case 6: Empty access_key_secret raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            StaticSTSCredentialsProvider(
                access_key_id="test_access_key_id",
                access_key_secret="",
                security_token="test_security_token"
            )

        self.assertIn("the access key secret is empty", str(context.exception))

    def test_init_missing_security_token(self):
        """
        Test case 7: Missing security_token raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            StaticSTSCredentialsProvider(
                access_key_id="test_access_key_id",
                access_key_secret="test_access_key_secret"
            )

        self.assertIn("the security token is empty", str(context.exception))

    def test_init_empty_security_token(self):
        """
        Test case 8: Empty security_token raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            StaticSTSCredentialsProvider(
                access_key_id="test_access_key_id",
                access_key_secret="test_access_key_secret",
                security_token=""
            )

        self.assertIn("the security token is empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.static_sts.auth_util')
    def test_init_missing_environment_variables(self, mock_auth_util):
        """
        Test case 9: Missing environment variables raises ValueError
        """
        mock_auth_util.environment_access_key_id = None
        mock_auth_util.environment_access_key_secret = None
        mock_auth_util.environment_security_token = None

        with self.assertRaises(ValueError) as context:
            StaticSTSCredentialsProvider()

        self.assertIn("the access key id is empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.static_sts.auth_util')
    def test_init_empty_environment_variables(self, mock_auth_util):
        """
        Test case 10: Empty environment variables raises ValueError
        """
        mock_auth_util.environment_access_key_id = ""
        mock_auth_util.environment_access_key_secret = ""
        mock_auth_util.environment_security_token = ""

        with self.assertRaises(ValueError) as context:
            StaticSTSCredentialsProvider()

        self.assertIn("the access key id is empty", str(context.exception))

    def test_get_credentials_valid_input(self):
        """
        Test case 11: Valid input, successfully retrieves credentials
        """
        provider = StaticSTSCredentialsProvider(
            access_key_id="test_access_key_id",
            access_key_secret="test_access_key_secret",
            security_token="test_security_token"
        )

        credentials = provider.get_credentials()

        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")
        self.assertEqual(credentials.get_access_key_secret(), "test_access_key_secret")
        self.assertEqual(credentials.get_security_token(), "test_security_token")
        self.assertEqual(credentials.get_provider_name(), "static_sts")

    @patch('alibabacloud_credentials.provider.static_sts.auth_util')
    def test_get_credentials_valid_environment_variables(self, mock_auth_util):
        """
        Test case 12: Valid input, successfully retrieves credentials from environment variables
        """
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"
        mock_auth_util.environment_security_token = "test_security_token"

        provider = StaticSTSCredentialsProvider()

        credentials = provider.get_credentials()

        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")
        self.assertEqual(credentials.get_access_key_secret(), "test_access_key_secret")
        self.assertEqual(credentials.get_security_token(), "test_security_token")
        self.assertEqual(credentials.get_provider_name(), "static_sts")

    def test_get_credentials_async_valid_input(self):
        """
        Test case 13: Valid input, successfully retrieves credentials asynchronously
        """
        provider = StaticSTSCredentialsProvider(
            access_key_id="test_access_key_id",
            access_key_secret="test_access_key_secret",
            security_token="test_security_token"
        )

        # 使用 asyncio.run() 替代 get_event_loop()
        async def run_test():
            return await provider.get_credentials_async()

        credentials = asyncio.run(run_test())

        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")
        self.assertEqual(credentials.get_access_key_secret(), "test_access_key_secret")
        self.assertEqual(credentials.get_security_token(), "test_security_token")
        self.assertEqual(credentials.get_provider_name(), "static_sts")

    @patch('alibabacloud_credentials.provider.static_sts.auth_util')
    def test_get_credentials_async_valid_environment_variables(self, mock_auth_util):
        """
        Test case 14: Valid input, successfully retrieves credentials asynchronously from environment variables
        """
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"
        mock_auth_util.environment_security_token = "test_security_token"

        provider = StaticSTSCredentialsProvider()

        # 使用 asyncio.run() 替代 get_event_loop()
        async def run_test():
            return await provider.get_credentials_async()

        credentials = asyncio.run(run_test())

        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")
        self.assertEqual(credentials.get_access_key_secret(), "test_access_key_secret")
        self.assertEqual(credentials.get_security_token(), "test_security_token")
        self.assertEqual(credentials.get_provider_name(), "static_sts")

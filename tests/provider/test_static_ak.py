import unittest
from unittest.mock import patch, MagicMock
import asyncio
from alibabacloud_credentials.provider.static_ak import StaticAKCredentialsProvider
from alibabacloud_credentials.exceptions import CredentialException


class TestStaticAKCredentialsProvider(unittest.TestCase):

    def test_init_valid_input(self):
        """
        Test case 1: Valid input, successfully initializes with provided access_key_id and access_key_secret
        """
        provider = StaticAKCredentialsProvider(
            access_key_id="test_access_key_id",
            access_key_secret="test_access_key_secret"
        )

        self.assertEqual(provider.access_key_id, "test_access_key_id")
        self.assertEqual(provider.access_key_secret, "test_access_key_secret")

    @patch('alibabacloud_credentials.provider.static_ak.auth_util')
    def test_init_valid_environment_variables(self, mock_auth_util):
        """
        Test case 2: Valid input, successfully initializes with environment variables
        """
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"

        provider = StaticAKCredentialsProvider()

        self.assertEqual(provider.access_key_id, "test_access_key_id")
        self.assertEqual(provider.access_key_secret, "test_access_key_secret")

    def test_init_missing_access_key_id(self):
        """
        Test case 3: Missing access_key_id raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            StaticAKCredentialsProvider(
                access_key_secret="test_access_key_secret"
            )

        self.assertIn("the access key id is empty", str(context.exception))

    def test_init_empty_access_key_id(self):
        """
        Test case 4: Empty access_key_id raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            StaticAKCredentialsProvider(
                access_key_id="",
                access_key_secret="test_access_key_secret"
            )

        self.assertIn("the access key id is empty", str(context.exception))

    def test_init_missing_access_key_secret(self):
        """
        Test case 5: Missing access_key_secret raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            StaticAKCredentialsProvider(
                access_key_id="test_access_key_id"
            )

        self.assertIn("the access key secret is empty", str(context.exception))

    def test_init_empty_access_key_secret(self):
        """
        Test case 6: Empty access_key_secret raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            StaticAKCredentialsProvider(
                access_key_id="test_access_key_id",
                access_key_secret=""
            )

        self.assertIn("the access key secret is empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.static_ak.auth_util')
    def test_init_missing_environment_variables(self, mock_auth_util):
        """
        Test case 7: Missing environment variables raises ValueError
        """
        mock_auth_util.environment_access_key_id = None
        mock_auth_util.environment_access_key_secret = None

        with self.assertRaises(ValueError) as context:
            StaticAKCredentialsProvider()

        self.assertIn("the access key id is empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.static_ak.auth_util')
    def test_init_empty_environment_variables(self, mock_auth_util):
        """
        Test case 8: Empty environment variables raises ValueError
        """
        mock_auth_util.environment_access_key_id = ""
        mock_auth_util.environment_access_key_secret = ""

        with self.assertRaises(ValueError) as context:
            StaticAKCredentialsProvider()

        self.assertIn("the access key id is empty", str(context.exception))

    def test_get_credentials_valid_input(self):
        """
        Test case 9: Valid input, successfully retrieves credentials
        """
        provider = StaticAKCredentialsProvider(
            access_key_id="test_access_key_id",
            access_key_secret="test_access_key_secret"
        )

        credentials = provider.get_credentials()

        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")
        self.assertEqual(credentials.get_access_key_secret(), "test_access_key_secret")
        self.assertIsNone(credentials.get_security_token())
        self.assertEqual(credentials.get_provider_name(), "static_ak")

    @patch('alibabacloud_credentials.provider.static_ak.auth_util')
    def test_get_credentials_valid_environment_variables(self, mock_auth_util):
        """
        Test case 10: Valid input, successfully retrieves credentials from environment variables
        """
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"

        provider = StaticAKCredentialsProvider()

        credentials = provider.get_credentials()

        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")
        self.assertEqual(credentials.get_access_key_secret(), "test_access_key_secret")
        self.assertIsNone(credentials.get_security_token())
        self.assertEqual(credentials.get_provider_name(), "static_ak")

    def test_get_credentials_async_valid_input(self):
        """
        Test case 11: Valid input, successfully retrieves credentials asynchronously
        """
        provider = StaticAKCredentialsProvider(
            access_key_id="test_access_key_id",
            access_key_secret="test_access_key_secret"
        )

        # 使用 asyncio.run() 替代 get_event_loop()
        async def run_test():
            return await provider.get_credentials_async()

        credentials = asyncio.run(run_test())

        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")
        self.assertEqual(credentials.get_access_key_secret(), "test_access_key_secret")
        self.assertIsNone(credentials.get_security_token())
        self.assertEqual(credentials.get_provider_name(), "static_ak")

    @patch('alibabacloud_credentials.provider.static_ak.auth_util')
    def test_get_credentials_async_valid_environment_variables(self, mock_auth_util):
        """
        Test case 12: Valid input, successfully retrieves credentials asynchronously from environment variables
        """
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"

        provider = StaticAKCredentialsProvider()

        # 使用 asyncio.run() 替代 get_event_loop()
        async def run_test():
            return await provider.get_credentials_async()

        credentials = asyncio.run(run_test())

        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")
        self.assertEqual(credentials.get_access_key_secret(), "test_access_key_secret")
        self.assertIsNone(credentials.get_security_token())
        self.assertEqual(credentials.get_provider_name(), "static_ak")

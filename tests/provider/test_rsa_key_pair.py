import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import calendar
import time
import json
from alibabacloud_credentials.provider.rsa_key_pair import (
    RsaKeyPairCredentialsProvider,
    CredentialException
)
from alibabacloud_credentials.http import HttpOptions
from Tea.core import TeaResponse


class TestRsaKeyPairCredentialsProvider(unittest.TestCase):

    def setUp(self):
        self.public_key_id = "test_public_key_id"
        self.private_key_file = "test_private_key_file"
        self.duration_seconds = 3600
        self.sts_region_id = "test_sts_region_id"
        self.sts_endpoint = "test_sts_endpoint"
        self.enable_vpc = True
        self.http_options = HttpOptions(connect_timeout=5000, read_timeout=10000, proxy="test_proxy")
        self.private_key_content = "test_private_key_content"

    def test_init_valid_input(self):
        """
        Test case 1: Valid input, successfully initializes with provided parameters
        """
        with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                   return_value=self.private_key_content):
            provider = RsaKeyPairCredentialsProvider(
                public_key_id=self.public_key_id,
                private_key_file=self.private_key_file,
                duration_seconds=self.duration_seconds,
                sts_region_id=self.sts_region_id,
                sts_endpoint=self.sts_endpoint,
                enable_vpc=self.enable_vpc,
                http_options=self.http_options
            )

            self.assertEqual(provider._public_key_id, self.public_key_id)
            self.assertEqual(provider._private_key_file, self.private_key_file)
            self.assertEqual(provider._duration_seconds, self.duration_seconds)
            self.assertEqual(provider._private_key, self.private_key_content)
            self.assertEqual(provider._sts_endpoint, self.sts_endpoint)
            self.assertEqual(provider._http_options, self.http_options)
            self.assertEqual(provider._runtime_options['connectTimeout'], self.http_options.connect_timeout)
            self.assertEqual(provider._runtime_options['readTimeout'], self.http_options.read_timeout)
            self.assertEqual(provider._runtime_options['httpsProxy'], self.http_options.proxy)

    def test_init_missing_public_key_id(self):
        """
        Test case 2: Missing public_key_id raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            RsaKeyPairCredentialsProvider(
                private_key_file=self.private_key_file,
                duration_seconds=self.duration_seconds
            )

        self.assertIn("public_key_id cannot be empty", str(context.exception))

    def test_init_empty_public_key_id(self):
        """
        Test case 3: Empty public_key_id raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            RsaKeyPairCredentialsProvider(
                public_key_id="",
                private_key_file=self.private_key_file,
                duration_seconds=self.duration_seconds
            )

        self.assertIn("public_key_id cannot be empty", str(context.exception))

    def test_init_missing_private_key_file(self):
        """
        Test case 4: Missing private_key_file raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            RsaKeyPairCredentialsProvider(
                public_key_id=self.public_key_id,
                duration_seconds=self.duration_seconds
            )

        self.assertIn("private_key_file cannot be empty", str(context.exception))

    def test_init_empty_private_key_file(self):
        """
        Test case 5: Empty private_key_file raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            RsaKeyPairCredentialsProvider(
                public_key_id=self.public_key_id,
                private_key_file="",
                duration_seconds=self.duration_seconds
            )

    def test_init_private_key_file_read_error(self):
        """
        Test case 6: Private key file read error raises ValueError
        """
        with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content', side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError) as context:
                RsaKeyPairCredentialsProvider(
                    public_key_id=self.public_key_id,
                    private_key_file=self.private_key_file,
                    duration_seconds=self.duration_seconds
                )

    def test_init_duration_seconds_too_short(self):
        """
        Test case 7: Duration seconds less than 900 raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            RsaKeyPairCredentialsProvider(
                public_key_id=self.public_key_id,
                private_key_file=self.private_key_file,
                duration_seconds=800
            )

        self.assertIn("session duration should be in the range of 900s - max session duration", str(context.exception))

    @patch('alibabacloud_credentials.provider.rsa_key_pair.au')
    def test_init_default_values(self, mock_auth_util):
        """
        Test case 8: Initializes with default values
        """
        mock_auth_util.environment_enable_vpc = 'false'
        mock_auth_util.environment_sts_region = None

        with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                   return_value=self.private_key_content):
            provider = RsaKeyPairCredentialsProvider(
                public_key_id=self.public_key_id,
                private_key_file=self.private_key_file
            )

            self.assertEqual(provider._public_key_id, self.public_key_id)
            self.assertEqual(provider._private_key_file, self.private_key_file)
            self.assertEqual(provider._duration_seconds, RsaKeyPairCredentialsProvider.DEFAULT_DURATION_SECONDS)
            self.assertEqual(provider._private_key, self.private_key_content)
            self.assertEqual(provider._sts_endpoint, 'sts.ap-northeast-1.aliyuncs.com')
            self.assertEqual(provider._runtime_options['connectTimeout'],
                             RsaKeyPairCredentialsProvider.DEFAULT_CONNECT_TIMEOUT)
            self.assertEqual(provider._runtime_options['readTimeout'],
                             RsaKeyPairCredentialsProvider.DEFAULT_READ_TIMEOUT)
            self.assertIsNone(provider._runtime_options['httpsProxy'])

    def test_get_credentials_valid_input(self):
        """
        Test case 9: Valid input, successfully retrieves credentials
        """
        response_body = json.dumps({
            "SessionAccessKey": {
                "SessionAccessKeyId": "test_access_key_id",
                "SessionAccessKeySecret": "test_access_key_secret",
                "Expiration": "2023-12-31T23:59:59Z"
            }
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                       return_value=self.private_key_content):
                provider = RsaKeyPairCredentialsProvider(
                    public_key_id=self.public_key_id,
                    private_key_file=self.private_key_file,
                    duration_seconds=self.duration_seconds,
                    sts_endpoint=self.sts_endpoint,
                    enable_vpc=self.enable_vpc,
                    http_options=self.http_options
                )

                credentials = provider._refresh_credentials()

                self.assertEqual(credentials.value().get_access_key_id(), "test_access_key_id")
                self.assertEqual(credentials.value().get_access_key_secret(), "test_access_key_secret")
                self.assertEqual(credentials.value().get_expiration(),
                                 calendar.timegm(time.strptime("2023-12-31T23:59:59Z", '%Y-%m-%dT%H:%M:%SZ')))
                self.assertEqual(credentials.value().get_provider_name(), "rsa_key_pair")

    def test_get_credentials_http_request_error(self):
        """
        Test case 10: HTTP request error raises CredentialException
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                       return_value=self.private_key_content):
                provider = RsaKeyPairCredentialsProvider(
                    public_key_id=self.public_key_id,
                    private_key_file=self.private_key_file,
                    duration_seconds=self.duration_seconds,
                    sts_endpoint=self.sts_endpoint,
                    enable_vpc=self.enable_vpc,
                    http_options=self.http_options
                )

                with self.assertRaises(CredentialException) as context:
                    provider.get_credentials()

                self.assertIn(
                    "error refreshing credentials from rsa_key_pair, http_code: 400, result: HTTP request failed",
                    str(context.exception))

    def test_get_credentials_response_format_error(self):
        """
        Test case 11: Response format error raises CredentialException
        """
        response_body = json.dumps({
            "Error": "Invalid request"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                       return_value=self.private_key_content):
                provider = RsaKeyPairCredentialsProvider(
                    public_key_id=self.public_key_id,
                    private_key_file=self.private_key_file,
                    duration_seconds=self.duration_seconds,
                    sts_endpoint=self.sts_endpoint,
                    enable_vpc=self.enable_vpc,
                    http_options=self.http_options
                )

                with self.assertRaises(CredentialException) as context:
                    provider.get_credentials()

                self.assertIn(
                    'error retrieving credentials from rsa_key_pair result: {"Error": "Invalid request"}',
                    str(context.exception))

    def test_get_credentials_async_valid_input(self):
        """
        Test case 12: Valid input, successfully retrieves credentials asynchronously
        """
        response_body = json.dumps({
            "SessionAccessKey": {
                "SessionAccessKeyId": "test_access_key_id",
                "SessionAccessKeySecret": "test_access_key_secret",
                "Expiration": "2023-12-31T23:59:59Z"
            }
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
            with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                       return_value=self.private_key_content):
                provider = RsaKeyPairCredentialsProvider(
                    public_key_id=self.public_key_id,
                    private_key_file=self.private_key_file,
                    duration_seconds=self.duration_seconds,
                    sts_endpoint=self.sts_endpoint,
                    enable_vpc=self.enable_vpc,
                    http_options=self.http_options
                )

                # 使用 asyncio.run() 替代 get_event_loop()
                async def run_test():
                    return await provider._refresh_credentials_async()

                credentials = asyncio.run(run_test())

                self.assertEqual(credentials.value().get_access_key_id(), "test_access_key_id")
                self.assertEqual(credentials.value().get_access_key_secret(),
                                 "test_access_key_secret")
                self.assertEqual(credentials.value().get_expiration(),
                                 calendar.timegm(
                                     time.strptime("2023-12-31T23:59:59Z", '%Y-%m-%dT%H:%M:%SZ')))
                self.assertEqual(credentials.value().get_provider_name(), "rsa_key_pair")

    def test_get_credentials_async_http_request_error(self):
        """
        Test case 13: HTTP request error raises CredentialException asynchronously
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
            with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                       return_value=self.private_key_content):
                provider = RsaKeyPairCredentialsProvider(
                    public_key_id=self.public_key_id,
                    private_key_file=self.private_key_file,
                    duration_seconds=self.duration_seconds,
                    sts_endpoint=self.sts_endpoint,
                    enable_vpc=self.enable_vpc,
                    http_options=self.http_options
                )

                with self.assertRaises(CredentialException) as context:
                    # 使用 asyncio.run() 替代 get_event_loop()
                    async def run_test():
                        return await provider.get_credentials_async()
                    
                    asyncio.run(run_test())

                self.assertIn(
                    "error refreshing credentials from rsa_key_pair, http_code: 400, result: HTTP request failed",
                    str(context.exception))

    def test_get_credentials_async_response_format_error(self):
        """
        Test case 14: Response format error raises CredentialException asynchronously
        """
        response_body = json.dumps({
            "Error": "Invalid request"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
            with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                       return_value=self.private_key_content):
                provider = RsaKeyPairCredentialsProvider(
                    public_key_id=self.public_key_id,
                    private_key_file=self.private_key_file,
                    duration_seconds=self.duration_seconds,
                    sts_endpoint=self.sts_endpoint,
                    enable_vpc=self.enable_vpc,
                    http_options=self.http_options
                )

                with self.assertRaises(CredentialException) as context:
                    # 使用 asyncio.run() 替代 get_event_loop()
                    async def run_test():
                        return await provider.get_credentials_async()
                    
                    asyncio.run(run_test())

                self.assertIn(
                    'error retrieving credentials from rsa_key_pair result: {"Error": "Invalid request"}',
                    str(context.exception))

    @patch('alibabacloud_credentials.provider.rsa_key_pair.au.environment_enable_vpc', 'true')
    @patch('alibabacloud_credentials.provider.rsa_key_pair.au.environment_sts_region', 'test_env_sts_region')
    def test_sts_endpoint_with_sts_region_id_and_enable_vpc_true(self):
        """
        Test case 15: sts_region_id is provided and enable_vpc is True
        """
        with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                   return_value=self.private_key_content):
            provider = RsaKeyPairCredentialsProvider(
                public_key_id=self.public_key_id,
                private_key_file=self.private_key_file,
                duration_seconds=self.duration_seconds,
                sts_region_id=self.sts_region_id,
                enable_vpc=True,
                http_options=self.http_options
            )

            self.assertEqual(provider._sts_endpoint, f'sts-vpc.{self.sts_region_id}.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.rsa_key_pair.au.environment_enable_vpc', 'false')
    @patch('alibabacloud_credentials.provider.rsa_key_pair.au.environment_sts_region', 'test_env_sts_region')
    def test_sts_endpoint_with_sts_region_id_and_enable_vpc_false(self):
        """
        Test case 16: sts_region_id is provided and enable_vpc is False
        """
        with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                   return_value=self.private_key_content):
            provider = RsaKeyPairCredentialsProvider(
                public_key_id=self.public_key_id,
                private_key_file=self.private_key_file,
                duration_seconds=self.duration_seconds,
                sts_region_id=self.sts_region_id,
                enable_vpc=False,
                http_options=self.http_options
            )

            self.assertEqual(provider._sts_endpoint, f'sts.{self.sts_region_id}.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.rsa_key_pair.au.environment_enable_vpc', 'true')
    @patch('alibabacloud_credentials.provider.rsa_key_pair.au.environment_sts_region', 'test_env_sts_region')
    def test_sts_endpoint_with_environment_sts_region_and_enable_vpc_true(self):
        """
        Test case 17: sts_region_id is not provided, environment_sts_region is provided, and enable_vpc is True
        """
        with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                   return_value=self.private_key_content):
            provider = RsaKeyPairCredentialsProvider(
                public_key_id=self.public_key_id,
                private_key_file=self.private_key_file,
                duration_seconds=self.duration_seconds,
                enable_vpc=True,
                http_options=self.http_options
            )

            self.assertEqual(provider._sts_endpoint, f'sts-vpc.test_env_sts_region.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.rsa_key_pair.au.environment_enable_vpc', 'false')
    @patch('alibabacloud_credentials.provider.rsa_key_pair.au.environment_sts_region', 'test_env_sts_region')
    def test_sts_endpoint_with_environment_sts_region_and_enable_vpc_false(self):
        """
        Test case 18: sts_region_id is not provided, environment_sts_region is provided, and enable_vpc is False
        """
        with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                   return_value=self.private_key_content):
            provider = RsaKeyPairCredentialsProvider(
                public_key_id=self.public_key_id,
                private_key_file=self.private_key_file,
                duration_seconds=self.duration_seconds,
                enable_vpc=False,
                http_options=self.http_options
            )

            self.assertEqual(provider._sts_endpoint, f'sts.test_env_sts_region.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.rsa_key_pair.au.environment_enable_vpc', 'true')
    @patch('alibabacloud_credentials.provider.rsa_key_pair.au.environment_sts_region', None)
    def test_sts_endpoint_with_no_sts_region_id_or_environment_sts_region_and_enable_vpc_true(self):
        """
        Test case 19: sts_region_id and environment_sts_region are not provided, and enable_vpc is True
        """
        with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                   return_value=self.private_key_content):
            provider = RsaKeyPairCredentialsProvider(
                public_key_id=self.public_key_id,
                private_key_file=self.private_key_file,
                duration_seconds=self.duration_seconds,
                enable_vpc=True,
                http_options=self.http_options
            )

            self.assertEqual(provider._sts_endpoint, 'sts.ap-northeast-1.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.rsa_key_pair.au.environment_enable_vpc', 'false')
    @patch('alibabacloud_credentials.provider.rsa_key_pair.au.environment_sts_region', None)
    def test_sts_endpoint_with_no_sts_region_id_or_environment_sts_region_and_enable_vpc_false(self):
        """
        Test case 20: sts_region_id and environment_sts_region are not provided, and enable_vpc is False
        """
        with patch('alibabacloud_credentials.provider.rsa_key_pair._get_content',
                   return_value=self.private_key_content):
            provider = RsaKeyPairCredentialsProvider(
                public_key_id=self.public_key_id,
                private_key_file=self.private_key_file,
                duration_seconds=self.duration_seconds,
                enable_vpc=False,
                http_options=self.http_options
            )

            self.assertEqual(provider._sts_endpoint, 'sts.ap-northeast-1.aliyuncs.com')

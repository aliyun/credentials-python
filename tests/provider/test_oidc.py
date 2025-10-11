import unittest
from unittest.mock import patch, AsyncMock
import asyncio
import calendar
import time
import json
from alibabacloud_credentials.provider.oidc import (
    OIDCRoleArnCredentialsProvider,
    CredentialException
)
from alibabacloud_credentials.http import HttpOptions
from Tea.core import TeaResponse


class TestOIDCRoleArnCredentialsProvider(unittest.TestCase):

    def setUp(self):
        self.role_arn = "test_role_arn"
        self.oidc_provider_arn = "test_oidc_provider_arn"
        self.oidc_token_file_path = "test_oidc_token_file_path"
        self.role_session_name = "test_role_session_name"
        self.duration_seconds = 3600
        self.policy = "test_policy"
        self.sts_region_id = "test_sts_region_id"
        self.sts_endpoint = "test_sts_endpoint"
        self.enable_vpc = True
        self.http_options = HttpOptions(connect_timeout=5000, read_timeout=10000, proxy="test_proxy")

    def test_init_valid_input(self):
        """
        Test case 1: Valid input, successfully initializes with provided parameters
        """
        provider = OIDCRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            oidc_provider_arn=self.oidc_provider_arn,
            oidc_token_file_path=self.oidc_token_file_path,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            sts_region_id=self.sts_region_id,
            sts_endpoint=self.sts_endpoint,
            enable_vpc=self.enable_vpc,
            http_options=self.http_options
        )

        self.assertEqual(provider._role_arn, self.role_arn)
        self.assertEqual(provider._oidc_provider_arn, self.oidc_provider_arn)
        self.assertEqual(provider._oidc_token_file_path, self.oidc_token_file_path)
        self.assertEqual(provider._role_session_name, self.role_session_name)
        self.assertEqual(provider._duration_seconds, self.duration_seconds)
        self.assertEqual(provider._policy, self.policy)
        self.assertEqual(provider._sts_endpoint, self.sts_endpoint)
        self.assertEqual(provider._http_options, self.http_options)
        self.assertEqual(provider._runtime_options['connectTimeout'], self.http_options.connect_timeout)
        self.assertEqual(provider._runtime_options['readTimeout'], self.http_options.read_timeout)
        self.assertEqual(provider._runtime_options['httpsProxy'], self.http_options.proxy)

    @patch('alibabacloud_credentials.provider.oidc.au')
    def test_init_valid_environment_variables(self, mock_auth_util):
        """
        Test case 2: Valid input, successfully initializes with environment variables
        """
        mock_auth_util.environment_role_arn = self.role_arn
        mock_auth_util.environment_oidc_provider_arn = self.oidc_provider_arn
        mock_auth_util.environment_oidc_token_file = self.oidc_token_file_path
        mock_auth_util.environment_role_session_name = self.role_session_name
        mock_auth_util.environment_enable_vpc = str(self.enable_vpc)
        mock_auth_util.environment_sts_region = self.sts_region_id

        provider = OIDCRoleArnCredentialsProvider()

        self.assertEqual(provider._role_arn, self.role_arn)
        self.assertEqual(provider._oidc_provider_arn, self.oidc_provider_arn)
        self.assertEqual(provider._oidc_token_file_path, self.oidc_token_file_path)
        self.assertEqual(provider._role_session_name, self.role_session_name)
        self.assertEqual(provider._duration_seconds, OIDCRoleArnCredentialsProvider.DEFAULT_DURATION_SECONDS)
        self.assertIsNone(provider._policy)
        self.assertEqual(provider._sts_endpoint, f'sts-vpc.{self.sts_region_id}.aliyuncs.com')
        self.assertEqual(provider._runtime_options['connectTimeout'],
                         OIDCRoleArnCredentialsProvider.DEFAULT_CONNECT_TIMEOUT)
        self.assertEqual(provider._runtime_options['readTimeout'], OIDCRoleArnCredentialsProvider.DEFAULT_READ_TIMEOUT)
        self.assertIsNone(provider._runtime_options['httpsProxy'])

    @patch('alibabacloud_credentials.provider.oidc.au')
    def test_init_missing_role_arn(self, mock_auth_util):
        """
        Test case 3: Missing role_arn raises ValueError
        """
        mock_auth_util.environment_role_arn = None
        with self.assertRaises(ValueError) as context:
            OIDCRoleArnCredentialsProvider(
                oidc_provider_arn=self.oidc_provider_arn,
                oidc_token_file_path=self.oidc_token_file_path
            )

        self.assertIn("role_arn or environment variable ALIBABA_CLOUD_ROLE_ARN cannot be empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.oidc.au')
    def test_init_empty_role_arn(self, mock_auth_util):
        """
        Test case 4: Empty role_arn raises ValueError
        """
        mock_auth_util.environment_role_arn = None
        with self.assertRaises(ValueError) as context:
            OIDCRoleArnCredentialsProvider(
                role_arn="",
                oidc_provider_arn=self.oidc_provider_arn,
                oidc_token_file_path=self.oidc_token_file_path
            )

        self.assertIn("role_arn or environment variable ALIBABA_CLOUD_ROLE_ARN cannot be empty", str(context.exception))

    @patch('alibabacloud_credentials.provider.oidc.au')
    def test_init_missing_oidc_provider_arn(self, mock_auth_util):
        """
        Test case 5: Missing oidc_provider_arn raises ValueError
        """
        mock_auth_util.environment_oidc_provider_arn = None
        with self.assertRaises(ValueError) as context:
            OIDCRoleArnCredentialsProvider(
                role_arn=self.role_arn,
                oidc_token_file_path=self.oidc_token_file_path
            )

        self.assertIn("oidc_provider_arn or environment variable ALIBABA_CLOUD_OIDC_PROVIDER_ARN cannot be empty",
                      str(context.exception))

    @patch('alibabacloud_credentials.provider.oidc.au')
    def test_init_empty_oidc_provider_arn(self, mock_auth_util):
        """
        Test case 6: Empty oidc_provider_arn raises ValueError
        """
        mock_auth_util.environment_oidc_provider_arn = None
        with self.assertRaises(ValueError) as context:
            OIDCRoleArnCredentialsProvider(
                role_arn=self.role_arn,
                oidc_provider_arn="",
                oidc_token_file_path=self.oidc_token_file_path
            )

        self.assertIn("oidc_provider_arn or environment variable ALIBABA_CLOUD_OIDC_PROVIDER_ARN cannot be empty",
                      str(context.exception))

    @patch('alibabacloud_credentials.provider.oidc.au')
    def test_init_missing_oidc_token_file_path(self, mock_auth_util):
        """
        Test case 7: Missing oidc_token_file_path raises ValueError
        """
        mock_auth_util.environment_oidc_token_file = None
        with self.assertRaises(ValueError) as context:
            OIDCRoleArnCredentialsProvider(
                role_arn=self.role_arn,
                oidc_provider_arn=self.oidc_provider_arn
            )

        self.assertIn("oidc_token_file_path or environment variable ALIBABA_CLOUD_OIDC_TOKEN_FILE cannot be empty",
                      str(context.exception))

    @patch('alibabacloud_credentials.provider.oidc.au')
    def test_init_empty_oidc_token_file_path(self, mock_auth_util):
        """
        Test case 8: Empty oidc_token_file_path raises ValueError
        """
        mock_auth_util.environment_oidc_token_file = None
        with self.assertRaises(ValueError) as context:
            OIDCRoleArnCredentialsProvider(
                role_arn=self.role_arn,
                oidc_provider_arn=self.oidc_provider_arn,
                oidc_token_file_path=""
            )

        self.assertIn("oidc_token_file_path or environment variable ALIBABA_CLOUD_OIDC_TOKEN_FILE cannot be empty",
                      str(context.exception))

    def test_init_duration_seconds_too_short(self):
        """
        Test case 9: Duration seconds less than 900 raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            OIDCRoleArnCredentialsProvider(
                role_arn=self.role_arn,
                oidc_provider_arn=self.oidc_provider_arn,
                oidc_token_file_path=self.oidc_token_file_path,
                duration_seconds=800
            )

        self.assertIn("session duration should be in the range of 900s - max session duration", str(context.exception))

    @patch('alibabacloud_credentials.provider.oidc.au')
    def test_init_default_values(self, mock_auth_util):
        """
        Test case 10: Initializes with default values
        """
        mock_auth_util.environment_role_arn = self.role_arn
        mock_auth_util.environment_oidc_provider_arn = self.oidc_provider_arn
        mock_auth_util.environment_oidc_token_file = self.oidc_token_file_path
        mock_auth_util.environment_role_session_name = None
        mock_auth_util.environment_enable_vpc = 'false'
        mock_auth_util.environment_sts_region = None

        provider = OIDCRoleArnCredentialsProvider()

        self.assertEqual(provider._role_arn, self.role_arn)
        self.assertEqual(provider._oidc_provider_arn, self.oidc_provider_arn)
        self.assertEqual(provider._oidc_token_file_path, self.oidc_token_file_path)
        self.assertTrue(provider._role_session_name.startswith('credentials-python-'))
        self.assertEqual(provider._duration_seconds, OIDCRoleArnCredentialsProvider.DEFAULT_DURATION_SECONDS)
        self.assertIsNone(provider._policy)
        self.assertEqual(provider._sts_endpoint, 'sts.aliyuncs.com')
        self.assertEqual(provider._runtime_options['connectTimeout'],
                         OIDCRoleArnCredentialsProvider.DEFAULT_CONNECT_TIMEOUT)
        self.assertEqual(provider._runtime_options['readTimeout'], OIDCRoleArnCredentialsProvider.DEFAULT_READ_TIMEOUT)
        self.assertIsNone(provider._runtime_options['httpsProxy'])

    def test_get_credentials_valid_input(self):
        """
        Test case 11: Valid input, successfully retrieves credentials
        """
        token = "test_token"
        response_body = json.dumps({
            "Credentials": {
                "AccessKeyId": "test_access_key_id",
                "AccessKeySecret": "test_access_key_secret",
                "SecurityToken": "test_security_token",
                "Expiration": "2023-12-31T23:59:59Z"
            }
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('alibabacloud_credentials.provider.oidc._get_token', return_value=token):
            with patch('Tea.core.TeaCore.do_action', return_value=response):
                provider = OIDCRoleArnCredentialsProvider(
                    role_arn=self.role_arn,
                    oidc_provider_arn=self.oidc_provider_arn,
                    oidc_token_file_path=self.oidc_token_file_path,
                    role_session_name=self.role_session_name,
                    duration_seconds=self.duration_seconds,
                    policy=self.policy,
                    sts_endpoint=self.sts_endpoint,
                    enable_vpc=self.enable_vpc,
                    http_options=self.http_options
                )

                credentials = provider._refresh_credentials()

                self.assertEqual(credentials.value().get_access_key_id(), "test_access_key_id")
                self.assertEqual(credentials.value().get_access_key_secret(), "test_access_key_secret")
                self.assertEqual(credentials.value().get_security_token(), "test_security_token")
                self.assertEqual(credentials.value().get_expiration(),
                                 calendar.timegm(time.strptime("2023-12-31T23:59:59Z", '%Y-%m-%dT%H:%M:%SZ')))
                self.assertEqual(credentials.value().get_provider_name(), "oidc_role_arn")

                with self.assertRaises(CredentialException) as context:
                    provider.get_credentials()

                self.assertIn("No cached value was found.", str(context.exception))

    def test_get_credentials_file_read_error(self):
        """
        Test case 12: File read error raises CredentialException
        """
        with patch('alibabacloud_credentials.provider.oidc._get_token', side_effect=FileNotFoundError):
            provider = OIDCRoleArnCredentialsProvider(
                role_arn=self.role_arn,
                oidc_provider_arn=self.oidc_provider_arn,
                oidc_token_file_path=self.oidc_token_file_path,
                role_session_name=self.role_session_name,
                duration_seconds=self.duration_seconds,
                policy=self.policy,
                sts_endpoint=self.sts_endpoint,
                enable_vpc=self.enable_vpc,
                http_options=self.http_options
            )

            with self.assertRaises(FileNotFoundError) as context:
                provider.get_credentials()

    def test_get_credentials_http_request_error(self):
        """
        Test case 13: HTTP request error raises CredentialException
        """
        token = "test_token"
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('alibabacloud_credentials.provider.oidc._get_token', return_value=token):
            with patch('Tea.core.TeaCore.do_action', return_value=response):
                provider = OIDCRoleArnCredentialsProvider(
                    role_arn=self.role_arn,
                    oidc_provider_arn=self.oidc_provider_arn,
                    oidc_token_file_path=self.oidc_token_file_path,
                    role_session_name=self.role_session_name,
                    duration_seconds=self.duration_seconds,
                    policy=self.policy,
                    sts_endpoint=self.sts_endpoint,
                    enable_vpc=self.enable_vpc,
                    http_options=self.http_options
                )

                with self.assertRaises(CredentialException) as context:
                    provider.get_credentials()

                self.assertIn(
                    "error refreshing credentials from oidc_role_arn, http_code: 400, result: HTTP request failed",
                    str(context.exception))

    def test_get_credentials_response_format_error(self):
        """
        Test case 14: Response format error raises CredentialException
        """
        token = "test_token"
        response_body = json.dumps({
            "Error": "Invalid request"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('alibabacloud_credentials.provider.oidc._get_token', return_value=token):
            with patch('Tea.core.TeaCore.do_action', return_value=response):
                provider = OIDCRoleArnCredentialsProvider(
                    role_arn=self.role_arn,
                    oidc_provider_arn=self.oidc_provider_arn,
                    oidc_token_file_path=self.oidc_token_file_path,
                    role_session_name=self.role_session_name,
                    duration_seconds=self.duration_seconds,
                    policy=self.policy,
                    sts_endpoint=self.sts_endpoint,
                    enable_vpc=self.enable_vpc,
                    http_options=self.http_options
                )

                with self.assertRaises(CredentialException) as context:
                    provider.get_credentials()

                self.assertIn('error retrieving credentials from oidc_role_arn result: {"Error": "Invalid request"}',
                              str(context.exception))

    def test_get_credentials_async_valid_input(self):
        """
        Test case 15: Valid input, successfully retrieves credentials asynchronously
        """
        token = "test_token"
        response_body = json.dumps({
            "Credentials": {
                "AccessKeyId": "test_access_key_id",
                "AccessKeySecret": "test_access_key_secret",
                "SecurityToken": "test_security_token",
                "Expiration": "2023-12-31T23:59:59Z"
            }
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('alibabacloud_credentials.provider.oidc._get_token_async', AsyncMock(return_value=token)):
            with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
                provider = OIDCRoleArnCredentialsProvider(
                    role_arn=self.role_arn,
                    oidc_provider_arn=self.oidc_provider_arn,
                    oidc_token_file_path=self.oidc_token_file_path,
                    role_session_name=self.role_session_name,
                    duration_seconds=self.duration_seconds,
                    policy=self.policy,
                    sts_endpoint=self.sts_endpoint,
                    enable_vpc=self.enable_vpc,
                    http_options=self.http_options
                )

                # 使用 asyncio.run() 替代 get_event_loop()
                async def run_test():
                    return await provider._refresh_credentials_async()

                credentials = asyncio.run(run_test())

                self.assertEqual(credentials.value().get_access_key_id(), "test_access_key_id")
                self.assertEqual(credentials.value().get_access_key_secret(), "test_access_key_secret")
                self.assertEqual(credentials.value().get_security_token(), "test_security_token")
                self.assertEqual(credentials.value().get_expiration(),
                                 calendar.timegm(time.strptime("2023-12-31T23:59:59Z", '%Y-%m-%dT%H:%M:%SZ')))
                self.assertEqual(credentials.value().get_provider_name(), "oidc_role_arn")

                with self.assertRaises(CredentialException) as context:
                    # 使用 asyncio.run() 替代 get_event_loop()
                    async def run_test():
                        return await provider.get_credentials_async()
                    
                    asyncio.run(run_test())

                self.assertIn("No cached value was found.", str(context.exception))

    def test_get_credentials_async_file_read_error(self):
        """
        Test case 16: File read error raises CredentialException asynchronously
        """
        with patch('alibabacloud_credentials.provider.oidc._get_token_async', AsyncMock(side_effect=FileNotFoundError)):
            provider = OIDCRoleArnCredentialsProvider(
                role_arn=self.role_arn,
                oidc_provider_arn=self.oidc_provider_arn,
                oidc_token_file_path=self.oidc_token_file_path,
                role_session_name=self.role_session_name,
                duration_seconds=self.duration_seconds,
                policy=self.policy,
                sts_endpoint=self.sts_endpoint,
                enable_vpc=self.enable_vpc,
                http_options=self.http_options
            )

            with self.assertRaises(FileNotFoundError) as context:
                # 使用 asyncio.run() 替代 get_event_loop()
                async def run_test():
                    return await provider.get_credentials_async()
                
                asyncio.run(run_test())

    def test_get_credentials_async_http_request_error(self):
        """
        Test case 17: HTTP request error raises CredentialException asynchronously
        """
        token = "test_token"
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('alibabacloud_credentials.provider.oidc._get_token_async', AsyncMock(return_value=token)):
            with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
                provider = OIDCRoleArnCredentialsProvider(
                    role_arn=self.role_arn,
                    oidc_provider_arn=self.oidc_provider_arn,
                    oidc_token_file_path=self.oidc_token_file_path,
                    role_session_name=self.role_session_name,
                    duration_seconds=self.duration_seconds,
                    policy=self.policy,
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
                    "error refreshing credentials from oidc_role_arn, http_code: 400, result: HTTP request failed",
                    str(context.exception))

    def test_get_credentials_async_response_format_error(self):
        """
        Test case 18: Response format error raises CredentialException asynchronously
        """
        token = "test_token"
        response_body = json.dumps({
            "Error": "Invalid request"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('alibabacloud_credentials.provider.oidc._get_token_async', AsyncMock(return_value=token)):
            with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
                provider = OIDCRoleArnCredentialsProvider(
                    role_arn=self.role_arn,
                    oidc_provider_arn=self.oidc_provider_arn,
                    oidc_token_file_path=self.oidc_token_file_path,
                    role_session_name=self.role_session_name,
                    duration_seconds=self.duration_seconds,
                    policy=self.policy,
                    sts_endpoint=self.sts_endpoint,
                    enable_vpc=self.enable_vpc,
                    http_options=self.http_options
                )

                with self.assertRaises(CredentialException) as context:
                    # 使用 asyncio.run() 替代 get_event_loop()
                    async def run_test():
                        return await provider.get_credentials_async()
                    
                    asyncio.run(run_test())

                self.assertIn('error retrieving credentials from oidc_role_arn result: {"Error": "Invalid request"}',
                              str(context.exception))

    @patch('alibabacloud_credentials.provider.oidc.au.environment_enable_vpc', 'true')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_sts_region', 'test_env_sts_region')
    def test_sts_endpoint_with_sts_region_id_and_enable_vpc_true(self):
        """
        Test case 19: sts_region_id is provided and enable_vpc is True
        """
        provider = OIDCRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            oidc_provider_arn=self.oidc_provider_arn,
            oidc_token_file_path=self.oidc_token_file_path,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            sts_region_id=self.sts_region_id,
            enable_vpc=True,
            http_options=self.http_options
        )

        self.assertEqual(provider._sts_endpoint, f'sts-vpc.{self.sts_region_id}.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.oidc.au.environment_enable_vpc', 'false')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_sts_region', 'test_env_sts_region')
    def test_sts_endpoint_with_sts_region_id_and_enable_vpc_false(self):
        """
        Test case 20: sts_region_id is provided and enable_vpc is False
        """
        provider = OIDCRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            oidc_provider_arn=self.oidc_provider_arn,
            oidc_token_file_path=self.oidc_token_file_path,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            sts_region_id=self.sts_region_id,
            enable_vpc=False,
            http_options=self.http_options
        )

        self.assertEqual(provider._sts_endpoint, f'sts.{self.sts_region_id}.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.oidc.au.environment_enable_vpc', 'true')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_sts_region', 'test_env_sts_region')
    def test_sts_endpoint_with_environment_sts_region_and_enable_vpc_true(self):
        """
        Test case 21: sts_region_id is not provided, environment_sts_region is provided, and enable_vpc is True
        """
        provider = OIDCRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            oidc_provider_arn=self.oidc_provider_arn,
            oidc_token_file_path=self.oidc_token_file_path,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            enable_vpc=True,
            http_options=self.http_options
        )

        self.assertEqual(provider._sts_endpoint, f'sts-vpc.test_env_sts_region.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.oidc.au.environment_enable_vpc', 'false')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_sts_region', 'test_env_sts_region')
    def test_sts_endpoint_with_environment_sts_region_and_enable_vpc_false(self):
        """
        Test case 22: sts_region_id is not provided, environment_sts_region is provided, and enable_vpc is False
        """
        provider = OIDCRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            oidc_provider_arn=self.oidc_provider_arn,
            oidc_token_file_path=self.oidc_token_file_path,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            enable_vpc=False,
            http_options=self.http_options
        )

        self.assertEqual(provider._sts_endpoint, f'sts.test_env_sts_region.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.oidc.au.environment_enable_vpc', 'true')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_sts_region', None)
    def test_sts_endpoint_with_no_sts_region_id_or_environment_sts_region_and_enable_vpc_true(self):
        """
        Test case 23: sts_region_id and environment_sts_region are not provided, and enable_vpc is True
        """
        provider = OIDCRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            oidc_provider_arn=self.oidc_provider_arn,
            oidc_token_file_path=self.oidc_token_file_path,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            enable_vpc=True,
            http_options=self.http_options
        )

        self.assertEqual(provider._sts_endpoint, 'sts.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.oidc.au.environment_enable_vpc', 'false')
    @patch('alibabacloud_credentials.provider.oidc.au.environment_sts_region', None)
    def test_sts_endpoint_with_no_sts_region_id_or_environment_sts_region_and_enable_vpc_false(self):
        """
        Test case 24: sts_region_id and environment_sts_region are not provided, and enable_vpc is False
        """
        provider = OIDCRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            oidc_provider_arn=self.oidc_provider_arn,
            oidc_token_file_path=self.oidc_token_file_path,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            enable_vpc=False,
            http_options=self.http_options
        )

        self.assertEqual(provider._sts_endpoint, 'sts.aliyuncs.com')

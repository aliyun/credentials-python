import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import calendar
import time
import json
from alibabacloud_credentials.provider.ram_role_arn import (
    RamRoleArnCredentialsProvider,
    CredentialException
)
from alibabacloud_credentials.http import HttpOptions
from Tea.core import TeaResponse


class TestRamRoleArnCredentialsProvider(unittest.TestCase):

    def setUp(self):
        self.access_key_id = "test_access_key_id"
        self.access_key_secret = "test_access_key_secret"
        self.security_token = "test_security_token"
        self.role_arn = "test_role_arn"
        self.role_session_name = "test_role_session_name"
        self.duration_seconds = 3600
        self.policy = "test_policy"
        self.external_id = "test_external_id"
        self.sts_region_id = "test_sts_region_id"
        self.sts_endpoint = "test_sts_endpoint"
        self.enable_vpc = True
        self.http_options = HttpOptions(connect_timeout=5000, read_timeout=10000, proxy="test_proxy")

    def test_init_valid_input(self):
        """
        Test case 1: Valid input, successfully initializes with provided parameters
        """
        provider = RamRoleArnCredentialsProvider(
            access_key_id=self.access_key_id,
            access_key_secret=self.access_key_secret,
            security_token=self.security_token,
            role_arn=self.role_arn,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            external_id=self.external_id,
            sts_region_id=self.sts_region_id,
            sts_endpoint=self.sts_endpoint,
            enable_vpc=self.enable_vpc,
            http_options=self.http_options
        )

        self.assertEqual(provider._credentials_provider.get_credentials().get_access_key_id(), self.access_key_id)
        self.assertEqual(provider._credentials_provider.get_credentials().get_access_key_secret(),
                         self.access_key_secret)
        self.assertEqual(provider._credentials_provider.get_credentials().get_security_token(), self.security_token)
        self.assertEqual(provider._role_arn, self.role_arn)
        self.assertEqual(provider._role_session_name, self.role_session_name)
        self.assertEqual(provider._duration_seconds, self.duration_seconds)
        self.assertEqual(provider._policy, self.policy)
        self.assertEqual(provider._external_id, self.external_id)
        self.assertEqual(provider._sts_endpoint, self.sts_endpoint)
        self.assertEqual(provider._http_options, self.http_options)
        self.assertEqual(provider._runtime_options['connectTimeout'], self.http_options.connect_timeout)
        self.assertEqual(provider._runtime_options['readTimeout'], self.http_options.read_timeout)
        self.assertEqual(provider._runtime_options['httpsProxy'], self.http_options.proxy)

    @patch('alibabacloud_credentials.provider.static_ak.auth_util')
    @patch('alibabacloud_credentials.provider.ram_role_arn.au')
    def test_init_valid_environment_variables(self, mock_ram_util, mock_ak_util):
        """
        Test case 2: Valid input, successfully initializes with environment variables
        """
        mock_ak_util.environment_access_key_id = self.access_key_id
        mock_ak_util.environment_access_key_secret = self.access_key_secret
        mock_ram_util.environment_role_arn = self.role_arn
        mock_ram_util.environment_role_session_name = self.role_session_name
        mock_ram_util.environment_enable_vpc = str(self.enable_vpc)
        mock_ram_util.environment_sts_region = self.sts_region_id

        provider = RamRoleArnCredentialsProvider()

        self.assertEqual(provider._credentials_provider.get_credentials().get_access_key_id(), self.access_key_id)
        self.assertEqual(provider._credentials_provider.get_credentials().get_access_key_secret(),
                         self.access_key_secret)
        self.assertEqual(provider._role_arn, self.role_arn)
        self.assertEqual(provider._role_session_name, self.role_session_name)
        self.assertEqual(provider._duration_seconds, RamRoleArnCredentialsProvider.DEFAULT_DURATION_SECONDS)
        self.assertIsNone(provider._policy)
        self.assertIsNone(provider._external_id)
        self.assertEqual(provider._sts_endpoint, f'sts-vpc.{self.sts_region_id}.aliyuncs.com')
        self.assertEqual(provider._runtime_options['connectTimeout'],
                         RamRoleArnCredentialsProvider.DEFAULT_CONNECT_TIMEOUT)
        self.assertEqual(provider._runtime_options['readTimeout'], RamRoleArnCredentialsProvider.DEFAULT_READ_TIMEOUT)
        self.assertIsNone(provider._runtime_options['httpsProxy'])

    def test_init_missing_role_arn(self):
        """
        Test case 3: Missing role_arn raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            RamRoleArnCredentialsProvider(
                access_key_id=self.access_key_id,
                access_key_secret=self.access_key_secret,
                security_token=self.security_token
            )

        self.assertIn("role_arn or environment variable ALIBABA_CLOUD_ROLE_ARN cannot be empty", str(context.exception))

    def test_init_empty_role_arn(self):
        """
        Test case 4: Empty role_arn raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            RamRoleArnCredentialsProvider(
                access_key_id=self.access_key_id,
                access_key_secret=self.access_key_secret,
                security_token=self.security_token,
                role_arn=""
            )

        self.assertIn("role_arn or environment variable ALIBABA_CLOUD_ROLE_ARN cannot be empty", str(context.exception))

    def test_init_duration_seconds_too_short(self):
        """
        Test case 5: Duration seconds less than 900 raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            RamRoleArnCredentialsProvider(
                access_key_id=self.access_key_id,
                access_key_secret=self.access_key_secret,
                security_token=self.security_token,
                role_arn=self.role_arn,
                duration_seconds=800
            )

        self.assertIn("session duration should be in the range of 900s - max session duration", str(context.exception))

    @patch('alibabacloud_credentials.provider.static_ak.auth_util')
    @patch('alibabacloud_credentials.provider.ram_role_arn.au')
    def test_init_default_values(self, mock_ram_util, mock_ak_util):
        """
        Test case 6: Initializes with default values
        """
        mock_ak_util.environment_access_key_id = self.access_key_id
        mock_ak_util.environment_access_key_secret = self.access_key_secret
        mock_ram_util.environment_role_arn = self.role_arn
        mock_ram_util.environment_role_session_name = None
        mock_ram_util.environment_enable_vpc = 'false'
        mock_ram_util.environment_sts_region = None

        provider = RamRoleArnCredentialsProvider()

        self.assertEqual(provider._credentials_provider.get_credentials().get_access_key_id(), self.access_key_id)
        self.assertEqual(provider._credentials_provider.get_credentials().get_access_key_secret(),
                         self.access_key_secret)
        self.assertEqual(provider._role_arn, self.role_arn)
        self.assertTrue(provider._role_session_name.startswith('credentials-python-'))
        self.assertEqual(provider._duration_seconds, RamRoleArnCredentialsProvider.DEFAULT_DURATION_SECONDS)
        self.assertIsNone(provider._policy)
        self.assertIsNone(provider._external_id)
        self.assertEqual(provider._sts_endpoint, 'sts.aliyuncs.com')
        self.assertEqual(provider._runtime_options['connectTimeout'],
                         RamRoleArnCredentialsProvider.DEFAULT_CONNECT_TIMEOUT)
        self.assertEqual(provider._runtime_options['readTimeout'], RamRoleArnCredentialsProvider.DEFAULT_READ_TIMEOUT)
        self.assertIsNone(provider._runtime_options['httpsProxy'])

    def test_get_credentials_valid_input(self):
        """
        Test case 7: Valid input, successfully retrieves credentials
        """
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

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            provider = RamRoleArnCredentialsProvider(
                access_key_id=self.access_key_id,
                access_key_secret=self.access_key_secret,
                security_token=self.security_token,
                role_arn=self.role_arn,
                role_session_name=self.role_session_name,
                duration_seconds=self.duration_seconds,
                policy=self.policy,
                external_id=self.external_id,
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
            self.assertEqual(credentials.value().get_provider_name(), "ram_role_arn/static_sts")

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn("No cached value was found.", str(context.exception))

    def test_get_credentials_http_request_error(self):
        """
        Test case 8: HTTP request error raises CredentialException
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            provider = RamRoleArnCredentialsProvider(
                access_key_id=self.access_key_id,
                access_key_secret=self.access_key_secret,
                security_token=self.security_token,
                role_arn=self.role_arn,
                role_session_name=self.role_session_name,
                duration_seconds=self.duration_seconds,
                policy=self.policy,
                external_id=self.external_id,
                sts_endpoint=self.sts_endpoint,
                enable_vpc=self.enable_vpc,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn(
                "error refreshing credentials from ram_role_arn, http_code: 400, result: HTTP request failed",
                str(context.exception))

    def test_get_credentials_response_format_error(self):
        """
        Test case 9: Response format error raises CredentialException
        """
        response_body = json.dumps({
            "Error": "Invalid request"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            provider = RamRoleArnCredentialsProvider(
                access_key_id=self.access_key_id,
                access_key_secret=self.access_key_secret,
                security_token=self.security_token,
                role_arn=self.role_arn,
                role_session_name=self.role_session_name,
                duration_seconds=self.duration_seconds,
                policy=self.policy,
                external_id=self.external_id,
                sts_endpoint=self.sts_endpoint,
                enable_vpc=self.enable_vpc,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn(
                'error retrieving credentials from ram_role_arn result: {"Error": "Invalid request"}',
                str(context.exception))

    def test_get_credentials_async_valid_input(self):
        """
        Test case 10: Valid input, successfully retrieves credentials asynchronously
        """
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

        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
            provider = RamRoleArnCredentialsProvider(
                access_key_id=self.access_key_id,
                access_key_secret=self.access_key_secret,
                security_token=self.security_token,
                role_arn=self.role_arn,
                role_session_name=self.role_session_name,
                duration_seconds=self.duration_seconds,
                policy=self.policy,
                external_id=self.external_id,
                sts_endpoint=self.sts_endpoint,
                enable_vpc=self.enable_vpc,
                http_options=self.http_options
            )

            loop = asyncio.get_event_loop()
            task = asyncio.ensure_future(
                provider._refresh_credentials_async()
            )
            loop.run_until_complete(task)
            credentials = task.result()

            self.assertEqual(credentials.value().get_access_key_id(), "test_access_key_id")
            self.assertEqual(credentials.value().get_access_key_secret(), "test_access_key_secret")
            self.assertEqual(credentials.value().get_security_token(), "test_security_token")
            self.assertEqual(credentials.value().get_expiration(),
                             calendar.timegm(
                                 time.strptime("2023-12-31T23:59:59Z", '%Y-%m-%dT%H:%M:%SZ')))
            self.assertEqual(credentials.value().get_provider_name(), "ram_role_arn/static_sts")

            with self.assertRaises(CredentialException) as context:
                loop = asyncio.get_event_loop()
                task = asyncio.ensure_future(
                    provider.get_credentials_async()
                )
                loop.run_until_complete(task)

            self.assertIn("No cached value was found.", str(context.exception))

    def test_get_credentials_async_http_request_error(self):
        """
        Test case 11: HTTP request error raises CredentialException asynchronously
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
            provider = RamRoleArnCredentialsProvider(
                access_key_id=self.access_key_id,
                access_key_secret=self.access_key_secret,
                security_token=self.security_token,
                role_arn=self.role_arn,
                role_session_name=self.role_session_name,
                duration_seconds=self.duration_seconds,
                policy=self.policy,
                external_id=self.external_id,
                sts_endpoint=self.sts_endpoint,
                enable_vpc=self.enable_vpc,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                loop = asyncio.get_event_loop()
                task = asyncio.ensure_future(
                    provider.get_credentials_async()
                )
                loop.run_until_complete(task)

            self.assertIn(
                "error refreshing credentials from ram_role_arn, http_code: 400, result: HTTP request failed",
                str(context.exception))

    def test_get_credentials_async_response_format_error(self):
        """
        Test case 12: Response format error raises CredentialException asynchronously
        """
        response_body = json.dumps({
            "Error": "Invalid request"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
            provider = RamRoleArnCredentialsProvider(
                access_key_id=self.access_key_id,
                access_key_secret=self.access_key_secret,
                security_token=self.security_token,
                role_arn=self.role_arn,
                role_session_name=self.role_session_name,
                duration_seconds=self.duration_seconds,
                policy=self.policy,
                external_id=self.external_id,
                sts_endpoint=self.sts_endpoint,
                enable_vpc=self.enable_vpc,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                loop = asyncio.get_event_loop()
                task = asyncio.ensure_future(
                    provider.get_credentials_async()
                )
                loop.run_until_complete(task)

            self.assertIn(
                'error retrieving credentials from ram_role_arn result: {"Error": "Invalid request"}',
                str(context.exception))

    @patch('alibabacloud_credentials.provider.ram_role_arn.au.environment_enable_vpc', 'true')
    @patch('alibabacloud_credentials.provider.ram_role_arn.au.environment_sts_region', 'test_env_sts_region')
    def test_sts_endpoint_with_sts_region_id_and_enable_vpc_true(self):
        """
        Test case 13: sts_region_id is provided and enable_vpc is True
        """
        provider = RamRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            access_key_id=self.access_key_id,
            access_key_secret=self.access_key_secret,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            sts_region_id=self.sts_region_id,
            enable_vpc=True,
            http_options=self.http_options
        )

        self.assertEqual(provider._sts_endpoint, f'sts-vpc.{self.sts_region_id}.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.ram_role_arn.au.environment_enable_vpc', 'false')
    @patch('alibabacloud_credentials.provider.ram_role_arn.au.environment_sts_region', 'test_env_sts_region')
    def test_sts_endpoint_with_sts_region_id_and_enable_vpc_false(self):
        """
        Test case 14: sts_region_id is provided and enable_vpc is False
        """
        provider = RamRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            access_key_id=self.access_key_id,
            access_key_secret=self.access_key_secret,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            sts_region_id=self.sts_region_id,
            enable_vpc=False,
            http_options=self.http_options
        )

        self.assertEqual(provider._sts_endpoint, f'sts.{self.sts_region_id}.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.ram_role_arn.au.environment_enable_vpc', 'true')
    @patch('alibabacloud_credentials.provider.ram_role_arn.au.environment_sts_region', 'test_env_sts_region')
    def test_sts_endpoint_with_environment_sts_region_and_enable_vpc_true(self):
        """
        Test case 15: sts_region_id is not provided, environment_sts_region is provided, and enable_vpc is True
        """
        provider = RamRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            access_key_id=self.access_key_id,
            access_key_secret=self.access_key_secret,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            enable_vpc=True,
            http_options=self.http_options
        )

        self.assertEqual(provider._sts_endpoint, f'sts-vpc.test_env_sts_region.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.ram_role_arn.au.environment_enable_vpc', 'false')
    @patch('alibabacloud_credentials.provider.ram_role_arn.au.environment_sts_region', 'test_env_sts_region')
    def test_sts_endpoint_with_environment_sts_region_and_enable_vpc_false(self):
        """
        Test case 16: sts_region_id is not provided, environment_sts_region is provided, and enable_vpc is False
        """
        provider = RamRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            access_key_id=self.access_key_id,
            access_key_secret=self.access_key_secret,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            enable_vpc=False,
            http_options=self.http_options
        )

        self.assertEqual(provider._sts_endpoint, f'sts.test_env_sts_region.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.ram_role_arn.au.environment_enable_vpc', 'true')
    @patch('alibabacloud_credentials.provider.ram_role_arn.au.environment_sts_region', None)
    def test_sts_endpoint_with_no_sts_region_id_or_environment_sts_region_and_enable_vpc_true(self):
        """
        Test case 17: sts_region_id and environment_sts_region are not provided, and enable_vpc is True
        """
        provider = RamRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            access_key_id=self.access_key_id,
            access_key_secret=self.access_key_secret,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            enable_vpc=True,
            http_options=self.http_options
        )

        self.assertEqual(provider._sts_endpoint, 'sts.aliyuncs.com')

    @patch('alibabacloud_credentials.provider.ram_role_arn.au.environment_enable_vpc', 'false')
    @patch('alibabacloud_credentials.provider.ram_role_arn.au.environment_sts_region', None)
    def test_sts_endpoint_with_no_sts_region_id_or_environment_sts_region_and_enable_vpc_false(self):
        """
        Test case 18: sts_region_id and environment_sts_region are not provided, and enable_vpc is False
        """
        provider = RamRoleArnCredentialsProvider(
            role_arn=self.role_arn,
            access_key_id=self.access_key_id,
            access_key_secret=self.access_key_secret,
            role_session_name=self.role_session_name,
            duration_seconds=self.duration_seconds,
            policy=self.policy,
            enable_vpc=False,
            http_options=self.http_options
        )

        self.assertEqual(provider._sts_endpoint, 'sts.aliyuncs.com')

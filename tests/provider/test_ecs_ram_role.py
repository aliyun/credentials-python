import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import calendar
import time
import json
from alibabacloud_credentials.provider.ecs_ram_role import (
    EcsRamRoleCredentialsProvider,
    CredentialException
)
from alibabacloud_credentials.http import HttpOptions
from Tea.core import TeaResponse


class TestEcsRamRoleCredentialsProvider(unittest.TestCase):

    def setUp(self):
        self.role_name = "test_role_name"
        self.disable_imds_v1 = False
        self.http_options = HttpOptions(connect_timeout=5000, read_timeout=10000, proxy="test_proxy")
        self.metadata_service_host = '100.100.100.200'
        self.metadata_token_duration = 21600
        self.metadata_token = "test_metadata_token"
        self.access_key_id = "test_access_key_id"
        self.access_key_secret = "test_access_key_secret"
        self.security_token = "test_security_token"
        self.expiration = "2023-12-31T23:59:59Z"
        self.response_body = json.dumps({
            "Code": "Success",
            "AccessKeyId": self.access_key_id,
            "AccessKeySecret": self.access_key_secret,
            "SecurityToken": self.security_token,
            "Expiration": self.expiration
        })
        self.response = TeaResponse()
        self.response.status_code = 200
        self.response.body = self.response_body.encode('utf-8')

    def test_init_valid_input(self):
        """
        Test case 1: Valid input, successfully initializes with provided parameters
        """
        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'false'):
            provider = EcsRamRoleCredentialsProvider(
                role_name=self.role_name,
                disable_imds_v1=self.disable_imds_v1,
                http_options=self.http_options,
                async_update_enabled=False
            )

            self.assertEqual(provider._role_name, self.role_name)
            self.assertEqual(provider._disable_imds_v1, self.disable_imds_v1)
            self.assertEqual(provider._http_options, self.http_options)
            self.assertEqual(provider._runtime_options['connectTimeout'], self.http_options.connect_timeout)
            self.assertEqual(provider._runtime_options['readTimeout'], self.http_options.read_timeout)
            self.assertEqual(provider._runtime_options['httpProxy'], self.http_options.proxy)

    def test_init_missing_role_name(self):
        """
        Test case 2: Missing role_name raises ValueError
        """
        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'true'):
            with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata', ''):
                with self.assertRaises(ValueError) as context:
                    EcsRamRoleCredentialsProvider(
                        disable_imds_v1=self.disable_imds_v1,
                        http_options=self.http_options
                    )

            self.assertIn("IMDS credentials is disabled", str(context.exception))

    def test_init_disable_metadata(self):
        """
        Test case 4: Disable metadata
        """
        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'true'):
            with self.assertRaises(ValueError) as context:
                EcsRamRoleCredentialsProvider(
                    role_name=self.role_name,
                    disable_imds_v1=True,
                    http_options=self.http_options
                )

            self.assertIn("IMDS credentials is disabled", str(context.exception))

    def test_get_credentials_valid_input(self):
        """
        Test case 5: Valid input, successfully retrieves credentials
        """
        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'false'):
            with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata', self.role_name):
                with patch(
                        'alibabacloud_credentials.provider.ecs_ram_role.EcsRamRoleCredentialsProvider._get_metadata_token',
                        return_value=self.metadata_token):
                    with patch('Tea.core.TeaCore.do_action', return_value=self.response):
                        provider = EcsRamRoleCredentialsProvider(
                            role_name=self.role_name,
                            disable_imds_v1=self.disable_imds_v1,
                            http_options=self.http_options
                        )

                        credentials = provider._refresh_credentials()

                        self.assertEqual(credentials.value().get_access_key_id(), self.access_key_id)
                        self.assertEqual(credentials.value().get_access_key_secret(), self.access_key_secret)
                        self.assertEqual(credentials.value().get_security_token(), self.security_token)
                        self.assertEqual(credentials.value().get_expiration(),
                                         calendar.timegm(time.strptime(self.expiration, '%Y-%m-%dT%H:%M:%SZ')))
                        self.assertEqual(credentials.value().get_provider_name(), "ecs_ram_role")

                        with self.assertRaises(CredentialException) as context:
                            provider.get_credentials()

                        self.assertIn("No cached value was found.", str(context.exception))

    def test_get_credentials_http_request_error(self):
        """
        Test case 6: HTTP request error raises CredentialException
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'false'):
            with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata', self.role_name):
                with patch(
                        'alibabacloud_credentials.provider.ecs_ram_role.EcsRamRoleCredentialsProvider._get_metadata_token',
                        return_value=self.metadata_token):
                    with patch('Tea.core.TeaCore.do_action', return_value=response):
                        provider = EcsRamRoleCredentialsProvider(
                            role_name=self.role_name,
                            disable_imds_v1=self.disable_imds_v1,
                            http_options=self.http_options
                        )

                        with self.assertRaises(CredentialException) as context:
                            provider.get_credentials()

                        self.assertIn(
                            "Failed to get RAM session credentials from ECS metadata service. HttpCode=400",
                            str(context.exception))

    def test_get_credentials_response_format_error(self):
        """
        Test case 7: Response format error raises CredentialException
        """
        response_body = json.dumps({
            "Code": "Failure",
            "Message": "Invalid request"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'false'):
            with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata', self.role_name):
                with patch(
                        'alibabacloud_credentials.provider.ecs_ram_role.EcsRamRoleCredentialsProvider._get_metadata_token',
                        return_value=self.metadata_token):
                    with patch('Tea.core.TeaCore.do_action', return_value=response):
                        provider = EcsRamRoleCredentialsProvider(
                            role_name=self.role_name,
                            disable_imds_v1=self.disable_imds_v1,
                            http_options=self.http_options
                        )

                        with self.assertRaises(CredentialException) as context:
                            provider.get_credentials()

                        self.assertIn('Failed to get RAM session credentials from ECS metadata service.',
                                      str(context.exception))

    def test_get_credentials_async_valid_input(self):
        """
        Test case 8: Valid input, successfully retrieves credentials asynchronously
        """
        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'false'):
            with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata', self.role_name):
                with patch(
                        'alibabacloud_credentials.provider.ecs_ram_role.EcsRamRoleCredentialsProvider._get_metadata_token_async',
                        AsyncMock(return_value=self.metadata_token)):
                    with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=self.response)):
                        provider = EcsRamRoleCredentialsProvider(
                            role_name=self.role_name,
                            disable_imds_v1=self.disable_imds_v1,
                            http_options=self.http_options
                        )

                        loop = asyncio.get_event_loop()
                        task = asyncio.ensure_future(
                            provider._refresh_credentials_async()
                        )
                        loop.run_until_complete(task)
                        credentials = task.result()

                        self.assertEqual(credentials.value().get_access_key_id(), self.access_key_id)
                        self.assertEqual(credentials.value().get_access_key_secret(), self.access_key_secret)
                        self.assertEqual(credentials.value().get_security_token(), self.security_token)
                        self.assertEqual(credentials.value().get_expiration(),
                                         calendar.timegm(time.strptime(self.expiration, '%Y-%m-%dT%H:%M:%SZ')))
                        self.assertEqual(credentials.value().get_provider_name(), "ecs_ram_role")

                        with self.assertRaises(CredentialException) as context:
                            loop = asyncio.get_event_loop()
                            task = asyncio.ensure_future(
                                provider.get_credentials_async()
                            )
                            loop.run_until_complete(task)

                        self.assertIn("No cached value was found.", str(context.exception))

    def test_get_credentials_async_http_request_error(self):
        """
        Test case 9: HTTP request error raises CredentialException asynchronously
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'false'):
            with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata', self.role_name):
                with patch(
                        'alibabacloud_credentials.provider.ecs_ram_role.EcsRamRoleCredentialsProvider._get_metadata_token_async',
                        AsyncMock(return_value=self.metadata_token)):
                    with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
                        provider = EcsRamRoleCredentialsProvider(
                            role_name=self.role_name,
                            disable_imds_v1=self.disable_imds_v1,
                            http_options=self.http_options
                        )

                        with self.assertRaises(CredentialException) as context:
                            loop = asyncio.get_event_loop()
                            task = asyncio.ensure_future(
                                provider.get_credentials_async()
                            )
                            loop.run_until_complete(task)

                        self.assertIn(
                            "Failed to get RAM session credentials from ECS metadata service. HttpCode=400",
                            str(context.exception))

    def test_get_credentials_async_response_format_error(self):
        """
        Test case 10: Response format error raises CredentialException asynchronously
        """
        response_body = json.dumps({
            "Code": "Failure",
            "Message": "Invalid request"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'false'):
            with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata', self.role_name):
                with patch(
                        'alibabacloud_credentials.provider.ecs_ram_role.EcsRamRoleCredentialsProvider._get_metadata_token_async',
                        AsyncMock(return_value=self.metadata_token)):
                    with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
                        provider = EcsRamRoleCredentialsProvider(
                            role_name=self.role_name,
                            disable_imds_v1=self.disable_imds_v1,
                            http_options=self.http_options
                        )

                        with self.assertRaises(CredentialException) as context:
                            loop = asyncio.get_event_loop()
                            task = asyncio.ensure_future(
                                provider.get_credentials_async()
                            )
                            loop.run_until_complete(task)

                        self.assertIn('Failed to get RAM session credentials from ECS metadata service.',
                                      str(context.exception))

    def test_get_metadata_token_valid_input(self):
        """
        Test case 11: Valid input, successfully retrieves metadata token
        """
        response_body = self.metadata_token
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_imds_v1_disabled', 'true'):
            with patch('Tea.core.TeaCore.do_action', return_value=response):
                provider = EcsRamRoleCredentialsProvider(
                    role_name=self.role_name,
                    http_options=self.http_options
                )

                metadata_token = provider._get_metadata_token()

                self.assertEqual(metadata_token, self.metadata_token)

    def test_get_metadata_token_http_request_error(self):
        """
        Test case 12: HTTP request error raises CredentialException
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_imds_v1_disabled', 'true'):
            with patch('Tea.core.TeaCore.do_action', return_value=response):
                provider = EcsRamRoleCredentialsProvider(
                    role_name=self.role_name,
                    http_options=self.http_options
                )

                with self.assertRaises(CredentialException) as context:
                    provider._get_metadata_token()

                self.assertIn(
                    "Failed to get token from ECS Metadata Service. HttpCode=400",
                    str(context.exception))

    def test_get_metadata_token_async_valid_input(self):
        """
        Test case 13: Valid input, successfully retrieves metadata token asynchronously
        """
        response_body = self.metadata_token
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_imds_v1_disabled', 'true'):
            with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
                provider = EcsRamRoleCredentialsProvider(
                    role_name=self.role_name,
                    http_options=self.http_options
                )

                loop = asyncio.get_event_loop()
                task = asyncio.ensure_future(
                    provider._get_metadata_token_async()
                )
                loop.run_until_complete(task)
                metadata_token = task.result()

                self.assertEqual(metadata_token, self.metadata_token)

    def test_get_metadata_token_async_http_request_error(self):
        """
        Test case 14: HTTP request error raises CredentialException asynchronously
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_imds_v1_disabled', 'true'):
            with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
                provider = EcsRamRoleCredentialsProvider(
                    role_name=self.role_name,
                    http_options=self.http_options
                )

                with self.assertRaises(CredentialException) as context:
                    loop = asyncio.get_event_loop()
                    task = asyncio.ensure_future(
                        provider._get_metadata_token_async()
                    )
                    loop.run_until_complete(task)

                self.assertIn(
                    "Failed to get token from ECS Metadata Service. HttpCode=400",
                    str(context.exception))

    def test_get_role_name_valid_input(self):
        """
        Test case 15: Valid input, successfully retrieves role name
        """
        response_body = self.role_name
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'false'):
            with patch('Tea.core.TeaCore.do_action', return_value=response):
                provider = EcsRamRoleCredentialsProvider(
                    role_name=self.role_name,
                    disable_imds_v1=self.disable_imds_v1,
                    http_options=self.http_options
                )

                role_name = provider._get_role_name()

                self.assertEqual(role_name, self.role_name)

    def test_get_role_name_http_request_error(self):
        """
        Test case 16: HTTP request error raises CredentialException
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'false'):
            with patch('Tea.core.TeaCore.do_action', return_value=response):
                provider = EcsRamRoleCredentialsProvider(
                    role_name=self.role_name,
                    disable_imds_v1=self.disable_imds_v1,
                    http_options=self.http_options
                )

                with self.assertRaises(CredentialException) as context:
                    provider._get_role_name()

                self.assertIn(
                    "Failed to get RAM session credentials from ECS metadata service. HttpCode=400",
                    str(context.exception))

    def test_get_role_name_async_valid_input(self):
        """
        Test case 17: Valid input, successfully retrieves role name asynchronously
        """
        response_body = self.role_name
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'false'):
            with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
                provider = EcsRamRoleCredentialsProvider(
                    role_name=self.role_name,
                    disable_imds_v1=self.disable_imds_v1,
                    http_options=self.http_options
                )

                loop = asyncio.get_event_loop()
                task = asyncio.ensure_future(
                    provider._get_role_name_async()
                )
                loop.run_until_complete(task)
                role_name = task.result()

                self.assertEqual(role_name, self.role_name)

    def test_get_role_name_async_http_request_error(self):
        """
        Test case 18: HTTP request error raises CredentialException asynchronously
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('alibabacloud_credentials.provider.ecs_ram_role.au.environment_ecs_metadata_disabled', 'false'):
            with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
                provider = EcsRamRoleCredentialsProvider(
                    role_name=self.role_name,
                    disable_imds_v1=self.disable_imds_v1,
                    http_options=self.http_options
                )

                with self.assertRaises(CredentialException) as context:
                    loop = asyncio.get_event_loop()
                    task = asyncio.ensure_future(
                        provider._get_role_name_async()
                    )
                    loop.run_until_complete(task)

                self.assertIn(
                    "Failed to get RAM session credentials from ECS metadata service. HttpCode=400",
                    str(context.exception))

    def test_ecs_ram_role_provider_methods(self):
        provider = EcsRamRoleCredentialsProvider()

        # Test _get_stale_time
        stale_time = provider._get_stale_time(1000)
        self.assertEqual(stale_time, 1000 - 15 * 60)

        stale_time = provider._get_stale_time(-1)
        current_time = int(time.mktime(time.localtime()))
        self.assertAlmostEqual(stale_time, current_time + 60 * 60, delta=1)

        # Test _get_prefetch_time
        prefetch_time = provider._get_prefetch_time(1000)
        current_time = int(time.mktime(time.localtime()))
        self.assertAlmostEqual(prefetch_time, current_time + 60 * 60, delta=1)

        prefetch_time = provider._get_prefetch_time(-1)
        current_time = int(time.mktime(time.localtime()))
        self.assertAlmostEqual(prefetch_time, current_time + 5 * 60, delta=1)

        # Test get_provider_name
        provider_name = provider.get_provider_name()
        self.assertEqual(provider_name, 'ecs_ram_role')

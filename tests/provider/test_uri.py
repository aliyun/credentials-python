import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import calendar
import time
import json
from alibabacloud_credentials.provider.uri import (
    URLCredentialsProvider,
    CredentialException
)
from alibabacloud_credentials.http import HttpOptions
from Tea.core import TeaResponse


class TestURLCredentialsProvider(unittest.TestCase):

    def setUp(self):
        self.uri = "http://example.com/credentials"
        self.protocol = "http"
        self.http_options = HttpOptions(connect_timeout=5000, read_timeout=10000, proxy="test_proxy")
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
        provider = URLCredentialsProvider(
            uri=self.uri,
            protocol=self.protocol,
            http_options=self.http_options
        )

        self.assertEqual(provider._uri, self.uri)
        self.assertEqual(provider._protocol, self.protocol)
        self.assertEqual(provider._http_options, self.http_options)
        self.assertEqual(provider._runtime_options['connectTimeout'], self.http_options.connect_timeout)
        self.assertEqual(provider._runtime_options['readTimeout'], self.http_options.read_timeout)
        self.assertEqual(provider._runtime_options['httpsProxy'], self.http_options.proxy)

    def test_init_missing_uri(self):
        """
        Test case 2: Missing uri raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            URLCredentialsProvider(
                protocol=self.protocol,
                http_options=self.http_options
            )

        self.assertIn("uri or environment variable ALIBABA_CLOUD_CREDENTIALS_URI cannot be empty",
                      str(context.exception))

    def test_init_empty_uri(self):
        """
        Test case 3: Empty uri raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            URLCredentialsProvider(
                uri="",
                protocol=self.protocol,
                http_options=self.http_options
            )

        self.assertIn("uri or environment variable ALIBABA_CLOUD_CREDENTIALS_URI cannot be empty",
                      str(context.exception))

    @patch('alibabacloud_credentials.provider.uri.au.environment_credentials_uri', "http://example.com/credentials")
    def test_init_valid_environment_variables(self):
        """
        Test case 4: Valid input, successfully initializes with environment variables
        """
        provider = URLCredentialsProvider()

        self.assertEqual(provider._uri, "http://example.com/credentials")
        self.assertEqual(provider._protocol, "http")
        self.assertEqual(provider._runtime_options['connectTimeout'], URLCredentialsProvider.DEFAULT_CONNECT_TIMEOUT)
        self.assertEqual(provider._runtime_options['readTimeout'], URLCredentialsProvider.DEFAULT_READ_TIMEOUT)
        self.assertIsNone(provider._runtime_options['httpsProxy'])

    def test_get_credentials_valid_input(self):
        """
        Test case 5: Valid input, successfully retrieves credentials
        """
        with patch('Tea.core.TeaCore.do_action', return_value=self.response):
            provider = URLCredentialsProvider(
                uri=self.uri,
                protocol=self.protocol,
                http_options=self.http_options
            )

            credentials = provider._refresh_credentials()

            self.assertEqual(credentials.value().get_access_key_id(), self.access_key_id)
            self.assertEqual(credentials.value().get_access_key_secret(), self.access_key_secret)
            self.assertEqual(credentials.value().get_security_token(), self.security_token)
            self.assertEqual(credentials.value().get_expiration(),
                             calendar.timegm(time.strptime(self.expiration, '%Y-%m-%dT%H:%M:%SZ')))
            self.assertEqual(credentials.value().get_provider_name(), "credential_uri")

    def test_get_credentials_http_request_error(self):
        """
        Test case 6: HTTP request error raises CredentialException
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            provider = URLCredentialsProvider(
                uri=self.uri,
                protocol=self.protocol,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn(
                f'error refreshing credentials from {self.uri},  http_code=400, result: HTTP request failed',
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

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            provider = URLCredentialsProvider(
                uri=self.uri,
                protocol=self.protocol,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn(f'error retrieving credentials from {self.uri} result: {response_body}',
                          str(context.exception))

    def test_get_credentials_async_valid_input(self):
        """
        Test case 8: Valid input, successfully retrieves credentials asynchronously
        """
        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=self.response)):
            provider = URLCredentialsProvider(
                uri=self.uri,
                protocol=self.protocol,
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
            self.assertEqual(credentials.value().get_provider_name(), "credential_uri")

    def test_get_credentials_async_http_request_error(self):
        """
        Test case 9: HTTP request error raises CredentialException asynchronously
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
            provider = URLCredentialsProvider(
                uri=self.uri,
                protocol=self.protocol,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                loop = asyncio.get_event_loop()
                task = asyncio.ensure_future(
                    provider.get_credentials_async()
                )
                loop.run_until_complete(task)

            self.assertIn(
                f'error refreshing credentials from {self.uri},  http_code=400, result: HTTP request failed',
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

        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
            provider = URLCredentialsProvider(
                uri=self.uri,
                protocol=self.protocol,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                loop = asyncio.get_event_loop()
                task = asyncio.ensure_future(
                    provider.get_credentials_async()
                )
                loop.run_until_complete(task)

            self.assertIn(f'error retrieving credentials from {self.uri} result: {response_body}',
                          str(context.exception))

    def test_get_credentials_missing_access_key_id(self):
        """
        Test case 11: Missing AccessKeyId in response raises CredentialException
        """
        response_body = json.dumps({
            "Code": "Success",
            "AccessKeySecret": self.access_key_secret,
            "SecurityToken": self.security_token,
            "Expiration": self.expiration
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            provider = URLCredentialsProvider(
                uri=self.uri,
                protocol=self.protocol,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn(f'error retrieving credentials from {self.uri} result: {response_body}',
                          str(context.exception))

    def test_get_credentials_missing_access_key_secret(self):
        """
        Test case 12: Missing AccessKeySecret in response raises CredentialException
        """
        response_body = json.dumps({
            "Code": "Success",
            "AccessKeyId": self.access_key_id,
            "SecurityToken": self.security_token,
            "Expiration": self.expiration
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            provider = URLCredentialsProvider(
                uri=self.uri,
                protocol=self.protocol,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn(f'error retrieving credentials from {self.uri} result: {response_body}',
                          str(context.exception))

    def test_get_credentials_missing_security_token(self):
        """
        Test case 13: Missing SecurityToken in response raises CredentialException
        """
        response_body = json.dumps({
            "Code": "Success",
            "AccessKeyId": self.access_key_id,
            "AccessKeySecret": self.access_key_secret,
            "Expiration": self.expiration
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            provider = URLCredentialsProvider(
                uri=self.uri,
                protocol=self.protocol,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn(f'error retrieving credentials from {self.uri} result: {response_body}',
                          str(context.exception))

    def test_get_credentials_missing_expiration(self):
        """
        Test case 14: Missing Expiration in response raises CredentialException
        """
        response_body = json.dumps({
            "Code": "Success",
            "AccessKeyId": self.access_key_id,
            "AccessKeySecret": self.access_key_secret,
            "SecurityToken": self.security_token
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            provider = URLCredentialsProvider(
                uri=self.uri,
                protocol=self.protocol,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn(f'error retrieving credentials from {self.uri} result: {response_body}',
                          str(context.exception))

    def test_get_credentials_invalid_code(self):
        """
        Test case 15: Invalid Code in response raises CredentialException
        """
        response_body = json.dumps({
            "Code": "Failure",
            "AccessKeyId": self.access_key_id,
            "AccessKeySecret": self.access_key_secret,
            "SecurityToken": self.security_token,
            "Expiration": self.expiration
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            provider = URLCredentialsProvider(
                uri=self.uri,
                protocol=self.protocol,
                http_options=self.http_options
            )

            with self.assertRaises(CredentialException) as context:
                provider.get_credentials()

            self.assertIn(f'error retrieving credentials from {self.uri} result: {response_body}',
                          str(context.exception))

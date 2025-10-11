import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import json
import time
import calendar
from alibabacloud_credentials.provider.cloud_sso import CloudSSOCredentialsProvider, _get_stale_time
from alibabacloud_credentials.exceptions import CredentialException
from alibabacloud_credentials.http import HttpOptions


class TestCloudSSOCredentialsProvider(unittest.TestCase):

    def setUp(self):
        self.sign_in_url = "https://sso.example.com"
        self.account_id = "test_account_id"
        self.access_config = "test_access_config"
        self.access_token = "test_access_token"
        self.access_token_expire = int(time.mktime(time.localtime())) + 3600  # 1 hour from now
        self.http_options = HttpOptions(connect_timeout=5000, read_timeout=10000)
        
        self.access_key_id = "test_access_key_id"
        self.access_key_secret = "test_access_key_secret"
        self.security_token = "test_security_token"
        self.expiration = "2030-12-31T23:59:59Z"
        
        # Mock response data
        self.response_data = {
            "CloudCredential": {
                "AccessKeyId": self.access_key_id,
                "AccessKeySecret": self.access_key_secret,
                "SecurityToken": self.security_token,
                "Expiration": self.expiration
            }
        }
        
        # Mock Tea response
        self.mock_response = MagicMock()
        self.mock_response.status_code = 200
        self.mock_response.body = json.dumps(self.response_data).encode('utf-8')

    def test_init_valid_input(self):
        """
        Test case 1: Valid input, successfully initializes with provided parameters
        """
        provider = CloudSSOCredentialsProvider(
            sign_in_url=self.sign_in_url,
            account_id=self.account_id,
            access_config=self.access_config,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire,
            http_options=self.http_options
        )

        self.assertEqual(provider._sign_in_url, self.sign_in_url)
        self.assertEqual(provider._account_id, self.account_id)
        self.assertEqual(provider._access_config, self.access_config)
        self.assertEqual(provider._access_token, self.access_token)
        self.assertEqual(provider._access_token_expire, self.access_token_expire)
        self.assertEqual(provider._http_options, self.http_options)

    def test_init_missing_sign_in_url(self):
        """
        Test case 2: Missing sign_in_url raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            CloudSSOCredentialsProvider(
                account_id=self.account_id,
                access_config=self.access_config,
                access_token=self.access_token,
                access_token_expire=self.access_token_expire
            )

        self.assertIn("CloudSSO sign in url or account id or access config is empty", str(context.exception))

    def test_init_missing_account_id(self):
        """
        Test case 3: Missing account_id raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            CloudSSOCredentialsProvider(
                sign_in_url=self.sign_in_url,
                access_config=self.access_config,
                access_token=self.access_token,
                access_token_expire=self.access_token_expire
            )

        self.assertIn("CloudSSO sign in url or account id or access config is empty", str(context.exception))

    def test_init_missing_access_config(self):
        """
        Test case 4: Missing access_config raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            CloudSSOCredentialsProvider(
                sign_in_url=self.sign_in_url,
                account_id=self.account_id,
                access_token=self.access_token,
                access_token_expire=self.access_token_expire
            )

        self.assertIn("CloudSSO sign in url or account id or access config is empty", str(context.exception))

    def test_init_missing_access_token(self):
        """
        Test case 5: Missing access_token raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            CloudSSOCredentialsProvider(
                sign_in_url=self.sign_in_url,
                account_id=self.account_id,
                access_config=self.access_config,
                access_token_expire=self.access_token_expire
            )

        self.assertIn("CloudSSO access token is empty or expired, please re-login with cli", str(context.exception))

    def test_init_expired_access_token(self):
        """
        Test case 6: Expired access_token raises ValueError
        """
        expired_time = int(time.mktime(time.localtime())) - 3600  # 1 hour ago
        
        with self.assertRaises(ValueError) as context:
            CloudSSOCredentialsProvider(
                sign_in_url=self.sign_in_url,
                account_id=self.account_id,
                access_config=self.access_config,
                access_token=self.access_token,
                access_token_expire=expired_time
            )

        self.assertIn("CloudSSO access token is empty or expired, please re-login with cli", str(context.exception))

    def test_init_zero_access_token_expire(self):
        """
        Test case 7: Zero access_token_expire raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            CloudSSOCredentialsProvider(
                sign_in_url=self.sign_in_url,
                account_id=self.account_id,
                access_config=self.access_config,
                access_token=self.access_token,
                access_token_expire=0
            )

        self.assertIn("CloudSSO access token is empty or expired, please re-login with cli", str(context.exception))

    def test_init_default_http_options(self):
        """
        Test case 8: Initializes with default http_options when not provided
        """
        provider = CloudSSOCredentialsProvider(
            sign_in_url=self.sign_in_url,
            account_id=self.account_id,
            access_config=self.access_config,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        self.assertIsInstance(provider._http_options, HttpOptions)
        self.assertEqual(provider._runtime_options['connectTimeout'], CloudSSOCredentialsProvider.DEFAULT_CONNECT_TIMEOUT)
        self.assertEqual(provider._runtime_options['readTimeout'], CloudSSOCredentialsProvider.DEFAULT_READ_TIMEOUT)

    @patch('alibabacloud_credentials.provider.cloud_sso.TeaCore.do_action')
    def test_get_credentials_success(self, mock_do_action):
        """
        Test case 9: Valid input, successfully retrieves credentials
        """
        mock_do_action.return_value = self.mock_response
        
        provider = CloudSSOCredentialsProvider(
            sign_in_url=self.sign_in_url,
            account_id=self.account_id,
            access_config=self.access_config,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        credentials = provider.get_credentials()

        self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
        self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
        self.assertEqual(credentials.get_security_token(), self.security_token)
        self.assertEqual(credentials.get_provider_name(), "cloud_sso")
        
        # Verify the request was made correctly
        mock_do_action.assert_called_once()
        call_args = mock_do_action.call_args
        tea_request = call_args[0][0]
        
        self.assertEqual(tea_request.method, 'POST')
        self.assertEqual(tea_request.pathname, '/cloud-credentials')
        self.assertEqual(tea_request.headers['Authorization'], f'Bearer {self.access_token}')
        self.assertEqual(tea_request.headers['Content-Type'], 'application/json')
        
        request_body = json.loads(tea_request.body)
        self.assertEqual(request_body['AccountId'], self.account_id)
        self.assertEqual(request_body['AccessConfigurationId'], self.access_config)

    @patch('alibabacloud_credentials.provider.cloud_sso.TeaCore.async_do_action')
    def test_get_credentials_async_success(self, mock_async_do_action):
        """
        Test case 10: Valid input, successfully retrieves credentials asynchronously
        """
        mock_async_do_action.return_value = self.mock_response
        
        provider = CloudSSOCredentialsProvider(
            sign_in_url=self.sign_in_url,
            account_id=self.account_id,
            access_config=self.access_config,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        async def run_test():
            credentials = await provider.get_credentials_async()
            return credentials

        loop = asyncio.get_event_loop()
        credentials = loop.run_until_complete(run_test())

        self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
        self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
        self.assertEqual(credentials.get_security_token(), self.security_token)
        self.assertEqual(credentials.get_provider_name(), "cloud_sso")

    @patch('alibabacloud_credentials.provider.cloud_sso.TeaCore.do_action')
    def test_get_credentials_http_error(self, mock_do_action):
        """
        Test case 11: HTTP error response raises CredentialException
        """
        error_response = MagicMock()
        error_response.status_code = 400
        error_response.body = b'{"error": "Bad Request"}'
        mock_do_action.return_value = error_response
        
        provider = CloudSSOCredentialsProvider(
            sign_in_url=self.sign_in_url,
            account_id=self.account_id,
            access_config=self.access_config,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()

        self.assertIn("error refreshing credentials from sso, http_code: 400", str(context.exception))

    @patch('alibabacloud_credentials.provider.cloud_sso.TeaCore.do_action')
    def test_get_credentials_missing_cloud_credential(self, mock_do_action):
        """
        Test case 12: Missing CloudCredential in response raises CredentialException
        """
        invalid_response = MagicMock()
        invalid_response.status_code = 200
        invalid_response.body = json.dumps({"error": "No credentials"}).encode('utf-8')
        mock_do_action.return_value = invalid_response
        
        provider = CloudSSOCredentialsProvider(
            sign_in_url=self.sign_in_url,
            account_id=self.account_id,
            access_config=self.access_config,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()

        self.assertIn("error retrieving credentials from sso result", str(context.exception))

    @patch('alibabacloud_credentials.provider.cloud_sso.TeaCore.do_action')
    def test_get_credentials_missing_required_fields(self, mock_do_action):
        """
        Test case 13: Missing required fields in CloudCredential raises CredentialException
        """
        incomplete_response = MagicMock()
        incomplete_response.status_code = 200
        incomplete_response.body = json.dumps({
            "CloudCredential": {
                "AccessKeyId": self.access_key_id,
                # Missing AccessKeySecret and SecurityToken
            }
        }).encode('utf-8')
        mock_do_action.return_value = incomplete_response
        
        provider = CloudSSOCredentialsProvider(
            sign_in_url=self.sign_in_url,
            account_id=self.account_id,
            access_config=self.access_config,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()

        self.assertIn("error retrieving credentials from sso result", str(context.exception))

    @patch('alibabacloud_credentials.provider.cloud_sso.TeaCore.do_action')
    def test_get_credentials_invalid_json(self, mock_do_action):
        """
        Test case 14: Invalid JSON response raises JSONDecodeError
        """
        invalid_json_response = MagicMock()
        invalid_json_response.status_code = 200
        invalid_json_response.body = b'invalid json'
        mock_do_action.return_value = invalid_json_response
        
        provider = CloudSSOCredentialsProvider(
            sign_in_url=self.sign_in_url,
            account_id=self.account_id,
            access_config=self.access_config,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        with self.assertRaises(json.JSONDecodeError):
            provider.get_credentials()

    def test_get_provider_name(self):
        """
        Test case 15: Returns correct provider name
        """
        provider = CloudSSOCredentialsProvider(
            sign_in_url=self.sign_in_url,
            account_id=self.account_id,
            access_config=self.access_config,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        self.assertEqual(provider.get_provider_name(), "cloud_sso")

    def test_get_stale_time_positive_expiration(self):
        """
        Test case 16: _get_stale_time with positive expiration returns expiration - 15 minutes
        """
        expiration = 1672531199  # 2023-01-01 00:00:00 UTC
        expected_stale_time = expiration - 15 * 60  # 15 minutes before
        
        stale_time = _get_stale_time(expiration)
        
        self.assertEqual(stale_time, expected_stale_time)

    def test_get_stale_time_negative_expiration(self):
        """
        Test case 17: _get_stale_time with negative expiration returns current time + 1 hour
        """
        with patch('time.mktime') as mock_mktime:
            mock_mktime.return_value = 1672531199  # Mock current time
            
            stale_time = _get_stale_time(-1)
            
            expected_stale_time = 1672531199 + 60 * 60  # current time + 1 hour
            self.assertEqual(stale_time, expected_stale_time)

    @patch('alibabacloud_credentials.provider.cloud_sso.TeaCore.do_action')
    def test_credentials_caching(self, mock_do_action):
        """
        Test case 18: Credentials are cached and not refreshed on subsequent calls
        """
        mock_do_action.return_value = self.mock_response
        
        provider = CloudSSOCredentialsProvider(
            sign_in_url=self.sign_in_url,
            account_id=self.account_id,
            access_config=self.access_config,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        # First call
        credentials1 = provider.get_credentials()
        
        # Second call should use cached credentials
        credentials2 = provider.get_credentials()
        
        # Both should return the same credentials
        self.assertEqual(credentials1.get_access_key_id(), credentials2.get_access_key_id())
        self.assertEqual(credentials1.get_access_key_secret(), credentials2.get_access_key_secret())
        self.assertEqual(credentials1.get_security_token(), credentials2.get_security_token())
        
        # But TeaCore.do_action should only be called once due to caching
        self.assertEqual(mock_do_action.call_count, 1)

    @patch('alibabacloud_credentials.provider.cloud_sso.TeaCore.do_action')
    def test_url_parsing(self, mock_do_action):
        """
        Test case 19: URL parsing works correctly for different URL formats
        """
        mock_do_action.return_value = self.mock_response
        
        # Test with different URL formats
        test_urls = [
            "https://sso.example.com",
            "https://sso.example.com:8080",
            "http://sso.example.com"
        ]
        
        for url in test_urls:
            provider = CloudSSOCredentialsProvider(
                sign_in_url=url,
                account_id=self.account_id,
                access_config=self.access_config,
                access_token=self.access_token,
                access_token_expire=self.access_token_expire
            )
            
            credentials = provider.get_credentials()
            self.assertIsNotNone(credentials)
            
            # Verify the request was made with correct host
            call_args = mock_do_action.call_args
            tea_request = call_args[0][0]
            
            if ":8080" in url:
                self.assertEqual(tea_request.port, 8080)
            else:
                self.assertEqual(tea_request.port, 80)

            if url.startswith("https"):
                self.assertEqual(tea_request.protocol, "https")
            else:
                self.assertEqual(tea_request.protocol, "http")

    @patch('alibabacloud_credentials.provider.cloud_sso.TeaCore.do_action')
    def test_expiration_time_parsing(self, mock_do_action):
        """
        Test case 20: Expiration time is correctly parsed from ISO format
        """
        mock_do_action.return_value = self.mock_response
        
        provider = CloudSSOCredentialsProvider(
            sign_in_url=self.sign_in_url,
            account_id=self.account_id,
            access_config=self.access_config,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        credentials = provider.get_credentials()
        
        # The expiration should be parsed correctly from "2023-12-31T23:59:59Z"
        expected_expiration = calendar.timegm(time.strptime(self.expiration, '%Y-%m-%dT%H:%M:%SZ'))
        self.assertEqual(credentials.get_expiration(), expected_expiration)

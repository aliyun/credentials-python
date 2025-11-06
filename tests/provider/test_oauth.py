import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import json
import time
import calendar
from alibabacloud_credentials.provider.oauth import OAuthCredentialsProvider, _get_stale_time
from alibabacloud_credentials.exceptions import CredentialException
from alibabacloud_credentials.http import HttpOptions


class TestOAuthCredentialsProvider(unittest.TestCase):

    def setUp(self):
        self.site_type = "CN"
        self.refresh_token = "test_refresh_token"
        self.access_token = "test_access_token"
        self.access_token_expire = int(time.mktime(time.localtime())) + 3600  # 1 hour from now
        self.http_options = HttpOptions(connect_timeout=5000, read_timeout=10000)

        self.access_key_id = "test_access_key_id"
        self.access_key_secret = "test_access_key_secret"
        self.security_token = "test_security_token"
        self.expiration = "2030-12-31T23:59:59Z"

        # Mock response data
        self.response_data = {
            "AccessKeyId": self.access_key_id,
            "AccessKeySecret": self.access_key_secret,
            "SecurityToken": self.security_token,
            "Expiration": self.expiration
        }

        # Mock Tea response
        self.mock_response = MagicMock()
        self.mock_response.status_code = 200
        self.mock_response.body = json.dumps(self.response_data).encode('utf-8')

    def test_init_valid_input_cn(self):
        """
        Test case 1: Valid input with CN client ID and sign-in URL, successfully initializes with provided parameters
        """
        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire,
            http_options=self.http_options
        )

        self.assertEqual(provider._client_id, "123")
        self.assertEqual(provider._sign_in_url, "https://oauth.aliyun.com")
        self.assertEqual(provider._access_token, self.access_token)
        self.assertEqual(provider._access_token_expire, self.access_token_expire)
        self.assertEqual(provider._http_options, self.http_options)

    def test_init_valid_input_intl(self):
        """
        Test case 2: Valid input with INTL client ID and sign-in URL, successfully initializes with provided parameters
        """
        provider = OAuthCredentialsProvider(
            client_id="456",
            sign_in_url="https://oauth.alibabacloud.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire,
            http_options=self.http_options
        )

        self.assertEqual(provider._client_id, "456")
        self.assertEqual(provider._sign_in_url, "https://oauth.alibabacloud.com")
        self.assertEqual(provider._access_token, self.access_token)
        self.assertEqual(provider._access_token_expire, self.access_token_expire)
        self.assertEqual(provider._http_options, self.http_options)

    def test_init_missing_client_id(self):
        """
        Test case 3: Missing client_id raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            OAuthCredentialsProvider(
                sign_in_url="https://oauth.aliyun.com",
                access_token=self.access_token,
                access_token_expire=self.access_token_expire
            )

        self.assertIn("the ClientId is empty", str(context.exception))

    def test_init_missing_sign_in_url(self):
        """
        Test case 4: Missing sign_in_url raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            OAuthCredentialsProvider(
                client_id="123",
                access_token=self.access_token,
                access_token_expire=self.access_token_expire
            )

        self.assertIn("the url for sign-in is empty", str(context.exception))

    def test_init_missing_access_token(self):
        """
        Test case 5: Missing access_token raises ValueError
        """
        with self.assertRaises(ValueError) as context:
            OAuthCredentialsProvider(
                client_id="123",
                sign_in_url="https://oauth.aliyun.com",
                access_token_expire=self.access_token_expire
            )

        self.assertIn("OAuth access token is empty or expired, please re-login with cli", str(context.exception))

    def test_init_missing_refresh_token(self):
        """
        Test case 6: Missing refresh_token raises ValueError
        """
        expired_time = int(time.mktime(time.localtime())) - 3600  # 1 hour ago

        with self.assertRaises(ValueError) as context:
            OAuthCredentialsProvider(
                client_id="123",
                sign_in_url="https://oauth.aliyun.com",
                access_token=self.access_token,
                access_token_expire=expired_time
            )

        self.assertIn("OAuth access token is empty or expired, please re-login with cli", str(context.exception))

    def test_init_default_http_options(self):
        """
        Test case 8: Initializes with default http_options when not provided
        """
        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        self.assertIsInstance(provider._http_options, HttpOptions)
        self.assertEqual(provider._runtime_options['connectTimeout'], OAuthCredentialsProvider.DEFAULT_CONNECT_TIMEOUT)
        self.assertEqual(provider._runtime_options['readTimeout'], OAuthCredentialsProvider.DEFAULT_READ_TIMEOUT)

    @patch('alibabacloud_credentials.provider.oauth.TeaCore.do_action')
    def test_get_credentials_success(self, mock_do_action):
        """
        Test case 9: Valid input, successfully retrieves credentials
        """
        mock_do_action.return_value = self.mock_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        credentials = provider.get_credentials()

        self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
        self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
        self.assertEqual(credentials.get_security_token(), self.security_token)
        self.assertEqual(credentials.get_provider_name(), "oauth")

        # Verify the request was made correctly
        mock_do_action.assert_called_once()
        call_args = mock_do_action.call_args
        tea_request = call_args[0][0]

        self.assertEqual(tea_request.method, 'POST')
        self.assertEqual(tea_request.pathname, '/v1/exchange')
        self.assertEqual(tea_request.headers['Authorization'], f'Bearer {self.access_token}')
        self.assertEqual(tea_request.headers['Content-Type'], 'application/json')

    @patch('alibabacloud_credentials.provider.oauth.TeaCore.async_do_action')
    def test_get_credentials_async_success(self, mock_async_do_action):
        """
        Test case 10: Valid input, successfully retrieves credentials asynchronously
        """
        mock_async_do_action.return_value = self.mock_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        async def run_test():
            credentials = await provider.get_credentials_async()
            return credentials

        # 使用 asyncio.run() 替代 get_event_loop()
        credentials = asyncio.run(run_test())

        self.assertEqual(credentials.get_access_key_id(), self.access_key_id)
        self.assertEqual(credentials.get_access_key_secret(), self.access_key_secret)
        self.assertEqual(credentials.get_security_token(), self.security_token)
        self.assertEqual(credentials.get_provider_name(), "oauth")

    @patch('alibabacloud_credentials.provider.oauth.TeaCore.do_action')
    def test_get_credentials_http_error(self, mock_do_action):
        """
        Test case 11: HTTP error response raises CredentialException
        """
        error_response = MagicMock()
        error_response.status_code = 400
        error_response.body = b'{"error": "Bad Request"}'
        mock_do_action.return_value = error_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()

        self.assertIn("error refreshing credentials from OAuth, http_code: 400", str(context.exception))

    @patch('alibabacloud_credentials.provider.oauth.TeaCore.do_action')
    def test_get_credentials_error_in_response(self, mock_do_action):
        """
        Test case 12: Error field in response raises CredentialException
        """
        error_response = MagicMock()
        error_response.status_code = 200
        error_response.body = json.dumps({"error": "Invalid token"}).encode('utf-8')
        mock_do_action.return_value = error_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()

        self.assertIn("error retrieving credentials from OAuth result", str(context.exception))

    @patch('alibabacloud_credentials.provider.oauth.TeaCore.do_action')
    def test_get_credentials_missing_required_fields(self, mock_do_action):
        """
        Test case 13: Missing required fields in response raises CredentialException
        """
        incomplete_response = MagicMock()
        incomplete_response.status_code = 200
        incomplete_response.body = json.dumps({
            "AccessKeyId": self.access_key_id,
            # Missing AccessKeySecret and SecurityToken
        }).encode('utf-8')
        mock_do_action.return_value = incomplete_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()

        self.assertIn("error retrieving credentials from OAuth result", str(context.exception))

    @patch('alibabacloud_credentials.provider.oauth.TeaCore.do_action')
    def test_get_credentials_invalid_json(self, mock_do_action):
        """
        Test case 14: Invalid JSON response raises JSONDecodeError
        """
        invalid_json_response = MagicMock()
        invalid_json_response.status_code = 200
        invalid_json_response.body = b'invalid json'
        mock_do_action.return_value = invalid_json_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        with self.assertRaises(json.JSONDecodeError):
            provider.get_credentials()

    def test_get_provider_name(self):
        """
        Test case 15: Returns correct provider name
        """
        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        self.assertEqual(provider.get_provider_name(), "oauth")

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

    @patch('alibabacloud_credentials.provider.oauth.TeaCore.do_action')
    def test_credentials_caching(self, mock_do_action):
        """
        Test case 18: Credentials are cached and not refreshed on subsequent calls
        """
        mock_do_action.return_value = self.mock_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
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

    @patch('alibabacloud_credentials.provider.oauth.TeaCore.do_action')
    def test_url_parsing_cn(self, mock_do_action):
        """
        Test case 19: URL parsing works correctly for CN site type
        """
        mock_do_action.return_value = self.mock_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        credentials = provider.get_credentials()
        self.assertIsNotNone(credentials)

        # Verify the request was made with correct host
        call_args = mock_do_action.call_args
        tea_request = call_args[0][0]

        self.assertEqual(tea_request.protocol, "https")
        self.assertEqual(tea_request.headers['host'], "oauth.aliyun.com")

    @patch('alibabacloud_credentials.provider.oauth.TeaCore.do_action')
    def test_url_parsing_intl(self, mock_do_action):
        """
        Test case 20: URL parsing works correctly for INTL site type
        """
        mock_do_action.return_value = self.mock_response

        provider = OAuthCredentialsProvider(
            client_id="456",
            sign_in_url="https://oauth.alibabacloud.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        credentials = provider.get_credentials()
        self.assertIsNotNone(credentials)

        # Verify the request was made with correct host
        call_args = mock_do_action.call_args
        tea_request = call_args[0][0]

        self.assertEqual(tea_request.protocol, "https")
        self.assertEqual(tea_request.headers['host'], "oauth.alibabacloud.com")

    @patch('alibabacloud_credentials.provider.oauth.TeaCore.do_action')
    def test_expiration_time_parsing(self, mock_do_action):
        """
        Test case 21: Expiration time is correctly parsed from ISO format
        """
        mock_do_action.return_value = self.mock_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        credentials = provider.get_credentials()

        # The expiration should be parsed correctly from "2030-12-31T23:59:59Z"
        expected_expiration = calendar.timegm(time.strptime(self.expiration, '%Y-%m-%dT%H:%M:%SZ'))
        self.assertEqual(credentials.get_expiration(), expected_expiration)

    def test_client_id_and_sign_in_url(self):
        """
        Test case 22: Client ID and sign-in URL are correctly set
        """
        # Test CN configuration
        provider_cn = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )
        self.assertEqual(provider_cn._client_id, "123")
        self.assertEqual(provider_cn._sign_in_url, "https://oauth.aliyun.com")

        # Test INTL configuration
        provider_intl = OAuthCredentialsProvider(
            client_id="456",
            sign_in_url="https://oauth.alibabacloud.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )
        self.assertEqual(provider_intl._client_id, "456")
        self.assertEqual(provider_intl._sign_in_url, "https://oauth.alibabacloud.com")

    @patch('alibabacloud_credentials.provider.oauth.TeaCore.do_action')
    def test_request_body_empty(self, mock_do_action):
        """
        Test case 23: Request body should be empty for OAuth exchange
        """
        mock_do_action.return_value = self.mock_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            refresh_token=self.refresh_token,
            access_token=self.access_token,
            access_token_expire=self.access_token_expire
        )

        provider.get_credentials()

        # Verify the request body is empty
        call_args = mock_do_action.call_args
        tea_request = call_args[0][0]

        self.assertIsNone(tea_request.body)

    @patch('Tea.core.TeaCore.do_action')
    def test_oauth_token_refresh_success(self, mock_do_action):
        """测试 OAuth 令牌刷新成功"""
        # 模拟成功的令牌刷新响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.body = json.dumps({
            "AccessKeyId": "test",
            "AccessKeySecret": "test",
            "SecurityToken": "test",
            "Expiration": "2021-10-20T04:27:09Z",
        }).encode('utf-8')
        mock_do_action.return_value = mock_response

        callback_called = False

        def test_callback(refresh_token, access_token, access_key, secret, security_token, access_token_expire,
                          sts_expire):
            nonlocal callback_called
            callback_called = True
            self.assertEqual(refresh_token, "old_refresh_token")
            self.assertEqual(access_token, "old_access_token")

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="old_access_token",
            access_token_expire=int(time.time()) + 3600,  # 未过期
            refresh_token="old_refresh_token",
            token_update_callback=test_callback
        )

        # 执行令牌刷新
        provider._refresh_credentials()

        # 验证回调被调用
        self.assertTrue(callback_called)

    @patch('Tea.core.TeaCore.do_action')
    def test_oauth_callback_in_credentials_refresh(self, mock_do_action):
        """测试在凭据刷新时调用回调函数"""
        # 模拟成功的凭据交换响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.body = json.dumps({
            "AccessKeyId": "test_access_key_id",
            "AccessKeySecret": "test_access_key_secret",
            "SecurityToken": "test_security_token",
            "Expiration": "2030-12-31T23:59:59Z"
        }).encode('utf-8')
        mock_do_action.return_value = mock_response

        callback_called = False
        callback_data = None

        def test_callback(refresh_token, access_token, access_key, secret, security_token, access_token_expire,
                          sts_expire):
            nonlocal callback_called, callback_data
            callback_called = True
            callback_data = (refresh_token, access_token, access_key, secret, security_token, access_token_expire,
                             sts_expire)

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="test_access_token",
            access_token_expire=int(time.time()) + 3600,
            refresh_token="test_refresh_token",
            token_update_callback=test_callback
        )

        # 获取凭据，这会触发回调
        credentials = provider.get_credentials()

        # 验证回调被调用
        self.assertTrue(callback_called)
        self.assertIsNotNone(callback_data)
        self.assertEqual(callback_data[0], "test_refresh_token")  # refresh_token
        self.assertEqual(callback_data[1], "test_access_token")  # access_token
        self.assertEqual(callback_data[2], "test_access_key_id")  # access_key
        self.assertEqual(callback_data[3], "test_access_key_secret")  # secret
        self.assertEqual(callback_data[4], "test_security_token")  # security_token

    @patch('Tea.core.TeaCore.do_action')
    def test_oauth_callback_error_handling(self, mock_do_action):
        """测试回调函数错误处理"""
        # 模拟成功的凭据交换响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.body = json.dumps({
            "AccessKeyId": "test_access_key_id",
            "AccessKeySecret": "test_access_key_secret",
            "SecurityToken": "test_security_token",
            "Expiration": "2030-12-31T23:59:59Z"
        }).encode('utf-8')
        mock_do_action.return_value = mock_response

        def error_callback(refresh_token, access_token, access_key, secret, security_token, access_token_expire,
                           sts_expire):
            raise Exception("Callback error")

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="test_access_token",
            access_token_expire=int(time.time()) + 3600,
            refresh_token="test_refresh_token",
            token_update_callback=error_callback
        )

        # 获取凭据，即使回调出错也应该成功
        credentials = provider.get_credentials()

        # 验证凭据仍然成功获取
        self.assertIsNotNone(credentials)
        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")

    def test_oauth_provider_without_refresh_token(self):
        """测试没有refresh_token的OAuth提供者"""
        with self.assertRaises(ValueError) as context:
            OAuthCredentialsProvider(
                client_id="123",
                sign_in_url="https://oauth.aliyun.com",
                access_token="test_access_token",
                access_token_expire=int(time.time()) + 3600
            )

        self.assertIn("OAuth access token is empty or expired, please re-login with cli", str(context.exception))

    def test_oauth_provider_with_empty_refresh_token(self):
        """测试空refresh_token的OAuth提供者"""
        with self.assertRaises(ValueError) as context:
            OAuthCredentialsProvider(
                client_id="123",
                sign_in_url="https://oauth.aliyun.com",
                access_token="test_access_token",
                access_token_expire=int(time.time()) + 3600,
                refresh_token=""
            )

        self.assertIn("OAuth access token is empty or expired, please re-login with cli", str(context.exception))

    @patch('Tea.core.TeaCore.do_action')
    def test_oauth_token_refresh_failure(self, mock_do_action):
        """测试OAuth令牌刷新失败"""
        # 模拟失败的令牌刷新响应
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.body = b'{"error": "Invalid refresh token"}'
        mock_do_action.return_value = mock_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="old_access_token",
            access_token_expire=int(time.time()) - 100,  # 已过期
            refresh_token="invalid_refresh_token"
        )

        # 执行令牌刷新，应该静默失败
        with self.assertRaises(CredentialException):
            provider._try_refresh_oauth_token()

        # 验证令牌没有被更新
        self.assertEqual(provider._access_token, "old_access_token")
        self.assertEqual(provider._refresh_token, "invalid_refresh_token")


    @patch('Tea.core.TeaCore.do_action')
    def test_oauth_token_refresh_network_error(self, mock_do_action):
        """测试OAuth令牌刷新时网络错误"""
        # 模拟网络错误
        mock_do_action.side_effect = Exception("Network error")

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="old_access_token",
            access_token_expire=int(time.time()) - 100,  # 已过期
            refresh_token="test_refresh_token"
        )

        # 执行令牌刷新
        with self.assertRaises(Exception):
            provider._try_refresh_oauth_token()

        # 验证令牌没有被更新
        self.assertEqual(provider._access_token, "old_access_token")

    def test_oauth_provider_http_options(self):
        """测试OAuth提供者的HTTP选项"""
        custom_http_options = HttpOptions(connect_timeout=10000, read_timeout=20000)

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="test_access_token",
            access_token_expire=int(time.time()) + 3600,
            refresh_token="test_refresh_token",
            http_options=custom_http_options
        )

        self.assertEqual(provider._http_options, custom_http_options)
        self.assertEqual(provider._runtime_options['connectTimeout'], 10000)
        self.assertEqual(provider._runtime_options['readTimeout'], 20000)

    def test_oauth_provider_runtime_options_with_proxy(self):
        """测试OAuth提供者的运行时选项包含代理"""
        custom_http_options = HttpOptions(proxy="http://proxy.example.com:8080")

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="test_access_token",
            access_token_expire=int(time.time()) + 3600,
            refresh_token="test_refresh_token",
            http_options=custom_http_options
        )

        self.assertEqual(provider._runtime_options['httpsProxy'], "http://proxy.example.com:8080")

    @patch('Tea.core.TeaCore.do_action')
    def test_oauth_credentials_refresh_with_callback(self, mock_do_action):
        """测试OAuth凭据刷新时调用回调"""
        # 模拟成功的凭据交换响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.body = json.dumps({
            "AccessKeyId": "test_access_key_id",
            "AccessKeySecret": "test_access_key_secret",
            "SecurityToken": "test_security_token",
            "Expiration": "2030-12-31T23:59:59Z"
        }).encode('utf-8')
        mock_do_action.return_value = mock_response

        callback_called = False
        callback_data = None

        def test_callback(refresh_token, access_token, access_key, secret, security_token, access_token_expire,
                          sts_expire):
            nonlocal callback_called, callback_data
            callback_called = True
            callback_data = (refresh_token, access_token, access_key, secret, security_token, access_token_expire,
                             sts_expire)

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="test_access_token",
            access_token_expire=int(time.time()) + 3600,
            refresh_token="test_refresh_token",
            token_update_callback=test_callback
        )

        # 获取凭据，这会触发回调
        credentials = provider.get_credentials()

        # 验证回调被调用
        self.assertTrue(callback_called)
        self.assertIsNotNone(callback_data)
        self.assertEqual(callback_data[0], "test_refresh_token")  # refresh_token
        self.assertEqual(callback_data[1], "test_access_token")  # access_token
        self.assertEqual(callback_data[2], "test_access_key_id")  # access_key
        self.assertEqual(callback_data[3], "test_access_key_secret")  # secret
        self.assertEqual(callback_data[4], "test_security_token")  # security_token

    @patch('Tea.core.TeaCore.async_do_action')
    def test_oauth_credentials_refresh_async_with_callback(self, mock_async_do_action):
        """测试OAuth异步凭据刷新时调用回调"""
        # 模拟成功的凭据交换响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.body = json.dumps({
            "AccessKeyId": "test_access_key_id",
            "AccessKeySecret": "test_access_key_secret",
            "SecurityToken": "test_security_token",
            "Expiration": "2030-12-31T23:59:59Z"
        }).encode('utf-8')
        mock_async_do_action.return_value = mock_response

        callback_called = False
        callback_data = None

        async def test_callback(refresh_token, access_token, access_key, secret, security_token, access_token_expire,
                          sts_expire):
            nonlocal callback_called, callback_data
            callback_called = True
            callback_data = (refresh_token, access_token, access_key, secret, security_token, access_token_expire,
                             sts_expire)

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="test_access_token",
            access_token_expire=int(time.time()) + 3600,
            refresh_token="test_refresh_token",
            token_update_callback_async=test_callback
        )

        async def run_test():
            return await provider.get_credentials_async()

        # 使用 asyncio.run() 替代 get_event_loop()
        credentials = asyncio.run(run_test())

        # 验证回调被调用
        self.assertTrue(callback_called)
        self.assertIsNotNone(callback_data)
        self.assertEqual(callback_data[0], "test_refresh_token")  # refresh_token
        self.assertEqual(callback_data[1], "test_access_token")  # access_token
        self.assertEqual(callback_data[2], "test_access_key_id")  # access_key
        self.assertEqual(callback_data[3], "test_access_key_secret")  # secret
        self.assertEqual(callback_data[4], "test_security_token")  # security_token

    def test_oauth_provider_validation_edge_cases(self):
        """测试OAuth提供者验证的边界情况"""
        # 测试空字符串client_id
        with self.assertRaises(ValueError) as context:
            OAuthCredentialsProvider(
                client_id="",
                sign_in_url="https://oauth.aliyun.com",
                access_token="test_access_token",
                access_token_expire=int(time.time()) + 3600,
                refresh_token="test_refresh_token"
            )
        self.assertIn("the ClientId is empty", str(context.exception))

        # 测试None client_id
        with self.assertRaises(ValueError) as context:
            OAuthCredentialsProvider(
                client_id=None,
                sign_in_url="https://oauth.aliyun.com",
                access_token="test_access_token",
                access_token_expire=int(time.time()) + 3600,
                refresh_token="test_refresh_token"
            )
        self.assertIn("the ClientId is empty", str(context.exception))

        # 测试空字符串sign_in_url
        with self.assertRaises(ValueError) as context:
            OAuthCredentialsProvider(
                client_id="123",
                sign_in_url="",
                access_token="test_access_token",
                access_token_expire=int(time.time()) + 3600,
                refresh_token="test_refresh_token"
            )
        self.assertIn("the url for sign-in is empty", str(context.exception))

        # 测试None sign_in_url
        with self.assertRaises(ValueError) as context:
            OAuthCredentialsProvider(
                client_id="123",
                sign_in_url=None,
                access_token="test_access_token",
                access_token_expire=int(time.time()) + 3600,
                refresh_token="test_refresh_token"
            )
        self.assertIn("the url for sign-in is empty", str(context.exception))

    def test_oauth_provider_refresh_token_validation(self):
        """测试OAuth提供者refresh_token验证"""
        # 测试None refresh_token
        with self.assertRaises(ValueError) as context:
            OAuthCredentialsProvider(
                client_id="123",
                sign_in_url="https://oauth.aliyun.com",
                access_token="test_access_token",
                access_token_expire=int(time.time()) + 3600,
                refresh_token=None
            )
        self.assertIn("OAuth access token is empty or expired, please re-login with cli", str(context.exception))

        # 测试空字符串refresh_token
        with self.assertRaises(ValueError) as context:
            OAuthCredentialsProvider(
                client_id="123",
                sign_in_url="https://oauth.aliyun.com",
                access_token="test_access_token",
                access_token_expire=int(time.time()) + 3600,
                refresh_token=""
            )
        self.assertIn("OAuth access token is empty or expired, please re-login with cli", str(context.exception))

    def test_oauth_provider_with_async_callback(self):
        """测试带有异步回调的OAuth提供者"""
        callback_called = False
        callback_data = None

        async def test_async_callback(refresh_token, access_token, access_key, secret, security_token, access_token_expire, sts_expire):
            nonlocal callback_called, callback_data
            callback_called = True
            callback_data = (refresh_token, access_token, access_key, secret, security_token, access_token_expire, sts_expire)

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="test_access_token",
            access_token_expire=int(time.time()) + 3600,
            refresh_token="test_refresh_token",
            token_update_callback_async=test_async_callback
        )

        self.assertIsNotNone(provider._token_update_callback_async)
        self.assertEqual(provider._client_id, "123")
        self.assertEqual(provider._sign_in_url, "https://oauth.aliyun.com")

    @patch('Tea.core.TeaCore.async_do_action')
    def test_oauth_async_token_refresh_success(self, mock_async_do_action):
        """测试异步OAuth令牌刷新成功"""
        # 模拟成功的令牌刷新响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.body = json.dumps({
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "expires_in": 3600
        }).encode('utf-8')
        mock_async_do_action.return_value = mock_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="old_access_token",
            access_token_expire=int(time.time()) - 100,  # 已过期
            refresh_token="old_refresh_token"
        )

        async def run_test():
            await provider._try_refresh_oauth_token_async()
            return provider._access_token, provider._refresh_token

        # 使用 asyncio.run() 替代 get_event_loop()
        new_access_token, new_refresh_token = asyncio.run(run_test())

        # 验证令牌被更新
        self.assertEqual(new_access_token, "new_access_token")
        self.assertEqual(new_refresh_token, "new_refresh_token")

    @patch('Tea.core.TeaCore.async_do_action')
    def test_oauth_async_token_refresh_failure(self, mock_async_do_action):
        """测试异步OAuth令牌刷新失败"""
        # 模拟失败的令牌刷新响应
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.body = b'{"error": "Invalid refresh token"}'
        mock_async_do_action.return_value = mock_response

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="old_access_token",
            access_token_expire=int(time.time()) - 100,  # 已过期
            refresh_token="invalid_refresh_token"
        )

        async def run_test():
            await provider._try_refresh_oauth_token_async()
            return provider._access_token, provider._refresh_token

        # 使用 asyncio.run() 替代 get_event_loop()
        with self.assertRaises(CredentialException):
            new_access_token, new_refresh_token = asyncio.run(run_test())


        # 验证令牌没有被更新
        self.assertEqual(provider._access_token, "old_access_token")
        self.assertEqual(provider._refresh_token, "invalid_refresh_token")

    @patch('Tea.core.TeaCore.async_do_action')
    def test_oauth_async_credentials_refresh_with_async_callback(self, mock_async_do_action):
        """测试异步凭据刷新时调用异步回调函数"""
        # 模拟成功的凭据交换响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.body = json.dumps({
            "AccessKeyId": "test_access_key_id",
            "AccessKeySecret": "test_access_key_secret",
            "SecurityToken": "test_security_token",
            "Expiration": "2030-12-31T23:59:59Z"
        }).encode('utf-8')
        mock_async_do_action.return_value = mock_response

        callback_called = False
        callback_data = None

        async def test_async_callback(refresh_token, access_token, access_key, secret, security_token, access_token_expire, sts_expire):
            nonlocal callback_called, callback_data
            callback_called = True
            callback_data = (refresh_token, access_token, access_key, secret, security_token, access_token_expire, sts_expire)

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="test_access_token",
            access_token_expire=int(time.time()) + 3600,
            refresh_token="test_refresh_token",
            token_update_callback_async=test_async_callback
        )

        async def run_test():
            return await provider.get_credentials_async()

        # 使用 asyncio.run() 替代 get_event_loop()
        credentials = asyncio.run(run_test())

        # 验证回调被调用
        self.assertTrue(callback_called)
        self.assertIsNotNone(callback_data)
        self.assertEqual(callback_data[0], "test_refresh_token")  # refresh_token
        self.assertEqual(callback_data[1], "test_access_token")  # access_token
        self.assertEqual(callback_data[2], "test_access_key_id")  # access_key
        self.assertEqual(callback_data[3], "test_access_key_secret")  # secret
        self.assertEqual(callback_data[4], "test_security_token")  # security_token

    @patch('Tea.core.TeaCore.async_do_action')
    def test_oauth_async_credentials_refresh_with_async_callback_error(self, mock_async_do_action):
        """测试异步回调函数错误处理"""
        # 模拟成功的凭据交换响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.body = json.dumps({
            "AccessKeyId": "test_access_key_id",
            "AccessKeySecret": "test_access_key_secret",
            "SecurityToken": "test_security_token",
            "Expiration": "2030-12-31T23:59:59Z"
        }).encode('utf-8')
        mock_async_do_action.return_value = mock_response

        async def error_async_callback(refresh_token, access_token, access_key, secret, security_token, access_token_expire, sts_expire):
            raise Exception("Async callback error")

        provider = OAuthCredentialsProvider(
            client_id="123",
            sign_in_url="https://oauth.aliyun.com",
            access_token="test_access_token",
            access_token_expire=int(time.time()) + 3600,
            refresh_token="test_refresh_token",
            token_update_callback_async=error_async_callback
        )

        async def run_test():
            return await provider.get_credentials_async()

        # 使用 asyncio.run() 替代 get_event_loop()
        credentials = asyncio.run(run_test())

        # 验证凭据仍然成功获取
        self.assertIsNotNone(credentials)
        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")

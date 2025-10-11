import calendar
import json
import logging
import time
from urllib.parse import urlparse, urlencode
from typing import Callable, Optional

from alibabacloud_credentials.provider.refreshable import Credentials, RefreshResult, RefreshCachedSupplier
from alibabacloud_credentials.http import HttpOptions
from Tea.core import TeaCore
from alibabacloud_credentials_api import ICredentialsProvider
from alibabacloud_credentials.utils import parameter_helper as ph
from alibabacloud_credentials.exceptions import CredentialException

log = logging.getLogger('credentials')
log.setLevel(logging.INFO)
ch = logging.StreamHandler()
log.addHandler(ch)

# OAuth 令牌更新回调函数类型
OAuthTokenUpdateCallback = Callable[[str, str, str, str, str, int, int], None]
OAuthTokenUpdateCallbackAsync = Callable[[str, str, str, str, str, int, int], None]


def _get_stale_time(expiration: int) -> int:
    if expiration < 0:
        return int(time.mktime(time.localtime())) + 60 * 60
    return expiration - 15 * 60


class OAuthCredentialsProvider(ICredentialsProvider):
    DEFAULT_CONNECT_TIMEOUT = 5000
    DEFAULT_READ_TIMEOUT = 10000

    def __init__(self, *,
                 client_id: str = None,
                 sign_in_url: str = None,
                 access_token: str = None,
                 access_token_expire: int = 0,
                 refresh_token: str = None,
                 http_options: HttpOptions = None,
                 token_update_callback: Optional[OAuthTokenUpdateCallback] = None,
                 token_update_callback_async: Optional[OAuthTokenUpdateCallbackAsync] = None):

        if not client_id:
            raise ValueError('the ClientId is empty')

        if not sign_in_url:
            raise ValueError('the url for sign-in is empty')

        if not refresh_token:
            raise ValueError('OAuth access token is empty or expired, please re-login with cli')

        self._client_id = client_id
        self._sign_in_url = sign_in_url
        self._access_token = access_token
        self._access_token_expire = access_token_expire
        self._refresh_token = refresh_token
        self._token_update_callback = token_update_callback
        self._token_update_callback_async = token_update_callback_async

        self._http_options = http_options if http_options is not None else HttpOptions()
        self._runtime_options = {
            'connectTimeout': self._http_options.connect_timeout if self._http_options.connect_timeout is not None else OAuthCredentialsProvider.DEFAULT_CONNECT_TIMEOUT,
            'readTimeout': self._http_options.read_timeout if self._http_options.read_timeout is not None else OAuthCredentialsProvider.DEFAULT_READ_TIMEOUT,
            'httpsProxy': self._http_options.proxy
        }
        self._credentials_cache = RefreshCachedSupplier(
            refresh_callable=self._refresh_credentials,
            refresh_callable_async=self._refresh_credentials_async,
        )

    def get_credentials(self) -> Credentials:
        return self._credentials_cache._sync_call()

    async def get_credentials_async(self) -> Credentials:
        return await self._credentials_cache._async_call()

    def _try_refresh_oauth_token(self) -> None:
        current_time = int(time.mktime(time.localtime()))
        # 构建刷新令牌请求
        r = urlparse(self._sign_in_url)
        tea_request = ph.get_new_request()
        tea_request.headers['host'] = r.hostname
        tea_request.port = r.port
        tea_request.protocol = r.scheme
        tea_request.method = 'POST'
        tea_request.pathname = '/v1/token'

        # 设置请求体
        body_data = {
            'grant_type': 'refresh_token',
            'refresh_token': self._refresh_token,
            'client_id': self._client_id,
            'Timestamp': ph.get_iso_8061_date()
        }
        tea_request.body = urlencode(body_data)
        tea_request.headers['Content-Type'] = 'application/x-www-form-urlencoded'

        response = TeaCore.do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(f"failed to refresh OAuth token, status code: {response.status_code}, response: {response.body.decode('utf-8')}")

        # 解析响应
        dic = json.loads(response.body.decode('utf-8'))
        if 'access_token' not in dic or 'refresh_token' not in dic:
            raise CredentialException(f"failed to refresh OAuth token: {response.body.decode('utf-8')}")

        # 更新令牌
        new_access_token = dic.get('access_token')
        new_refresh_token = dic.get('refresh_token')
        expires_in = dic.get('expires_in', 3600)
        new_access_token_expire = current_time + expires_in

        self._access_token = new_access_token
        self._refresh_token = new_refresh_token
        self._access_token_expire = new_access_token_expire

    async def _try_refresh_oauth_token_async(self) -> None:
        current_time = int(time.mktime(time.localtime()))
        # 构建刷新令牌请求
        r = urlparse(self._sign_in_url)
        tea_request = ph.get_new_request()
        tea_request.headers['host'] = r.hostname
        tea_request.port = r.port
        tea_request.protocol = r.scheme
        tea_request.method = 'POST'
        tea_request.pathname = '/v1/token'

        # 设置请求体
        body_data = {
            'grant_type': 'refresh_token',
            'refresh_token': self._refresh_token,
            'client_id': self._client_id,
            'Timestamp': ph.get_iso_8061_date()
        }
        tea_request.body = urlencode(body_data)
        tea_request.headers['Content-Type'] = 'application/x-www-form-urlencoded'

        response = await TeaCore.async_do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(f"failed to refresh OAuth token, status code: {response.status_code}, response: {response.body.decode('utf-8')}")

        # 解析响应
        dic = json.loads(response.body.decode('utf-8'))
        if 'access_token' not in dic or 'refresh_token' not in dic:
            raise CredentialException(f"failed to refresh OAuth token: {response.body.decode('utf-8')}")

        # 更新令牌
        new_access_token = dic.get('access_token')
        new_refresh_token = dic.get('refresh_token')
        expires_in = dic.get('expires_in', 3600)
        new_access_token_expire = current_time + expires_in

        self._access_token = new_access_token
        self._refresh_token = new_refresh_token
        self._access_token_expire = new_access_token_expire

    def _refresh_credentials(self) -> RefreshResult[Credentials]:
        if self._access_token is None or self._access_token_expire <= 0 or self._access_token_expire - int(
                time.mktime(time.localtime())) <= 180:
            self._try_refresh_oauth_token()

        r = urlparse(self._sign_in_url)
        tea_request = ph.get_new_request()
        tea_request.headers['host'] = r.hostname
        tea_request.port = r.port
        tea_request.protocol = r.scheme
        tea_request.method = 'POST'
        tea_request.pathname = '/v1/exchange'

        tea_request.headers['Content-Type'] = 'application/json'
        tea_request.headers['Authorization'] = f'Bearer {self._access_token}'

        response = TeaCore.do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(
                f"error refreshing credentials from OAuth, http_code: {response.status_code}, result: {response.body.decode('utf-8')}")

        dic = json.loads(response.body.decode('utf-8'))
        if 'error' in dic:
            raise CredentialException(
                f"error retrieving credentials from OAuth result: {response.body.decode('utf-8')}")

        if 'AccessKeyId' not in dic or 'AccessKeySecret' not in dic or 'SecurityToken' not in dic:
            raise CredentialException(
                f"error retrieving credentials from OAuth result: {response.body.decode('utf-8')}")

        # 先转换为时间数组
        time_array = time.strptime(dic.get('Expiration'), '%Y-%m-%dT%H:%M:%SZ')
        # 转换为时间戳
        expiration = calendar.timegm(time_array)
        credentials = Credentials(
            access_key_id=dic.get('AccessKeyId'),
            access_key_secret=dic.get('AccessKeySecret'),
            security_token=dic.get('SecurityToken'),
            expiration=expiration,
            provider_name=self.get_provider_name()
        )

        # 调用令牌更新回调函数
        if self._token_update_callback:
            try:
                self._token_update_callback(
                    self._refresh_token,
                    self._access_token,
                    credentials.get_access_key_id(),
                    credentials.get_access_key_secret(),
                    credentials.get_security_token(),
                    self._access_token_expire,
                    expiration
                )
            except Exception as e:
                log.warning(f'failed to update OAuth tokens in config file: {e}')

        return RefreshResult(value=credentials,
                             stale_time=_get_stale_time(expiration))

    async def _refresh_credentials_async(self) -> RefreshResult[Credentials]:
        if self._access_token is None or self._access_token_expire <= 0 or self._access_token_expire - int(
                time.mktime(time.localtime())) <= 180:
            await self._try_refresh_oauth_token_async()

        r = urlparse(self._sign_in_url)
        tea_request = ph.get_new_request()
        tea_request.headers['host'] = r.hostname
        tea_request.port = r.port
        tea_request.protocol = r.scheme
        tea_request.method = 'POST'
        tea_request.pathname = '/v1/exchange'

        tea_request.headers['Content-Type'] = 'application/json'
        tea_request.headers['Authorization'] = f'Bearer {self._access_token}'

        response = await TeaCore.async_do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(
                f"error refreshing credentials from OAuth, http_code: {response.status_code}, result: {response.body.decode('utf-8')}")

        dic = json.loads(response.body.decode('utf-8'))
        if 'error' in dic:
            raise CredentialException(
                f"error retrieving credentials from OAuth result: {response.body.decode('utf-8')}")

        if 'AccessKeyId' not in dic or 'AccessKeySecret' not in dic or 'SecurityToken' not in dic:
            raise CredentialException(
                f"error retrieving credentials from OAuth result: {response.body.decode('utf-8')}")

        # 先转换为时间数组
        time_array = time.strptime(dic.get('Expiration'), '%Y-%m-%dT%H:%M:%SZ')
        # 转换为时间戳
        expiration = calendar.timegm(time_array)
        credentials = Credentials(
            access_key_id=dic.get('AccessKeyId'),
            access_key_secret=dic.get('AccessKeySecret'),
            security_token=dic.get('SecurityToken'),
            expiration=expiration,
            provider_name=self.get_provider_name()
        )

        if self._token_update_callback_async:
            try:
                await self._token_update_callback_async(
                    self._refresh_token,
                    self._access_token,
                    credentials.get_access_key_id(),
                    credentials.get_access_key_secret(),
                    credentials.get_security_token(),
                    self._access_token_expire,
                    expiration
                )
            except Exception as e:
                log.warning(f'failed to update OAuth tokens in config file: {e}')

        return RefreshResult(value=credentials,
                             stale_time=_get_stale_time(expiration))

    def _get_client_id(self) -> str:
        """获取客户端ID"""
        return self._client_id

    def get_provider_name(self) -> str:
        return 'oauth'

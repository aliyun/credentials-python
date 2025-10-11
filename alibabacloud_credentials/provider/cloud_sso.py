import calendar
import json
import time
from urllib.parse import urlparse

from alibabacloud_credentials.provider.refreshable import Credentials, RefreshResult, RefreshCachedSupplier
from alibabacloud_credentials.http import HttpOptions
from Tea.core import TeaCore
from alibabacloud_credentials_api import ICredentialsProvider
from alibabacloud_credentials.utils import parameter_helper as ph
from alibabacloud_credentials.exceptions import CredentialException


def _get_stale_time(expiration: int) -> int:
    if expiration < 0:
        return int(time.mktime(time.localtime())) + 60 * 60
    return expiration - 15 * 60


class CloudSSOCredentialsProvider(ICredentialsProvider):
    DEFAULT_CONNECT_TIMEOUT = 5000
    DEFAULT_READ_TIMEOUT = 10000

    def __init__(self, *,
                 sign_in_url: str = None,
                 account_id: str = None,
                 access_config: str = None,
                 access_token: str = None,
                 access_token_expire: int = 0,
                 http_options: HttpOptions = None):

        self._sign_in_url = sign_in_url
        self._account_id = account_id
        self._access_config = access_config
        self._access_token = access_token
        self._access_token_expire = access_token_expire

        if self._access_token is None or self._access_token_expire == 0 or self._access_token_expire - int(
                time.mktime(time.localtime())) <= 0:
            raise ValueError(
                'CloudSSO access token is empty or expired, please re-login with cli')
        if self._sign_in_url is None or self._account_id is None or self._access_config is None:
            raise ValueError(
                'CloudSSO sign in url or account id or access config is empty')

        self._http_options = http_options if http_options is not None else HttpOptions()
        self._runtime_options = {
            'connectTimeout': self._http_options.connect_timeout if self._http_options.connect_timeout is not None else CloudSSOCredentialsProvider.DEFAULT_CONNECT_TIMEOUT,
            'readTimeout': self._http_options.read_timeout if self._http_options.read_timeout is not None else CloudSSOCredentialsProvider.DEFAULT_READ_TIMEOUT,
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

    def _refresh_credentials(self) -> RefreshResult[Credentials]:
        r = urlparse(self._sign_in_url)
        tea_request = ph.get_new_request()
        tea_request.headers['host'] = r.hostname
        tea_request.port = r.port
        tea_request.protocol = r.scheme
        tea_request.method = 'POST'
        tea_request.pathname = '/cloud-credentials'

        tea_request.body = json.dumps({
            'AccountId': self._account_id,
            'AccessConfigurationId': self._access_config,
        })

        tea_request.headers['Accept'] = 'application/json'
        tea_request.headers['Content-Type'] = 'application/json'
        tea_request.headers['Authorization'] = f'Bearer {self._access_token}'

        response = TeaCore.do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(
                f'error refreshing credentials from sso, http_code: {response.status_code}, result: {response.body.decode("utf-8")}')

        dic = json.loads(response.body.decode('utf-8'))
        if 'CloudCredential' not in dic:
            raise CredentialException(
                f'error retrieving credentials from sso result: {response.body.decode("utf-8")}')

        cre = dic.get('CloudCredential')
        if 'AccessKeyId' not in cre or 'AccessKeySecret' not in cre or 'SecurityToken' not in cre:
            raise CredentialException(
                f'error retrieving credentials from sso result: {response.body.decode("utf-8")}')

        # 先转换为时间数组
        time_array = time.strptime(cre.get('Expiration'), '%Y-%m-%dT%H:%M:%SZ')
        # 转换为时间戳
        expiration = calendar.timegm(time_array)
        credentials = Credentials(
            access_key_id=cre.get('AccessKeyId'),
            access_key_secret=cre.get('AccessKeySecret'),
            security_token=cre.get('SecurityToken'),
            expiration=expiration,
            provider_name=self.get_provider_name()
        )
        return RefreshResult(value=credentials,
                             stale_time=_get_stale_time(expiration))

    async def _refresh_credentials_async(self) -> RefreshResult[Credentials]:
        r = urlparse(self._sign_in_url)
        tea_request = ph.get_new_request()
        tea_request.headers['host'] = r.hostname
        tea_request.port = r.port
        tea_request.protocol = r.scheme
        tea_request.method = 'POST'
        tea_request.pathname = '/cloud-credentials'

        tea_request.body = json.dumps({
            'AccountId': self._account_id,
            'AccessConfigurationId': self._access_config,
        })

        tea_request.headers['Accept'] = 'application/json'
        tea_request.headers['Content-Type'] = 'application/json'
        tea_request.headers['Authorization'] = f'Bearer {self._access_token}'

        response = await TeaCore.async_do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(
                f'error refreshing credentials from sso, http_code: {response.status_code}, result: {response.body.decode("utf-8")}')

        dic = json.loads(response.body.decode('utf-8'))
        if 'CloudCredential' not in dic:
            raise CredentialException(
                f'error retrieving credentials from sso result: {response.body.decode("utf-8")}')

        cre = dic.get('CloudCredential')
        if 'AccessKeyId' not in cre or 'AccessKeySecret' not in cre or 'SecurityToken' not in cre:
            raise CredentialException(
                f'error retrieving credentials from sso result: {response.body.decode("utf-8")}')

        # 先转换为时间数组
        time_array = time.strptime(cre.get('Expiration'), '%Y-%m-%dT%H:%M:%SZ')
        # 转换为时间戳
        expiration = calendar.timegm(time_array)
        credentials = Credentials(
            access_key_id=cre.get('AccessKeyId'),
            access_key_secret=cre.get('AccessKeySecret'),
            security_token=cre.get('SecurityToken'),
            expiration=expiration,
            provider_name=self.get_provider_name()
        )
        return RefreshResult(value=credentials,
                             stale_time=_get_stale_time(expiration))

    def get_provider_name(self) -> str:
        return 'cloud_sso'

import calendar
import json
import time
from urllib.parse import urlparse, parse_qs

from alibabacloud_credentials.provider.refreshable import Credentials, RefreshResult, RefreshCachedSupplier
from alibabacloud_credentials.http import HttpOptions
from Tea.core import TeaCore
from alibabacloud_credentials_api import ICredentialsProvider
from alibabacloud_credentials.utils import auth_util as au
from alibabacloud_credentials.utils import parameter_helper as ph
from alibabacloud_credentials.exceptions import CredentialException


def _get_stale_time(expiration: int) -> int:
    if expiration < 0:
        return int(time.mktime(time.localtime())) + 60 * 60
    return expiration - 15 * 60


class URLCredentialsProvider(ICredentialsProvider):
    DEFAULT_CONNECT_TIMEOUT = 5000
    DEFAULT_READ_TIMEOUT = 10000

    def __init__(self, *,
                 uri: str = None,
                 protocol: str = 'http',
                 http_options: HttpOptions = None):

        self._uri = uri or au.environment_credentials_uri
        if self._uri is None or self._uri == '':
            raise ValueError('uri or environment variable ALIBABA_CLOUD_CREDENTIALS_URI cannot be empty')
        self._protocol = protocol

        self._http_options = http_options if http_options is not None else HttpOptions()
        self._runtime_options = {
            'connectTimeout': self._http_options.connect_timeout if self._http_options.connect_timeout is not None else URLCredentialsProvider.DEFAULT_CONNECT_TIMEOUT,
            'readTimeout': self._http_options.read_timeout if self._http_options.read_timeout is not None else URLCredentialsProvider.DEFAULT_READ_TIMEOUT,
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
        r = urlparse(self._uri)
        tea_request = ph.get_new_request()
        tea_request.headers['host'] = r.hostname
        tea_request.port = r.port
        tea_request.protocol = r.scheme or self._protocol or 'http'
        tea_request.method = 'GET'
        tea_request.pathname = r.path
        for key, values in parse_qs(r.query).items():
            for value in values:
                tea_request.query[key] = value

        response = TeaCore.do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(
                f'error refreshing credentials from {self._uri},  http_code={str(response.status_code)}, result: {response.body.decode("utf-8")}')

        body = response.body.decode('utf-8')

        dic = json.loads(body)
        content_code = dic.get('Code')

        if content_code != "Success" or 'AccessKeyId' not in dic or 'AccessKeySecret' not in dic or 'SecurityToken' not in dic or 'Expiration' not in dic:
            raise CredentialException(
                f'error retrieving credentials from {self._uri} result: {response.body.decode("utf-8")}')

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
        return RefreshResult(value=credentials,
                             stale_time=_get_stale_time(expiration))

    async def _refresh_credentials_async(self) -> RefreshResult[Credentials]:
        r = urlparse(self._uri)
        tea_request = ph.get_new_request()
        tea_request.headers['host'] = r.hostname
        tea_request.port = r.port
        tea_request.protocol = r.scheme or self._protocol or 'http'
        tea_request.method = 'GET'
        tea_request.pathname = r.path
        for key, values in parse_qs(r.query).items():
            for value in values:
                tea_request.query[key] = value

        response = await TeaCore.async_do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(
                f'error refreshing credentials from {self._uri},  http_code={str(response.status_code)}, result: {response.body.decode("utf-8")}')

        body = response.body.decode('utf-8')

        dic = json.loads(body)
        content_code = dic.get('Code')

        if content_code != "Success" or 'AccessKeyId' not in dic or 'AccessKeySecret' not in dic or 'SecurityToken' not in dic or 'Expiration' not in dic:
            raise CredentialException(
                f'error retrieving credentials from {self._uri} result: {response.body.decode("utf-8")}')

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
        return RefreshResult(value=credentials,
                             stale_time=_get_stale_time(expiration))

    def get_provider_name(self) -> str:
        return 'credential_uri'

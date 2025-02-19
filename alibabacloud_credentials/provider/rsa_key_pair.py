import calendar
import json
import time

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


def _get_content(file_path: str) -> str:
    with open(file_path, mode='r') as file:
        content = file.read()
    return content


class RsaKeyPairCredentialsProvider(ICredentialsProvider):
    DEFAULT_DURATION_SECONDS = 3600
    DEFAULT_CONNECT_TIMEOUT = 5000
    DEFAULT_READ_TIMEOUT = 10000

    def __init__(self, *,
                 public_key_id: str = None,
                 private_key_file: str = None,
                 duration_seconds: int = DEFAULT_DURATION_SECONDS,
                 sts_region_id: str = None,
                 sts_endpoint: str = None,
                 enable_vpc: bool = None,
                 http_options: HttpOptions = None):

        self._public_key_id = public_key_id
        self._private_key_file = private_key_file
        self._duration_seconds = duration_seconds

        if self._duration_seconds is None:
            self._duration_seconds = self.DEFAULT_DURATION_SECONDS
        if self._duration_seconds < 900:
            raise ValueError('session duration should be in the range of 900s - max session duration')
        if self._public_key_id is None or self._public_key_id == '':
            raise ValueError('public_key_id cannot be empty')
        if self._private_key_file is None or self._private_key_file == '':
            raise ValueError('private_key_file cannot be empty')
        self._private_key = _get_content(self._private_key_file)
        if self._private_key is None or self._private_key == '':
            raise ValueError('private_key cannot be empty')

        if sts_endpoint is not None and sts_endpoint != '':
            self._sts_endpoint = sts_endpoint
        else:
            if enable_vpc is not None:
                prefix = 'sts-vpc' if enable_vpc else 'sts'
            else:
                prefix = 'sts-vpc' if au.environment_enable_vpc.lower() == 'true' else 'sts'
            if sts_region_id is not None and sts_region_id != '':
                self._sts_endpoint = f'{prefix}.{sts_region_id}.aliyuncs.com'
            elif au.environment_sts_region is not None and au.environment_sts_region != '':
                self._sts_endpoint = f'{prefix}.{au.environment_sts_region}.aliyuncs.com'
            else:
                self._sts_endpoint = 'sts.ap-northeast-1.aliyuncs.com'

        self._http_options = http_options if http_options is not None else HttpOptions()
        self._runtime_options = {
            'connectTimeout': self._http_options.connect_timeout if self._http_options.connect_timeout is not None else RsaKeyPairCredentialsProvider.DEFAULT_CONNECT_TIMEOUT,
            'readTimeout': self._http_options.read_timeout if self._http_options.read_timeout is not None else RsaKeyPairCredentialsProvider.DEFAULT_READ_TIMEOUT,
            'httpsProxy': self._http_options.proxy
        }
        self._credentials_cache = RefreshCachedSupplier(
            refresh_callable=self._refresh_credentials,
            refresh_callable_async=self._refresh_credentials_async,
        )

    def get_credentials(self) -> Credentials:
        return self._credentials_cache()

    async def get_credentials_async(self) -> Credentials:
        return await self._credentials_cache()

    def _refresh_credentials(self) -> RefreshResult[Credentials]:
        tea_request = ph.get_new_request()
        tea_request.query = {
            'Action': 'GenerateSessionAccessKey',
            'Format': 'JSON',
            'Version': '2015-04-01',
            'DurationSeconds': str(self._duration_seconds),
            'SignatureMethod': 'HMAC-SHA1',
            'SignatureVersion': '1.0',
            'Timestamp': ph.get_iso_8061_date(),
            'SignatureNonce': ph.get_uuid(),
            'AccessKeyId': self._public_key_id,
        }

        string_to_sign = ph.compose_string_to_sign('GET', tea_request.query)
        signature = ph.sign_string(string_to_sign, self._private_key + '&')
        tea_request.query['Signature'] = signature
        tea_request.protocol = 'https'
        tea_request.headers['host'] = self._sts_endpoint

        response = TeaCore.do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(
                f'error refreshing credentials from rsa_key_pair, http_code: {response.status_code}, result: {response.body.decode("utf-8")}')

        dic = json.loads(response.body.decode('utf-8'))
        if 'SessionAccessKey' not in dic:
            raise CredentialException(
                f'error retrieving credentials from rsa_key_pair result: {response.body.decode("utf-8")}')

        cre = dic.get('SessionAccessKey')
        if 'SessionAccessKeyId' not in cre or 'SessionAccessKeySecret' not in cre:
            raise CredentialException(
                f'error retrieving credentials from rsa_key_pair result: {response.body.decode("utf-8")}')

        # 先转换为时间数组
        time_array = time.strptime(cre.get('Expiration'), '%Y-%m-%dT%H:%M:%SZ')
        # 转换为时间戳
        expiration = calendar.timegm(time_array)
        credentials = Credentials(
            access_key_id=cre.get('SessionAccessKeyId'),
            access_key_secret=cre.get('SessionAccessKeySecret'),
            expiration=expiration,
            provider_name=self.get_provider_name()
        )
        return RefreshResult(value=credentials,
                             stale_time=_get_stale_time(expiration))

    async def _refresh_credentials_async(self) -> RefreshResult[Credentials]:
        tea_request = ph.get_new_request()
        tea_request.query = {
            'Action': 'GenerateSessionAccessKey',
            'Format': 'JSON',
            'Version': '2015-04-01',
            'DurationSeconds': str(self._duration_seconds),
            'SignatureMethod': 'HMAC-SHA1',
            'SignatureVersion': '1.0',
            'Timestamp': ph.get_iso_8061_date(),
            'SignatureNonce': ph.get_uuid(),
            'AccessKeyId': self._public_key_id,
        }

        string_to_sign = ph.compose_string_to_sign('GET', tea_request.query)
        signature = ph.sign_string(string_to_sign, self._private_key + '&')
        tea_request.query['Signature'] = signature
        tea_request.protocol = 'https'
        tea_request.headers['host'] = self._sts_endpoint

        response = await TeaCore.async_do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(
                f'error refreshing credentials from rsa_key_pair, http_code: {response.status_code}, result: {response.body.decode("utf-8")}')

        dic = json.loads(response.body.decode('utf-8'))
        if 'SessionAccessKey' not in dic:
            raise CredentialException(
                f'error retrieving credentials from rsa_key_pair result: {response.body.decode("utf-8")}')

        cre = dic.get('SessionAccessKey')
        if 'SessionAccessKeyId' not in cre or 'SessionAccessKeySecret' not in cre:
            raise CredentialException(
                f'error retrieving credentials from rsa_key_pair result: {response.body.decode("utf-8")}')

        # 先转换为时间数组
        time_array = time.strptime(cre.get('Expiration'), '%Y-%m-%dT%H:%M:%SZ')
        # 转换为时间戳
        expiration = calendar.timegm(time_array)
        credentials = Credentials(
            access_key_id=cre.get('SessionAccessKeyId'),
            access_key_secret=cre.get('SessionAccessKeySecret'),
            expiration=expiration,
            provider_name=self.get_provider_name()
        )
        return RefreshResult(value=credentials,
                             stale_time=_get_stale_time(expiration))

    def get_provider_name(self) -> str:
        return 'rsa_key_pair'

import calendar
import json
import time
import aiofiles

from alibabacloud_credentials.provider.refreshable import Credentials, RefreshResult, RefreshCachedSupplier
from alibabacloud_credentials.http import HttpOptions
from Tea.core import TeaCore
from alibabacloud_credentials_api import ICredentialsProvider
from alibabacloud_credentials.utils import auth_util as au
from alibabacloud_credentials.utils import parameter_helper as ph
from alibabacloud_credentials.exceptions import CredentialException


async def _get_token_async(file_path: str) -> str:
    async with aiofiles.open(file_path, mode='r') as file:
        token = await file.read()
    return token


def _get_token(file_path: str) -> str:
    with open(file_path, mode='r') as file:
        token = file.read()
    return token


def _get_stale_time(expiration: int) -> int:
    if expiration < 0:
        return int(time.mktime(time.localtime())) + 60 * 60
    return expiration - 15 * 60


class OIDCRoleArnCredentialsProvider(ICredentialsProvider):
    DEFAULT_DURATION_SECONDS = 3600
    DEFAULT_CONNECT_TIMEOUT = 5000
    DEFAULT_READ_TIMEOUT = 10000

    def __init__(self, *,
                 role_arn: str = None,
                 oidc_provider_arn: str = None,
                 oidc_token_file_path: str = None,
                 role_session_name: str = None,
                 duration_seconds: int = DEFAULT_DURATION_SECONDS,
                 policy: str = None,
                 sts_region_id: str = None,
                 sts_endpoint: str = None,
                 enable_vpc: bool = None,
                 http_options: HttpOptions = None):

        self._role_arn = role_arn or au.environment_role_arn
        self._oidc_provider_arn = oidc_provider_arn or au.environment_oidc_provider_arn
        self._oidc_token_file_path = oidc_token_file_path or au.environment_oidc_token_file
        self._role_session_name = role_session_name or au.environment_role_session_name
        self._duration_seconds = duration_seconds
        self._policy = policy

        if self._role_session_name is None or self._role_session_name == '':
            self._role_session_name = f'credentials-python-{str(int(time.mktime(time.localtime())))}'
        if self._duration_seconds is None:
            self._duration_seconds = self.DEFAULT_DURATION_SECONDS
        if self._duration_seconds < 900:
            raise ValueError('session duration should be in the range of 900s - max session duration')
        if self._role_arn is None or self._role_arn == '':
            raise ValueError('role_arn or environment variable ALIBABA_CLOUD_ROLE_ARN cannot be empty')
        if self._oidc_provider_arn is None or self._oidc_provider_arn == '':
            raise ValueError(
                'oidc_provider_arn or environment variable ALIBABA_CLOUD_OIDC_PROVIDER_ARN cannot be empty')
        if self._oidc_token_file_path is None or self._oidc_token_file_path == '':
            raise ValueError(
                'oidc_token_file_path or environment variable ALIBABA_CLOUD_OIDC_TOKEN_FILE cannot be empty')

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
                self._sts_endpoint = 'sts.aliyuncs.com'

        self._http_options = http_options if http_options is not None else HttpOptions()
        self._runtime_options = {
            'connectTimeout': self._http_options.connect_timeout if self._http_options.connect_timeout is not None else OIDCRoleArnCredentialsProvider.DEFAULT_CONNECT_TIMEOUT,
            'readTimeout': self._http_options.read_timeout if self._http_options.read_timeout is not None else OIDCRoleArnCredentialsProvider.DEFAULT_READ_TIMEOUT,
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
        token = _get_token(self._oidc_token_file_path)
        tea_request = ph.get_new_request()
        tea_request.query = {
            'Action': 'AssumeRoleWithOIDC',
            'Format': 'JSON',
            'Version': '2015-04-01',
            'DurationSeconds': str(self._duration_seconds),
            'RoleArn': self._role_arn,
            'OIDCProviderArn': self._oidc_provider_arn,
            'OIDCToken': token,
            'RoleSessionName': self._role_session_name,
            'Timestamp': ph.get_iso_8061_date()
        }

        if self._policy is not None and self._policy != '':
            tea_request.query['Policy'] = self._policy

        tea_request.protocol = 'https'
        tea_request.headers['host'] = self._sts_endpoint

        response = TeaCore.do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(
                f'error refreshing credentials from oidc_role_arn, http_code: {response.status_code}, result: {response.body.decode("utf-8")}')

        dic = json.loads(response.body.decode('utf-8'))
        if 'Credentials' not in dic:
            raise CredentialException(
                f'error retrieving credentials from oidc_role_arn result: {response.body.decode("utf-8")}')

        cre = dic.get('Credentials')
        if 'AccessKeyId' not in cre or 'AccessKeySecret' not in cre or 'SecurityToken' not in cre:
            raise CredentialException(
                f'error retrieving credentials from oidc_role_arn result: {response.body.decode("utf-8")}')

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
        token = await _get_token_async(self._oidc_token_file_path)
        tea_request = ph.get_new_request()
        tea_request.query = {
            'Action': 'AssumeRoleWithOIDC',
            'Format': 'JSON',
            'Version': '2015-04-01',
            'DurationSeconds': str(self._duration_seconds),
            'RoleArn': self._role_arn,
            'OIDCProviderArn': self._oidc_provider_arn,
            'OIDCToken': token,
            'RoleSessionName': self._role_session_name,
            'Timestamp': ph.get_iso_8061_date()
        }

        if self._policy is not None and self._policy != '':
            tea_request.query['Policy'] = self._policy

        tea_request.protocol = 'https'
        tea_request.headers['host'] = self._sts_endpoint

        response = await TeaCore.async_do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(
                f'error refreshing credentials from oidc_role_arn, http_code: {response.status_code}, result: {response.body.decode("utf-8")}')

        dic = json.loads(response.body.decode('utf-8'))
        if 'Credentials' not in dic:
            raise CredentialException(
                f'error retrieving credentials from oidc_role_arn result: {response.body.decode("utf-8")}')

        cre = dic.get('Credentials')
        if 'AccessKeyId' not in cre or 'AccessKeySecret' not in cre or 'SecurityToken' not in cre:
            raise CredentialException(
                f'error retrieving credentials from oidc_role_arn result: {response.body.decode("utf-8")}')

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
        return 'oidc_role_arn'

import calendar
import json
import time
import signal
import logging

from alibabacloud_credentials.provider.refreshable import Credentials, RefreshResult, StaleValueBehavior, \
    RefreshCachedSupplier, NonBlocking
from alibabacloud_credentials.http import HttpOptions
from Tea.core import TeaCore
from apscheduler.schedulers.background import BackgroundScheduler
from alibabacloud_credentials_api import ICredentialsProvider
from alibabacloud_credentials.utils import auth_util as au
from alibabacloud_credentials.utils import parameter_helper as ph
from alibabacloud_credentials.exceptions import CredentialException

log = logging.getLogger('credentials')
log.setLevel(logging.INFO)
ch = logging.StreamHandler()
log.addHandler(ch)


class EcsRamRoleCredentialsProvider(ICredentialsProvider):
    DEFAULT_METADATA_TOKEN_DURATION = 21600
    DEFAULT_CONNECT_TIMEOUT = 1000
    DEFAULT_READ_TIMEOUT = 1000

    def __init__(self, *,
                 role_name: str = None,
                 disable_imds_v1: bool = None,
                 http_options: HttpOptions = None,
                 async_update_enabled: bool = True):

        if au.environment_ecs_metadata_disabled.lower() == 'true':
            raise ValueError('IMDS credentials is disabled')

        self.__url_in_ecs_metadata = '/latest/meta-data/ram/security-credentials/'
        self.__url_in_ecs_metadata_token = '/latest/api/token'
        self.__ecs_metadata_fetch_error_msg = 'Failed to get RAM session credentials from ECS metadata service.'
        self.__ecs_metadata_token_fetch_error_msg = 'Failed to get token from ECS Metadata Service.'
        self.__metadata_service_host = '100.100.100.200'
        self._should_refresh = False

        self._role_name = role_name if role_name is not None else au.environment_ecs_metadata
        self._disable_imds_v1 = disable_imds_v1 if disable_imds_v1 is not None else au.environment_imds_v1_disabled.lower() == 'true'
        self._http_options = http_options if http_options is not None else HttpOptions()
        self._runtime_options = {
            'connectTimeout': self._http_options.connect_timeout if self._http_options.connect_timeout is not None else EcsRamRoleCredentialsProvider.DEFAULT_CONNECT_TIMEOUT,
            'readTimeout': self._http_options.read_timeout if self._http_options.read_timeout is not None else EcsRamRoleCredentialsProvider.DEFAULT_READ_TIMEOUT,
            'httpProxy': self._http_options.proxy
        }

        if async_update_enabled:
            self._credentials_cache = RefreshCachedSupplier(
                refresh_callable=self._refresh_credentials,
                refresh_callable_async=self._refresh_credentials_async,
                stale_value_behavior=StaleValueBehavior.ALLOW,
                prefetch_strategy=NonBlocking()
            )

            scheduler = BackgroundScheduler()

            def refresh_task():
                if self._should_refresh:
                    log.debug(f'Begin checking or refreshing credentials asynchronously')
                    self.get_credentials()

            scheduler.add_job(refresh_task, 'interval', minutes=1)
            scheduler.start()

            def shutdown_handler(signum, frame):
                log.debug(f'Shutting down scheduler...')
                scheduler.shutdown(wait=False)

            signal.signal(signal.SIGINT, shutdown_handler)
            signal.signal(signal.SIGTERM, shutdown_handler)

        else:
            self._credentials_cache = RefreshCachedSupplier(
                refresh_callable=self._refresh_credentials,
                refresh_callable_async=self._refresh_credentials_async,
                stale_value_behavior=StaleValueBehavior.ALLOW
            )

    def get_credentials(self) -> Credentials:
        return self._credentials_cache._sync_call()

    async def get_credentials_async(self) -> Credentials:
        return await self._credentials_cache._async_call()

    def _get_role_name(self, url: str = None) -> str:
        tea_request = ph.get_new_request()
        tea_request.headers['host'] = url if url else self.__metadata_service_host
        metadata_token = self._get_metadata_token(url)
        if metadata_token is not None:
            tea_request.headers['X-aliyun-ecs-metadata-token'] = metadata_token
        if not url:
            tea_request.pathname = self.__url_in_ecs_metadata
        response = TeaCore.do_action(tea_request, self._runtime_options)
        if response.status_code != 200:
            raise CredentialException(self.__ecs_metadata_fetch_error_msg + ' HttpCode=' + str(response.status_code))
        return response.body.decode('utf-8')

    async def _get_role_name_async(self, url: str = None) -> str:
        tea_request = ph.get_new_request()
        tea_request.headers['host'] = url if url else self.__metadata_service_host
        metadata_token = await self._get_metadata_token_async(url)
        if metadata_token is not None:
            tea_request.headers['X-aliyun-ecs-metadata-token'] = metadata_token
        if not url:
            tea_request.pathname = self.__url_in_ecs_metadata
        response = await TeaCore.async_do_action(tea_request, self._runtime_options)
        if response.status_code != 200:
            raise CredentialException(self.__ecs_metadata_fetch_error_msg + ' HttpCode=' + str(response.status_code))
        return response.body.decode('utf-8')

    def _get_metadata_token(self, url: str = None) -> str:
        tea_request = ph.get_new_request()
        tea_request.method = 'PUT'
        tea_request.headers['host'] = url if url else self.__metadata_service_host
        tea_request.headers['X-aliyun-ecs-metadata-token-ttl-seconds'] = str(
            EcsRamRoleCredentialsProvider.DEFAULT_METADATA_TOKEN_DURATION)
        if not url:
            tea_request.pathname = self.__url_in_ecs_metadata_token
        try:
            response = TeaCore.do_action(tea_request, self._runtime_options)
            if response.status_code != 200:
                raise CredentialException(
                    self.__ecs_metadata_token_fetch_error_msg + ' HttpCode=' + str(response.status_code))
            return response.body.decode('utf-8')
        except Exception as e:
            if self._disable_imds_v1:
                raise e
            return None

    async def _get_metadata_token_async(self, url: str = None) -> str:
        tea_request = ph.get_new_request()
        tea_request.method = 'PUT'
        tea_request.headers['host'] = url if url else self.__metadata_service_host
        tea_request.headers['X-aliyun-ecs-metadata-token-ttl-seconds'] = str(
            EcsRamRoleCredentialsProvider.DEFAULT_METADATA_TOKEN_DURATION)
        if not url:
            tea_request.pathname = self.__url_in_ecs_metadata_token
        try:
            response = await TeaCore.async_do_action(tea_request, self._runtime_options)
            if response.status_code != 200:
                raise CredentialException(
                    self.__ecs_metadata_token_fetch_error_msg + ' HttpCode=' + str(response.status_code))
            return response.body.decode('utf-8')
        except Exception as e:
            if self._disable_imds_v1:
                raise e
            return None

    def _refresh_credentials(self, url: str = None) -> RefreshResult[Credentials]:
        role_name = self._role_name
        if self._role_name is None or self._role_name == '':
            role_name = self._get_role_name(url)
        tea_request = ph.get_new_request()
        tea_request.headers['host'] = url if url else self.__metadata_service_host
        metadata_token = self._get_metadata_token(url)
        if metadata_token is not None:
            tea_request.headers['X-aliyun-ecs-metadata-token'] = metadata_token
        if not url:
            tea_request.pathname = self.__url_in_ecs_metadata + role_name
        # request
        response = TeaCore.do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(self.__ecs_metadata_fetch_error_msg + ' HttpCode=' + str(response.status_code))

        dic = json.loads(response.body.decode('utf-8'))
        content_code = dic.get('Code')
        content_access_key_id = dic.get('AccessKeyId')
        content_access_key_secret = dic.get('AccessKeySecret')
        content_security_token = dic.get('SecurityToken')
        content_expiration = dic.get('Expiration')

        if content_code != 'Success':
            raise CredentialException(self.__ecs_metadata_fetch_error_msg)

        # 先转换为时间数组
        time_array = time.strptime(content_expiration, '%Y-%m-%dT%H:%M:%SZ')
        # 转换为时间戳
        expiration = calendar.timegm(time_array)
        credentials = Credentials(
            access_key_id=content_access_key_id,
            access_key_secret=content_access_key_secret,
            security_token=content_security_token,
            expiration=expiration,
            provider_name=self.get_provider_name()
        )
        self._should_refresh = True
        return RefreshResult(value=credentials,
                             stale_time=self._get_stale_time(expiration),
                             prefetch_time=self._get_prefetch_time(expiration))

    async def _refresh_credentials_async(self, url: str = None) -> RefreshResult[Credentials]:
        role_name = self._role_name
        if self._role_name is None:
            role_name = await self._get_role_name_async(url)
        tea_request = ph.get_new_request()
        tea_request.headers['host'] = url if url else self.__metadata_service_host
        metadata_token = await self._get_metadata_token_async(url)
        if metadata_token is not None:
            tea_request.headers['X-aliyun-ecs-metadata-token'] = metadata_token
        if not url:
            tea_request.pathname = self.__url_in_ecs_metadata + role_name

        # request
        response = await TeaCore.async_do_action(tea_request, self._runtime_options)

        if response.status_code != 200:
            raise CredentialException(self.__ecs_metadata_fetch_error_msg + ' HttpCode=' + str(response.status_code))

        dic = json.loads(response.body.decode('utf-8'))
        content_code = dic.get('Code')
        content_access_key_id = dic.get('AccessKeyId')
        content_access_key_secret = dic.get('AccessKeySecret')
        content_security_token = dic.get('SecurityToken')
        content_expiration = dic.get('Expiration')

        if content_code != 'Success':
            raise CredentialException(self.__ecs_metadata_fetch_error_msg)

        # 先转换为时间数组
        time_array = time.strptime(content_expiration, '%Y-%m-%dT%H:%M:%SZ')
        # 转换为时间戳
        expiration = calendar.timegm(time_array)
        credentials = Credentials(
            access_key_id=content_access_key_id,
            access_key_secret=content_access_key_secret,
            security_token=content_security_token,
            expiration=expiration,
            provider_name=self.get_provider_name()
        )
        self._should_refresh = True
        return RefreshResult(value=credentials,
                             stale_time=self._get_stale_time(expiration),
                             prefetch_time=self._get_prefetch_time(expiration))

    def _get_stale_time(self, expiration: int) -> int:
        if expiration < 0:
            return int(time.mktime(time.localtime())) + 60 * 60
        return expiration - 15 * 60

    def _get_prefetch_time(self, expiration: int) -> int:
        if expiration < 0:
            return int(time.mktime(time.localtime())) + 5 * 60
        return int(time.mktime(time.localtime())) + 60 * 60

    def get_provider_name(self) -> str:
        return 'ecs_ram_role'

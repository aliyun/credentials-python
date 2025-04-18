import os
import json
from typing import Any, Dict

import aiofiles

from alibabacloud_credentials.provider import StaticAKCredentialsProvider, EcsRamRoleCredentialsProvider, \
    RamRoleArnCredentialsProvider, OIDCRoleArnCredentialsProvider, StaticSTSCredentialsProvider
from .refreshable import Credentials
from alibabacloud_credentials_api import ICredentialsProvider
from alibabacloud_credentials.utils import auth_constant as ac
from alibabacloud_credentials.utils import auth_util as au
from alibabacloud_credentials.exceptions import CredentialException


async def _load_config_async(file_path: str) -> Any:
    async with aiofiles.open(file_path, mode='r') as f:
        content = await f.read()
    return json.loads(content)


def _load_config(file_path: str) -> Any:
    with open(file_path, mode='r') as f:
        content = f.read()
    return json.loads(content)


class CLIProfileCredentialsProvider(ICredentialsProvider):

    def __init__(self, *,
                 profile_name: str = None):
        self._profile_file = os.path.join(ac.HOME, ".aliyun/config.json")
        self._profile_name = profile_name or au.environment_profile_name
        self.__innerProvider = None

    def _should_reload_credentials_provider(self) -> bool:
        if self.__innerProvider is None:
            return True
        return False

    def get_credentials(self) -> Credentials:
        if au.environment_cli_profile_disabled.lower() == "true":
            raise CredentialException('cli credentials file is disabled')

        if self._should_reload_credentials_provider():
            if not os.path.exists(self._profile_file) or not os.path.isfile(self._profile_file):
                raise CredentialException(f'unable to open credentials file: {self._profile_file}')
            try:
                config = _load_config(self._profile_file)
            except Exception as e:
                raise CredentialException(
                    f'failed to parse credential form cli credentials file: {self._profile_file}')
            if config is None:
                raise CredentialException(
                    f'failed to parse credential form cli credentials file: {self._profile_file}')

            profile_name = self._profile_name
            if self._profile_name is None or self._profile_name == '':
                profile_name = config.get('current')
            self.__innerProvider = self._get_credentials_provider(config, profile_name)

        cre = self.__innerProvider.get_credentials()
        credentials = Credentials(
            access_key_id=cre.get_access_key_id(),
            access_key_secret=cre.get_access_key_secret(),
            security_token=cre.get_security_token(),
            provider_name=f'{self.get_provider_name()}/{cre.get_provider_name()}'
        )
        return credentials

    async def get_credentials_async(self) -> Credentials:
        if au.environment_cli_profile_disabled.lower() == "true":
            raise CredentialException('cli credentials file is disabled')

        if self._should_reload_credentials_provider():
            if not os.path.exists(self._profile_file) or not os.path.isfile(self._profile_file):
                raise CredentialException(f'unable to open credentials file: {self._profile_file}')
            try:
                config = await _load_config_async(self._profile_file)
            except Exception as e:
                raise CredentialException(
                    f'failed to parse credential form cli credentials file: {self._profile_file}')
            if config is None:
                raise CredentialException(
                    f'failed to parse credential form cli credentials file: {self._profile_file}')

            profile_name = self._profile_name
            if self._profile_name is None or self._profile_name == '':
                profile_name = config.get('current')
            self.__innerProvider = self._get_credentials_provider(config, profile_name)

        cre = await self.__innerProvider.get_credentials_async()
        credentials = Credentials(
            access_key_id=cre.get_access_key_id(),
            access_key_secret=cre.get_access_key_secret(),
            security_token=cre.get_security_token(),
            provider_name=f'{self.get_provider_name()}/{cre.get_provider_name()}'
        )
        return credentials

    def _get_credentials_provider(self, config: Dict, profile_name: str) -> ICredentialsProvider:
        if profile_name is None or profile_name == '':
            raise CredentialException('invalid profile name')

        profiles = config.get('profiles', [])

        if not profiles:
            raise CredentialException(f"unable to get profile with '{profile_name}' form cli credentials file.")

        for profile in profiles:
            if profile.get('name') is not None and profile['name'] == profile_name:
                mode = profile.get('mode')
                if mode == "AK":
                    return StaticAKCredentialsProvider(
                        access_key_id=profile.get('access_key_id'),
                        access_key_secret=profile.get('access_key_secret')
                    )
                elif mode == "StsToken":
                    return StaticSTSCredentialsProvider(
                        access_key_id=profile.get('access_key_id'),
                        access_key_secret=profile.get('access_key_secret'),
                        security_token=profile.get('sts_token')
                    )
                elif mode == "RamRoleArn":
                    pre_provider = StaticAKCredentialsProvider(
                        access_key_id=profile.get('access_key_id'),
                        access_key_secret=profile.get('access_key_secret')
                    )
                    return RamRoleArnCredentialsProvider(
                        credentials_provider=pre_provider,
                        role_arn=profile.get('ram_role_arn'),
                        role_session_name=profile.get('ram_session_name'),
                        duration_seconds=profile.get('expired_seconds'),
                        policy=profile.get('policy'),
                        external_id=profile.get('external_id'),
                        sts_region_id=profile.get('sts_region'),
                        enable_vpc=profile.get('enable_vpc'),
                    )
                elif mode == "EcsRamRole":
                    return EcsRamRoleCredentialsProvider(
                        role_name=profile.get('ram_role_name')
                    )
                elif mode == "OIDC":
                    return OIDCRoleArnCredentialsProvider(
                        role_arn=profile.get('ram_role_arn'),
                        oidc_provider_arn=profile.get('oidc_provider_arn'),
                        oidc_token_file_path=profile.get('oidc_token_file'),
                        role_session_name=profile.get('role_session_name'),
                        duration_seconds=profile.get('expired_seconds'),
                        policy=profile.get('policy'),
                        sts_region_id=profile.get('sts_region'),
                        enable_vpc=profile.get('enable_vpc'),
                    )
                elif mode == "ChainableRamRoleArn":
                    previous_provider = self._get_credentials_provider(config, profile.get('source_profile'))
                    return RamRoleArnCredentialsProvider(
                        credentials_provider=previous_provider,
                        role_arn=profile.get('ram_role_arn'),
                        role_session_name=profile.get('ram_session_name'),
                        duration_seconds=profile.get('expired_seconds'),
                        policy=profile.get('policy'),
                        external_id=profile.get('external_id'),
                        sts_region_id=profile.get('sts_region'),
                        enable_vpc=profile.get('enable_vpc'),
                    )
                else:
                    raise CredentialException(f"unsupported profile mode '{mode}' form cli credentials file.")

        raise CredentialException(f"unable to get profile with '{profile_name}' form cli credentials file.")

    def get_provider_name(self) -> str:
        return 'cli_profile'

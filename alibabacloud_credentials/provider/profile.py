import os
import configparser
from typing import Dict

import aiofiles

from alibabacloud_credentials.provider import StaticAKCredentialsProvider, EcsRamRoleCredentialsProvider, \
    RamRoleArnCredentialsProvider, OIDCRoleArnCredentialsProvider, RsaKeyPairCredentialsProvider
from alibabacloud_credentials.provider.refreshable import Credentials
from alibabacloud_credentials_api import ICredentialsProvider
from alibabacloud_credentials.utils import auth_constant as ac
from alibabacloud_credentials.utils import auth_util as au
from alibabacloud_credentials.exceptions import CredentialException


async def _load_ini_async(file_path: str) -> Dict[str, Dict[str, str]]:
    config = configparser.ConfigParser()
    async with aiofiles.open(file_path, mode='r') as f:
        content = await f.read()
    config.read_string(content)
    ini_map = {}
    for section in config.sections():
        option = {}
        for key, value in config.items(section):
            if '#' in value:
                option[key] = value.split('#')[0].strip()
            else:
                option[key] = value.strip()
        ini_map[section] = option
    return ini_map


def _load_ini(file_path: str) -> Dict[str, Dict[str, str]]:
    config = configparser.ConfigParser()
    config.read(file_path, encoding='utf-8')
    ini_map = {}
    for section in config.sections():
        option = {}
        for key, value in config.items(section):
            if '#' in value:
                option[key] = value.split('#')[0].strip()
            else:
                option[key] = value.strip()
        ini_map[section] = option
    return ini_map


def _get_default_file() -> str:
    return os.path.join(ac.HOME, ".alibabacloud/credentials.ini")


class ProfileCredentialsProvider(ICredentialsProvider):

    def __init__(self, *,
                 profile_file: str = None,
                 profile_name: str = None):
        self._profile_file = profile_file or au.environment_credentials_file
        self._profile_name = profile_name or au.client_type
        self.__innerProvider = None

        if self._profile_file is None or self._profile_file == '':
            self._profile_file = _get_default_file()

    def _should_reload_credentials_provider(self) -> bool:
        if self.__innerProvider is None:
            return True
        return False

    def get_credentials(self) -> Credentials:
        if self._should_reload_credentials_provider():
            ini_map = _load_ini(self._profile_file)
            section = ini_map.get(self._profile_name)
            if section is None:
                raise CredentialException(f'failed to get credential from credentials file: ${self._profile_file}')
            self.__innerProvider = self._get_credentials_provider(section)

        cre = self.__innerProvider.get_credentials()
        credentials = Credentials(
            access_key_id=cre.get_access_key_id(),
            access_key_secret=cre.get_access_key_secret(),
            security_token=cre.get_security_token(),
            provider_name=f'{self.get_provider_name()}/{cre.get_provider_name()}'
        )
        return credentials

    async def get_credentials_async(self) -> Credentials:
        if self._should_reload_credentials_provider():
            ini_map = await _load_ini_async(self._profile_file)
            section = ini_map.get(self._profile_name)
            if section is None:
                raise CredentialException(f'failed to get credential from credentials file: ${self._profile_file}')
            self.__innerProvider = self._get_credentials_provider(section)

        cre = await self.__innerProvider.get_credentials_async()
        credentials = Credentials(
            access_key_id=cre.get_access_key_id(),
            access_key_secret=cre.get_access_key_secret(),
            security_token=cre.get_security_token(),
            provider_name=f'{self.get_provider_name()}/{cre.get_provider_name()}'
        )
        return credentials

    def _get_credentials_provider(self, section: Dict) -> ICredentialsProvider:

        config_type = section.get(ac.INI_TYPE)
        if 'access_key' == config_type:
            return StaticAKCredentialsProvider(
                access_key_id=section.get('access_key_id'),
                access_key_secret=section.get('access_key_secret')
            )
        elif 'ram_role_arn' == config_type:
            pre_provider = StaticAKCredentialsProvider(
                access_key_id=section.get('access_key_id'),
                access_key_secret=section.get('access_key_secret')
            )
            return RamRoleArnCredentialsProvider(
                credentials_provider=pre_provider,
                role_arn=section.get('role_arn'),
                role_session_name=section.get('role_session_name'),
                policy=section.get('policy')
            )
        elif 'oidc_role_arn' == config_type:
            return OIDCRoleArnCredentialsProvider(
                role_arn=section.get('role_arn'),
                oidc_provider_arn=section.get('oidc_provider_arn'),
                oidc_token_file_path=section.get('oidc_token_file_path'),
                role_session_name=section.get('role_session_name'),
                policy=section.get('policy')
            )
        elif 'ecs_ram_role' == config_type:
            return EcsRamRoleCredentialsProvider(
                role_name=section.get('role_name')
            )
        elif 'rsa_key_pair' == config_type:
            return RsaKeyPairCredentialsProvider(
                public_key_id=section.get('public_key_id'),
                private_key_file=section.get('private_key_file')
            )
        else:
            raise CredentialException(
                f'unsupported credential type {config_type} from credentials file {self._profile_file}')

    def get_provider_name(self) -> str:
        return 'profile'

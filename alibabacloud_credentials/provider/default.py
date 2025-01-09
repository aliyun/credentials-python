from . import EnvironmentVariableCredentialsProvider, EcsRamRoleCredentialsProvider, \
    OIDCRoleArnCredentialsProvider, URLCredentialsProvider, CLIProfileCredentialsProvider, ProfileCredentialsProvider

from alibabacloud_credentials.provider.refreshable import Credentials
from alibabacloud_credentials_api import ICredentialsProvider
from alibabacloud_credentials.utils import auth_util as au
from alibabacloud_credentials.exceptions import CredentialException


class DefaultCredentialsProvider(ICredentialsProvider):

    def __init__(self, *,
                 reuse_last_provider_enabled: bool = True):

        self.__reuse_last_provider_enabled = reuse_last_provider_enabled
        self.__last_used_provider = None

        self.__providers_chain = [
            EnvironmentVariableCredentialsProvider()
        ]
        if au.enable_oidc_credential:
            self.__providers_chain.append(OIDCRoleArnCredentialsProvider())

        self.__providers_chain.append(CLIProfileCredentialsProvider())
        self.__providers_chain.append(ProfileCredentialsProvider())
        if au.environment_ecs_metadata_disabled.lower() != 'true':
            self.__providers_chain.append(EcsRamRoleCredentialsProvider())

        if au.environment_credentials_uri is not None and au.environment_credentials_uri != '':
            self.__providers_chain.append(URLCredentialsProvider())

    def get_credentials(self) -> Credentials:
        if self.__reuse_last_provider_enabled and self.__last_used_provider is not None:
            credentials = self.__last_used_provider.get_credentials()
            return Credentials(
                access_key_id=credentials.get_access_key_id(),
                access_key_secret=credentials.get_access_key_secret(),
                security_token=credentials.get_security_token(),
                provider_name=f'{self.get_provider_name()}/{credentials.get_provider_name()}'
            )

        error_messages = []
        for provider in self.__providers_chain:
            try:
                credentials = provider.get_credentials()
                if credentials is not None:
                    self.__last_used_provider = provider
                    return Credentials(
                        access_key_id=credentials.get_access_key_id(),
                        access_key_secret=credentials.get_access_key_secret(),
                        security_token=credentials.get_security_token(),
                        provider_name=f'{self.get_provider_name()}/{credentials.get_provider_name()}'
                    )
            except Exception as e:
                error_messages.append(f'{type(provider).__name__}: {str(e)}')

        raise CredentialException(
            f'unable to load credentials from any of the providers in the chain: {error_messages}')

    async def get_credentials_async(self) -> Credentials:
        if self.__reuse_last_provider_enabled and self.__last_used_provider is not None:
            credentials = await self.__last_used_provider.get_credentials_async()
            return Credentials(
                access_key_id=credentials.get_access_key_id(),
                access_key_secret=credentials.get_access_key_secret(),
                security_token=credentials.get_security_token(),
                provider_name=f'{self.get_provider_name()}/{credentials.get_provider_name()}'
            )

        error_messages = []
        for provider in self.__providers_chain:
            try:
                credentials = await provider.get_credentials_async()
                if credentials is not None:
                    self.__last_used_provider = provider
                    return Credentials(
                        access_key_id=credentials.get_access_key_id(),
                        access_key_secret=credentials.get_access_key_secret(),
                        security_token=credentials.get_security_token(),
                        provider_name=f'{self.get_provider_name()}/{credentials.get_provider_name()}'
                    )
            except Exception as e:
                error_messages.append(f'{type(provider).__name__}: {str(e)}')

        raise CredentialException(
            f'unable to load credentials from any of the providers in the chain: {error_messages}')

    def get_provider_name(self) -> str:
        return 'default'

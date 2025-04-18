from functools import wraps

from alibabacloud_credentials_api import ICredentialsProvider
from alibabacloud_credentials import credentials
from alibabacloud_credentials.exceptions import CredentialException
from alibabacloud_credentials.models import Config, CredentialModel
from alibabacloud_credentials.http import HttpOptions
from alibabacloud_credentials.provider import (StaticAKCredentialsProvider,
                                               StaticSTSCredentialsProvider,
                                               RamRoleArnCredentialsProvider,
                                               OIDCRoleArnCredentialsProvider,
                                               RsaKeyPairCredentialsProvider,
                                               EcsRamRoleCredentialsProvider,
                                               URLCredentialsProvider,
                                               DefaultCredentialsProvider)
from alibabacloud_credentials.utils import auth_constant as ac
from Tea.decorators import deprecated


def attribute_error_return_none(f):
    @wraps(f)
    def i(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except AttributeError:
            return

    return i


class _CredentialsProviderWrap:

    def __init__(self,
                 *,
                 type_name: str = None,
                 provider: ICredentialsProvider = None):
        self.type_name = type_name
        self.provider = provider

    def get_access_key_id(self) -> str:
        credential = self.provider.get_credentials()
        return credential.get_access_key_id()

    async def get_access_key_id_async(self) -> str:
        credential = await self.provider.get_credentials_async()
        return credential.get_access_key_id()

    def get_access_key_secret(self) -> str:
        credential = self.provider.get_credentials()
        return credential.get_access_key_secret()

    async def get_access_key_secret_async(self) -> str:
        credential = await self.provider.get_credentials_async()
        return credential.get_access_key_secret()

    def get_security_token(self):
        credential = self.provider.get_credentials()
        return credential.get_security_token()

    async def get_security_token_async(self):
        credential = await self.provider.get_credentials_async()
        return credential.get_security_token()

    def get_credential(self) -> CredentialModel:
        credential = self.provider.get_credentials()
        return CredentialModel(
            access_key_id=credential.get_access_key_id(),
            access_key_secret=credential.get_access_key_secret(),
            security_token=credential.get_security_token(),
            type=self.type_name,
            provider_name=credential.get_provider_name(),
        )

    async def get_credential_async(self) -> CredentialModel:
        credential = await self.provider.get_credentials_async()
        return CredentialModel(
            access_key_id=credential.get_access_key_id(),
            access_key_secret=credential.get_access_key_secret(),
            security_token=credential.get_security_token(),
            type=self.type_name,
            provider_name=credential.get_provider_name(),
        )

    def get_type(self) -> str:
        return self.type_name


class Client:
    cloud_credential = None

    def __init__(self,
                 config: Config = None,
                 provider: ICredentialsProvider = None):
        if provider is not None:
            self.cloud_credential = _CredentialsProviderWrap(type_name=provider.get_provider_name(), provider=provider)
        elif config is None:
            provider = DefaultCredentialsProvider()
            self.cloud_credential = _CredentialsProviderWrap(type_name='default', provider=provider)
        else:
            self.cloud_credential = Client.get_credentials(config)

    def get_credential(self) -> CredentialModel:
        """
        Get credential
        @return: the whole credential
        """
        return self.cloud_credential.get_credential()

    async def get_credential_async(self) -> CredentialModel:
        """
        Get credential
        @return: the whole credential
        """
        return await self.cloud_credential.get_credential_async()

    @staticmethod
    def get_credentials(config):
        if config.type == ac.ACCESS_KEY:
            provider = StaticAKCredentialsProvider(
                access_key_id=config.access_key_id,
                access_key_secret=config.access_key_secret,
            )
            return _CredentialsProviderWrap(type_name='access_key', provider=provider)
        elif config.type == ac.STS:
            provider = StaticSTSCredentialsProvider(
                access_key_id=config.access_key_id,
                access_key_secret=config.access_key_secret,
                security_token=config.security_token,
            )
            return _CredentialsProviderWrap(type_name='sts', provider=provider)
        elif config.type == ac.BEARER:
            return credentials.BearerTokenCredential(config.bearer_token)
        elif config.type == ac.ECS_RAM_ROLE:
            provider = EcsRamRoleCredentialsProvider(
                role_name=config.role_name,
                disable_imds_v1=config.disable_imds_v1,
                http_options=HttpOptions(
                    read_timeout=config.timeout,
                    connect_timeout=config.connect_timeout,
                    proxy=config.proxy,
                ),
            )
            return _CredentialsProviderWrap(type_name='ecs_ram_role', provider=provider)
        elif config.type == ac.CREDENTIALS_URI:
            provider = URLCredentialsProvider(
                uri=config.credentials_uri,
                http_options=HttpOptions(
                    read_timeout=config.timeout,
                    connect_timeout=config.connect_timeout,
                    proxy=config.proxy,
                ),
            )
            return _CredentialsProviderWrap(type_name='credentials_uri', provider=provider)
        elif config.type == ac.RAM_ROLE_ARN:
            if config.security_token is not None and config.security_token != '':
                previous_provider = StaticSTSCredentialsProvider(
                    access_key_id=config.access_key_id,
                    access_key_secret=config.access_key_secret,
                    security_token=config.security_token,
                )
            else:
                previous_provider = StaticAKCredentialsProvider(
                    access_key_id=config.access_key_id,
                    access_key_secret=config.access_key_secret,
                )
            provider = RamRoleArnCredentialsProvider(
                credentials_provider=previous_provider,
                role_arn=config.role_arn,
                role_session_name=config.role_session_name,
                duration_seconds=config.role_session_expiration,
                policy=config.policy,
                external_id=config.external_id,
                sts_endpoint=config.sts_endpoint,
                http_options=HttpOptions(
                    read_timeout=config.timeout,
                    connect_timeout=config.connect_timeout,
                    proxy=config.proxy,
                ),
            )
            return _CredentialsProviderWrap(type_name='ram_role_arn', provider=provider)
        elif config.type == ac.RSA_KEY_PAIR:
            provider = RsaKeyPairCredentialsProvider(
                public_key_id=config.public_key_id,
                private_key_file=config.private_key_file,
                duration_seconds=config.role_session_expiration,
                sts_endpoint=config.sts_endpoint,
                http_options=HttpOptions(
                    read_timeout=config.timeout,
                    connect_timeout=config.connect_timeout,
                    proxy=config.proxy,
                ),
            )
            return _CredentialsProviderWrap(type_name='rsa_key_pair', provider=provider)
        elif config.type == ac.OIDC_ROLE_ARN:
            provider = OIDCRoleArnCredentialsProvider(
                role_arn=config.role_arn,
                oidc_provider_arn=config.oidc_provider_arn,
                oidc_token_file_path=config.oidc_token_file_path,
                role_session_name=config.role_session_name,
                duration_seconds=config.role_session_expiration,
                policy=config.policy,
                sts_endpoint=config.sts_endpoint,
                http_options=HttpOptions(
                    read_timeout=config.timeout,
                    connect_timeout=config.connect_timeout,
                    proxy=config.proxy,
                ),
            )
            return _CredentialsProviderWrap(type_name='oidc_role_arn', provider=provider)
        raise CredentialException(
            'invalid type option, support: access_key, sts, bearer, ecs_ram_role, ram_role_arn, rsa_key_pair, oidc_role_arn, credentials_uri')

    @deprecated("Use 'get_credential().access_key_id' instead")
    def get_access_key_id(self):
        return self.cloud_credential.get_access_key_id()

    @deprecated("Use 'get_credential().access_key_secret' instead")
    def get_access_key_secret(self):
        return self.cloud_credential.get_access_key_secret()

    @deprecated("Use 'get_credential().security_token' instead")
    def get_security_token(self):
        return self.cloud_credential.get_security_token()

    @deprecated("Use 'get_credential_async().access_key_id' instead")
    async def get_access_key_id_async(self):
        return await self.cloud_credential.get_access_key_id_async()

    @deprecated("Use 'get_credential_async().access_key_secret' instead")
    async def get_access_key_secret_async(self):
        return await self.cloud_credential.get_access_key_secret_async()

    @deprecated("Use 'get_credential_async().security_token' instead")
    async def get_security_token_async(self):
        return await self.cloud_credential.get_security_token_async()

    @deprecated("Use 'get_credential().type' instead")
    @attribute_error_return_none
    def get_type(self):
        return self.cloud_credential.get_type()

    @deprecated("Use 'get_credential().bearer_token' instead")
    @attribute_error_return_none
    def get_bearer_token(self):
        return self.cloud_credential.bearer_token

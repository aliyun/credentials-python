from alibabacloud_credentials import providers, credentials
from alibabacloud_credentials.utils import auth_constant as ac
from functools import wraps


def attribute_error_return_none(f):
    @wraps(f)
    def i(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except AttributeError:
            return

    return i


class Client:
    cloud_credential = None

    def __init__(self, config=None):
        if config is None:
            provider = providers.DefaultCredentialsProvider()
            self.cloud_credential = provider.get_credentials()
        self.cloud_credential = self.get_credential(config)

    def get_credential(self, config):
        if config.type == ac.ACCESS_KEY:
            return credentials.AccessKeyCredential(config.access_key_id, config.access_key_secret)
        elif config.type == ac.STS:
            return credentials.StsCredential(config.access_key_id, config.access_key_secret, config.security_token)
        elif config.type == ac.BEARER:
            return credentials.BearerTokenCredential(config.bearer_token)
        else:
            return self.get_provider(config).get_credentials()

    @staticmethod
    def get_provider(config):
        if config.type == ac.ECS_RAM_ROLE:
            return providers.EcsRamRoleCredentialProvider(config=config)
        elif config.type == ac.RAM_ROLE_ARN:
            return providers.RamRoleArnCredentialProvider(config=config)
        elif config.type == ac.RSA_KEY_PAIR:
            return providers.RsaKeyPairCredentialProvider(config=config)
        return providers.DefaultCredentialsProvider()

    @attribute_error_return_none
    def get_access_key_id(self):
        return self.cloud_credential.access_key_id

    @attribute_error_return_none
    def get_access_key_secret(self):
        return self.cloud_credential.access_key_secret

    @attribute_error_return_none
    def get_security_token(self):
        return self.cloud_credential.security_token

    @attribute_error_return_none
    def get_type(self):
        return self.cloud_credential.credential_type

    @attribute_error_return_none
    def get_bearer_token(self):
        return self.cloud_credential.bearer_token

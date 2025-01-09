from alibabacloud_credentials.provider.refreshable import Credentials
from alibabacloud_credentials_api import ICredentialsProvider
from alibabacloud_credentials.utils import auth_util


class StaticSTSCredentialsProvider(ICredentialsProvider):

    def __init__(self, *,
                 access_key_id: str = None,
                 access_key_secret: str = None,
                 security_token: str = None):

        self.access_key_id = access_key_id or auth_util.environment_access_key_id
        self.access_key_secret = access_key_secret or auth_util.environment_access_key_secret
        self.security_token = security_token or auth_util.environment_security_token

        if self.access_key_id is None or self.access_key_id == '':
            raise ValueError('the access key id is empty')
        if self.access_key_secret is None or self.access_key_secret == '':
            raise ValueError('the access key secret is empty')
        if self.security_token is None or self.security_token == '':
            raise ValueError('the security token is empty')

    def get_credentials(self) -> Credentials:

        return Credentials(
            access_key_id=self.access_key_id,
            access_key_secret=self.access_key_secret,
            security_token=self.security_token,
            provider_name=self.get_provider_name()
        )

    async def get_credentials_async(self) -> Credentials:
        return self.get_credentials()

    def get_provider_name(self) -> str:
        return 'static_sts'

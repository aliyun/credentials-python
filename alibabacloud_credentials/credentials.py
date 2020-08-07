import time

from alibabacloud_credentials.utils import auth_constant as ac


class _AutomaticallyRefreshCredentials:
    def __init__(self, expiration, provider, refresh_fields):
        self.expiration = expiration
        self.provider = provider
        self._REFRESH_FIELDS = refresh_fields

    def _with_should_refresh(self):
        return int(time.mktime(time.localtime())) >= (object.__getattribute__(self, 'expiration') - 180)

    def _get_new_credential(self):
        return self.provider.get_credentials()

    def _refresh_credential(self):
        if self._with_should_refresh():
            return self._get_new_credential()

    def __getattribute__(self, item):
        if item in object.__getattribute__(self, '__dict__')['_REFRESH_FIELDS']:
            self._refresh_credential()
        return object.__getattribute__(self, item)


class AccessKeyCredential:
    """AccessKeyCredential"""

    def __init__(self, access_key_id, access_key_secret):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.credential_type = ac.ACCESS_KEY


class BearerTokenCredential:
    """BearerTokenCredential"""

    def __init__(self, bearer_token):
        self.bearer_token = bearer_token
        self.credential_type = ac.BEARER


class EcsRamRoleCredential(_AutomaticallyRefreshCredentials):
    """EcsRamRoleCredential"""

    def __init__(self, access_key_id, access_key_secret, security_token, expiration, provider):
        refresh_fields = (
            'access_key_id',
            'access_key_secret',
            'security_token',
            'expiration'
        )
        super().__init__(expiration, provider, refresh_fields)
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.security_token = security_token
        self.credential_type = ac.ECS_RAM_ROLE

    def _refresh_credential(self):
        credential = super()._refresh_credential()
        if credential:
            self.access_key_id = credential.access_key_id
            self.access_key_secret = credential.access_key_secret
            self.expiration = credential.expiration
            self.security_token = credential.security_token


class RamRoleArnCredential(_AutomaticallyRefreshCredentials):
    """RamRoleArnCredential"""

    def __init__(self, access_key_id, access_key_secret, security_token, expiration, provider):
        refresh_fields = (
            'access_key_id',
            'access_key_secret',
            'security_token',
            'expiration'
        )
        super().__init__(expiration, provider, refresh_fields)
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.security_token = security_token
        self.credential_type = ac.RAM_ROLE_ARN

    def _refresh_credential(self):
        credential = super()._refresh_credential()
        if credential:
            self.access_key_id = credential.access_key_id
            self.access_key_secret = credential.access_key_secret
            self.expiration = credential.expiration
            self.security_token = credential.security_token


class RsaKeyPairCredential(_AutomaticallyRefreshCredentials):
    def __init__(self, access_key_id, access_key_secret, expiration, provider):
        refresh_fields = (
            'access_key_id',
            'access_key_secret',
            'expiration'
        )
        super().__init__(expiration, provider, refresh_fields)
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.credential_type = ac.RSA_KEY_PAIR

    def _refresh_credential(self):
        credential = super()._refresh_credential()
        if credential:
            self.access_key_id = credential.access_key_id
            self.access_key_secret = credential.access_key_secret
            self.expiration = credential.expiration


class StsCredential:
    def __init__(self, access_key_id, access_key_secret, security_token):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.security_token = security_token
        self.credential_type = ac.STS

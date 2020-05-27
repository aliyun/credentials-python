import time

from alibabacloud_credentials.utils import auth_constant as ac


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


class EcsRamRoleCredential:
    """EcsRamRoleCredential"""

    def __init__(self, access_key_id, access_key_secret, security_token, expiration, provider):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.security_token = security_token
        self.expiration = expiration
        self.provider = provider
        self.credential_type = ac.ECS_RAM_ROLE


class RamRoleArnCredential:
    """RamRoleArnCredential"""

    def __init__(self, access_key_id, access_key_secret, security_token, expiration, provider):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.security_token = security_token
        self.expiration = expiration
        self.provider = provider
        self.credential_type = ac.RAM_ROLE_ARN
        self._REFRESH_FIELDS = (
            'access_key_id',
            'access_key_secret',
            'security_token',
            'expiration'
        )

    def _with_should_refresh(self):
        return int(time.mktime(time.localtime())) >= (object.__getattribute__(self, 'expiration') - 180)

    def _get_new_credential(self):
        return self.provider.get_credentials()

    def _refresh_credential(self):
        if self._with_should_refresh():
            credential = self._get_new_credential()
            self.access_key_id = credential.access_key_id
            self.access_key_secret = credential.access_key_secret
            self.expiration = credential.expiration
            self.security_token = credential.security_token

    def __getattribute__(self, item):
        if item in object.__getattribute__(self, '__dict__')['_REFRESH_FIELDS']:
            self._refresh_credential()
        return object.__getattribute__(self, item)


class RsaKeyPairCredential:
    def __init__(self, access_key_id, access_key_secret, expiration, provider):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.expiration = expiration
        self.provider = provider
        self.credential_type = ac.RSA_KEY_PAIR


class StsCredential:
    def __init__(self, access_key_id, access_key_secret, security_token):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.security_token = security_token
        self.credential_type = ac.STS

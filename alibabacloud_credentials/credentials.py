import time

from alibabacloud_credentials.utils import auth_constant as ac


class _AutomaticallyRefreshCredentials:
    def __init__(self, expiration, provider):
        self.expiration = expiration
        self.provider = provider

    def _with_should_refresh(self):
        return int(time.mktime(time.localtime())) >= (self.expiration - 180)

    def _get_new_credential(self):
        return self.provider.get_credentials()

    def _refresh_credential(self):
        if self._with_should_refresh():
            return self._get_new_credential()


class AccessKeyCredential:
    """AccessKeyCredential"""

    def __init__(self, access_key_id, access_key_secret):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.credential_type = ac.ACCESS_KEY

    def get_access_key_id(self):
        return self.access_key_id

    def get_access_key_secret(self):
        return self.access_key_secret


class BearerTokenCredential:
    """BearerTokenCredential"""

    def __init__(self, bearer_token):
        self.bearer_token = bearer_token
        self.credential_type = ac.BEARER


class EcsRamRoleCredential(_AutomaticallyRefreshCredentials):
    """EcsRamRoleCredential"""

    def __init__(self, access_key_id, access_key_secret, security_token, expiration, provider):
        super().__init__(expiration, provider)
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

    def get_access_key_id(self):
        self._refresh_credential()
        return self.access_key_id

    def get_access_key_secret(self):
        self._refresh_credential()
        return self.access_key_secret

    def get_security_token(self):
        self._refresh_credential()
        return self.security_token


class RamRoleArnCredential(_AutomaticallyRefreshCredentials):
    """RamRoleArnCredential"""

    def __init__(self, access_key_id, access_key_secret, security_token, expiration, provider):
        super().__init__(expiration, provider)
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

    def get_access_key_id(self):
        self._refresh_credential()
        return self.access_key_id

    def get_access_key_secret(self):
        self._refresh_credential()
        return self.access_key_secret

    def get_security_token(self):
        self._refresh_credential()
        return self.security_token


class RsaKeyPairCredential(_AutomaticallyRefreshCredentials):
    def __init__(self, access_key_id, access_key_secret, expiration, provider):
        super().__init__(expiration, provider)
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.credential_type = ac.RSA_KEY_PAIR

    def _refresh_credential(self):
        credential = super()._refresh_credential()
        if credential:
            self.access_key_id = credential.access_key_id
            self.access_key_secret = credential.access_key_secret
            self.expiration = credential.expiration

    def get_access_key_id(self):
        self._refresh_credential()
        return self.access_key_id

    def get_access_key_secret(self):
        self._refresh_credential()
        return self.access_key_secret


class StsCredential:
    def __init__(self, access_key_id, access_key_secret, security_token):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.security_token = security_token
        self.credential_type = ac.STS

    def get_access_key_id(self):
        return self.access_key_id

    def get_access_key_secret(self):
        return self.access_key_secret

    def get_security_token(self):
        return self.security_token

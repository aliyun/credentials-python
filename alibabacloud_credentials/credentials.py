import time

from alibabacloud_credentials.utils import auth_constant as ac


class Credential:
    def get_access_key_id(self):
        return

    def get_access_key_secret(self):
        return

    def get_security_token(self):
        return

    async def get_access_key_id_async(self):
        return

    async def get_access_key_secret_async(self):
        return

    async def get_security_token_async(self):
        return


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

    async def _get_new_credential_async(self):
        return await self.provider.get_credentials_async()


class AccessKeyCredential(Credential):
    """AccessKeyCredential"""

    def __init__(self, access_key_id, access_key_secret):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.credential_type = ac.ACCESS_KEY

    def get_access_key_id(self):
        return self.access_key_id

    def get_access_key_secret(self):
        return self.access_key_secret

    async def get_access_key_id_async(self):
        return self.access_key_id

    async def get_access_key_secret_async(self):
        return self.access_key_secret


class BearerTokenCredential(Credential):
    """BearerTokenCredential"""

    def __init__(self, bearer_token):
        self.bearer_token = bearer_token
        self.credential_type = ac.BEARER


class EcsRamRoleCredential(Credential, _AutomaticallyRefreshCredentials):
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

    async def _refresh_credential_async(self):
        credential = None
        if self._with_should_refresh():
            credential = await self._get_new_credential_async()

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

    async def get_access_key_id_async(self):
        await self._refresh_credential_async()
        return self.access_key_id

    async def get_access_key_secret_async(self):
        await self._refresh_credential_async()
        return self.access_key_secret

    async def get_security_token_async(self):
        await self._refresh_credential_async()
        return self.security_token


class RamRoleArnCredential(Credential, _AutomaticallyRefreshCredentials):
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

    async def _refresh_credential_async(self):
        credential = None
        if self._with_should_refresh():
            credential = await self._get_new_credential_async()

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

    async def get_access_key_id_async(self):
        await self._refresh_credential_async()
        return self.access_key_id

    async def get_access_key_secret_async(self):
        await self._refresh_credential_async()
        return self.access_key_secret

    async def get_security_token_async(self):
        await self._refresh_credential_async()
        return self.security_token


class RsaKeyPairCredential(Credential, _AutomaticallyRefreshCredentials):
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

    async def _refresh_credential_async(self):
        credential = None
        if self._with_should_refresh():
            credential = await self._get_new_credential_async()

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

    async def get_access_key_id_async(self):
        await self._refresh_credential_async()
        return self.access_key_id

    async def get_access_key_secret_async(self):
        await self._refresh_credential_async()
        return self.access_key_secret


class StsCredential(Credential):
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

    async def get_access_key_id_async(self):
        return self.access_key_id

    async def get_access_key_secret_async(self):
        return self.access_key_secret

    async def get_security_token_async(self):
        return self.security_token

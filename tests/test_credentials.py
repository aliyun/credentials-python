import unittest

from alibabacloud_credentials import credentials, providers


class TestCredentials(unittest.TestCase):
    class TestEcsRamRoleProvider:
        def get_credentials(self):
            return credentials.EcsRamRoleCredential("accessKeyId", "accessKeySecret", "securityToken", 100000000000,
                                                    None)

    class TestRamRoleArnProvider:
        def get_credentials(self):
            return credentials.RamRoleArnCredential("accessKeyId", "accessKeySecret", "securityToken", 100000000000,
                                                    None)

    class TestRsaKeyPairProvider:
        def get_credentials(self):
            return credentials.RsaKeyPairCredential("accessKeyId", "accessKeySecret", 100000000000,
                                                    None)

    def test_EcsRamRoleCredential(self):
        provider = providers.EcsRamRoleCredentialProvider("roleName")
        access_key_id = 'access_key_id'
        access_key_secret = 'access_key_secret'
        security_token = 'security_token'
        expiration = 900000000000
        cred = credentials.EcsRamRoleCredential(
            access_key_id,
            access_key_secret,
            security_token,
            expiration,
            provider
        )

        self.assertEqual('access_key_id', cred.get_access_key_id())
        self.assertEqual('access_key_secret', cred.get_access_key_secret())
        self.assertEqual('security_token', cred.get_security_token())
        self.assertEqual(900000000000, cred.expiration)
        self.assertIsInstance(cred.provider, providers.EcsRamRoleCredentialProvider)
        self.assertEqual('ecs_ram_role', cred.credential_type)

        cred = credentials.EcsRamRoleCredential(
            access_key_id,
            access_key_secret,
            security_token,
            100,
            self.TestEcsRamRoleProvider()
        )
        # refresh token
        self.assertEqual('accessKeyId', cred.get_access_key_id())
        self.assertEqual('accessKeySecret', cred.get_access_key_secret())
        self.assertEqual('securityToken', cred.get_security_token())
        self.assertEqual(100000000000, cred.expiration)

    def test_AccessKeyCredential(self):
        access_key_id = 'access_key_id'
        access_key_secret = 'access_key_secret'
        cred = credentials.AccessKeyCredential(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret
        )
        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual('access_key', cred.credential_type)

    def test_BearerTokenCredential(self):
        bearer_token = 'bearer_token'
        cred = credentials.BearerTokenCredential(bearer_token=bearer_token)
        self.assertEqual('bearer_token', cred.bearer_token)
        self.assertEqual('bearer', cred.credential_type)

    def test_RamRoleArnCredential(self):
        access_key_id, access_key_secret, security_token, expiration = \
            'access_key_id', 'access_key_secret', 'security_token', 640900000000
        provider = self.TestRamRoleArnProvider()
        cred = credentials.RamRoleArnCredential(
            access_key_id, access_key_secret, security_token, expiration, provider
        )

        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual('security_token', cred.security_token)
        self.assertEqual(640900000000, cred.expiration)

        access_key_id, access_key_secret, security_token, expiration = \
            'access_key_id', 'access_key_secret', 'security_token', 6409
        provider = self.TestRamRoleArnProvider()
        cred = credentials.RamRoleArnCredential(
            access_key_id, access_key_secret, security_token, expiration, provider
        )

        # refresh token
        self.assertTrue(cred._with_should_refresh())

        self.assertEqual('accessKeyId', cred.get_access_key_id())
        self.assertEqual('accessKeySecret', cred.access_key_secret)
        self.assertEqual('securityToken', cred.security_token)
        self.assertEqual(100000000000, cred.expiration)
        self.assertEqual('ram_role_arn', cred.credential_type)
        self.assertIsInstance(cred.provider, self.TestRamRoleArnProvider)

        self.assertFalse(cred._with_should_refresh())

        g = cred._get_new_credential()
        self.assertIsNotNone(g)

        cred._refresh_credential()
        self.assertIsNotNone(cred)

    def test_RsaKeyPairCredential(self):
        access_key_id, access_key_secret, expiration = 'access_key_id', 'access_key_secret', 90000000000
        provider = providers.RsaKeyPairCredentialProvider(access_key_id, access_key_secret)
        cred = credentials.RsaKeyPairCredential(
            access_key_id, access_key_secret, expiration, provider
        )
        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual(90000000000, cred.expiration)
        self.assertIsInstance(cred.provider, providers.RsaKeyPairCredentialProvider)
        self.assertEqual('rsa_key_pair', cred.credential_type)

        cred = credentials.RsaKeyPairCredential(
            access_key_id,
            access_key_secret,
            900,
            self.TestRsaKeyPairProvider()
        )

        # refresh token
        self.assertEqual('accessKeyId', cred.get_access_key_id())
        self.assertEqual('accessKeySecret', cred.access_key_secret)
        self.assertEqual(100000000000, cred.expiration)

    def test_CredentialsURICredential(self):
        credentials_uri = 'http://localhost:6666/test'
        cred = credentials.CredentialsURICredential(
            credentials_uri
        )
        self.assertIsNone(cred.access_key_id)
        self.assertIsNone(cred.access_key_secret)
        self.assertIsNone(cred.security_token)
        self.assertEqual('http://localhost:6666/test', cred.credentials_uri)
        self.assertEqual('credentials_uri', cred.credential_type)

    def test_StsCredential(self):
        access_key_id, access_key_secret, security_token = \
            'access_key_id', 'access_key_secret', 'security_token'
        cred = credentials.StsCredential(
            access_key_id, access_key_secret, security_token
        )
        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual('security_token', cred.security_token)
        self.assertEqual('sts', cred.credential_type)

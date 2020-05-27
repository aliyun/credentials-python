import unittest

from alibabacloud_credentials import credentials, providers


class TestCredentials(unittest.TestCase):
    class AlibabaCredentialProvider:
        def get_credentials(self):
            return credentials.RamRoleArnCredential("accessKeyId", "accessKeySecret", "securityToken", 10000, None)
    
    def test_EcsRamRoleCredential(self):
        provider = providers.EcsRamRoleCredentialProvider("roleName")
        access_key_id = 'access_key_id'
        access_key_secret = 'access_key_secret'
        security_token = 'security_token'
        expiration = 100
        cred = credentials.EcsRamRoleCredential(
            access_key_id,
            access_key_secret,
            security_token,
            expiration,
            provider
        )

        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual('security_token', cred.security_token)
        self.assertEqual(100, cred.expiration)
        self.assertIsInstance(cred.provider, providers.EcsRamRoleCredentialProvider)
        self.assertEqual('ecs_ram_role', cred.credential_type)

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
            'access_key_id', 'access_key_secret', 'security_token', 64090527132000
        provider = self.AlibabaCredentialProvider()
        cred = credentials.RamRoleArnCredential(
            access_key_id, access_key_secret, security_token, expiration, provider
        )
        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual('security_token', cred.security_token)
        self.assertEqual(64090527132000, cred.expiration)
        self.assertEqual('ram_role_arn', cred.credential_type)
        self.assertIsInstance(cred.provider, self.AlibabaCredentialProvider)

        self.assertFalse(cred._with_should_refresh())

        g = cred._get_new_credential
        self.assertIsNotNone(g)

        cred._refresh_credential()
        self.assertIsNotNone(cred)

    def test_RsaKeyPairCredential(self):
        access_key_id, access_key_secret, expiration = 'access_key_id', 'access_key_secret', 100
        provider = providers.RsaKeyPairCredentialProvider(access_key_id, access_key_secret)
        cred = credentials.RsaKeyPairCredential(
            access_key_id, access_key_secret, expiration, provider
        )
        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual(100, cred.expiration)
        self.assertIsInstance(cred.provider, providers.RsaKeyPairCredentialProvider)
        self.assertEqual('rsa_key_pair', cred.credential_type)

    def test_StsCredential(self):
        access_key_id, access_key_secret, security_token =\
            'access_key_id', 'access_key_secret', 'security_token'
        cred = credentials.StsCredential(
            access_key_id, access_key_secret, security_token
        )
        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual('security_token', cred.security_token)
        self.assertEqual('sts', cred.credential_type)

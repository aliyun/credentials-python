import unittest
import json
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
from alibabacloud_credentials import credentials, providers
from alibabacloud_credentials.exceptions import CredentialException
from Tea.core import TeaResponse


class TestCredentials(unittest.TestCase):
    class TestEcsRamRoleProvider:
        def get_credentials(self):
            return credentials.EcsRamRoleCredential("accessKeyId", "accessKeySecret", "securityToken", 100000000000,
                                                    None)

    class TestRamRoleArnProvider:
        def get_credentials(self):
            return credentials.RamRoleArnCredential("accessKeyId", "accessKeySecret", "securityToken", 100000000000,
                                                    None)

    class TestOIDCRoleArnProvider:
        def get_credentials(self):
            return credentials.OIDCRoleArnCredential("accessKeyId", "accessKeySecret", "securityToken", 100000000000,
                                                     None)

    class TestRsaKeyPairProvider:
        def get_credentials(self):
            return credentials.RsaKeyPairCredential("accessKeyId", "accessKeySecret", 100000000000, None)

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

        model = cred.get_credential()
        self.assertEqual('access_key_id', model.access_key_id)
        self.assertEqual('access_key_secret', model.access_key_secret)
        self.assertEqual('security_token', model.security_token)
        self.assertEqual(900000000000, cred.expiration)

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
        model = cred.get_credential()
        self.assertEqual('accessKeyId', model.access_key_id)
        self.assertEqual('accessKeySecret', model.access_key_secret)
        self.assertEqual('securityToken', model.security_token)
        self.assertEqual(100000000000, cred.expiration)

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
        model = cred.get_credential()
        self.assertEqual('access_key_id', model.access_key_id)
        self.assertEqual('access_key_secret', model.access_key_secret)
        self.assertEqual('access_key', model.type)

        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual('access_key', cred.credential_type)

    def test_BearerTokenCredential(self):
        bearer_token = 'bearer_token'
        cred = credentials.BearerTokenCredential(bearer_token=bearer_token)
        model = cred.get_credential()
        self.assertEqual('bearer_token', model.bearer_token)
        self.assertEqual('bearer', model.type)

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

        model = cred.get_credential()
        self.assertEqual('accessKeyId', model.access_key_id)
        self.assertEqual('accessKeySecret', model.access_key_secret)
        self.assertEqual('securityToken', model.security_token)
        self.assertEqual('ram_role_arn', model.type)
        self.assertEqual(100000000000, cred.expiration)

        self.assertEqual('accessKeyId', cred.get_access_key_id())
        self.assertEqual('accessKeySecret', cred.get_access_key_secret())
        self.assertEqual('securityToken', cred.get_security_token())
        self.assertEqual(100000000000, cred.expiration)
        self.assertEqual('ram_role_arn', cred.credential_type)
        self.assertIsInstance(cred.provider, self.TestRamRoleArnProvider)

        self.assertFalse(cred._with_should_refresh())

        g = cred._get_new_credential()
        self.assertIsNotNone(g)

        cred._refresh_credential()
        self.assertIsNotNone(cred)

    def test_OIDCRoleArnCredential(self):
        access_key_id, access_key_secret, security_token, expiration = \
            'access_key_id', 'access_key_secret', 'security_token', 640900000000
        provider = self.TestOIDCRoleArnProvider()
        cred = credentials.OIDCRoleArnCredential(
            access_key_id, access_key_secret, security_token, expiration, provider
        )

        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual('security_token', cred.security_token)
        self.assertEqual(640900000000, cred.expiration)

        access_key_id, access_key_secret, security_token, expiration = \
            'access_key_id', 'access_key_secret', 'security_token', 6409
        provider = self.TestOIDCRoleArnProvider()
        cred = credentials.OIDCRoleArnCredential(
            access_key_id, access_key_secret, security_token, expiration, provider
        )

        # refresh token
        self.assertTrue(cred._with_should_refresh())

        model = cred.get_credential()
        self.assertEqual('accessKeyId', model.access_key_id)
        self.assertEqual('accessKeySecret', model.access_key_secret)
        self.assertEqual('securityToken', model.security_token)
        self.assertEqual('oidc_role_arn', model.type)
        self.assertEqual(100000000000, cred.expiration)

        self.assertEqual('accessKeyId', cred.get_access_key_id())
        self.assertEqual('accessKeySecret', cred.get_access_key_secret())
        self.assertEqual('securityToken', cred.get_security_token())
        self.assertEqual(100000000000, cred.expiration)
        self.assertEqual('oidc_role_arn', cred.credential_type)
        self.assertIsInstance(cred.provider, self.TestOIDCRoleArnProvider)

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

        model = cred.get_credential()
        self.assertEqual('accessKeyId', model.access_key_id)
        self.assertEqual('accessKeySecret', model.access_key_secret)
        self.assertEqual('rsa_key_pair', model.type)
        self.assertEqual(100000000000, cred.expiration)

        self.assertEqual('accessKeyId', cred.get_access_key_id())
        self.assertEqual('accessKeySecret', cred.get_access_key_secret())
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

        model = cred.get_credential()
        self.assertEqual('access_key_id', model.access_key_id)
        self.assertEqual('access_key_secret', model.access_key_secret)
        self.assertEqual('security_token', model.security_token)
        self.assertEqual('sts', model.type)

    def test_CredentialsURICredential_normal(self):
        """
        Test case 1: Successfully retrieves credentials from URI
        """
        response_body = json.dumps({
            "Code": "Success",
            "AccessKeyId": "test_access_key_id",
            "AccessKeySecret": "test_access_key_secret",
            "SecurityToken": "test_security_token",
            "Expiration": "2023-12-31T23:59:59Z"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            credentials_uri = 'http://localhost:6666/test'
            cred = credentials.CredentialsURICredential(credentials_uri)

            model = cred.get_credential()
            self.assertEqual('test_access_key_id', model.access_key_id)
            self.assertEqual('test_access_key_secret', model.access_key_secret)
            self.assertEqual('test_security_token', model.security_token)
            self.assertEqual('credentials_uri', model.type)

    def test_CredentialsURICredential_refresh(self):
        """
        Test case 2: Refreshes credentials when expired
        """
        response_body = json.dumps({
            "Code": "Success",
            "AccessKeyId": "test_access_key_id",
            "AccessKeySecret": "test_access_key_secret",
            "SecurityToken": "test_security_token",
            "Expiration": "2023-12-31T23:59:59Z"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            credentials_uri = 'http://localhost:6666/test'
            cred = credentials.CredentialsURICredential(credentials_uri)

            # Set expiration to a past time to trigger refresh
            cred.expiration = 1

            model = cred.get_credential()
            self.assertEqual('test_access_key_id', model.access_key_id)
            self.assertEqual('test_access_key_secret', model.access_key_secret)
            self.assertEqual('test_security_token', model.security_token)
            self.assertEqual('credentials_uri', model.type)

    def test_CredentialsURICredential_http_request_error(self):
        """
        Test case 3: HTTP request error raises CredentialException
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            credentials_uri = 'http://localhost:6666/test'
            cred = credentials.CredentialsURICredential(credentials_uri)

            with self.assertRaises(CredentialException) as context:
                cred.get_credential()

            self.assertIn(
                "Get credentials from http://localhost:6666/test failed,  HttpCode=400",
                str(context.exception))

    def test_CredentialsURICredential_response_format_error(self):
        """
        Test case 4: Response format error raises CredentialException
        """
        response_body = json.dumps({
            "Code": "Failure",
            "Message": "Invalid request"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.do_action', return_value=response):
            credentials_uri = 'http://localhost:6666/test'
            cred = credentials.CredentialsURICredential(credentials_uri)

            with self.assertRaises(CredentialException) as context:
                cred.get_credential()

            self.assertIn(
                "Get credentials from http://localhost:6666/test failed,  Code is Failure",
                str(context.exception))

    def test_CredentialsURICredential_async_normal(self):
        """
        Test case 5: Successfully retrieves credentials from URI asynchronously
        """
        response_body = json.dumps({
            "Code": "Success",
            "AccessKeyId": "test_access_key_id",
            "AccessKeySecret": "test_access_key_secret",
            "SecurityToken": "test_security_token",
            "Expiration": "2023-12-31T23:59:59Z"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
            credentials_uri = 'http://localhost:6666/test'
            cred = credentials.CredentialsURICredential(credentials_uri)

            loop = asyncio.get_event_loop()
            task = asyncio.ensure_future(
                cred.get_credential_async()
            )
            loop.run_until_complete(task)
            model = task.result()

            self.assertEqual('test_access_key_id', model.access_key_id)
            self.assertEqual('test_access_key_secret', model.access_key_secret)
            self.assertEqual('test_security_token', model.security_token)
            self.assertEqual('credentials_uri', model.type)

    def test_CredentialsURICredential_async_refresh(self):
        """
        Test case 6: Refreshes credentials when expired
        """
        response_body = json.dumps({
            "Code": "Success",
            "AccessKeyId": "test_access_key_id",
            "AccessKeySecret": "test_access_key_secret",
            "SecurityToken": "test_security_token",
            "Expiration": "2023-12-31T23:59:59Z"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
            credentials_uri = 'http://localhost:6666/test'
            cred = credentials.CredentialsURICredential(credentials_uri)

            # Set expiration to a past time to trigger refresh
            cred.expiration = 1

            loop = asyncio.get_event_loop()
            task = asyncio.ensure_future(
                cred.get_credential_async()
            )
            loop.run_until_complete(task)
            model = task.result()
            self.assertEqual('test_access_key_id', model.access_key_id)
            self.assertEqual('test_access_key_secret', model.access_key_secret)
            self.assertEqual('test_security_token', model.security_token)
            self.assertEqual('credentials_uri', model.type)

    def test_CredentialsURICredential_async_http_request_error(self):
        """
        Test case 7: HTTP request error raises CredentialException
        """
        response = TeaResponse()
        response.status_code = 400
        response.body = b'HTTP request failed'

        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
            credentials_uri = 'http://localhost:6666/test'
            cred = credentials.CredentialsURICredential(credentials_uri)

            with self.assertRaises(CredentialException) as context:
                loop = asyncio.get_event_loop()
                task = asyncio.ensure_future(
                    cred.get_credential_async()
                )
                loop.run_until_complete(task)

            self.assertIn(
                "Get credentials from http://localhost:6666/test failed,  HttpCode=400",
                str(context.exception))

    def test_CredentialsURICredential_async_response_format_error(self):
        """
        Test case 8: Response format error raises CredentialException
        """
        response_body = json.dumps({
            "Code": "Failure",
            "Message": "Invalid request"
        })
        response = TeaResponse()
        response.status_code = 200
        response.body = response_body.encode('utf-8')

        with patch('Tea.core.TeaCore.async_do_action', AsyncMock(return_value=response)):
            credentials_uri = 'http://localhost:6666/test'
            cred = credentials.CredentialsURICredential(credentials_uri)

            with self.assertRaises(CredentialException) as context:
                loop = asyncio.get_event_loop()
                task = asyncio.ensure_future(
                    cred.get_credential_async()
                )
                loop.run_until_complete(task)

            self.assertIn(
                "Get credentials from http://localhost:6666/test failed,  Code is Failure",
                str(context.exception))

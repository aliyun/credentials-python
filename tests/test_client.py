import asyncio
import unittest

from . import txt_file
from alibabacloud_credentials.models import Config
from alibabacloud_credentials.utils import auth_constant
from alibabacloud_credentials.client import Client, _CredentialsProviderWrap
from alibabacloud_credentials import credentials
from alibabacloud_credentials.utils import auth_util


class TestClient(unittest.TestCase):
    def test_client_ak(self):
        conf = Config()
        conf.type = auth_constant.ACCESS_KEY
        conf.access_key_id = '123456'
        conf.access_key_secret = '654321'
        cred = Client(conf)
        self.assertEqual('123456', cred.get_access_key_id())
        self.assertEqual('654321', cred.get_access_key_secret())
        self.assertEqual(auth_constant.ACCESS_KEY, cred.get_type())
        self.assertIsNone(cred.get_security_token())

        model = cred.get_credential()
        self.assertEqual('123456', model.get_access_key_id())
        self.assertEqual('654321', model.get_access_key_secret())
        self.assertIsNone(model.get_security_token())
        self.assertEqual(auth_constant.ACCESS_KEY, model.get_type())
        self.assertEqual('static_ak', model.get_provider_name())

        enable_oidc_credential = auth_util.enable_oidc_credential
        auth_util.enable_oidc_credential = False
        try:
            cred = Client()
            cred.get_credential()
        except Exception as ex:
            self.assertTrue(str(ex).startswith('unable to load credentials from any of the providers in the chain'))
        auth_util.enable_oidc_credential = enable_oidc_credential

    def test_client_sts(self):
        conf = Config(
            type='sts',
            access_key_id='123456',
            access_key_secret='654321',
            security_token='token', )
        cred = Client(conf)
        self.assertIsInstance(cred.cloud_credential, _CredentialsProviderWrap)

    def test_client_bearer(self):
        conf = Config(type='bearer')
        cred = Client(conf)
        self.assertIsInstance(cred.cloud_credential, credentials.BearerTokenCredential)

    def test_client_ecs_ram_role(self):
        conf = Config(type='ecs_ram_role')
        self.assertIsInstance(Client.get_credentials(conf), _CredentialsProviderWrap)

    def test_client_credentials_uri(self):
        conf = Config(
            type='credentials_uri',
            credentials_uri='http://localhost:8080')
        self.assertIsInstance(Client.get_credentials(conf), _CredentialsProviderWrap)

    def test_client_ram_role_arn(self):
        conf = Config(
            type='ram_role_arn',
            access_key_id='123456',
            access_key_secret='654321',
            role_arn='arn:aws:iam::123456789012:role/role-name',
        )
        self.assertIsInstance(Client.get_credentials(conf), _CredentialsProviderWrap)

    def test_client_oidc_role_arn(self):
        conf = Config(
            type='oidc_role_arn',
            role_arn='arn:aws:iam::123456789012:role/role-name',
            oidc_provider_arn='arn:aws:iam::123456789012:role/role-name',
            oidc_token_file_path='oidc_token_file_path')
        self.assertIsInstance(Client.get_credentials(conf), _CredentialsProviderWrap)

    def test_client_rsa_key_pair(self):
        conf = Config(
            type='rsa_key_pair',
            private_key_file=txt_file,
            public_key_id='test',
        )
        self.assertIsInstance(Client.get_credentials(conf), _CredentialsProviderWrap)

    def test_async_call(self):
        conf = Config(
            access_key_id='ak1',
            access_key_secret='sk1',
            type='access_key'
        )
        client = Client(conf)

        async def get_security_token_async():
            return await client.get_security_token_async()

        result = asyncio.run(get_security_token_async())
        self.assertIsNone(result)

        async def get_access_key_id_async():
            return await client.get_access_key_id_async()

        result = asyncio.run(get_access_key_id_async())
        self.assertEqual('ak1', result)

        async def get_access_key_secret_async():
            return await client.get_access_key_secret_async()

        result = asyncio.run(get_access_key_secret_async())
        self.assertEqual('sk1', result)

        async def get_credential_async():
            return await client.get_credential_async()

        credential = asyncio.run(get_credential_async())
        self.assertEqual('ak1', credential.access_key_id)

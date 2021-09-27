import asyncio
import unittest

from alibabacloud_credentials.models import Config
from alibabacloud_credentials.utils import auth_constant
from alibabacloud_credentials.client import Client
from alibabacloud_credentials import credentials

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
        try:
            cred = Client()
            cred.get_access_key_id()
        except Exception as ex:
            self.assertEqual('not found credentials', str(ex))

    def test_client_sts(self):
        conf = Config(type='sts')
        cred = Client(conf)
        self.assertIsInstance(cred.cloud_credential, credentials.StsCredential)

    def test_client_bearer(self):
        conf = Config(type='bearer')
        cred = Client(conf)
        self.assertIsInstance(cred.cloud_credential, credentials.BearerTokenCredential)

    def test_client_ecs_ram_role(self):
        conf = Config(type='ecs_ram_role')
        self.assertIsInstance(Client.get_credential(conf), credentials.EcsRamRoleCredential)

    def test_client_credentials_uri(self):
        conf = Config(type='credentials_uri')
        self.assertIsInstance(Client.get_credential(conf), credentials.CredentialsURICredential)

    def test_client_ram_role_arn(self):
        conf = Config(type='ram_role_arn')
        self.assertIsInstance(Client.get_credential(conf), credentials.RamRoleArnCredential)

    def test_client_rsa_key_pair(self):
        conf = Config(type='rsa_key_pair')
        self.assertIsInstance(Client.get_credential(conf), credentials.RsaKeyPairCredential)

    def test_async_call(self):
        conf = Config(
            access_key_id='ak1',
            access_key_secret='sk1',
            type='access_key'
        )
        client = Client(conf)
        loop = asyncio.get_event_loop()
        task = asyncio.ensure_future(client.get_security_token_async())
        loop.run_until_complete(task)
        self.assertIsNone(task.result())
        task = asyncio.ensure_future(client.get_access_key_id_async())
        loop.run_until_complete(task)
        self.assertEqual('ak1', task.result())
        task = asyncio.ensure_future(client.get_access_key_secret_async())
        loop.run_until_complete(task)
        self.assertEqual('sk1', task.result())

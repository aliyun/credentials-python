import asyncio
import unittest

from alibabacloud_credentials.models import Config
from alibabacloud_credentials.utils import auth_constant
from alibabacloud_credentials.client import Client
from alibabacloud_credentials import credentials
from alibabacloud_credentials import providers


class TestClient(unittest.TestCase):
    def test_ak_client(self):
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
        except Exception as e:
            self.assertEqual('not found credentials', str(e))

        conf = Config(type='sts')
        cred = Client(conf)
        self.assertIsInstance(cred.cloud_credential, credentials.StsCredential)

        conf = Config(type='bearer')
        cred = Client(conf)
        self.assertIsInstance(cred.cloud_credential, credentials.BearerTokenCredential)

        conf = Config(type='ecs_ram_role')
        self.assertIsInstance(Client.get_credential(conf), credentials.EcsRamRoleCredential)

        conf = Config(type='ram_role_arn')
        self.assertIsInstance(Client.get_credential(conf), credentials.RamRoleArnCredential)

        conf = Config(type='rsa_key_pair')
        self.assertIsInstance(Client.get_credential(conf), credentials.RsaKeyPairCredential)

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

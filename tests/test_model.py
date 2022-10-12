import unittest
from alibabacloud_credentials.models import Config


class TestModel(unittest.TestCase):
    def test_model_config(self):
        conf1 = Config()
        self.assertEqual('', conf1.access_key_id)
        self.assertEqual('', conf1.access_key_secret)
        self.assertEqual('', conf1.role_name)
        self.assertEqual(1000, conf1.timeout)

        conf1.timeout = 0
        conf1.access_key_id = 'access_key_id'
        self.assertEqual('access_key_id', conf1.access_key_id)
        self.assertEqual(0, conf1.timeout)

        conf2 = Config(
            access_key_id='access_key_id',
            access_key_secret='access_key_secret'
        )
        self.assertEqual('access_key_id', conf2.access_key_id)
        self.assertEqual('access_key_secret', conf2.access_key_secret)

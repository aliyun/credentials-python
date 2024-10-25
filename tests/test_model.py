import unittest
from alibabacloud_credentials.models import Config, CredentialModel


class TestModel(unittest.TestCase):
    def test_model_config(self):
        conf1 = Config()
        self.assertEqual('', conf1.access_key_id)
        self.assertEqual('', conf1.access_key_secret)
        self.assertEqual('', conf1.role_name)
        self.assertEqual(1000, conf1.timeout)
        self.assertEqual(1000, conf1.connect_timeout)
        self.assertFalse(conf1.disable_imds_v1)
        self.assertIsNone(conf1.sts_endpoint)

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

    def test_model_credential(self):
        cred = CredentialModel()
        self.assertIsNone(cred.access_key_id)
        self.assertIsNone(cred.access_key_secret)
        self.assertIsNone(cred.security_token)
        self.assertIsNone(cred.bearer_token)
        self.assertIsNone(cred.type)

        cred = CredentialModel(
            access_key_id='access_key_id',
            access_key_secret='access_key_secret',
            security_token='security_token',
            bearer_token='bearer_token',
            type='type',
        )
        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual('security_token', cred.security_token)
        self.assertEqual('bearer_token', cred.bearer_token)
        self.assertEqual('type', cred.type)

        cred_map = cred.to_map()
        self.assertEqual('access_key_id', cred_map['accessKeyId'])
        self.assertEqual('access_key_secret', cred_map['accessKeySecret'])
        self.assertEqual('security_token', cred_map['securityToken'])
        self.assertEqual('bearer_token', cred_map['bearerToken'])
        self.assertEqual('type', cred_map['type'])

        cred = CredentialModel()
        cred.from_map(cred_map)
        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual('security_token', cred.security_token)
        self.assertEqual('bearer_token', cred.bearer_token)
        self.assertEqual('type', cred.type)
        self.assertEqual('access_key_id', cred.get_access_key_id())
        self.assertEqual('access_key_secret', cred.get_access_key_secret())
        self.assertEqual('security_token', cred.get_security_token())
        self.assertEqual('bearer_token', cred.get_bearer_token())
        self.assertEqual('type', cred.get_type())

import unittest
from alibabacloud_credentials.models import Config, CredentialModel

class TestModel(unittest.TestCase):
    def test_config_default_values(self):
        conf = Config()
        self.assertIsNone(conf.type)
        self.assertIsNone(conf.access_key_id)
        self.assertIsNone(conf.access_key_secret)
        self.assertIsNone(conf.security_token)
        self.assertIsNone(conf.bearer_token)
        self.assertIsNone(conf.duration_seconds)
        self.assertIsNone(conf.role_arn)
        self.assertIsNone(conf.oidc_provider_arn)
        self.assertIsNone(conf.oidc_token_file_path)
        self.assertIsNone(conf.role_session_name)
        self.assertIsNone(conf.role_session_expiration)
        self.assertIsNone(conf.policy)
        self.assertIsNone(conf.external_id)
        self.assertIsNone(conf.sts_endpoint)
        self.assertIsNone(conf.public_key_id)
        self.assertIsNone(conf.private_key_file)
        self.assertIsNone(conf.role_name)
        self.assertIsNone(conf.enable_imds_v2)
        self.assertFalse(conf.disable_imds_v1)
        self.assertIsNone(conf.metadata_token_duration)
        self.assertIsNone(conf.credentials_uri)
        self.assertIsNone(conf.host)
        self.assertEqual(None, conf.timeout)
        self.assertEqual(None, conf.connect_timeout)
        self.assertIsNone(conf.proxy)

    def test_config_custom_values(self):
        conf = Config(
            type='access_key',
            access_key_id='access_key_id',
            access_key_secret='access_key_secret',
            security_token='security_token',
            bearer_token='bearer_token',
            duration_seconds=3600,
            role_arn='role_arn',
            oidc_provider_arn='oidc_provider_arn',
            oidc_token_file_path='oidc_token_file_path',
            role_session_name='role_session_name',
            role_session_expiration=3600,
            policy='policy',
            external_id='external_id',
            sts_endpoint='sts_endpoint',
            public_key_id='public_key_id',
            private_key_file='private_key_file',
            role_name='role_name',
            enable_imds_v2=True,
            disable_imds_v1=False,
            metadata_token_duration=3600,
            credentials_uri='credentials_uri',
            host='host',
            timeout=5000,
            connect_timeout=10000,
            proxy='proxy'
        )
        self.assertEqual('access_key', conf.type)
        self.assertEqual('access_key_id', conf.access_key_id)
        self.assertEqual('access_key_secret', conf.access_key_secret)
        self.assertEqual('security_token', conf.security_token)
        self.assertEqual('bearer_token', conf.bearer_token)
        self.assertEqual(3600, conf.duration_seconds)
        self.assertEqual('role_arn', conf.role_arn)
        self.assertEqual('oidc_provider_arn', conf.oidc_provider_arn)
        self.assertEqual('oidc_token_file_path', conf.oidc_token_file_path)
        self.assertEqual('role_session_name', conf.role_session_name)
        self.assertEqual(3600, conf.role_session_expiration)
        self.assertEqual('policy', conf.policy)
        self.assertEqual('external_id', conf.external_id)
        self.assertEqual('sts_endpoint', conf.sts_endpoint)
        self.assertEqual('public_key_id', conf.public_key_id)
        self.assertEqual('private_key_file', conf.private_key_file)
        self.assertEqual('role_name', conf.role_name)
        self.assertTrue(conf.enable_imds_v2)
        self.assertFalse(conf.disable_imds_v1)
        self.assertEqual(3600, conf.metadata_token_duration)
        self.assertEqual('credentials_uri', conf.credentials_uri)
        self.assertEqual('host', conf.host)
        self.assertEqual(5000, conf.timeout)
        self.assertEqual(10000, conf.connect_timeout)
        self.assertEqual('proxy', conf.proxy)

    def test_config_to_map(self):
        conf = Config(
            type='access_key',
            access_key_id='access_key_id',
            access_key_secret='access_key_secret',
            security_token='security_token',
            bearer_token='bearer_token',
            duration_seconds=3600,
            role_arn='role_arn',
            oidc_provider_arn='oidc_provider_arn',
            oidc_token_file_path='oidc_token_file_path',
            role_session_name='role_session_name',
            role_session_expiration=3600,
            policy='policy',
            external_id='external_id',
            sts_endpoint='sts_endpoint',
            public_key_id='public_key_id',
            private_key_file='private_key_file',
            role_name='role_name',
            enable_imds_v2=True,
            disable_imds_v1=False,
            metadata_token_duration=3600,
            credentials_uri='credentials_uri',
            host='host',
            timeout=5000,
            connect_timeout=10000,
            proxy='proxy'
        )
        conf_map = conf.to_map()
        self.assertEqual('access_key', conf_map['type'])
        self.assertEqual('access_key_id', conf_map['accessKeyId'])
        self.assertEqual('access_key_secret', conf_map['accessKeySecret'])
        self.assertEqual('security_token', conf_map['securityToken'])
        self.assertEqual('bearer_token', conf_map['bearerToken'])
        self.assertEqual(3600, conf_map['durationSeconds'])
        self.assertEqual('role_arn', conf_map['roleArn'])
        self.assertEqual('oidc_provider_arn', conf_map['oidcProviderArn'])
        self.assertEqual('oidc_token_file_path', conf_map['oidcTokenFilePath'])
        self.assertEqual('role_session_name', conf_map['roleSessionName'])
        self.assertEqual(3600, conf_map['roleSessionExpiration'])
        self.assertEqual('policy', conf_map['policy'])
        self.assertEqual('external_id', conf_map['externalId'])
        self.assertEqual('sts_endpoint', conf_map['stsEndpoint'])
        self.assertEqual('public_key_id', conf_map['publicKeyId'])
        self.assertEqual('private_key_file', conf_map['privateKeyFile'])
        self.assertEqual('role_name', conf_map['roleName'])
        self.assertTrue(conf_map['enableIMDSv2'])
        self.assertFalse(conf_map['disableIMDSv1'])
        self.assertEqual(3600, conf_map['metadataTokenDuration'])
        self.assertEqual('credentials_uri', conf_map['credentialsUri'])
        self.assertEqual('host', conf_map['host'])
        self.assertEqual(5000, conf_map['timeout'])
        self.assertEqual(10000, conf_map['connectTimeout'])
        self.assertEqual('proxy', conf_map['proxy'])

    def test_config_from_map(self):
        conf_map = {
            'type': 'access_key',
            'accessKeyId': 'access_key_id',
            'accessKeySecret': 'access_key_secret',
            'securityToken': 'security_token',
            'bearerToken': 'bearer_token',
            'durationSeconds': 3600,
            'roleArn': 'role_arn',
            'oidcProviderArn': 'oidc_provider_arn',
            'oidcTokenFilePath': 'oidc_token_file_path',
            'roleSessionName': 'role_session_name',
            'roleSessionExpiration': 3600,
            'policy': 'policy',
            'externalId': 'external_id',
            'stsEndpoint': 'sts_endpoint',
            'publicKeyId': 'public_key_id',
            'privateKeyFile': 'private_key_file',
            'roleName': 'role_name',
            'enableIMDSv2': True,
            'disableIMDSv1': False,
            'metadataTokenDuration': 3600,
            'credentialsUri': 'credentials_uri',
            'host': 'host',
            'timeout': 5000,
            'connectTimeout': 10000,
            'proxy': 'proxy'
        }
        conf = Config().from_map(conf_map)
        self.assertEqual('access_key', conf.type)
        self.assertEqual('access_key_id', conf.access_key_id)
        self.assertEqual('access_key_secret', conf.access_key_secret)
        self.assertEqual('security_token', conf.security_token)
        self.assertEqual('bearer_token', conf.bearer_token)
        self.assertEqual(3600, conf.duration_seconds)
        self.assertEqual('role_arn', conf.role_arn)
        self.assertEqual('oidc_provider_arn', conf.oidc_provider_arn)
        self.assertEqual('oidc_token_file_path', conf.oidc_token_file_path)
        self.assertEqual('role_session_name', conf.role_session_name)
        self.assertEqual(3600, conf.role_session_expiration)
        self.assertEqual('policy', conf.policy)
        self.assertEqual('external_id', conf.external_id)
        self.assertEqual('sts_endpoint', conf.sts_endpoint)
        self.assertEqual('public_key_id', conf.public_key_id)
        self.assertEqual('private_key_file', conf.private_key_file)
        self.assertEqual('role_name', conf.role_name)
        self.assertTrue(conf.enable_imds_v2)
        self.assertFalse(conf.disable_imds_v1)
        self.assertEqual(3600, conf.metadata_token_duration)
        self.assertEqual('credentials_uri', conf.credentials_uri)
        self.assertEqual('host', conf.host)
        self.assertEqual(5000, conf.timeout)
        self.assertEqual(10000, conf.connect_timeout)
        self.assertEqual('proxy', conf.proxy)

    def test_credential_model_default_values(self):
        cred = CredentialModel()
        self.assertIsNone(cred.access_key_id)
        self.assertIsNone(cred.access_key_secret)
        self.assertIsNone(cred.security_token)
        self.assertIsNone(cred.bearer_token)
        self.assertIsNone(cred.type)

    def test_credential_model_custom_values(self):
        cred = CredentialModel(
            access_key_id='access_key_id',
            access_key_secret='access_key_secret',
            security_token='security_token',
            bearer_token='bearer_token',
            type='type',
            provider_name='provider_name',
        )
        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual('security_token', cred.security_token)
        self.assertEqual('bearer_token', cred.bearer_token)
        self.assertEqual('type', cred.type)
        self.assertEqual('provider_name', cred.provider_name)

    def test_credential_model_to_map(self):
        cred = CredentialModel(
            access_key_id='access_key_id',
            access_key_secret='access_key_secret',
            security_token='security_token',
            bearer_token='bearer_token',
            type='type',
            provider_name='provider_name',
        )
        cred_map = cred.to_map()
        self.assertEqual('access_key_id', cred_map['accessKeyId'])
        self.assertEqual('access_key_secret', cred_map['accessKeySecret'])
        self.assertEqual('security_token', cred_map['securityToken'])
        self.assertEqual('bearer_token', cred_map['bearerToken'])
        self.assertEqual('type', cred_map['type'])
        self.assertEqual('provider_name', cred_map['providerName'])

    def test_credential_model_from_map(self):
        cred_map = {
            'accessKeyId': 'access_key_id',
            'accessKeySecret': 'access_key_secret',
            'securityToken': 'security_token',
            'bearerToken': 'bearer_token',
            'type': 'type',
            'providerName': 'provider_name',
        }
        cred = CredentialModel().from_map(cred_map)
        self.assertEqual('access_key_id', cred.access_key_id)
        self.assertEqual('access_key_secret', cred.access_key_secret)
        self.assertEqual('security_token', cred.security_token)
        self.assertEqual('bearer_token', cred.bearer_token)
        self.assertEqual('type', cred.type)
        self.assertEqual('provider_name', cred.provider_name)

    def test_credential_model_getters(self):
        cred = CredentialModel(
            access_key_id='access_key_id',
            access_key_secret='access_key_secret',
            security_token='security_token',
            bearer_token='bearer_token',
            type='type',
            provider_name='provider_name',
        )
        self.assertEqual('access_key_id', cred.get_access_key_id())
        self.assertEqual('access_key_secret', cred.get_access_key_secret())
        self.assertEqual('security_token', cred.get_security_token())
        self.assertEqual('bearer_token', cred.get_bearer_token())
        self.assertEqual('type', cred.get_type())
        self.assertEqual('provider_name', cred.get_provider_name())
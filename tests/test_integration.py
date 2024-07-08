import os
import unittest

from alibabacloud_credentials import providers, models
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.utils import auth_util


class TestIntegration(unittest.TestCase):
    def test_RamRoleArn(self):
        access_key_id = os.environ.get('SUB_ALIBABA_CLOUD_ACCESS_KEY')
        access_key_secret = os.environ.get('SUB_ALIBABA_CLOUD_SECRET_KEY')
        role_session_name = os.environ.get('ALIBABA_CLOUD_ROLE_SESSION_NAME')
        role_arn = os.environ.get('SUB_ALIBABA_CLOUD_ROLE_ARN')

        conf = models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            role_session_name=role_session_name,
            role_arn=role_arn
        )
        prov = providers.RamRoleArnCredentialProvider(config=conf)
        cred = prov.get_credentials()
        self.assertIsNotNone(cred.access_key_id)

    def test_OIDCRoleArn(self):
        self.assertIsNotNone(auth_util.environment_role_arn)
        self.assertIsNotNone(auth_util.environment_oidc_provider_arn)
        self.assertIsNotNone(auth_util.environment_role_session_name)
        self.assertIsNotNone(auth_util.environment_oidc_token_file)
        self.assertTrue(auth_util.enable_oidc_credential)
        default_client = Client()
        credential = default_client.get_credential()
        self.assertIsNotNone(credential.access_key_id)
        self.assertIsNotNone(credential.access_key_secret)
        self.assertIsNotNone(credential.security_token)

        role_session_name = os.environ.get('ALIBABA_CLOUD_ROLE_SESSION_NAME')
        oidc_role_arn = os.environ.get('ALIBABA_CLOUD_ROLE_ARN')
        oidc_provider_arn = os.environ.get('ALIBABA_CLOUD_OIDC_PROVIDER_ARN')
        oidc_token_file = os.environ.get('ALIBABA_CLOUD_OIDC_TOKEN_FILE')
        config = models.Config(
            role_session_name=role_session_name,
            role_arn=oidc_role_arn,
            oidc_provider_arn=oidc_provider_arn,
            oidc_token_file_path=oidc_token_file,
            type='oidc_role_arn',
        )
        client = Client(config)
        credential = client.get_credential()
        self.assertIsNotNone(credential.access_key_id)
        self.assertIsNotNone(credential.access_key_secret)
        self.assertIsNotNone(credential.security_token)
        self.assertEqual('oidc_role_arn', credential.type)

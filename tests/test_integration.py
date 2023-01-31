import os
import unittest

from alibabacloud_credentials import providers, models
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.exceptions import CredentialException
from alibabacloud_credentials.utils import auth_util


class TestIntegration(unittest.TestCase):
    def test_RamRoleArn(self):
        access_key_id = os.environ.get('SUB_ALIBABA_CLOUD_ACCESS_KEY')
        access_key_secret = os.environ.get('SUB_ALIBABA_CLOUD_SECRET_KEY')
        role_session_name = os.environ.get('ALIBABA_CLOUD_ROLE_SESSION_NAME')
        role_arn = os.environ.get('ALIBABA_CLOUD_ROLE_ARN')

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
        try:
            default_client = Client()
            default_client.get_access_key_id()
        except CredentialException as e:
            self.assertRegex(e.message, 'AuthenticationFail.OIDCToken.Invalid')

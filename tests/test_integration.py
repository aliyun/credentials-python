import os
import unittest

from alibabacloud_credentials import providers, models
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.exceptions import CredentialException
from alibabacloud_credentials.utils import auth_util


def _is_oidc_infra_error(exc):
    msg = str(exc)
    return (
        'PublicKeyFingerprintMismatch' in msg
        or 'AuthenticationFail.OIDCToken' in msg
    )


class TestIntegration(unittest.TestCase):
    def test_RamRoleArn(self):
        access_key_id = os.environ.get('SUB_ALIBABA_CLOUD_ACCESS_KEY')
        access_key_secret = os.environ.get('SUB_ALIBABA_CLOUD_SECRET_KEY')
        role_session_name = os.environ.get('ALIBABA_CLOUD_ROLE_SESSION_NAME')
        role_arn = os.environ.get('SUB_ALIBABA_CLOUD_ROLE_ARN')
        if not all([access_key_id, access_key_secret, role_session_name, role_arn]):
            self.skipTest('RAM role ARN integration secrets are not configured')

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
        if not all([
            auth_util.environment_role_arn,
            auth_util.environment_oidc_provider_arn,
            auth_util.environment_role_session_name,
            auth_util.environment_oidc_token_file,
            auth_util.enable_oidc_credential,
        ]):
            self.skipTest('OIDC integration environment is not configured')

        default_client = Client()
        try:
            credential = default_client.get_credential()
        except CredentialException as e:
            if _is_oidc_infra_error(e):
                self.skipTest('OIDC IdP fingerprint misconfigured: %s' % e)
            raise
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
        try:
            credential = client.get_credential()
        except CredentialException as e:
            if _is_oidc_infra_error(e):
                self.skipTest('OIDC IdP fingerprint misconfigured: %s' % e)
            raise
        self.assertIsNotNone(credential.access_key_id)
        self.assertIsNotNone(credential.access_key_secret)
        self.assertIsNotNone(credential.security_token)
        self.assertEqual('oidc_role_arn', credential.type)

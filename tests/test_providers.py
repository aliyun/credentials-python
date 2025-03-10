import unittest
import time
import asyncio

from Tea.exceptions import RetryError
from alibabacloud_credentials import providers, models, credentials, exceptions
from alibabacloud_credentials.exceptions import CredentialException
from alibabacloud_credentials.utils import auth_util
from . import ini_file

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

loop = asyncio.get_event_loop()


class Request(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"Code": "Success", "AccessKeyId": "ak",'
                         b' "Expiration": "3999-08-07T20:20:20Z", "Credentials":'
                         b' {"Expiration": "3999-08-07T20:20:20Z", "AccessKeyId": "AccessKeyId"}, "SessionAccessKey":'
                         b' {"Expiration": "3999-08-07T20:20:20Z", "SessionAccessKeyId": "SessionAccessKeyId"}}')

    def do_PUT(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'token')


class RequestError(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(500)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'error')

    def do_PUT(self):
        self.send_response(500)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'error')


def run_server():
    server = HTTPServer(('localhost', 8888), Request)
    server.serve_forever()


def run_server_error():
    server_error = HTTPServer(('localhost', 9999), RequestError)
    server_error.serve_forever()


class TestProviders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server = threading.Thread(target=run_server)
        server.setDaemon(True)
        server.start()
        server_error = threading.Thread(target=run_server_error)
        server_error.setDaemon(True)
        server_error.start()

    @staticmethod
    def strftime(t):
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.localtime(t))

    def test_EcsRamRoleCredentialProvider(self):
        prov = providers.EcsRamRoleCredentialProvider("roleName")
        self.assertIsNotNone(prov)
        self.assertEqual("roleName", prov.role_name)

        auth_util.environment_imds_v1_disabled = 'False'
        prov = providers.EcsRamRoleCredentialProvider("roleName")
        self.assertIsNotNone(prov)
        self.assertEqual("roleName", prov.role_name)
        self.assertFalse(prov.disable_imds_v1)

        auth_util.environment_imds_v1_disabled = '1'
        prov = providers.EcsRamRoleCredentialProvider("roleName")
        self.assertIsNotNone(prov)
        self.assertEqual("roleName", prov.role_name)
        self.assertFalse(prov.disable_imds_v1)

        auth_util.environment_imds_v1_disabled = 'True'
        prov = providers.EcsRamRoleCredentialProvider("roleName")
        self.assertIsNotNone(prov)
        self.assertEqual("roleName", prov.role_name)
        self.assertTrue(prov.disable_imds_v1)

        auth_util.environment_imds_v1_disabled = None

        cfg = models.Config()
        cfg.role_name = "roleNameConfig"
        cfg.timeout = 1100
        cfg.connect_timeout = 1200
        prov = providers.EcsRamRoleCredentialProvider(config=cfg)
        self.assertIsNotNone(prov)
        self.assertEqual("roleNameConfig", prov.role_name)
        self.assertEqual(1100, prov.timeout)
        token = prov._get_metadata_token(url='127.0.0.1:8888')
        self.assertEqual('token', token)

        cred = prov._create_credential(url='127.0.0.1:8888')
        self.assertEqual('ak', cred.access_key_id)

        prov._get_role_name(url='http://127.0.0.1:8888')
        self.assertIsNotNone(prov.role_name)

        # request error
        token = prov._get_metadata_token(url='127.0.0.1:9999')
        self.assertIsNone(token)
        try:
            prov._create_credential(url='127.0.0.1:9999')
            self.fail()
        except CredentialException as e:
            self.assertEqual('Failed to get RAM session credentials from ECS metadata service. HttpCode=500', e.message)
        try:
            prov._get_role_name(url='http://127.0.0.1:9999')
            self.fail()
        except CredentialException as e:
            self.assertEqual('Failed to get RAM session credentials from ECS metadata service. HttpCode=500', e.message)


        cfg.disable_imds_v1 = True
        prov = providers.EcsRamRoleCredentialProvider(config=cfg)
        self.assertIsNotNone(prov)
        self.assertTrue(prov.disable_imds_v1)
        self.assertEqual("roleNameConfig", prov.role_name)
        self.assertEqual(1100, prov.timeout)
        prov._get_metadata_token(url='127.0.0.1:8888')
        cred = prov._create_credential(url='127.0.0.1:8888')
        self.assertEqual('ak', cred.access_key_id)

        prov._get_role_name(url='http://127.0.0.1:8888')
        self.assertIsNotNone(prov.role_name)

        # request error
        try:
            prov._get_metadata_token(url='127.0.0.1:9999')
            self.fail()
        except CredentialException as e:
            self.assertEqual('Failed to get token from ECS Metadata Service. HttpCode=500', e.message)
        try:
            prov._create_credential(url='127.0.0.1:9999')
            self.fail()
        except CredentialException as e:
            self.assertEqual('Failed to get token from ECS Metadata Service. HttpCode=500', e.message)
        try:
            prov._get_role_name(url='http://127.0.0.1:9999')
            self.fail()
        except CredentialException as e:
            self.assertEqual('Failed to get token from ECS Metadata Service. HttpCode=500', e.message)


    def test_EcsRamRoleCredentialProvider_async(self):
        async def main():
            prov = providers.EcsRamRoleCredentialProvider("roleName")
            self.assertIsNotNone(prov)
            self.assertEqual("roleName", prov.role_name)

            cfg = models.Config()
            cfg.role_name = "roleNameConfig"
            cfg.timeout = 1100
            cfg.connect_timeout = 1200
            prov = providers.EcsRamRoleCredentialProvider(config=cfg)
            self.assertIsNotNone(prov)
            self.assertEqual("roleNameConfig", prov.role_name)
            self.assertEqual(1100, prov.timeout)
            cred = await prov._create_credential_async(url='127.0.0.1:8888')
            self.assertEqual('ak', cred.access_key_id)

            await prov._get_role_name_async(url='127.0.0.1:8888')
            self.assertIsNotNone(prov.role_name)

        loop.run_until_complete(main())

    def test_DefaultCredentialsProvider(self):
        prov = providers.DefaultCredentialsProvider()
        p = providers.EnvironmentVariableCredentialsProvider()

        # add_credentials_provider
        prov.add_credentials_provider(p)
        self.assertTrue(prov.user_configuration_providers.__contains__(p))

        # contains_credentials_provider
        res = prov.contains_credentials_provider(p)
        self.assertTrue(res)

        # remove_credentials_provider
        prov.remove_credentials_provider(p)
        self.assertFalse(prov.user_configuration_providers.__contains__(p))

        # clear_credentials_provider
        prov.add_credentials_provider(p)
        prov.add_credentials_provider(p)
        prov.clear_credentials_provider()
        self.assertEqual([], prov.user_configuration_providers)

        # not found credentials
        try:
            prov.get_credentials()
        except Exception as e:
            self.assertEqual('not found credentials', e.message)

        prov.add_credentials_provider(p)
        prov.clear_credentials_provider()
        self.assertRaises(exceptions.CredentialException, prov.get_credentials)

        environment_role_arn = auth_util.environment_role_arn
        environment_oidc_provider_arn = auth_util.environment_oidc_provider_arn
        environment_oidc_token_file = auth_util.environment_oidc_token_file
        enable_oidc_credential = auth_util.enable_oidc_credential

        auth_util.environment_role_arn = 'acs:ram::roleArn:role/roleArn'
        auth_util.environment_oidc_provider_arn = 'acs:ram::roleArn'
        auth_util.environment_oidc_token_file = 'tests/private_key.txt'
        auth_util.enable_oidc_credential = True
        prov = providers.DefaultCredentialsProvider()
        try:
            prov.get_credentials()
        except Exception as e:
            self.assertRegex(e.message, 'AuthenticationFail.NoPermission')
        auth_util.environment_role_arn = environment_role_arn
        auth_util.environment_oidc_provider_arn = environment_oidc_provider_arn
        auth_util.environment_oidc_token_file = environment_oidc_token_file
        auth_util.enable_oidc_credential = enable_oidc_credential

    def test_RamRoleArnCredentialProvider(self):
        access_key_id, access_key_secret, role_session_name, role_arn, region_id, policy = \
            'access_key_id', 'access_key_secret', 'role_session_name', 'role_arn', 'region_id', 'policy'
        prov = providers.RamRoleArnCredentialProvider(
            access_key_id, access_key_secret, role_session_name, role_arn, region_id, policy
        )
        self.assertEqual('access_key_id', prov.access_key_id)
        self.assertEqual('access_key_secret', prov.access_key_secret)
        self.assertEqual('role_session_name', prov.role_session_name)
        self.assertEqual('role_arn', prov.role_arn)
        self.assertEqual('region_id', prov.region_id)
        self.assertEqual('policy', prov.policy)

        conf = models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            role_session_name=role_session_name,
            role_arn=role_arn,
            sts_endpoint='http://127.0.0.1:8888'
        )
        prov = providers.RamRoleArnCredentialProvider(config=conf)
        self.assertEqual('access_key_id', prov.access_key_id)
        self.assertEqual('access_key_secret', prov.access_key_secret)
        self.assertEqual('role_session_name', prov.role_session_name)
        self.assertEqual('role_arn', prov.role_arn)
        self.assertIsNone(prov.region_id)
        self.assertIsNone(prov.policy)
        self.assertEqual('http://127.0.0.1:8888', prov.sts_endpoint)

        cred = prov._create_credentials()
        self.assertEqual('AccessKeyId', cred.access_key_id)

        auth_util.environment_sts_region = 'cn-hangzhou'
        prov = providers.RamRoleArnCredentialProvider(config=conf)
        self.assertEqual('cn-hangzhou', prov.region_id)
        self.assertEqual('sts.cn-hangzhou.aliyuncs.com', prov.sts_endpoint)
        auth_util.environment_sts_region = None

    def test_OIDCRoleArnCredentialProvider(self):
        access_key_id, access_key_secret, role_session_name, role_arn, oidc_provider_arn, oidc_token_file_path, region_id, policy = \
            'access_key_id', 'access_key_secret', 'role_session_name', 'role_arn', 'oidc_provider_arn', 'tests/private_key.txt', 'region_id', 'policy'
        prov = providers.OIDCRoleArnCredentialProvider(
            role_session_name, role_arn, oidc_provider_arn, oidc_token_file_path,
            region_id, policy
        )
        self.assertEqual('role_session_name', prov.role_session_name)
        self.assertEqual('role_arn', prov.role_arn)
        self.assertEqual('oidc_provider_arn', prov.oidc_provider_arn)
        self.assertEqual('tests/private_key.txt', prov.oidc_token_file_path)
        self.assertEqual('region_id', prov.region_id)
        self.assertEqual('policy', prov.policy)

        conf = models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            role_session_name=role_session_name,
            role_arn=role_arn,
            oidc_provider_arn=oidc_provider_arn,
            oidc_token_file_path=oidc_token_file_path,
            sts_endpoint='http://127.0.0.1:8888'
        )
        prov = providers.OIDCRoleArnCredentialProvider(config=conf)
        self.assertEqual('access_key_id', prov.access_key_id)
        self.assertEqual('access_key_secret', prov.access_key_secret)
        self.assertEqual('role_session_name', prov.role_session_name)
        self.assertEqual('role_arn', prov.role_arn)
        self.assertEqual('oidc_provider_arn', prov.oidc_provider_arn)
        self.assertEqual('tests/private_key.txt', prov.oidc_token_file_path)
        self.assertIsNone(prov.region_id)
        self.assertIsNone(prov.policy)
        self.assertEqual('http://127.0.0.1:8888', prov.sts_endpoint)

        cred = prov._create_credentials()
        self.assertEqual('AccessKeyId', cred.access_key_id)

        auth_util.environment_sts_region = 'cn-hangzhou'
        prov = providers.OIDCRoleArnCredentialProvider(config=conf)
        self.assertEqual('cn-hangzhou', prov.region_id)
        self.assertEqual('sts.cn-hangzhou.aliyuncs.com', prov.sts_endpoint)
        auth_util.environment_sts_region = None

    def test_RamRoleArnCredentialProvider_async(self):
        async def main():
            access_key_id, access_key_secret, role_session_name, role_arn, region_id, policy = \
                'access_key_id', 'access_key_secret', 'role_session_name', 'role_arn', 'region_id', 'policy'
            prov = providers.RamRoleArnCredentialProvider(
                access_key_id, access_key_secret, role_session_name, role_arn, region_id, policy
            )
            self.assertEqual('access_key_id', prov.access_key_id)
            self.assertEqual('access_key_secret', prov.access_key_secret)
            self.assertEqual('role_session_name', prov.role_session_name)
            self.assertEqual('role_arn', prov.role_arn)
            self.assertEqual('region_id', prov.region_id)
            self.assertEqual('policy', prov.policy)

            conf = models.Config(
                access_key_id=access_key_id,
                access_key_secret=access_key_secret,
                role_session_name=role_session_name,
                role_arn=role_arn,
                sts_endpoint='http://127.0.0.1:8888'
            )
            prov = providers.RamRoleArnCredentialProvider(config=conf)
            self.assertEqual('access_key_id', prov.access_key_id)
            self.assertEqual('access_key_secret', prov.access_key_secret)
            self.assertEqual('role_session_name', prov.role_session_name)
            self.assertEqual('role_arn', prov.role_arn)
            self.assertIsNone(prov.region_id)
            self.assertIsNone(prov.policy)
            self.assertEqual('http://127.0.0.1:8888', prov.sts_endpoint)

            cred = await prov._create_credentials_async()
            self.assertEqual('AccessKeyId', cred.access_key_id)

        loop.run_until_complete(main())

    def test_RsaKeyPairCredentialProvider(self):
        access_key_id, access_key_secret, region_id = \
            'access_key_id', 'access_key_secret', 'region_id'
        prov = providers.RsaKeyPairCredentialProvider(
            access_key_id, access_key_secret, region_id
        )
        self.assertEqual('access_key_id', prov.access_key_id)
        self.assertEqual('access_key_secret', prov.access_key_secret)
        self.assertEqual('region_id', prov.region_id)

        conf = models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret
        )
        prov = providers.RsaKeyPairCredentialProvider(config=conf)
        self.assertEqual('access_key_id', prov.access_key_id)
        self.assertEqual('access_key_secret', prov.access_key_secret)
        self.assertIsNone(prov.region_id)

        cred = prov._create_credential(turl='http://127.0.0.1:8888')
        self.assertEqual('SessionAccessKeyId', cred.access_key_id)

    def test_RsaKeyPairCredentialProvider_async(self):
        async def main():
            access_key_id, access_key_secret, region_id = \
                'access_key_id', 'access_key_secret', 'region_id'
            prov = providers.RsaKeyPairCredentialProvider(
                access_key_id, access_key_secret, region_id
            )
            self.assertEqual('access_key_id', prov.access_key_id)
            self.assertEqual('access_key_secret', prov.access_key_secret)
            self.assertEqual('region_id', prov.region_id)

            conf = models.Config(
                access_key_id=access_key_id,
                access_key_secret=access_key_secret
            )
            prov = providers.RsaKeyPairCredentialProvider(config=conf)
            self.assertEqual('access_key_id', prov.access_key_id)
            self.assertEqual('access_key_secret', prov.access_key_secret)
            self.assertIsNone(prov.region_id)

            cred = await prov._create_credential_async(turl='http://127.0.0.1:8888')
            self.assertEqual('SessionAccessKeyId', cred.access_key_id)

        loop.run_until_complete(main())

    def test_ProfileCredentialsProvider(self):
        prov = providers.ProfileCredentialsProvider(ini_file)
        auth_util.client_type = 'default'
        c = prov.get_credentials()
        self.assertIsInstance(c, credentials.AccessKeyCredential)
        auth_util.client_type = 'client2'
        self.assertRaises(exceptions.CredentialException, prov.get_credentials)

        auth_util.client_type = 'client4'
        auth_util.environment_access_key_secret = 'test'
        self.assertRaises(exceptions.CredentialException, prov.get_credentials)

        auth_util.client_type = 'client1'
        self.assertRaises(RetryError, prov.get_credentials)

        auth_util.client_type = 'client6'
        self.assertIsNone(prov.get_credentials())
        auth_util.client_type = 'client7'
        self.assertIsNone(prov.get_credentials())
        prov = providers.ProfileCredentialsProvider()
        self.assertIsNone(prov.get_credentials())

    def test_EnvironmentVariableCredentialsProvider(self):
        prov = providers.EnvironmentVariableCredentialsProvider()
        auth_util.client_type = 'aa'
        self.assertEqual(None, prov.get_credentials())

        auth_util.client_type = 'default'
        auth_util.environment_access_key_id = 'accessKeyIdTest'
        self.assertIsNone(prov.get_credentials())

        auth_util.environment_access_key_secret = 'accessKeySecretTest'
        cred = prov.get_credentials()
        self.assertEqual('accessKeyIdTest', cred.access_key_id)
        self.assertEqual('accessKeySecretTest', cred.access_key_secret)

        auth_util.environment_security_token = 'token'
        cred = prov.get_credentials()
        self.assertEqual('accessKeyIdTest', cred.access_key_id)
        self.assertEqual('accessKeySecretTest', cred.access_key_secret)
        self.assertEqual('token', cred.security_token)
        self.assertEqual('sts', cred.credential_type)

        auth_util.environment_access_key_id = None
        self.assertIsNone(prov.get_credentials())

        auth_util.environment_access_key_id = ''
        self.assertRaises(exceptions.CredentialException, prov.get_credentials)

        auth_util.environment_access_key_id = 'a'
        auth_util.environment_access_key_secret = ''
        self.assertRaises(exceptions.CredentialException, prov.get_credentials)

        auth_util.environment_access_key_id = None
        auth_util.environment_access_key_secret = None
        auth_util.environment_security_token = None

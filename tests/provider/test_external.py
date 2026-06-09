import asyncio
import json
import os
import tempfile
import time
import unittest

from alibabacloud_credentials.exceptions import CredentialException
from alibabacloud_credentials.provider.external import ExternalCredentialsProvider, _get_stale_time


class TestExternalCredentialsProvider(unittest.TestCase):

    def _create_script(self, content):
        temp_dir = tempfile.mkdtemp()
        script_path = os.path.join(temp_dir, 'external_credential.sh')
        with open(script_path, 'w') as f:
            f.write(content)
        os.chmod(script_path, 0o755)
        return script_path

    def test_init_validation(self):
        with self.assertRaises(ValueError) as context:
            ExternalCredentialsProvider()
        self.assertIn('process_command is empty', str(context.exception))

    def test_get_credentials_ak_success(self):
        script_path = self._create_script(
            "#!/bin/sh\n"
            "echo '{\"mode\":\"AK\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}'\n"
        )
        provider = ExternalCredentialsProvider(process_command=script_path)

        credentials = provider.get_credentials()

        self.assertEqual(credentials.get_access_key_id(), 'akid')
        self.assertEqual(credentials.get_access_key_secret(), 'secret')
        self.assertIsNone(credentials.get_security_token())
        self.assertEqual(credentials.get_provider_name(), 'external')

    def test_get_credentials_sts_success_with_callback(self):
        expiration = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 3600))
        script_path = self._create_script(
            "#!/bin/sh\n"
            "echo '" + json.dumps({
                'mode': 'StsToken',
                'access_key_id': 'akid',
                'access_key_secret': 'secret',
                'sts_token': 'token',
                'expiration': expiration,
            }) + "'\n"
        )
        callback_args = []
        provider = ExternalCredentialsProvider(
            process_command=script_path,
            credential_update_callback=lambda *args: callback_args.append(args),
        )

        credentials = provider.get_credentials()

        self.assertEqual(credentials.get_security_token(), 'token')
        self.assertEqual(len(callback_args), 1)
        self.assertEqual(callback_args[0][0], 'akid')
        self.assertEqual(callback_args[0][1], 'secret')
        self.assertEqual(callback_args[0][2], 'token')
        self.assertGreater(callback_args[0][3], 0)

    def test_get_credentials_async_success_with_callback(self):
        async def run_test():
            expiration = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 3600))
            script_path = self._create_script(
                "#!/bin/sh\n"
                "echo '" + json.dumps({
                    'mode': 'StsToken',
                    'access_key_id': 'akid',
                    'access_key_secret': 'secret',
                    'sts_token': 'token',
                    'expiration': expiration,
                }) + "'\n"
            )
            callback_args = []

            async def callback(*args):
                callback_args.append(args)

            provider = ExternalCredentialsProvider(
                process_command=script_path,
                credential_update_callback_async=callback,
            )

            credentials = await provider.get_credentials_async()
            self.assertEqual(credentials.get_access_key_id(), 'akid')
            self.assertEqual(credentials.get_security_token(), 'token')
            self.assertEqual(len(callback_args), 1)

        asyncio.run(run_test())

    def test_invalid_json(self):
        script_path = self._create_script("#!/bin/sh\necho 'invalid json'\n")
        provider = ExternalCredentialsProvider(process_command=script_path)

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()
        self.assertIn('failed to parse external command output', str(context.exception))

    def test_missing_access_key(self):
        script_path = self._create_script(
            "#!/bin/sh\n"
            "echo '{\"mode\":\"AK\",\"access_key_id\":\"\",\"access_key_secret\":\"secret\"}'\n"
        )
        provider = ExternalCredentialsProvider(process_command=script_path)

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()
        self.assertIn('access_key_id or access_key_secret is empty', str(context.exception))

    def test_missing_sts_token(self):
        script_path = self._create_script(
            "#!/bin/sh\n"
            "echo '{\"mode\":\"StsToken\",\"access_key_id\":\"akid\",\"access_key_secret\":\"secret\"}'\n"
        )
        provider = ExternalCredentialsProvider(process_command=script_path)

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()
        self.assertIn('sts_token is empty', str(context.exception))

    def test_command_failure(self):
        script_path = self._create_script("#!/bin/sh\necho failed >&2\nexit 1\n")
        provider = ExternalCredentialsProvider(process_command=script_path)

        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()
        self.assertIn('failed to execute external command', str(context.exception))

    def test_get_stale_time(self):
        now = int(time.mktime(time.localtime()))
        self.assertLessEqual(_get_stale_time(0), now)
        self.assertEqual(_get_stale_time(1000), 820)


if __name__ == '__main__':
    unittest.main()

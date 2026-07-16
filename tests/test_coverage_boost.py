import asyncio
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from alibabacloud_credentials.utils import auth_util
from alibabacloud_credentials.provider.profile import _load_ini, _load_ini_async, _get_default_file
from alibabacloud_credentials.provider.external import ExternalCredentialsProvider
from alibabacloud_credentials.exceptions import CredentialException
from alibabacloud_credentials.utils import auth_constant as ac


class TestCoverageBoost(unittest.TestCase):
    def test_get_home_windows_variants(self):
        with patch('alibabacloud_credentials.utils.auth_util.platform.system', return_value='Windows'):
            with patch.dict(os.environ, {'HOME': 'C:\\Users\\a'}, clear=False):
                self.assertEqual(auth_util.get_home(), 'C:\\Users\\a')
            env = {'HOMEPATH': 'C:\\Users\\b', 'HOMEDRIVE': 'C:'}
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(auth_util.get_home(), 'C:\\Users\\b')
            env = {'HOMEPATH': '\\Users\\c', 'HOMEDRIVE': 'D:'}
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(auth_util.get_home(), os.path.join('D:', '\\Users\\c'))
            with patch.dict(os.environ, {}, clear=True):
                with patch('alibabacloud_credentials.utils.auth_util.os.path.expanduser', return_value='Z:\\home'):
                    self.assertEqual(auth_util.get_home(), 'Z:\\home')

    def test_load_ini_strips_inline_comments(self):
        temp = tempfile.NamedTemporaryFile('w', delete=False, suffix='.ini')
        try:
            temp.write('[default]\naccess_key_id = akid # comment\naccess_key_secret = secret\n')
            temp.close()
            data = _load_ini(temp.name)
            self.assertEqual(data['default']['access_key_id'], 'akid')

            async def run():
                return await _load_ini_async(temp.name)

            data2 = asyncio.run(run())
            self.assertEqual(data2['default']['access_key_id'], 'akid')
        finally:
            os.unlink(temp.name)

    def test_get_default_file(self):
        path = _get_default_file()
        self.assertTrue(path.endswith(os.path.join('.alibabacloud', 'credentials.ini')))
        self.assertEqual(path, os.path.join(ac.HOME, '.alibabacloud', 'credentials.ini'))

    def test_external_empty_command(self):
        provider = ExternalCredentialsProvider(process_command='   ')
        with self.assertRaises(CredentialException):
            provider.get_credentials()

    def test_external_timeout(self):
        cmd = '%s -c "import time; time.sleep(5)"' % sys.executable
        provider = ExternalCredentialsProvider(process_command=cmd, timeout=0.2)
        with self.assertRaises(CredentialException) as ctx:
            provider.get_credentials()
        self.assertIn('timed out', str(ctx.exception))

    def test_external_async_empty_and_timeout(self):
        provider = ExternalCredentialsProvider(process_command=' ')
        with self.assertRaises(CredentialException):
            asyncio.run(provider.get_credentials_async())

        cmd = '%s -c "import time; time.sleep(5)"' % sys.executable
        provider = ExternalCredentialsProvider(process_command=cmd, timeout=0.2)
        with self.assertRaises(CredentialException) as ctx:
            asyncio.run(provider.get_credentials_async())
        self.assertIn('timed out', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()

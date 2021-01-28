import unittest
from alibabacloud_credentials.exceptions import CredentialException


class TestException(unittest.TestCase):
    def test_CredentialException(self):
        try:
            raise CredentialException('error', 1000, 123456789)
        except CredentialException as e:
            self.assertEqual('error', e.message)
            self.assertEqual(1000, e.code)
            self.assertEqual(123456789, e.request_id)

        try:
            raise CredentialException('error', 123456789)
        except CredentialException as e:
            self.assertEqual('error', e.message)
            self.assertEqual(123456789, e.code)
            self.assertEqual(None, e.request_id)

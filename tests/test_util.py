from alibabacloud_credentials.utils import auth_util, parameter_helper

import unittest
import re
from . import txt_file


class TestUtil(unittest.TestCase):

    def test_get_private_key(self):
        key = auth_util.get_private_key(txt_file)
        self.assertEqual('test_private_key', key)

    def test_parameter_helper(self):
        def test_get_uuid(test):
            test.assertIsNotNone(parameter_helper.get_uuid())

        def test_get_iso_8061_date(test):
            test.assertIsNotNone(parameter_helper.get_iso_8061_date())

        def test_compose_string_to_sign(test):
            method, queries = 'GET', {}
            string_to_sign = parameter_helper.compose_string_to_sign(method, queries)
            test.assertEqual('GET&%2F&', string_to_sign)

        def test_sign_string(test):
            sign, secret = '123', 'secret'
            signature = parameter_helper.sign_string(sign, secret)
            test.assertEqual('sU6S6xf2t47FogXuDhqyIPt/htc=', signature)

        def test_compose_url(test):
            endpoint, queries, protocol = 'aliyun.com', {"tests": "test"}, 'https'
            res = parameter_helper.compose_url(endpoint, queries, protocol)
            test.assertEqual('https://aliyun.com/?tests=test', res)

        def test_get_new_request(test):
            request = parameter_helper.get_new_request()
            test.assertEqual({}, request.query)
            test.assertEqual('http', request.protocol)
            test.assertEqual(80, request.port)
            test.assertEqual('GET', request.method)
            test.assertEqual('', request.pathname)
            test.assertIsNone(request.body)
            test.assertEqual('', request.pathname)
            test.assertIsNotNone(
                re.match('AlibabaCloud (.+; .+) Python/.+ Credentials/.+ TeaDSL/1',
                         request.headers.get('user-agent')))

        test_get_uuid(self)
        test_get_iso_8061_date(self)
        test_compose_string_to_sign(self)
        test_sign_string(self)
        test_compose_url(self)
        test_get_new_request(self)

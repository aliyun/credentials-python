from alibabacloud_credentials.utils import auth_util, parameter_helper

import unittest
from . import txt_file


class TestUtil(unittest.TestCase):

    def test_get_private_key(self):
        key = auth_util.get_private_key(txt_file)
        self.assertEqual('test_private_key', key)

    def test_parameter_helper(self):
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

        test_compose_string_to_sign(self)
        test_sign_string(self)
        test_compose_url(self)

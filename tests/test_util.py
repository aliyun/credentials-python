from alibabacloud_credentials.utils import auth_util, parameter_helper, auth_constant

import os
import unittest
from unittest.mock import patch
import re
from . import txt_file
import platform


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

    def test_home(self):
        @patch.dict(os.environ, {'HOME': '/mock/home/linux'})
        def test_home_exists():
            """case1：HOME exists"""
            assert auth_util.get_home() == '/mock/home/linux'

        @patch.dict(os.environ, {'HOME': ''})
        @patch.dict(os.environ, {'HOMEPATH': ''})
        def test_home_empty():
            """case2：HOME exists but empty"""
            with patch('os.path.expanduser', return_value='/fallback'):
                assert auth_util.get_home() == '/fallback'

        @patch.dict(os.environ, {'HOME': ''})
        @patch.dict(os.environ, {'HOMEPATH': '\\Users\\mockuser'})
        @patch.dict(os.environ, {'HOMEDRIVE': 'C:'})
        def test_home_path_and_drive_windows():
            """case3：Windows HOMEPATH exists and HOMEDRIVE exists"""
            if platform.system() == 'Windows':
                assert auth_util.get_home() == 'C:\\Users\\mockuser'
            else:
                assert auth_util.get_home() == '\\Users\\mockuser'

        @patch.dict(os.environ, {'HOME': ''})
        @patch.dict(os.environ, {'HOMEPATH': 'D:\\Users\\mockuser'})
        @patch.dict(os.environ, {'HOMEDRIVE': 'C:'})
        def test_home_path_windows():
            """case4：Windows HOMEPATH exists"""
            assert auth_util.get_home() == 'D:\\Users\\mockuser'

        def test_real_system():
            """case5：test real system"""
            assert auth_constant.HOME
            assert os.path.exists(auth_constant.HOME)
            assert auth_constant.HOME == os.path.expanduser('~')
            assert auth_util.get_home() == os.path.expanduser('~')

        test_home_exists()
        test_home_empty()
        test_home_path_and_drive_windows()
        test_home_path_windows()
        test_real_system()

import unittest
from unittest.mock import patch, MagicMock
from alibabacloud_credentials.providers.env import EnvironmentVariableCredentialsProvider
from alibabacloud_credentials.exceptions import CredentialException
from alibabacloud_credentials.providers.env import auth_util

class TestEnvironmentVariableCredentialsProvider(unittest.TestCase):
    
    @patch('alibabacloud_credentials.providers.env.auth_util')
    def test_get_credentials_valid_input(self, mock_auth_util):
        """
        测试用例1: 正常情况下获取凭证
        """
        # 设定mock对象返回值
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()
        
        credentials = provider.get_credentials()
        
        self.assertEqual(credentials.get_access_key_id(), "test_access_key_id")
        self.assertEqual(credentials.get_access_key_secret(), "test_access_key_secret")
        self.assertEqual(credentials.get_security_token(), "test_security_token")
        self.assertEqual(credentials.get_provider_name(), "env")

    @patch('alibabacloud_credentials.providers.env.auth_util')
    def test_get_credentials_missing_access_key_id(self, mock_auth_util):
        """
        测试用例2: 缺少环境变量 accessKeyId 导致异常抛出
        """
        mock_auth_util.environment_access_key_id = None
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()
        
        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()
            
        self.assertIn("Environment variable accessKeyId cannot be empty", str(context.exception))

    @patch('alibabacloud_credentials.providers.env.auth_util')
    def test_get_credentials_empty_access_key_id(self, mock_auth_util):
        """
        测试用例3: 环境变量 accessKeyId 为空字符串导致异常抛出
        """
        mock_auth_util.environment_access_key_id = ""
        mock_auth_util.environment_access_key_secret = "test_access_key_secret"
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()
        
        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()
            
        self.assertIn("Environment variable accessKeyId cannot be empty", str(context.exception))
    
    @patch('alibabacloud_credentials.providers.env.auth_util')
    def test_get_credentials_missing_access_key_secret(self, mock_auth_util):
        """
        测试用例4: 缺少环境变量 accessKeySecret 导致异常抛出
        """
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = None
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()
        
        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()
            
        self.assertIn("Environment variable accessKeySecret cannot be empty", str(context.exception))

    @patch('alibabacloud_credentials.providers.env.auth_util')
    def test_get_credentials_empty_access_key_secret(self, mock_auth_util):
        """
        测试用例5: 环境变量 accessKeySecret 为空字符串导致异常抛出
        """
        mock_auth_util.environment_access_key_id = "test_access_key_id"
        mock_auth_util.environment_access_key_secret = ""
        mock_auth_util.environment_security_token = "test_security_token"

        provider = EnvironmentVariableCredentialsProvider()
        
        with self.assertRaises(CredentialException) as context:
            provider.get_credentials()
            
        self.assertIn("Environment variable accessKeySecret cannot be empty", str(context.exception))

if __name__ == '__main__':
    unittest.main()
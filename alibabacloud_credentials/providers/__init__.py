from .static_ak import StaticAKCredentialsProvider
from .static_sts import StaticSTSCredentialsProvider
from .env import EnvironmentVariableCredentialsProvider
from .ecs_ram_role import EcsRamRoleCredentialsProvider
from .ram_role_arn import RamRoleArnCredentialsProvider
from .oidc import OIDCRoleArnCredentialsProvider
from .rsa_key_pair import RsaKeyPairCredentialsProvider
from .uri import URLCredentialsProvider
from .cli_profile import CLIProfileCredentialsProvider
from .profile import ProfileCredentialsProvider
from .default import DefaultCredentialsProvider

__all__ = [
    'StaticAKCredentialsProvider',
    'StaticSTSCredentialsProvider',
    'EnvironmentVariableCredentialsProvider',
    'EcsRamRoleCredentialsProvider',
    'RamRoleArnCredentialsProvider',
    'OIDCRoleArnCredentialsProvider',
    'RsaKeyPairCredentialsProvider',
    'URLCredentialsProvider',
    'CLIProfileCredentialsProvider',
    'ProfileCredentialsProvider',
    'DefaultCredentialsProvider'
]


class HttpOptions:
    def __init__(self, *,
                 proxy: str = None,
                 connect_timeout: int = None,
                 read_timeout: int = None):
        self.proxy = proxy
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
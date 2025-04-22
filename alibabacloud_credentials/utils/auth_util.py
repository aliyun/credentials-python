import os
import platform
import re

client_type = os.environ.get('ALIBABA_CLOUD_PROFILE', 'default')

environment_access_key_id = os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_ID')
environment_access_key_secret = os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_SECRET')
environment_security_token = os.environ.get('ALIBABA_CLOUD_SECURITY_TOKEN')

environment_ECSMeta_data = os.environ.get('ALIBABA_CLOUD_ECS_METADATA')
environment_ecs_metadata = os.environ.get('ALIBABA_CLOUD_ECS_METADATA')
environment_imds_v1_disabled = os.environ.get('ALIBABA_CLOUD_IMDSV1_DISABLED', 'false')
environment_ecs_metadata_disabled = os.environ.get('ALIBABA_CLOUD_ECS_METADATA_DISABLED', 'false')

environment_credentials_file = os.environ.get('ALIBABA_CLOUD_CREDENTIALS_FILE')
environment_profile_name = os.environ.get('ALIBABA_CLOUD_PROFILE')
environment_oidc_token_file = os.environ.get('ALIBABA_CLOUD_OIDC_TOKEN_FILE')
environment_role_arn = os.environ.get('ALIBABA_CLOUD_ROLE_ARN')
environment_oidc_provider_arn = os.environ.get('ALIBABA_CLOUD_OIDC_PROVIDER_ARN')
environment_role_session_name = os.environ.get('ALIBABA_CLOUD_ROLE_SESSION_NAME')

environment_credentials_uri = os.environ.get('ALIBABA_CLOUD_CREDENTIALS_URI')

environment_cli_profile_disabled = os.environ.get('ALIBABA_CLOUD_CLI_PROFILE_DISABLED', 'false')

environment_sts_region = os.environ.get('ALIBABA_CLOUD_STS_REGION')
environment_enable_vpc = os.environ.get('ALIBABA_CLOUD_VPC_ENDPOINT_ENABLED', 'false')

enable_oidc_credential = environment_oidc_token_file is not None and environment_oidc_token_file != '' \
                         and environment_role_arn is not None and environment_role_arn != '' \
                         and environment_oidc_provider_arn is not None and environment_oidc_provider_arn != ''
private_key = None


def get_private_key(file_path):
    with open(file_path, encoding='utf-8') as f:
        key = f.read()
    return key


def get_home():
    if platform.system() == 'Windows':
        home = os.getenv('HOME')
        home_path = os.getenv('HOMEPATH')
        home_drive = os.getenv('HOMEDRIVE')
        if home:
            return home
        elif home_path:
            has_drive_in_home_path = bool(re.match(r'^[A-Za-z]:', home_path))
            return home_path if has_drive_in_home_path else os.path.join(home_drive or '', home_path)
        else:
            return os.path.expanduser("~")
    else:
        return os.getenv('HOME') or os.getenv('HOMEPATH') or os.path.expanduser("~")

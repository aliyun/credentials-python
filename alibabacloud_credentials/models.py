# -*- coding: utf-8 -*-
# This file is auto-generated, don't edit it. Thanks.
from Tea.model import TeaModel


class Config(TeaModel):
    """
    Model for initializing credential
    """

    def __init__(
            self,
            *,
            type: str = None,
            access_key_id: str = None,
            access_key_secret: str = None,
            security_token: str = None,
            bearer_token: str = None,
            duration_seconds: int = None,
            role_arn: str = None,
            oidc_provider_arn: str = None,
            oidc_token_file_path: str = None,
            role_session_name: str = None,
            role_session_expiration: int = None,
            policy: str = None,
            external_id: str = None,
            sts_endpoint: str = None,
            public_key_id: str = None,
            private_key_file: str = None,
            role_name: str = None,
            enable_imds_v2: bool = None,
            disable_imds_v1: bool = None,
            metadata_token_duration: int = None,
            credentials_uri: str = None,
            host: str = None,
            timeout: int = None,
            connect_timeout: int = None,
            proxy: str = None,
    ):
        """
        Initialize the credential object.

        ### Parameters

        #### General Parameters
        - `type` (str): Credential type, including `access_key`, `sts`, `bearer`, `ecs_ram_role`, `ram_role_arn`, `rsa_key_pair`, `oidc_role_arn`, `credentials_uri`.

        #### Access Key Type
        - `access_key_id` (str): Access Key ID.
        - `access_key_secret` (str): Access Key Secret.
        - `security_token` (str, optional): Security token.

        #### Bearer Token Type
        - `bearer_token` (str): Bearer token.

        #### RAM Role ARN and OIDC Role ARN Types
        - `role_arn` (str): Role ARN.
        - `oidc_provider_arn` (str, for `oidc_role_arn` only): OIDC provider ARN.
        - `oidc_token_file_path` (str, for `oidc_role_arn` only): Path to the OIDC token file.
        - `role_session_name` (str): Role session name.
        - `role_session_expiration` (int, optional): Role session expiration time in seconds.
        - `policy` (str, optional): Policy.
        - `external_id` (str, optional): External ID.
        - `sts_endpoint` (str, optional): STS endpoint.
        - `duration_seconds`: deprecated

        #### RSA Key Pair Type
        - `public_key_id` (str): Public key ID.
        - `private_key_file` (str): Path to the private key file.

        #### ECS RAM Role Type
        - `role_name` (str): Role name.
        - `disable_imds_v1` (bool, optional): Whether to disable IMDS v1. Default is `False`.

        #### Credentials URI Type
        - `credentials_uri` (str): Credentials URI.

        #### HTTP Options
        - `host` (str, optional): Host address.
        - `timeout` (int, optional): Read timeout in milliseconds. Default values:
          - `ecs_ram_role`: 1000ms
          - `ram_role_arn`: 5000ms
          - `oidc_role_arn`: 5000ms
        - `connect_timeout` (int, optional): Connection timeout in milliseconds. Default values:
          - `ecs_ram_role`: 1000ms
          - `ram_role_arn`: 10000ms
          - `oidc_role_arn`: 10000ms
        - `proxy` (str, optional): HTTP or HTTPS proxy.

        #### Other Parameters
        - `duration_seconds` (int, optional): Duration in seconds, mainly used for `sts` type credentials.

        Note: Some parameters are only valid for specific credential types. Please use them according to your actual needs.
        """
        self.type = type
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.security_token = security_token
        self.bearer_token = bearer_token
        self.duration_seconds = duration_seconds
        self.role_arn = role_arn
        self.oidc_provider_arn = oidc_provider_arn
        self.oidc_token_file_path = oidc_token_file_path
        self.role_session_name = role_session_name
        self.role_session_expiration = role_session_expiration
        self.policy = policy
        self.external_id = external_id
        self.sts_endpoint = sts_endpoint
        self.public_key_id = public_key_id
        self.private_key_file = private_key_file
        self.role_name = role_name
        self.disable_imds_v1 = disable_imds_v1
        self.enable_imds_v2 = enable_imds_v2
        self.metadata_token_duration = metadata_token_duration
        self.credentials_uri = credentials_uri
        self.host = host
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.proxy = proxy

    def validate(self):
        pass

    def to_map(self):
        result = dict()
        if self.type is not None:
            result['type'] = self.type
        if self.access_key_id is not None:
            result['accessKeyId'] = self.access_key_id
        if self.access_key_secret is not None:
            result['accessKeySecret'] = self.access_key_secret
        if self.security_token is not None:
            result['securityToken'] = self.security_token
        if self.bearer_token is not None:
            result['bearerToken'] = self.bearer_token
        if self.duration_seconds is not None:
            result['durationSeconds'] = self.duration_seconds
        if self.role_arn is not None:
            result['roleArn'] = self.role_arn
        if self.oidc_provider_arn is not None:
            result['oidcProviderArn'] = self.oidc_provider_arn
        if self.oidc_token_file_path is not None:
            result['oidcTokenFilePath'] = self.oidc_token_file_path
        if self.role_session_name is not None:
            result['roleSessionName'] = self.role_session_name
        if self.role_session_expiration is not None:
            result['roleSessionExpiration'] = self.role_session_expiration
        if self.policy is not None:
            result['policy'] = self.policy
        if self.external_id is not None:
            result['externalId'] = self.external_id
        if self.sts_endpoint is not None:
            result['stsEndpoint'] = self.sts_endpoint
        if self.public_key_id is not None:
            result['publicKeyId'] = self.public_key_id
        if self.private_key_file is not None:
            result['privateKeyFile'] = self.private_key_file
        if self.role_name is not None:
            result['roleName'] = self.role_name
        if self.disable_imds_v1 is not None:
            result['disableIMDSv1'] = self.disable_imds_v1
        if self.enable_imds_v2 is not None:
            result['enableIMDSv2'] = self.enable_imds_v2
        if self.metadata_token_duration is not None:
            result['metadataTokenDuration'] = self.metadata_token_duration
        if self.credentials_uri is not None:
            result['credentialsUri'] = self.credentials_uri
        if self.host is not None:
            result['host'] = self.host
        if self.timeout is not None:
            result['timeout'] = self.timeout
        if self.connect_timeout is not None:
            result['connectTimeout'] = self.connect_timeout
        if self.proxy is not None:
            result['proxy'] = self.proxy
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('type') is not None:
            self.type = m.get('type')
        if m.get('accessKeyId') is not None:
            self.access_key_id = m.get('accessKeyId')
        if m.get('accessKeySecret') is not None:
            self.access_key_secret = m.get('accessKeySecret')
        if m.get('securityToken') is not None:
            self.security_token = m.get('securityToken')
        if m.get('bearerToken') is not None:
            self.bearer_token = m.get('bearerToken')
        if m.get('durationSeconds') is not None:
            self.duration_seconds = m.get('durationSeconds')
        if m.get('roleArn') is not None:
            self.role_arn = m.get('roleArn')
        if m.get('oidcProviderArn') is not None:
            self.oidc_provider_arn = m.get('oidcProviderArn')
        if m.get('oidcTokenFilePath') is not None:
            self.oidc_token_file_path = m.get('oidcTokenFilePath')
        if m.get('roleSessionName') is not None:
            self.role_session_name = m.get('roleSessionName')
        if m.get('roleSessionExpiration') is not None:
            self.role_session_expiration = m.get('roleSessionExpiration')
        if m.get('policy') is not None:
            self.policy = m.get('policy')
        if m.get('externalId') is not None:
            self.external_id = m.get('externalId')
        if m.get('stsEndpoint') is not None:
            self.sts_endpoint = m.get('stsEndpoint')
        if m.get('publicKeyId') is not None:
            self.public_key_id = m.get('publicKeyId')
        if m.get('privateKeyFile') is not None:
            self.private_key_file = m.get('privateKeyFile')
        if m.get('roleName') is not None:
            self.role_name = m.get('roleName')
        if m.get('disableIMDSv1') is not None:
            self.disable_imds_v1 = m.get('disableIMDSv1')
        if m.get('enableIMDSv2') is not None:
            self.enable_imds_v2 = m.get('enableIMDSv2')
        if m.get('metadataTokenDuration') is not None:
            self.metadata_token_duration = m.get('metadataTokenDuration')
        if m.get('credentialsUri') is not None:
            self.credentials_uri = m.get('credentialsUri')
        if m.get('host') is not None:
            self.host = m.get('host')
        if m.get('timeout') is not None:
            self.timeout = m.get('timeout')
        if m.get('connectTimeout') is not None:
            self.connect_timeout = m.get('connectTimeout')
        if m.get('proxy') is not None:
            self.proxy = m.get('proxy')
        return self


class CredentialModel(TeaModel):
    def __init__(
            self,
            access_key_id: str = None,
            access_key_secret: str = None,
            security_token: str = None,
            bearer_token: str = None,
            type: str = None,
            provider_name: str = None,
    ):
        # accesskey id
        self.access_key_id = access_key_id
        # accesskey secret
        self.access_key_secret = access_key_secret
        # security token
        self.security_token = security_token
        # bearer token
        self.bearer_token = bearer_token
        # type
        self.type = type
        # provider name
        self.provider_name = provider_name

    def validate(self):
        pass

    def to_map(self) -> dict:
        _map = super().to_map()
        if _map is not None:
            return _map

        result = dict()
        if self.access_key_id is not None:
            result['accessKeyId'] = self.access_key_id
        if self.access_key_secret is not None:
            result['accessKeySecret'] = self.access_key_secret
        if self.security_token is not None:
            result['securityToken'] = self.security_token
        if self.bearer_token is not None:
            result['bearerToken'] = self.bearer_token
        if self.type is not None:
            result['type'] = self.type
        if self.provider_name is not None:
            result['providerName'] = self.provider_name
        return result

    def from_map(self, m: dict = None):
        m = m or dict()
        if m.get('accessKeyId') is not None:
            self.access_key_id = m.get('accessKeyId')
        if m.get('accessKeySecret') is not None:
            self.access_key_secret = m.get('accessKeySecret')
        if m.get('securityToken') is not None:
            self.security_token = m.get('securityToken')
        if m.get('bearerToken') is not None:
            self.bearer_token = m.get('bearerToken')
        if m.get('type') is not None:
            self.type = m.get('type')
        if m.get('providerName') is not None:
            self.provider_name = m.get('providerName')
        return self

    def get_access_key_id(self) -> str:
        return self.access_key_id

    def get_access_key_secret(self) -> str:
        return self.access_key_secret

    def get_security_token(self) -> str:
        return self.security_token

    def get_bearer_token(self) -> str:
        return self.bearer_token

    def get_type(self) -> str:
        return self.type

    def get_provider_name(self) -> str:
        return self.provider_name

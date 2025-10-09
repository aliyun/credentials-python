English | [简体中文](README-CN.md)

![Alibaba Cloud Logo](https://aliyunsdk-pages.alicdn.com/icons/AlibabaCloud.svg)

# Alibaba Cloud Credentials for Python

[![PyPI version](https://badge.fury.io/py/alibabacloud_credentials.svg)](https://badge.fury.io/py/alibabacloud_credentials)
[![Python Test](https://github.com/aliyun/credentials-python/actions/workflows/testPython.yml/badge.svg)](https://github.com/aliyun/credentials-python/actions/workflows/testPython.yml)
[![codecov](https://codecov.io/gh/aliyun/credentials-python/graph/badge.svg?token=Y0J1E7T35I)](https://codecov.io/gh/aliyun/credentials-python)

## Important Updates

- Starting from version 1.0rc1, the package `alibabacloud-credentials` only supports Python 3.7 and above.

## Installation

- **Install with pip**

Python SDK uses a common package management tool named `pip`. If pip is not installed, see the [pip user guide](https://pip.pypa.io/en/stable/installing/ "pip User Guide") to install pip.

```bash
# Install the alibabacloud-credentials
pip install alibabacloud-credentials
```

## Usage

Before you begin, you need to sign up for an Alibaba Cloud account and retrieve your [Credentials](https://usercenter.console.aliyun.com/#/manage/ak).

### **Parameters** of the **Credentials tool**

-----------------------------------------------------------

The parameters of the Credentials tool are defined in the `Config` class of the `alibabacloud_credentials.models` module. The credential type is determined by the value of `type`, which is a required parameter in the configurations. After you determine a credential type, configure parameters based on the credential type. The following table describes the valid values of `type` and the parameters supported by each credential type. In the table, a check mark (`✓`) indicates that the parameter is required, a hyphen (`-`) indicates that the parameter is optional, and an X mark (`×`) indicates that the parameter is not supported. 

**Note**

We recommend that you do not use parameters that are not listed in the following table.

| **type** | **access_key** | **sts** | **ram_role_arn** | **ecs_ram_role** | **oidc_role_arn** | **credentials_uri** | **bearer** |
| --- | --- | ---- | --- | --- | --- | --- | --- |
| access_key_id: the AccessKey ID.                                                                                                                                                                                                      | ✓              | ✓       | ✓                | ×                | ×                 | ×                   | ×          |
| access_key_secret: the AccessKey secret.                                                                                                                                                                                              | ✓              | ✓       | ✓                | ×                | ×                 | ×                   | ×          |
| security_token: Security Token Service (STS) token.                                                                                                                                                                                   | ×              | ✓       | -                | ×                | ×                 | ×                   | ×          |
| role_arn: the Alibaba Cloud Resource Name (ARN) of the Resource Access Management (RAM) role.                                                                                                                                         | ×              | ×       | ✓                | ×                | ✓                 | ×                   | ×          |
| role_session_name: the name of the custom session. The default format is `credentials-java-The current timestamp`.                                                                                                    | ×              | ×       | -                | ×                | -                 | ×                   | ×          |
| role_name: specifies the name of the RAM role.                                                                                                                                                                                        | ×              | ×       | ×                | -                | ×                 | ×                   | ×          |
| disable_imds_v1: specifies whether to forcibly use the security hardening mode (IMDSv2). If you set this parameter to true, the security hardening mode (IMDSv2) is used. Default value: `false`.                     | ×              | ×       | ×                | -                | ×                 | ×                   | ×          |
| bearer_token: a bearer token.                                                                                                                                                                                                         | ×              | ×       | ×                | ×                | ×                 | ×                   | ✓          |
| policy: a custom policy.                                                                                                                                                                                                              | ×              | ×       | -                | ×                | -                 | ×                   | ×          |
| role_session_expiration: the session timeout period. Default value: 3600. Unit: seconds.                                                                                                                                              | ×              | ×       | -                | ×                | -                 | ×                   | ×          |
| oidc_provider_arn: the ARN of the OpenID Connect (OIDC) identity provider (IdP).                                                                                                                                                      | ×              | ×       | ×                | ×                | ✓                 | ×                   | ×          |
| oidc_token_file_path: the absolute path to the OIDC token.                                                                                                                                                                            | ×              | ×       | ×                | ×                | ✓                 | ×                   | ×          |
| external_id: the external ID of the role, which is used to prevent the confused deputy issue.                        | ×              | ×       | -                | ×                | ×                 | ×                   | ×          |
| credentials_uri: the URI of the credential.                                                                                                                                                                                           | ×              | ×       | ×                | ×                | ×                 | ✓                   | ×          |
| sts_endpoint: the endpoint of STS. VPC endpoints and Internet endpoints are supported. Default value: `sts.aliyuncs.com`. | ×              | ×       | -                | ×                | -                 | ×                   | ×          |
| timeout: the timeout period of HTTP read requests. Default value: 5000. Unit: milliseconds.                                                                                                                                           | ×              | ×       | -                | -                | -                 | -                   | ×          |
| connect_timeout: the timeout period of HTTP connection requests. Default value: 10000. Unit: milliseconds.                                                                                                                            | ×              | ×       | -                | -                | -                 | -                   | ×          |


Initialize a Credentials client
------------------------------------------------

You can use one of the following methods to initialize a Credentials client as needed: 

**Important**

* If you use a plaintext AccessKey pair in a project, the AccessKey pair may be leaked due to improper permission management on the code repository. This may threaten the security of all resources within the account to which the AccessKey pair belongs. We recommend that you store the AccessKey pair in environment variables or configuration files.

* We recommend that you initialize the Credentials client in single-instance mode. This mode not only enables the credential caching feature of the SDK, but also effectively prevents traffic control issues and waste of performance resources caused by multiple API calls. 

### Credential Type

#### Use the default credential provider chain

If you do not specify a method to initialize a Credentials client, the default credential provider chain is used. For more information, see [Default credential provider chain](#default-credential-provider-chain).

```python
from alibabacloud_credentials.client import Client as CredClient

# Do not specify a method to initialize a Credentials client.
credentialsClient = CredClient()

credential = credentialsClient.get_credential()
access_key_id = credential.get_access_key_id()
access_key_secret = credential.get_access_key_secret()
security_token = credential.get_security_token()
cred_type = credential.get_type()
```

#### Access Key

Setup access_key credential through [User Information Management][ak], it have full authority over the account, please keep it safe. For security reasons, you cannot hand over a primary account AccessKey with full access to the developer of a project. You may create a sub-account [RAM Sub-account][ram] , grant its [authorization][permissions]，and use the AccessKey of RAM Sub-account.

```python
import os
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='access_key',
    access_key_id=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_ID'),
    access_key_secret=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_SECRET'),
)
cred = Client(config)

credential = cred.get_credential()
access_key_id = credential.get_access_key_id()
access_key_secret = credential.get_access_key_secret()
security_token = credential.get_security_token()
cred_type = credential.get_type()
```

#### STS

Create a temporary security credential by applying Temporary Security Credentials (TSC) through the Security Token Service (STS).

```python
import os

from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='sts',
    # Obtain the AccessKey ID from the environment variable.
    access_key_id=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_ID'),
    # Obtain the AccessKey secret from the environment variable.
    access_key_secret=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_SECRET'),
    # Obtain the temporary STS token from the environment variable.
    security_token=os.environ.get('ALIBABA_CLOUD_SECURITY_TOKEN')
)
credClient = Client(config)

credential = credClient.get_credential()
access_key_id = credential.get_access_key_id()
access_key_secret = credential.get_access_key_secret()
security_token = credential.get_security_token()
cred_type = credential.get_type()
```

#### RAM Role ARN

The underlying logic of this method is to use an STS token to initialize a Credentials client. After you specify the Alibaba Cloud Resource Name (ARN) of a RAM role, the Credentials tool obtains the security token from STS. You can also use the `policy` parameter to limit the permissions of the RAM role.

```python
import os

from alibabacloud_credentials.client import Client as CredClient
from alibabacloud_credentials.models import Config as CredConfig

credentialsConfig = CredConfig(
    access_key_id=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_ID'),
    access_key_secret=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_SECRET'),
    type='ram_role_arn',
    # Specify the ARN of the RAM role that you want your application to assume by specifying the ALIBABA_CLOUD_ROLE_ARN environment variable. Example: acs:ram::123456789012****:role/adminrole.
    role_arn='<role_arn>',
    # Specify the role session name by specifying the ALIBABA_CLOUD_ROLE_SESSION_NAME environment variable.
    role_session_name='<role_session_name>',
    # Optional. Specify the minimum permissions for the RAM role. Example: {"Statement": [{"Action": ["*"],"Effect": "Allow","Resource": ["*"]}],"Version":"1"}
    policy='<policy>',
    role_session_expiration=3600
)
credentialsClient = CredClient(credentialsConfig)

credential = credentialsClient.get_credential()
access_key_id = credential.get_access_key_id()
access_key_secret = credential.get_access_key_secret()
security_token = credential.get_security_token()
cred_type = credential.get_type()
```

#### ECS RAM Role

ECS instances and elastic container instances can be assigned RAM roles. Programs that run on the instances can use the Credentials tool to automatically obtain an STS token for the RAM role. The STS token can be used to initialize the Credentials client.

By default, the Credentials tool accesses the metadata server of ECS in security hardening mode (IMDSv2). If an exception is thrown, the Credentials tool switches to the normal mode (IMDSv1). You can also configure the `disable_imds_v1` parameter or the *ALIBABA_CLOUD_IMDSV1_DISABLE* environment variable to specify the exception handling logic. Valid values:

* false (default): The Credentials tool continues to obtain the access credential in normal mode (IMDSv1).

* true: The exception is thrown and the Credentials tool continues to obtain the access credential in security hardening mode.

The configurations for the metadata server determine whether the server supports the security hardening mode (IMDSv2).

In addition, you can specify ALIBABA_CLOUD_ECS_METADATA_DISABLED=true to disable access from the Credentials tool to the metadata server of ECS.

```python
from alibabacloud_credentials.client import Client as CredClient
from alibabacloud_credentials.models import Config as CredConfig

credentialsConfig = CredConfig(
    type='ecs_ram_role',
    # Optional. Specify the name of the RAM role of the ECS instance by specifying the ALIBABA_CLOUD_ECS_METADATA environment variable. If you do not specify this parameter, the value is automatically obtained. We recommend that you specify this parameter to reduce the number of requests.
    role_name='<role_name>',
    # Default value: False. This parameter is optional. True: The security hardening mode (IMDSv2) is forcibly used. False: The system preferentially attempts to obtain the access credential in security hardening mode (IMDSv2). If the attempt fails, the system switches to the normal mode (IMDSv1) to obtain access credentials.
    # disable_imds_v1=True,
)
credentialsClient = CredClient(credentialsConfig)

credential = credentialsClient.get_credential()
access_key_id = credential.get_access_key_id()
access_key_secret = credential.get_access_key_secret()
security_token = credential.get_security_token()
cred_type = credential.get_type()
```

#### OIDC Role ARN

To ensure the security of cloud resources and enable untrusted applications to securely obtain required STS tokens, you can use the [RAM Roles for Service Accounts (RRSA)] feature to grant minimum necessary permissions to an application. ACK creates and mounts corresponding OpenID Connect (OIDC) token files for different application pods, and passes relevant configuration information to environment variables. The Credentials tool obtains the configuration information from the environment variables and calls the [AssumeRoleWithOIDC] operation of STS to obtain the STS token for attached roles.

The following environment variables are injected into the pod:

***ALIBABA_CLOUD_ROLE_ARN*** : the ARN of the RAM role.

***ALIBABA_CLOUD_OIDC_PROVIDER_ARN*** : the ARN of the OIDC identity provider (IdP).

***ALIBABA_CLOUD_OIDC_TOKEN_FILE*** : the path of the OIDC token file.

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='oidc_role_arn',
    # Specify the ARN of the RAM role by specifying the ALIBABA_CLOUD_ROLE_ARN environment variable.
    role_arn='<role_arn>',
    # Specify the ARN of the OIDC IdP by specifying the ALIBABA_CLOUD_OIDC_PROVIDER_ARN environment variable.
    oidc_provider_arn='<oidc_provider_arn>',
    # Specify the path of the OIDC token file by specifying the ALIBABA_CLOUD_OIDC_TOKEN_FILE environment variable.
    oidc_token_file_path='<oidc_token_file_path>',
    # Specify the role session name by specifying the ALIBABA_CLOUD_ROLE_SESSION_NAME environment variable.
    role_session_name='<role_session_name>',
    # Optional. Specify the minimum permissions for the RAM role. Example: {"Statement": [{"Action": ["*"],"Effect": "Allow","Resource": ["*"]}],"Version":"1"}
    policy='<policy>',
    # Specify the validity period of the session.
    role_session_expiration=3600
)
cred = Client(config)

credential = cred.get_credential()
access_key_id = credential.get_access_key_id()
access_key_secret = credential.get_access_key_secret()
security_token = credential.get_security_token()
cred_type = credential.get_type()
```

#### Credentials URI

This method lets you encapsulate an STS token in your application and provide a custom URI to external resources. Other services can obtain the STS token only through the URI. This minimizes the risk of AccessKey exposure. The Credentials tool lets you obtain the STS token by calling the service URI to initialize the Credentials client.

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='credentials_uri',
    # Specify the URI of the credential in the http://local_or_remote_uri/ format by specifying the ALIBABA_CLOUD_CREDENTIALS_URI environment variable.
    credentials_uri='<credentials_uri>',
)
cred = Client(config)

credential = cred.get_credential()
access_key_id = credential.get_access_key_id()
access_key_secret = credential.get_access_key_secret()
security_token = credential.get_security_token()
cred_type = credential.get_type()
```

The URI must meet the following requirements:

* GET requests are supported.

* The HTTP 200 status code can be returned.

* The following response body structure is used:

  ```json
  {
    "Code": "Success",
    "AccessKeySecret": "AccessKeySecret",
    "AccessKeyId": "AccessKeyId",
    "Expiration": "2021-09-26T03:46:38Z",
    "SecurityToken": "SecurityToken"
  }
  ```

#### Bearer

Only [Cloud Call Center](https://api.aliyun.com/api/CCC/2020-07-01/ListPrivilegesOfUser){#0764d4314be87} lets you use a bearer token to initialize an SDK client.

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='bearer',
    # Enter the bearer token.
    bearer_token='<BearerToken>',
)
cred = Client(config)

credential = cred.get_credential()
access_key_id = credential.get_access_key_id()
access_key_secret = credential.get_access_key_secret()
security_token = credential.get_security_token()
cred_type = credential.get_type()
```

### Default credential provider chain

If you want to use different types of credentials in the development and production environments of your application, you generally need to obtain the environment information from the code and write code branches to obtain different credentials for the development and production environments. The default credential provider chain of Alibaba Cloud Credentials for Java allows you to use the same code to obtain credentials for different environments based on configurations independent of the application. If you use `cred = CredClient()`{#e19090ab80ah6} to initialize a Credentials client without specifying an initialization method, the Credentials tool obtains the credential information in the following order:

1. btain the credential information from environment variables

    Look for environment credentials in environment variable. If the `ALIBABA_CLOUD_ACCESS_KEY_ID` and `ALIBABA_CLOUD_ACCESS_KEY_SECRET` environment variables are defined and are not empty, the program will use them to create default credentials. If the `ALIBABA_CLOUD_ACCESS_KEY_ID`, `ALIBABA_CLOUD_ACCESS_KEY_SECRET` and `ALIBABA_CLOUD_SECURITY_TOKEN` environment variables are defined and are not empty, the program will use them to create temporary security credentials(STS). Note: This token has an expiration time, it is recommended to use it in a temporary environment.

2. Obtain the credential information by using the RAM role of an OIDC IdP

    If no credentials with a higher priority are found, the Credentials tool checks the following environment variables that are related to the RAM role of the OIDC IdP:

    * ***ALIBABA_CLOUD_ROLE_ARN*** : the ARN of the RAM role.

    * ***ALIBABA_CLOUD_OIDC_PROVIDER_ARN*** : the ARN of the OIDC IdP.

    * ***ALIBABA_CLOUD_OIDC_TOKEN_FILE:*** the file path of the OIDC token.

    If the preceding three environment variables are specified and valid, the Credentials tool uses the environment variables to call the [AssumeRoleWithOIDC] operation of STS to obtain an STS token as the default credential.

3. Obtain the credential information from a configuration file

    **Note**
    Make sure that the version of alibabacloud_credentials is **1.0rc3** or later.

    If no credentials with a higher priority are found, the Credentials tool attempts to load the `config.json`{#d4a26eb196u7q} file. Default file path:

    * Linux/macOS: `~/.aliyun/config.json`

    * Windows: `C:\Users\USER_NAME\.aliyun\config.json`

    Do not change the preceding default paths. If you want to use this method to configure an access credential, manually create a config.json file in the corresponding path. Example:

    ```json
    {
        "current": "<PROFILE_NAME>",
        "profiles": [
            {
                "name": "<PROFILE_NAME>",
                "mode": "AK",
                "access_key_id": "<ALIBABA_CLOUD_ACCESS_KEY_ID>",
                "access_key_secret": "<ALIBABA_CLOUD_ACCESS_KEY_SECRET>"
            },
            {
                "name": "<PROFILE_NAME1>",
                "mode": "StsToken",
                "access_key_id": "<ALIBABA_CLOUD_ACCESS_KEY_ID>",
                "access_key_secret": "<ALIBABA_CLOUD_ACCESS_KEY_SECRET>",
                "sts_token": "<SECURITY_TOKEN>"
            },
            {
                "name": "<PROFILE_NAME2>",
                "mode": "RamRoleArn",
                "access_key_id": "<ALIBABA_CLOUD_ACCESS_KEY_ID>",
                "access_key_secret": "<ALIBABA_CLOUD_ACCESS_KEY_SECRET>",
                "ram_role_arn": "<ROLE_ARN>",
                "ram_session_name": "<ROLE_SESSION_NAME>",
                "expired_seconds": 3600
            },
            {
                "name": "<PROFILE_NAME3>",
                "mode": "EcsRamRole",
                "ram_role_name": "<RAM_ROLE_ARN>"
            },
            {
                "name": "<PROFILE_NAME4>",
                "mode": "OIDC",
                "oidc_provider_arn": "<OIDC_PROVIDER_ARN>",
                "oidc_token_file": "<OIDC_TOKEN_FILE>",
                "ram_role_arn": "<ROLE_ARN>",
                "ram_session_name": "<ROLE_SESSION_NAME>",
                "expired_seconds": 3600
            },
            {
                "name": "<PROFILE_NAME5>",
                "mode": "ChainableRamRoleArn",
                "source_profile": "<PROFILE_NAME>",
                "ram_role_arn": "<ROLE_ARN>",
                "ram_session_name": "<ROLE_SESSION_NAME>",
                "expired_seconds": 3600
            }
        ]
    }
    ```
    In the config.json file, you can use mode to specify a type of credential:

    * AK: uses the AccessKey pair of a RAM user to obtain the credential information.

    * StsToken: uses the STS token as the credential information.

    * RamRoleArn: uses the ARN of a RAM role to obtain the credential information.

    * EcsRamRole: uses the RAM role attached to an ECS instance to obtain the credential information.

    * OIDC: uses the ARN of an OIDC IdP and the OIDC token file to obtain the credential information.

    * ChainableRamRoleArn: utilizes a role chaining mechanism. It allows you to assume a new RAM role and acquire a new, temporary credential by referencing another credential profile, which is specified by the `source_profile` parameter.

    After you complete the configurations, the Credentials tool selects the credential specified by the **current** parameter in the configuration file and initialize the client. You can also specify the ***ALIBABA_CLOUD_PROFILE*** environment variable to specify the credential information. For example, you can set the ***ALIBABA_CLOUD_PROFILE*** environment variable to **client1** .


3. Obtain the credential information by using the RAM role of an ECS instance

   By default, if no credential that has a higher priority exists, the Credential tool accesses the metadata server of ECS in security hardening mode (IMDSv2) to obtain the STS token of the RAM role used by the ECS instance and uses the STS token as the default credential. The program automatically access the metadata server of ECS to obtain the name of the RAM role (RoleName) and then obtains the credential. Two requests are sent in this process. If you want to send only one request, add the ***ALIBABA_CLOUD_ECS_METADATA*** environment variable to specify the name of the RAM role. If an exception occurs in the security hardening mode (IMDSv2), the Credentials tool obtains the access credential in normal mode. You can also configure the ***ALIBABA_CLOUD_IMDSV1_DISABLED*** environment variable to specify an exception handling logic. Valid values of the environment variable:

   1. false: The Credentials tool continues to obtain the access credential in normal mode.

   2. true: The exception is thrown and the Credentials tool continues to obtain the access credential in security hardening mode.

   The configurations for the metadata server determine whether the server supports the security hardening mode (IMDSv2).
   
   In addition, you can specify ALIBABA_CLOUD_ECS_METADATA_DISABLED=true to disable access from the Credentials tool to the metadata server of ECS.

4. Obtain the credential information based on a URI

    If no valid credential is obtained using the preceding methods, the Credentials tool checks the ***ALIBABA_CLOUD_CREDENTIALS_URI*** environment variable. If this environment variable exists and specifies a valid URI, the Credentials tool initiates an HTTP requests to obtain an STS token as the default credential.

## Issues

[Opening an Issue](https://github.com/aliyun/credentials-python/issues/new), Issues not conforming to the guidelines may be closed immediately.

## Changelog

Detailed changes for each release are documented in the [release notes](./ChangeLog.md).

## References

- [Latest Release](https://github.com/aliyun/credentials-python)

## License

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2009-present, Alibaba Cloud All rights reserved.

[ak]: https://usercenter.console.aliyun.com/#/manage/ak
[ram]: https://ram.console.aliyun.com/users
[permissions]: https://ram.console.aliyun.com/permissions
[RAM Role]: https://ram.console.aliyun.com/#/role/list
[OIDC Role]: https://help.aliyun.com/zh/ram/user-guide/role-based-sso-by-using-oidc
[policy]: https://help.aliyun.com/zh/ram/user-guide/policy-management/

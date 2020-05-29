English | [简体中文](README-CN.md)
![](https://aliyunsdk-pages.alicdn.com/icons/AlibabaCloud.svg)

# Alibaba Cloud Credentials for Python

## Installation
- **Install with pip**

Python SDK uses a common package management tool named `pip`. If pip is not installed, see the [pip user guide](https://pip.pypa.io/en/stable/installing/ "pip User Guide") to install pip.

```bash
# Install the alibabacloud_credentials
pip install alibabacloud_credentials
```

## Usage

Before you begin, you need to sign up for an Alibaba Cloud account and retrieve your [Credentials](https://usercenter.console.aliyun.com/#/manage/ak).

### Credential Type

#### access_key

Setup access_key credential through [User Information Management][ak], it have full authority over the account, please keep it safe. Sometimes for security reasons, you cannot hand over a primary account AccessKey with full access to the developer of a project. You may create a sub-account [RAM Sub-account][ram] , grant its [authorization][permissions]，and use the AccessKey of RAM Sub-account.

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='access_key',                    # credential type
    access_key_id='accessKeyId',          # AccessKeyId
    access_key_secret='accessKeySecret',  # AccessKeySecret
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
cred_type = cred.get_type()
```



#### sts

Create a temporary security credential by applying Temporary Security Credentials (TSC) through the Security Token Service (STS).

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='sts',                           # credential type
    access_key_id='accessKeyId',          # AccessKeyId
    access_key_secret='accessKeySecret',  # AccessKeySecret
    security_token='securityToken'        # STS Token
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
security_token = cred.get_security_token()
cred_type = cred.get_type()
```



#### ram_role_arn

By specifying [RAM Role][RAM Role], the credential will be able to automatically request maintenance of STS Token. If you want to limit the permissions([How to make a policy][policy]) of STS Token, you can assign value for `Policy`.

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='ram_role_arn',                  # credential type
    access_key_id='accessKeyId',          # AccessKeyId
    access_key_secret='accessKeySecret',  # AccessKeySecret
    security_token='securityToken',       # STS Token
    role_arn='roleArn',                   # Format: acs:ram::USER_ID:role/ROLE_NAME
    role_session_name='roleSessionName',  # Role Session Name
    policy='policy',                      # Not required, limit the permissions of STS Token
    role_session_expiration=3600          # Not required, limit the Valid time of STS Token
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
security_token = cred.get_security_token()
cred_type = cred.get_type()
```



#### ecs_ram_role

By specifying the role name, the credential will be able to automatically request maintenance of STS Token.

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='ecs_ram_role',      # credential type
    role_name='roleName'      # `roleName` is optional. It will be retrieved automatically if not set. It is highly recommended to set it up to reduce requests.
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
security_token = cred.get_security_token()
cred_type = cred.get_type()
```



#### rsa_key_pair

By specifying the public key ID and the private key file, the credential will be able to automatically request maintenance of the AccessKey before sending the request. Only Japan station is supported.

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='rsa_key_pair',                  # credential type
    private_key_file='privateKeyFile',    # The file path to store the PrivateKey
    public_key_id='publicKeyId'           # PublicKeyId of your account
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
security_token = cred.get_security_token()
cred_type = cred.get_type()
```



#### bearer

If credential is required by the Cloud Call Centre (CCC), please apply for Bearer Token maintenance by yourself.

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='bearer',                        # credential type
    bearer_token='bearerToken',           # BearerToken
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
security_token = cred.get_security_token()
cred_type = cred.get_type()
```



## Issues

[Opening an Issue](https://github.com/aliyun/credentials-python/issues/new), Issues not conforming to the guidelines may be closed immediately.

## Changelog
Detailed changes for each release are documented in the [release notes](./ChangeLog.md).

## References
* [Latest Release](https://github.com/aliyun/credentials-python)

## License
[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2009-present, Alibaba Cloud All rights reserved.
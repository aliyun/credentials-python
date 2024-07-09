[English](README.md) | 简体中文

![Alibaba Cloud Logo](https://aliyunsdk-pages.alicdn.com/icons/AlibabaCloud.svg)

# Alibaba Cloud Credentials for Python

[![PyPI version](https://badge.fury.io/py/alibabacloud_credentials.svg)](https://badge.fury.io/py/alibabacloud_credentials)
[![Python Test](https://github.com/aliyun/credentials-python/actions/workflows/testPython.yml/badge.svg)](https://github.com/aliyun/credentials-python/actions/workflows/testPython.yml)
[![codecov](https://codecov.io/gh/aliyun/credentials-python/graph/badge.svg?token=Y0J1E7T35I)](https://codecov.io/gh/aliyun/credentials-python)

## 安装

- **使用 pip 安装(推荐)**

如未安装 `pip`, 请先至pip官网 [pip user guide](https://pip.pypa.io/en/stable/installing/ "pip User Guide") 安装pip .

```bash
# 安装 alibabacloud_credentials
pip install alibabacloud_credentials
```

## 使用说明

在您开始之前，您需要注册阿里云帐户并获取您的[凭证](https://usercenter.console.aliyun.com/#/manage/ak)。

### 凭证类型

#### Access Key

通过[用户信息管理](https://usercenter.console.aliyun.com/#/manage/ak)设置 access_key，它们具有该账户完全的权限，请妥善保管。有时出于安全考虑，您不能把具有完全访问权限的主账户 AccessKey 交于一个项目的开发者使用，您可以[创建RAM子账户](https://ram.console.aliyun.com/users)并为子账户[授权](https://ram.console.aliyun.com/permissions)，使用RAM子用户的 AccessKey 来进行API调用。

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='access_key',                    # 凭证类型
    access_key_id='accessKeyId',          # AccessKeyId
    access_key_secret='accessKeySecret',  # AccessKeySecret
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
cred_type = cred.get_type()
```

#### STS

通过安全令牌服务（Security Token Service，简称 STS），申请临时安全凭证（Temporary Security Credentials，简称 TSC），创建临时安全凭证。

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='sts',                           # 凭证类型
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

#### RAM Role ARN

通过指定[RAM角色](https://ram.console.aliyun.com/#/role/list)，让凭证自动申请维护 STS Token。你可以通过为 `Policy` 赋值来限制获取到的 STS Token 的权限。

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='ram_role_arn',                  # 凭证类型
    access_key_id='accessKeyId',          # AccessKeyId
    access_key_secret='accessKeySecret',  # AccessKeySecret
    security_token='securityToken',       # STS Token
    role_arn='roleArn',                   # 格式: acs:ram::用户ID:role/角色名
    role_session_name='roleSessionName',  # 角色会话名称
    policy='policy',                      # 可选, 限制 STS Token 的权限
    role_session_expiration=3600          # 可选, 限制 STS Token 的有效时间
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
security_token = cred.get_security_token()
cred_type = cred.get_type()
```

#### OIDC Role ARN

通过指定[OIDC角色]，让凭证自动申请维护 STS Token。你可以通过为 `Policy` 赋值来限制获取到的 STS Token 的权限。

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='oidc_role_arn',                  # 凭证类型
    access_key_id='accessKeyId',          # AccessKeyId
    access_key_secret='accessKeySecret',  # AccessKeySecret
    security_token='securityToken',       # STS Token
    role_arn='roleArn',                   # 格式: acs:ram::用户ID:role/角色名
    oidc_provider_arn='oidcProviderArn',  # 格式: acs:ram::用户Id:oidc-provider/OIDC身份提供商名称
    oidc_token_file_path='/Users/xxx/xxx',# 格式: path，可不设，但需要通过设置 ALIBABA_CLOUD_OIDC_TOKEN_FILE 来代替
    role_session_name='roleSessionName',  # 角色会话名称
    policy='policy',                      # 可选, 限制 STS Token 的权限
    role_session_expiration=3600          # 可选, 限制 STS Token 的有效时间
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
security_token = cred.get_security_token()
cred_type = cred.get_type()
```

#### ECS RAM Role

通过指定角色名称，让凭证自动申请维护 STS Token

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='ecs_ram_role',      # 凭证类型
    role_name='roleName',     # 账户RoleName，非必填，不填则自动获取，建议设置，可以减少请求
    enable_imds_v2=True       # 开启 V2 安全访问，非必填，可以设置环境变量来开启：ALIBABA_CLOUD_ECS_IMDSV2_ENABLE=true
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
security_token = cred.get_security_token()
cred_type = cred.get_type()
```

#### Credentials URI

通过指定一个 Credentials 地址，从外部服务申请并自动维护 STS Token

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='credentials_uri',                        # 凭证类型
    credentials_uri='http://local_or_remote_uri/', # Credentials URI
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
security_token = cred.get_security_token()
cred_type = cred.get_type()
```

#### Bearer

如呼叫中心(CCC)需用此凭证，请自行申请维护 Bearer Token。

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='bearer',                        # 凭证类型
    bearer_token='bearerToken',           # BearerToken
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
security_token = cred.get_security_token()
cred_type = cred.get_type()
```

### 使用默认凭证提供链

```python
from alibabacloud_credentials.client import Client as CredClient
from alibabacloud_ocr20191230.client import Client as OcrClient
from alibabacloud_ocr20191230.models import GetAsyncJobResultRequest
from alibabacloud_tea_rpc.models import Config
from alibabacloud_tea_util.models import RuntimeOptions

cred = CredClient()
config = Config(credential=cred)

client = OcrClient(config)

request = GetAsyncJobResultRequest(
    job_id='<job_id>'
)

runtime_options = RuntimeOptions()
response = client.get_async_job_result(request, runtime_options)
```

默认凭证提供程序链查找可用的凭证，寻找顺序如下：

1. 环境凭证

    在环境变量里寻找环境凭证，如果定义了 `ALIBABA_CLOUD_ACCESS_KEY_ID` 和 `ALIBABA_CLOUD_ACCESS_KEY_SECRET` 环境变量且不为空，程序将使用它们创建默认凭证。如果定义了 `ALIBABA_CLOUD_ACCESS_KEY_ID`、`ALIBABA_CLOUD_ACCESS_KEY_SECRET` 和 `ALIBABA_CLOUD_SECURITY_TOKEN` 环境变量且不为空，则创建 STS 方式的临时凭证，注意：该 token 存在过期时间，推荐在临时环境中使用。

2. 配置文件

    如果用户主目录存在默认文件 `~/.alibabacloud/credentials.ini （Windows 为 C:\Users\USER_NAME\.alibabacloud\credentials.ini）`，程序会自动创建指定类型和名称的凭证。默认文件可以不存在，但解析错误会抛出异常。配置名小写。不同的项目、工具之间可以共用这个配置文件，因为不在项目之内，也不会被意外提交到版本控制。\

    可以通过定义 `ALIBABA_CLOUD_CREDENTIALS_FILE` 环境变量修改默认文件的路径。不配置则使用默认配置 `default`，也可以设置环境变量 `ALIBABA_CLOUD_PROFILE` 使用配置。

    ```ini
    [default]                          # 默认配置
    enable = true                      # 启用，没有该选项默认不启用
    type = access_key                  # 认证方式为 access_key
    access_key_id = foo                # Key
    access_key_secret = bar            # Secret

    [client1]                          # 命名为 `client1` 的配置
    type = ecs_ram_role                # 认证方式为 ecs_ram_role
    role_name = EcsRamRoleTest         # Role Name

    [client2]                          # 命名为 `client2` 的配置
    enable = false                     # 不启用
    type = ram_role_arn                # 认证方式为 ram_role_arn
    region_id = cn-test                # 获取session用的region
    policy = test                      # 选填 指定权限
    access_key_id = foo
    access_key_secret = bar
    role_arn = role_arn
    role_session_name = session_name   # 选填

    [client3]                          # 命名为 `client3` 的配置
    enable = false                     # 不启用
    type = oidc_role_arn               # 认证方式为 oidc_role_arn
    region_id = cn-test                # 获取session用的region
    policy = test                      # 选填 指定权限
    access_key_id = foo                # 选填
    access_key_secret = bar            # 选填
    role_arn = role_arn
    oidc_provider_arn = oidc_provider_arn
    oidc_token_file_path = /xxx/xxx    # 可通过设置环境变量 ALIBABA_CLOUD_OIDC_TOKEN_FILE 来代替
    role_session_name = session_name   # 选填
    ```

3. 实例 RAM 角色

    如果定义了环境变量 `ALIBABA_CLOUD_ECS_METADATA` 且不为空，程序会将该环境变量的值作为角色名称，请求 <http://100.100.100.200/latest/meta-data/ram/security-credentials/> 获取临时安全凭证。

4. Credentials URI

    如果定义了环境变量 `ALIBABA_CLOUD_CREDENTIALS_URI` 且不为空, 程序会将该环境变量的值作为 Credentials URI 地址，在调用时，获取临时安全凭证。

## 问题

[提交 Issue](https://github.com/aliyun/credentials-python/issues/new)，不符合指南的问题可能会立即关闭。

## 发行说明

每个版本的详细更改记录在[发行说明](./ChangeLog.md)中。

## 相关

- [最新源码](https://github.com/aliyun/credentials-python)

## 许可证

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2009-present, Alibaba Cloud All rights reserved.

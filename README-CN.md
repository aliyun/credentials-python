[English](README.md) | 简体中文

![Alibaba Cloud Logo](https://aliyunsdk-pages.alicdn.com/icons/AlibabaCloud.svg)

# Alibaba Cloud Credentials for Python

[![PyPI version](https://badge.fury.io/py/alibabacloud_credentials.svg)](https://badge.fury.io/py/alibabacloud_credentials)
[![Python Test](https://github.com/aliyun/credentials-python/actions/workflows/testPython.yml/badge.svg)](https://github.com/aliyun/credentials-python/actions/workflows/testPython.yml)
[![codecov](https://codecov.io/gh/aliyun/credentials-python/graph/badge.svg?token=Y0J1E7T35I)](https://codecov.io/gh/aliyun/credentials-python)

## 重要的更新

- `alibabacloud-credentials` 包版本从 1.0rc1 开始，仅支持 Python 3.7 及以上的环境。

## 安装

- **使用 pip 安装(推荐)**

如未安装 `pip`, 请先至pip官网 [pip user guide](https://pip.pypa.io/en/stable/installing/ "pip User Guide") 安装pip .

```bash
# 安装 alibabacloud-credentials
pip install alibabacloud-credentials
```

## 使用说明

在您开始之前，您需要注册阿里云帐户并获取您的[凭证](https://usercenter.console.aliyun.com/#/manage/ak)。

### Credentials工具**配置参数**介绍
----------------------------------------------

Credentials工具的配置参数定义在`alibabacloud_credentials.models`模块的`Config`类中，凭据类型由必填参数`type`指定。确定凭据类型后，需根据该凭据类型选择相应的参数。下表将详细介绍`type`的取值范围及各类凭据类型所支持的参数。其中，`√`表示必填参数，`-`表示可选参数，`×`表示不支持参数。

**说明**
未在下表中列出的凭据类型及参数表示不建议继续使用。


| **type** | **access_key** | **sts** | **ram_role_arn** | **ecs_ram_role** | **oidc_role_arn** | **credentials_uri** | **bearer** |
| --- | --- | ---- | --- | --- | --- | --- | --- |
| access_key_id：访问凭据ID。                                                                                                          | √              | √       | √                | ×                | ×                 | ×                   | ×          |
| access_key_secret：访问凭据密钥。                                                                                                      | √              | √       | √                | ×                | ×                 | ×                   | ×          |
| security_token：STS Token。                                                                                                      | ×              | √       | -                | ×                | ×                 | ×                   | ×          |
| role_arn：RAM角色的ARN。                                                                                                            | ×              | ×       | √                | ×                | √                 | ×                   | ×          |
| role_session_name：自定义会话名称，默认格式为`credentials-python-当前时间的时间戳`。                                                  | ×              | ×       | -                | ×                | -                 | ×                   | ×          |
| role_name：RAM角色名称。                                                                                                             | ×              | ×       | ×                | -                | ×                 | ×                   | ×          |
| disable_imds_v1：是否强制使用加固模式，默认值为`false`。                                                                        | ×              | ×       | ×                | -                | ×                 | ×                   | ×          |
| bearer_token：bearer token。                                                                                                     | ×              | ×       | ×                | ×                | ×                 | ×                   | √          |
| policy：自定义权限策略。                                                                                                                | ×              | ×       | -                | ×                | -                 | ×                   | ×          |
| role_session_expiration：会话过期时间，默认3600秒。                                                                                        | ×              | ×       | -                | ×                | -                 | ×                   | ×          |
| oidc_provider_arn：OIDC提供商ARN。                                                                                                  | ×              | ×       | ×                | ×                | √                 | ×                   | ×          |
| oidc_token_file_path：OIDC Token文件路径。                                                                                           | ×              | ×       | ×                | ×                | √                 | ×                   | ×          |
| external_id：角色外部 ID，主要功能是防止混淆代理人问题。                              | ×              | ×       | -                | ×                | ×                 | ×                   | ×          |
| credentials_uri：凭证的URI。                                                                                                        | ×              | ×       | ×                | ×                | ×                 | √                   | ×          |
| sts_endpoint：STS的服务接入点，支持VPC服务接入点和公网服务接入点，默认值为`sts.aliyuncs.com`。 | ×              | ×       | -                | ×                | -                 | ×                   | ×          |
| timeout：HTTP请求的读超时时间，默认值为5000毫秒。                                                                                               | ×              | ×       | -                | -                | -                 | -                   | ×          |
| connect_timeout：HTTP请求的连接超时时间，默认值为10000毫秒。                                                                                     | ×              | ×       | -                | -                | -                 | -                   | ×          |


### 初始化凭据客户端
-------------------------

Credentials工具支持多种方式初始化凭据客户端，您可根据实际情况选择合适的方式进行凭据客户端初始化。

**重要**

* 在项目中使用明文AccessKey，容易因代码仓库权限管理不当造成AccessKey泄露，会威胁该账号下所有资源的安全。建议通过环境变量、配置文件等方式获取AccessKey。

* 在初始化凭据客户端时建议采用单例模式，这不仅可启用SDK的凭证缓存功能，还能有效防止因多次调用接口导致的流量控制问题和性能资源的浪费。


### 凭证类型

#### 使用默认凭据链

当您在初始化凭据客户端不传入任何参数时，Credentials工具会使用默认凭据链方式初始化客户端。默认凭据的读取逻辑请参见[默认凭据链](#默认凭证链)。

```python
from alibabacloud_credentials.client import Client as CredClient

# 不指定参数
credentialsClient = CredClient()

credential = credentialsClient.get_credential()
access_key_id = credential.get_access_key_id()
access_key_secret = credential.get_access_key_secret()
security_token = credential.get_security_token()
cred_type = credential.get_type()
```

#### Access Key

通过[用户信息管理](https://usercenter.console.aliyun.com/#/manage/ak)设置 access_key，它们具有该账户完全的权限，请妥善保管。出于安全考虑，您不能把具有完全访问权限的主账户 AccessKey 交于一个项目的开发者使用，您可以[创建RAM子账户](https://ram.console.aliyun.com/users)并为子账户[授权](https://ram.console.aliyun.com/permissions)，使用RAM子用户的 AccessKey 来进行API调用。

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

通过安全令牌服务（Security Token Service，简称 STS），申请临时安全凭证（Temporary Security Credentials，简称 TSC），创建临时安全凭证。

```python
import os

from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='sts',
    # 从环境变量中获取AccessKey ID的值
    access_key_id=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_ID'),
    # 从环境变量中获取AccessKeySecret的值
    access_key_secret=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_SECRET'),
    # 从环境变量中获取临时SecurityToken的值
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

通过指定[RAM角色](https://ram.console.aliyun.com/#/role/list)，Credentials工具可以帮助开发者前往STS换取STS Token。您可以通过为 `Policy` 赋值来限制RAM角色到一个更小的权限集合。

```python
import os

from alibabacloud_credentials.client import Client as CredClient
from alibabacloud_credentials.models import Config as CredConfig

credentialsConfig = CredConfig(
    access_key_id=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_ID'),
    access_key_secret=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_SECRET'),
    type='ram_role_arn',
    # 要扮演的RAM角色ARN，示例值：acs:ram::123456789012****:role/adminrole，可以通过环境变量ALIBABA_CLOUD_ROLE_ARN设置role_arn
    role_arn='<role_arn>',
    # 角色会话名称，可以通过环境变量ALIBABA_CLOUD_ROLE_SESSION_NAME设置role_session_name
    role_session_name='<role_session_name>',
    # 设置更小的权限策略，非必填。示例值：{"Statement": [{"Action": ["*"],"Effect": "Allow","Resource": ["*"]}],"Version":"1"}
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

ECS和ECI实例均支持绑定实例RAM角色，运行于实例中的程序可通过Credentials工具自动获取该角色的STS Token，从而完成凭据客户端的初始化。

Credentials工具将默认采用加固模式（IMDSv2）访问ECS的元数据服务（Meta Data Server），在使用加固模式时若发生异常，将使用普通模式兜底来获取访问凭据。您也可以通过设置参数`disable_imds_v1`或环境变量 *ALIBABA_CLOUD_IMDSV1_DISABLE* ，执行不同的异常处理逻辑：

- 当值为false（默认值）时，会使用普通模式继续获取访问凭据。

- 当值为true时，表示只能使用加固模式获取访问凭据，会抛出异常。

服务端是否支持IMDSv2，取决于您在服务器的配置。

另外，您可以通过配置环境变量ALIBABA_CLOUD_ECS_METADATA_DISABLED=true来关闭ECS元数据的凭证访问。

**说明**
使用加固模式获取临时身份凭证时，alibabacloud-credentials的版本不低于 **0.3.6** 。

```python
from alibabacloud_credentials.client import Client as CredClient
from alibabacloud_credentials.models import Config as CredConfig

credentialsConfig = CredConfig(
    type='ecs_ram_role',
    # 选填，该ECS角色的角色名称，不填会自动获取，但是建议加上以减少请求次数，可以通过环境变量ALIBABA_CLOUD_ECS_METADATA设置role_name
    role_name='<role_name>',
    # 选填，默认值：False。True：表示强制使用加固模式。False：系统将首先尝试在加固模式下获取凭据。如果失败，则会切换到普通模式（IMDSv1）进行尝试
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

为了避免影响云上资源的安全，同时又能让不可信的应用安全地获取所需的 STS Token，实现应用级别的权限最小化，您可以使用[RRSA（RAM Roles for Service Account）]功能。阿里云容器集群会为不同的应用Pod创建和挂载相应的服务账户OIDC Token文件，并将相关配置信息注入到环境变量中，Credentials工具通过获取环境变量的配置信息，调用STS服务的[AssumeRoleWithOIDC]接口换取绑定角色的STS Token。

注入的环境变量如下：

***ALIBABA_CLOUD_ROLE_ARN：*** RAM角色名称ARN；

***ALIBABA_CLOUD_OIDC_PROVIDER_ARN：*** OIDC提供商ARN；

***ALIBABA_CLOUD_OIDC_TOKEN_FILE：*** OIDC Token文件路径；

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='oidc_role_arn',
    # RAM角色名称ARN，可以通过环境变量ALIBABA_CLOUD_ROLE_ARN设置role_arn
    role_arn='<role_arn>',
    # OIDC提供商ARN，可以通过环境变量ALIBABA_CLOUD_OIDC_PROVIDER_ARN设置oidc_provider_arn
    oidc_provider_arn='<oidc_provider_arn>',
    # OIDC Token文件路径，可以通过环境变量ALIBABA_CLOUD_OIDC_TOKEN_FILE设置oidc_token_file_path
    oidc_token_file_path='<oidc_token_file_path>',
    # 角色会话名称，可以通过环境变量ALIBABA_CLOUD_ROLE_SESSION_NAME设置role_session_name
    role_session_name='<role_session_name>',
    # 设置更小的权限策略，非必填。示例值：{"Statement": [{"Action": ["*"],"Effect": "Allow","Resource": ["*"]}],"Version":"1"}
    policy='<policy>',
    # 设置session过期时间
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

通过在应用内部封装STS Token服务并对外提供自定义URI，其他服务仅能通过该URI获取STS Token，这样能够有效降低AK等信息的暴露风险。Credentials工具支持通过请求该服务的URI来获取STS Token，从而实现凭据客户端的初始化。

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='credentials_uri',
    # 凭证的 URI，格式为http://local_or_remote_uri/，可以通过环境变量ALIBABA_CLOUD_CREDENTIALS_URI设置credentials_uri
    credentials_uri='<credentials_uri>',
)
cred = Client(config)

credential = cred.get_credential()
access_key_id = credential.get_access_key_id()
access_key_secret = credential.get_access_key_secret()
security_token = credential.get_security_token()
cred_type = credential.get_type()
```

该地址必须满足如下条件：

* 支持GET请求。

* 响应 200 状态码。

* 响应体为如下的结构：

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

目前只有云呼叫中心[CCC](https://api.aliyun.com/api/CCC/2020-07-01/ListPrivilegesOfUser)这款产品支持Bearer Token的凭据初始化方式。

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='bearer',
    # 填入您的Bearer Token
    bearer_token='<BearerToken>',
)
cred = Client(config)

credential = cred.get_credential()
access_key_id = credential.get_access_key_id()
access_key_secret = credential.get_access_key_secret()
security_token = credential.get_security_token()
cred_type = credential.get_type()
```

### 默认凭证链

当您的程序开发环境和生产环境采用不同的凭据类型，常见做法是在代码中获取当前环境信息，编写获取不同凭据的分支代码。借助Credentials工具的默认凭据链，您可以用同一套代码，通过程序之外的配置来控制不同环境下的凭据获取方式。当您在不传入参数的情况下，直接使用`cred = CredClient()`初始化凭据客户端时，阿里云SDK将会尝试按照如下顺序查找相关凭据信息。

1. 使用环境变量

    在环境变量里寻找环境凭证，如果定义了 `ALIBABA_CLOUD_ACCESS_KEY_ID` 和 `ALIBABA_CLOUD_ACCESS_KEY_SECRET` 环境变量且不为空，程序将使用它们创建默认凭证。如果定义了 `ALIBABA_CLOUD_ACCESS_KEY_ID`、`ALIBABA_CLOUD_ACCESS_KEY_SECRET` 和 `ALIBABA_CLOUD_SECURITY_TOKEN` 环境变量且不为空，则创建 STS 方式的临时凭证，注意：该 token 存在过期时间，推荐在临时环境中使用。

2. 使用OIDC RAM角色

    如果未找到更高优先级的凭据信息，Credentials工具会检查以下与OIDC RAM角色相关的环境变量：

    * ***ALIBABA_CLOUD_ROLE_ARN：*** RAM角色名称ARN。

    * ***ALIBABA_CLOUD_OIDC_PROVIDER_ARN：*** OIDC提供商ARN。

    * ***ALIBABA_CLOUD_OIDC_TOKEN_FILE：*** OIDC Token文件路径。

    如果以上三个变量均被设置且内容有效，Credentials将会使用变量内容调用STS服务的[AssumeRoleWithOIDC]接口换取STS Token作为默认凭据。

3. 使用配置文件

    **说明**
    该功能要求alibabacloud_credentials的版本不低于 **1.0rc3** 。

    如果未找到更高优先级的凭据信息，Credentials工具会尝试加载`config.json`配置文件。该文件的默认完整路径如下：

    * Linux/Mac系统：`~/.aliyun/config.json`

    * Windows系统：`C:\Users\USER_NAME\.aliyun\config.json`

    请注意，这些默认路径不可更改为其他路径。如果您需要通过此方式配置访问凭据，您可以手动在相应路径下创建config.json配置文件，内容格式示例如下：

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
    在config.json配置文件中可以通过mode指定不同的凭据：

    * AK：使用用户的Access Key作为凭据信息；

    * StsToken：使用STS Token作为凭据信息；

    * RamRoleArn：使用RAM角色的ARN来获取凭据信息；

    * EcsRamRole：利用ECS绑定的RAM角色来获取凭据信息；

    * OIDC：通过OIDC ARN和OIDC Token来获取凭据信息；

    * ChainableRamRoleArn：采用角色链的方式，通过`source_profile`指定`config.json`配置文件中其他凭据的名称，以重新获取新的凭据信息。

    配置完成后，Credentials将根据配置文件中 **current** 所指定的凭据名称，选择对应的凭据初始化凭据客户端。此外，还可以通过环境变量 ***ALIBABA_CLOUD_PROFILE*** 指定具体的凭据名称，例如将 ***ALIBABA_CLOUD_PROFILE*** 的值设置为 **client1** 。


4. 使用ECS实例RAM角色

   若不存在优先级更高的凭据信息，Credentials工具将默认采用加固模式（IMDSv2）访问ECS的元数据服务（Meta Data Server），以获取ECS实例RAM角色的STS Token作为默认凭据信息。程序会自动访问ECS的元数据服务拿到RoleName信息，再去获取凭证，也就是两次请求。若想减少一次请求，可以直接在环境变量中配置 ***ALIBABA_CLOUD_ECS_METADATA*** 来指定实例RAM角色名称。在使用加固模式时若发生异常，将使用普通模式兜底来获取访问凭据。您也可以通过设置环境变量 ***ALIBABA_CLOUD_IMDSV1_DISABLED*** ，执行不同的异常处理逻辑：

   - 当值为false时，会使用普通模式继续获取访问凭据。

   - 当值为true时，表示只能使用加固模式获取访问凭据，会抛出异常。

   服务端是否支持IMDSv2，取决于您在服务器的配置。

   另外，您可以通过配置环境变量ALIBABA_CLOUD_ECS_METADATA_DISABLED=true来关闭ECS元数据的凭证访问。

5. 使用Credentials工具URI

    如果上述方式均未找到有效的凭据信息，Credentials工具会检查环境变量 ***ALIBABA_CLOUD_CREDENTIALS_URI*** ，如果该变量存在且指向一个有效的URI地址，Credentials会向该URI发起HTTP请求，获取临时安全凭证作为默认凭据。

## 问题

[提交 Issue](https://github.com/aliyun/credentials-python/issues/new)，不符合指南的问题可能会立即关闭。

## 发行说明

每个版本的详细更改记录在[发行说明](./ChangeLog.md)中。

## 相关

- [最新源码](https://github.com/aliyun/credentials-python)

## 许可证

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2009-present, Alibaba Cloud All rights reserved.

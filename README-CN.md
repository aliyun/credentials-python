[English](README.md) | 简体中文

![](https://aliyunsdk-pages.alicdn.com/icons/AlibabaCloud.svg)

# Alibaba Cloud Credentials for Python


## 安装

- **使用 pip 安装(推荐)**

如未安装 `pip`, 请先至pip官网 [pip user guide](https://pip.pypa.io/en/stable/installing/ "pip User Guide") 安装pip .

```bash
# 安装 alibabacloud_credentials
pip install alibabacloud_credentials
```

## 使用说明

在您开始之前，您需要注册阿里云帐户并获取您的[凭证](https://usercenter.console.aliyun.com/#/manage/ak)。

#### 凭证类型

##### access_key

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



##### sts

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



##### Ram_role_arn

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



##### ecs_ram_role

通过指定角色名称，让凭证自动申请维护 STS Token

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='ecs_ram_role',      # 凭证类型
    role_name='roleName'      # 账户RoleName，非必填，不填则自动获取，建议设置，可以减少请求
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
security_token = cred.get_security_token()
cred_type = cred.get_type()
```



##### Ras_key_pair

通过指定公钥ID和私钥文件，让凭证自动申请维护 AccessKey。仅支持日本站。

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='rsa_key_pair',                  # 凭证类型
    private_key_file='privateKeyFile',    # PrivateKey文件路径
    public_key_id='publicKeyId'           # 账户PublicKeyId
)
cred = Client(config)

access_key_id = cred.get_access_key_id()
access_key_secret = cred.get_access_key_secret()
security_token = cred.get_security_token()
cred_type = cred.get_type()
```



##### bearer

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



## 问题

[提交 Issue](https://github.com/aliyun/credentials-python/issues/new)，不符合指南的问题可能会立即关闭。

## 发行说明
每个版本的详细更改记录在[发行说明](./ChangeLog.md)中。

## 相关
* [最新源码](https://github.com/aliyun/credentials-python)

## 许可证
[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2009-present, Alibaba Cloud All rights reserved.


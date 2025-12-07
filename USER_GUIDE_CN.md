# 阿里云凭证工具（Python）用户使用指南

## 1. 项目简介

阿里云凭证工具（alibabacloud-credentials-python）是为 Python 开发者提供的统一凭证管理解决方案。它支持多种凭证类型，包括 AccessKey、STS Token、RAM 角色、ECS 实例角色、OIDC 令牌等，帮助开发者在各种环境中安全、便捷地管理和获取阿里云 API 访问凭证。

### 核心能力

- **多种凭证类型支持**：支持 AccessKey、STS、Bearer Token、ECS RAM Role、RAM Role ARN、RSA Key Pair、OIDC Role ARN、Credentials URI 等多种凭证类型
- **默认凭证链**：自动按优先级从多个来源（环境变量、配置文件、ECS 元数据服务等）查找凭证
- **凭证缓存与自动刷新**：自动缓存临时凭证并在过期前刷新，避免频繁调用 STS 服务
- **安全加固模式**：支持 ECS 元数据服务的 IMDSv2 安全加固模式
- **异步支持**：提供完整的异步 API，支持高并发场景

### 典型应用场景

1. **本地开发环境**：使用环境变量或配置文件存储 AccessKey
2. **ECS/ECI 实例**：使用实例 RAM 角色自动获取临时凭证
3. **容器环境（ACK）**：使用 OIDC 令牌实现服务账号权限管理
4. **跨账号访问**：使用 RAM Role ARN 实现角色扮演
5. **CI/CD 流水线**：使用 STS 临时凭证或 OIDC 令牌
6. **微服务架构**：使用 Credentials URI 集中管理凭证分发

---

## 2. 使用前提与环境要求

### 操作系统要求

- **Linux**：主流发行版（Ubuntu、CentOS、Debian 等）
- **macOS**：10.14 及以上版本
- **Windows**：Windows 7/Server 2012 及以上版本

### 运行时环境

- **Python 版本**：≥ 3.7（从 1.0rc1 版本开始，仅支持 Python 3.7 及以上）
  - 推荐使用 Python 3.8 或更高版本以获得更好的性能和安全性
  
### 依赖库

项目依赖以下核心库（通过 pip 自动安装）：

- `alibabacloud-tea` (≥ 0.4.0)
- `alibabacloud_credentials_api` (≥ 1.0.0, < 2.0.0)
- `APScheduler` (≥ 3.10.0)：用于凭证自动刷新
- `aiofiles` (≥ 22.1.0)：用于异步文件操作

**注意**：Python 3.8 及以下版本对 `APScheduler` 和 `aiofiles` 有特定版本限制。

### 网络要求

- **互联网访问**：
  - 需要访问阿里云 STS 服务（`sts.aliyuncs.com` 或区域化端点）
  - 如果使用 VPC 端点，需要配置 VPC 网络环境
- **ECS 元数据服务**（仅 ECS 实例）：
  - 需要能够访问 `100.100.100.200`（元数据服务地址）
  - 默认端口：80（HTTP）
- **Credentials URI**（如使用）：
  - 需要能够访问自定义凭证服务的 HTTP/HTTPS 端点

### 权限要求

- **阿里云账号或 RAM 用户**：
  - 拥有相应操作权限的 AccessKey ID 和 AccessKey Secret
  - 或配置了 RAM 角色的 ECS 实例权限
- **文件系统权限**：
  - 读取配置文件（如 `~/.aliyun/config.json`、`~/.alibabacloud/credentials.ini`）
  - 写入日志文件（如果启用日志功能）
- **特殊场景权限**：
  - ECS RAM Role：实例需要绑定 RAM 角色
  - OIDC Token：需要有读取 OIDC Token 文件的权限

### API 密钥获取

在使用本工具前，您需要：

1. 登录[阿里云控制台](https://usercenter.console.aliyun.com/#/manage/ak)
2. 创建或获取 AccessKey ID 和 AccessKey Secret
3. （可选）创建 RAM 用户或 RAM 角色以实现最小权限原则

---

## 3. 快速开始指南

### 安装

#### 使用 pip 安装（推荐）

```bash
pip install alibabacloud-credentials
```

#### 从源码安装

```bash
git clone https://github.com/aliyun/credentials-python.git
cd credentials-python
pip install .
```

### 基础配置

#### 方式 1：通过环境变量配置（推荐用于生产环境）

```bash
# AccessKey 方式
export ALIBABA_CLOUD_ACCESS_KEY_ID="your_access_key_id"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your_access_key_secret"

# STS Token 方式（临时凭证）
export ALIBABA_CLOUD_ACCESS_KEY_ID="your_access_key_id"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your_access_key_secret"
export ALIBABA_CLOUD_SECURITY_TOKEN="your_security_token"

# OIDC 方式（适用于容器环境）
export ALIBABA_CLOUD_ROLE_ARN="acs:ram::123456789:role/your-role"
export ALIBABA_CLOUD_OIDC_PROVIDER_ARN="acs:ram::123456789:oidc-provider/your-provider"
export ALIBABA_CLOUD_OIDC_TOKEN_FILE="/path/to/oidc/token"
```

#### 方式 2：通过配置文件

创建配置文件 `~/.aliyun/config.json`：

```json
{
  "current": "default",
  "profiles": [
    {
      "name": "default",
      "mode": "AK",
      "access_key_id": "<YOUR_ACCESS_KEY_ID>",
      "access_key_secret": "<YOUR_ACCESS_KEY_SECRET>"
    }
  ]
}
```

### 启动与验证

#### 示例 1：使用默认凭证链

```python
from alibabacloud_credentials.client import Client as CredClient

# 不传入任何参数，自动使用默认凭证链
client = CredClient()

# 获取凭证
credential = client.get_credential()
print(f"AccessKey ID: {credential.access_key_id}")
print(f"AccessKey Secret: {credential.access_key_secret}")
print(f"Security Token: {credential.security_token}")
print(f"Credential Type: {credential.type}")
```

**预期输出**：
```
AccessKey ID: LTAI4G...
AccessKey Secret: ******
Security Token: None
Credential Type: default/env
```

#### 示例 2：显式指定凭证类型

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='access_key',
    access_key_id='your_access_key_id',
    access_key_secret='your_access_key_secret'
)
client = Client(config)

credential = client.get_credential()
print(f"AccessKey ID: {credential.access_key_id}")
```

**预期输出**：
```
AccessKey ID: your_access_key_id
```

#### 示例 3：在 ECS 实例上使用实例 RAM 角色

```python
from alibabacloud_credentials.client import Client
from alibabacloud_credentials.models import Config

config = Config(
    type='ecs_ram_role',
    role_name='your_ecs_role_name'  # 可选，不填会自动获取
)
client = Client(config)

credential = client.get_credential()
print(f"AccessKey ID: {credential.access_key_id}")
print(f"Security Token: {credential.security_token}")
```

**预期输出**：
```
AccessKey ID: STS.NUxxx...
Security Token: CAISxxx...
```

### 构建与测试

#### 运行测试套件

```bash
# 安装测试依赖
pip install pytest coverage

# 运行所有测试
python -m unittest discover

# 查看代码覆盖率
coverage run -m unittest discover
coverage report
```

#### 运行单个测试

```bash
python -m unittest tests.test_client
```

---

## 4. 常见问题解答（FAQ）

以下问题基于代码中所有潜在的失败路径和异常分支进行整理，帮助您快速定位和解决实际使用中可能遇到的问题。

### 4.1 通用问题

#### Q1：初始化凭证客户端时报错 `invalid type option`

**问题现象**：
```
CredentialException: invalid type option, support: access_key, sts, bearer, ecs_ram_role, ram_role_arn, rsa_key_pair, oidc_role_arn, credentials_uri
```

**根本原因**：
传入的 `type` 参数值不在支持的凭证类型范围内。代码中 `client.py` 的 `get_credentials` 方法只支持以下类型：
- `access_key`、`sts`、`bearer`、`ecs_ram_role`、`ram_role_arn`、`rsa_key_pair`、`oidc_role_arn`、`credentials_uri`

**解决方案**：
1. 检查 `Config` 对象的 `type` 参数是否拼写正确（区分大小写，使用下划线）
2. 确认使用的是上述支持的类型之一
3. 示例正确用法：
```python
config = Config(
    type='access_key',  # 正确：使用下划线
    access_key_id='...',
    access_key_secret='...'
)
```

---

#### Q2：默认凭证链失败，提示 `unable to load credentials from any of the providers in the chain`

**问题现象**：
```
CredentialException: unable to load credentials from any of the providers in the chain: ['EnvironmentVariableCredentialsProvider: ...', 'ProfileCredentialsProvider: ...', ...]
```

**根本原因**：
默认凭证链按以下顺序查找凭证，但所有方式都失败了：
1. 环境变量
2. OIDC 令牌（如果环境变量已配置）
3. CLI 配置文件 (`~/.aliyun/config.json`)
4. INI 配置文件 (`~/.alibabacloud/credentials.ini`)
5. ECS 元数据服务
6. Credentials URI

错误消息会列出每个提供者的具体失败原因。

**解决方案**：
1. **检查环境变量**：
   ```bash
   echo $ALIBABA_CLOUD_ACCESS_KEY_ID
   echo $ALIBABA_CLOUD_ACCESS_KEY_SECRET
   ```
   确保环境变量已设置且非空。

2. **检查配置文件**：
   - 确认 `~/.aliyun/config.json` 或 `~/.alibabacloud/credentials.ini` 文件存在
   - 验证文件格式正确（JSON 或 INI 格式）
   - 确认 `current` 字段或 `ALIBABA_CLOUD_PROFILE` 环境变量指向的配置项存在

3. **ECS 实例检查**（如果在 ECS 上运行）：
   - 确认实例已绑定 RAM 角色
   - 检查元数据服务是否可访问：
     ```bash
     curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
     ```

4. **逐个排查**：查看错误消息中每个提供者的具体失败原因，针对性解决。

---

#### Q3：凭证过期或失效

**问题现象**：
调用阿里云 API 时返回 `InvalidAccessKeyId.NotFound` 或 `SecurityTokenExpired` 错误。

**根本原因**：
- AccessKey 已被删除或禁用
- STS Token 已过期（默认有效期 3600 秒）
- ECS 实例角色凭证已过期但未正确刷新

**解决方案**：
1. **AccessKey 问题**：
   - 登录阿里云控制台，检查 AccessKey 状态
   - 创建新的 AccessKey 替换已失效的密钥

2. **STS Token 问题**：
   - 凭证工具会自动缓存和刷新临时凭证（在过期前 15 分钟刷新）
   - 如果手动管理 STS Token，确保及时更新环境变量或配置文件
   - 检查 `role_session_expiration` 参数设置（默认 3600 秒）

3. **强制刷新凭证**：
   ```python
   # 重新初始化客户端以强制获取新凭证
   client = CredClient()
   credential = client.get_credential()
   ```

---

### 4.2 环境变量凭证问题

#### Q4：设置了环境变量但仍提示凭证为空

**问题现象**：
```
CredentialException: Environment variable accessKeyId cannot be empty
CredentialException: Environment variable accessKeySecret cannot be empty
```

**根本原因**：
代码 `env.py` 中检查环境变量时，如果环境变量存在但值为空字符串（`len == 0`），会抛出异常而不是返回 `None`。

**解决方案**：
1. 检查环境变量是否确实有值：
   ```bash
   echo "[$ALIBABA_CLOUD_ACCESS_KEY_ID]"
   echo "[$ALIBABA_CLOUD_ACCESS_KEY_SECRET]"
   ```
   
2. 避免设置空环境变量：
   ```bash
   # 错误示例
   export ALIBABA_CLOUD_ACCESS_KEY_ID=""  # 会导致错误
   
   # 正确示例
   unset ALIBABA_CLOUD_ACCESS_KEY_ID  # 完全不设置
   # 或
   export ALIBABA_CLOUD_ACCESS_KEY_ID="your_actual_key"  # 设置实际值
   ```

3. 如果使用 Shell 脚本设置环境变量，确保变量赋值时没有多余的空格或引号。

---

### 4.3 配置文件问题

#### Q5：CLI 配置文件无法加载，提示文件不存在

**问题现象**：
```
CredentialException: unable to open credentials file: /Users/xxx/.aliyun/config.json
```

**根本原因**：
代码 `cli_profile.py` 检查文件是否存在且为文件类型（`os.path.exists` 和 `os.path.isfile`），如果文件不存在或为目录会抛出异常。

**解决方案**：
1. **创建配置文件**：
   ```bash
   # Linux/macOS
   mkdir -p ~/.aliyun
   cat > ~/.aliyun/config.json << EOF
   {
     "current": "default",
     "profiles": [
       {
         "name": "default",
         "mode": "AK",
         "access_key_id": "your_access_key_id",
         "access_key_secret": "your_access_key_secret"
       }
     ]
   }
   EOF
   
   # Windows (PowerShell)
   New-Item -Path "$env:USERPROFILE\.aliyun" -ItemType Directory -Force
   @"
   {
     "current": "default",
     "profiles": [...]
   }
   "@ | Out-File -FilePath "$env:USERPROFILE\.aliyun\config.json" -Encoding UTF8
   ```

2. **禁用 CLI 配置文件**：
   如果不需要使用配置文件，可以禁用：
   ```bash
   export ALIBABA_CLOUD_CLI_PROFILE_DISABLED=true
   ```

3. **检查文件权限**：
   ```bash
   ls -la ~/.aliyun/config.json
   chmod 600 ~/.aliyun/config.json  # 设置仅所有者可读写
   ```

---

#### Q6：配置文件格式错误，无法解析

**问题现象**：
```
CredentialException: failed to parse credential form cli credentials file: /Users/xxx/.aliyun/config.json
```

**根本原因**：
JSON 配置文件格式不正确，例如：
- 缺少逗号、括号
- 使用了单引号而非双引号
- 包含注释（JSON 不支持注释）
- 编码问题（非 UTF-8）

**解决方案**：
1. **验证 JSON 格式**：
   ```bash
   python3 -m json.tool ~/.aliyun/config.json
   ```
   
2. **常见格式错误修复**：
   ```json
   {
     "current": "default",  // 错误：JSON 不支持注释
     "profiles": [
       {
         "name": "default",
         'mode': 'AK'  // 错误：应使用双引号
       }
     ]
   }
   ```
   
   正确格式：
   ```json
   {
     "current": "default",
     "profiles": [
       {
         "name": "default",
         "mode": "AK",
         "access_key_id": "...",
         "access_key_secret": "..."
       }
     ]
   }
   ```

3. **使用在线 JSON 验证工具**：如 JSONLint.com 检查格式。

---

#### Q7：配置文件中指定的 profile 不存在

**问题现象**：
```
CredentialException: failed to get credential from credentials file: ~/.alibabacloud/credentials.ini
```

**根本原因**：
配置文件中 `current` 字段或环境变量 `ALIBABA_CLOUD_PROFILE` 指定的配置项名称在配置文件中不存在。

**解决方案**：
1. **检查配置项名称**：
   ```json
   {
     "current": "production",  // 指定使用 "production" 配置
     "profiles": [
       {
         "name": "default",  // 实际只有 "default" 配置
         ...
       }
     ]
   }
   ```
   确保 `current` 值与某个 `profiles` 数组中的 `name` 匹配。

2. **使用环境变量覆盖**：
   ```bash
   export ALIBABA_CLOUD_PROFILE=default
   ```

3. **INI 格式配置文件**（`~/.alibabacloud/credentials.ini`）：
   确保节名称（section name）存在：
   ```ini
   [default]
   type = access_key
   access_key_id = ...
   access_key_secret = ...
   ```

---

### 4.4 ECS RAM Role 问题

#### Q8：ECS 元数据服务无法访问

**问题现象**：
```
CredentialException: Failed to get RAM session credentials from ECS metadata service. HttpCode=404
CredentialException: Failed to get RAM session credentials from ECS metadata service. HttpCode=500
```

**根本原因**：
- 实例未绑定 RAM 角色
- 元数据服务 (100.100.100.200) 不可达
- 网络配置问题（防火墙、安全组）
- 元数据服务版本问题（IMDSv1/IMDSv2）

**解决方案**：
1. **确认实例已绑定 RAM 角色**：
   ```bash
   # 在 ECS 实例上执行
   curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
   ```
   应返回角色名称，如果返回 404 说明未绑定角色。

2. **检查元数据服务可访问性**：
   ```bash
   ping 100.100.100.200
   telnet 100.100.100.200 80
   ```

3. **检查安全组规则**：
   确保没有规则阻止访问 100.100.100.200:80。

4. **检查环境变量**：
   ```bash
   # 确保未禁用元数据服务
   echo $ALIBABA_CLOUD_ECS_METADATA_DISABLED
   ```
   如果设置为 `true`，需要改为 `false` 或 `unset`。

5. **指定角色名称以减少请求**：
   ```python
   config = Config(
       type='ecs_ram_role',
       role_name='your_role_name'  # 直接指定角色名称
   )
   ```

---

#### Q9：IMDSv2 强制模式下无法获取凭证

**问题现象**：
```
CredentialException: Failed to get token from ECS Metadata Service. HttpCode=403
```

**根本原因**：
启用了 `disable_imds_v1=True` 或环境变量 `ALIBABA_CLOUD_IMDSV1_DISABLED=true`，强制使用 IMDSv2 模式，但元数据服务不支持 IMDSv2 或配置不正确。

代码逻辑（`ecs_ram_role.py`）：
- 默认先尝试 IMDSv2（获取 token）
- 如果失败且 `disable_imds_v1=False`，降级到 IMDSv1
- 如果 `disable_imds_v1=True`，直接抛出异常

**解决方案**：
1. **检查元数据服务 IMDSv2 配置**：
   联系管理员确认 ECS 实例元数据服务是否支持 IMDSv2。

2. **降级到 IMDSv1**：
   ```python
   config = Config(
       type='ecs_ram_role',
       disable_imds_v1=False  # 允许降级到 IMDSv1
   )
   ```

3. **检查环境变量**：
   ```bash
   unset ALIBABA_CLOUD_IMDSV1_DISABLED
   # 或
   export ALIBABA_CLOUD_IMDSV1_DISABLED=false
   ```

4. **网络延迟或超时调整**：
   ```python
   from alibabacloud_credentials.http import HttpOptions
   
   config = Config(
       type='ecs_ram_role',
       timeout=5000,  # 读超时 5 秒
       connect_timeout=2000  # 连接超时 2 秒
   )
   ```

---

#### Q10：ECS 元数据服务已被禁用

**问题现象**：
```
ValueError: IMDS credentials is disabled
```

**根本原因**：
环境变量 `ALIBABA_CLOUD_ECS_METADATA_DISABLED=true` 被设置，代码在初始化 `EcsRamRoleCredentialsProvider` 时直接抛出异常。

**解决方案**：
1. **启用元数据服务**：
   ```bash
   unset ALIBABA_CLOUD_ECS_METADATA_DISABLED
   # 或
   export ALIBABA_CLOUD_ECS_METADATA_DISABLED=false
   ```

2. **使用其他凭证方式**：
   如果确实需要禁用元数据服务，请使用其他凭证类型（如 AccessKey、配置文件等）。

---

### 4.5 RAM Role ARN 问题

#### Q11：RAM Role ARN 凭证刷新失败，提示角色 ARN 为空

**问题现象**：
```
ValueError: role_arn or environment variable ALIBABA_CLOUD_ROLE_ARN cannot be empty
```

**根本原因**：
未通过参数或环境变量提供 `role_arn`。代码在 `ram_role_arn.py` 中会检查 `role_arn` 是否为 `None` 或空字符串。

**解决方案**：
1. **通过参数传入**：
   ```python
   config = Config(
       type='ram_role_arn',
       access_key_id='...',
       access_key_secret='...',
       role_arn='acs:ram::123456789:role/your-role',  # 必须提供
       role_session_name='session-name'
   )
   ```

2. **通过环境变量传入**：
   ```bash
   export ALIBABA_CLOUD_ROLE_ARN="acs:ram::123456789:role/your-role"
   export ALIBABA_CLOUD_ROLE_SESSION_NAME="session-name"
   ```

3. **检查 ARN 格式**：
   确保 ARN 格式正确：`acs:ram::<account_id>:role/<role_name>`

---

#### Q12：会话持续时间设置不当

**问题现象**：
```
ValueError: session duration should be in the range of 900s - max session duration
```

**根本原因**：
`duration_seconds` 参数小于 900 秒（15 分钟），不符合 STS 服务的最小会话时长要求。

**解决方案**：
1. **设置合理的会话时长**：
   ```python
   config = Config(
       type='ram_role_arn',
       ...,
       role_session_expiration=3600  # 默认 1 小时，最小 900 秒
   )
   ```

2. **允许的范围**：
   - 最小值：900 秒（15 分钟）
   - 最大值：取决于角色的最大会话时长设置（通常为 12 小时）

---

#### Q13：STS 服务调用失败

**问题现象**：
```
CredentialException: error refreshing credentials from ram_role_arn, http_code: 400, result: {...}
CredentialException: unable to load original credentials from the provider in RAM role arn
```

**根本原因**：
- 底层凭证提供者（AccessKey 或 STS Token）返回 `None`
- STS API 调用失败（权限不足、网络问题、参数错误）
- 响应体中缺少 `Credentials` 字段

**解决方案**：
1. **检查底层凭证**：
   确保 `access_key_id` 和 `access_key_secret` 正确：
   ```python
   # 测试底层凭证是否有效
   from alibabacloud_credentials.provider import StaticAKCredentialsProvider
   
   provider = StaticAKCredentialsProvider(
       access_key_id='...',
       access_key_secret='...'
   )
   cred = provider.get_credentials()
   print(cred.get_access_key_id())
   ```

2. **检查 RAM 角色权限**：
   - 确认当前 AccessKey 对应的 RAM 用户有 `sts:AssumeRole` 权限
   - 确认角色的信任策略允许当前账号/用户扮演

3. **检查网络连接**：
   ```bash
   curl https://sts.aliyuncs.com
   ```

4. **查看详细错误信息**：
   错误消息中的 `result` 字段包含 STS API 返回的详细错误码和消息，根据错误码查阅[STS API 文档](https://help.aliyun.com/document_detail/28756.html)。

5. **使用正确的 STS 端点**：
   如果在特定区域或 VPC 环境：
   ```python
   config = Config(
       type='ram_role_arn',
       ...,
       sts_endpoint='sts-vpc.cn-hangzhou.aliyuncs.com'  # VPC 端点
   )
   ```

---

### 4.6 OIDC Role ARN 问题

#### Q14：OIDC Token 文件不存在或路径错误

**问题现象**：
```
ValueError: oidc_token_file_path or environment variable ALIBABA_CLOUD_OIDC_TOKEN_FILE cannot be empty
FileNotFoundError: [Errno 2] No such file or directory: '/path/to/oidc/token'
```

**根本原因**：
- 未提供 OIDC Token 文件路径
- 文件路径错误或文件不存在
- 文件权限不足

**解决方案**：
1. **检查文件是否存在**：
   ```bash
   ls -la /var/run/secrets/tokens/oidc-token
   cat /var/run/secrets/tokens/oidc-token
   ```

2. **通过环境变量设置**（K8s 场景通常自动注入）：
   ```bash
   export ALIBABA_CLOUD_OIDC_TOKEN_FILE="/var/run/secrets/tokens/oidc-token"
   ```

3. **检查文件权限**：
   ```bash
   chmod 400 /path/to/oidc/token  # 仅所有者可读
   ```

4. **在容器中验证文件挂载**：
   ```yaml
   # Kubernetes Pod 配置示例
   spec:
     volumes:
     - name: oidc-token
       projected:
         sources:
         - serviceAccountToken:
             path: oidc-token
             expirationSeconds: 7200
             audience: sts.aliyuncs.com
     containers:
     - name: app
       volumeMounts:
       - name: oidc-token
         mountPath: /var/run/secrets/tokens
         readOnly: true
   ```

---

#### Q15：OIDC Provider ARN 或 Role ARN 缺失

**问题现象**：
```
ValueError: oidc_provider_arn or environment variable ALIBABA_CLOUD_OIDC_PROVIDER_ARN cannot be empty
ValueError: role_arn or environment variable ALIBABA_CLOUD_ROLE_ARN cannot be empty
```

**根本原因**：
代码 `oidc.py` 要求必须同时提供 `role_arn`、`oidc_provider_arn` 和 `oidc_token_file_path`，任何一个为空都会抛出异常。

**解决方案**：
1. **完整配置三个必需参数**：
   ```python
   config = Config(
       type='oidc_role_arn',
       role_arn='acs:ram::123456789:role/your-role',
       oidc_provider_arn='acs:ram::123456789:oidc-provider/your-provider',
       oidc_token_file_path='/var/run/secrets/tokens/oidc-token',
       role_session_name='my-session'  # 可选，会自动生成
   )
   ```

2. **通过环境变量配置**（ACK 环境通常自动注入）：
   ```bash
   export ALIBABA_CLOUD_ROLE_ARN="acs:ram::123456789:role/your-role"
   export ALIBABA_CLOUD_OIDC_PROVIDER_ARN="acs:ram::123456789:oidc-provider/your-provider"
   export ALIBABA_CLOUD_OIDC_TOKEN_FILE="/var/run/secrets/tokens/oidc-token"
   ```

3. **验证环境变量**：
   ```bash
   env | grep ALIBABA_CLOUD
   ```

---

### 4.7 Credentials URI 问题

#### Q16：Credentials URI 为空或格式错误

**问题现象**：
```
ValueError: uri or environment variable ALIBABA_CLOUD_CREDENTIALS_URI cannot be empty
```

**根本原因**：
未提供 `credentials_uri` 参数，且环境变量 `ALIBABA_CLOUD_CREDENTIALS_URI` 未设置或为空。

**解决方案**：
1. **设置 URI**：
   ```python
   config = Config(
       type='credentials_uri',
       credentials_uri='http://your-credential-server:8080/credentials'
   )
   ```

2. **通过环境变量设置**：
   ```bash
   export ALIBABA_CLOUD_CREDENTIALS_URI="http://your-credential-server:8080/credentials"
   ```

3. **URI 格式要求**：
   - 支持 HTTP 和 HTTPS
   - 支持查询参数
   - 示例：`http://127.0.0.1:8080/credentials?role=admin`

---

#### Q17：Credentials URI 服务返回错误格式

**问题现象**：
```
CredentialException: error refreshing credentials from http://...,  http_code=200, result: {...}
CredentialException: error retrieving credentials from http://... result: {...}
```

**根本原因**：
代码 `uri.py` 要求响应体必须满足以下条件：
- HTTP 状态码为 200
- 响应体 JSON 中 `Code` 字段值为 `Success`
- 必须包含 `AccessKeyId`、`AccessKeySecret`、`SecurityToken`、`Expiration` 四个字段

**解决方案**：
1. **检查服务端响应格式**：
   ```bash
   curl -X GET "http://your-credential-server:8080/credentials"
   ```
   
   期望的响应格式：
   ```json
   {
     "Code": "Success",
     "AccessKeyId": "STS.xxx",
     "AccessKeySecret": "xxx",
     "SecurityToken": "CAISxxx",
     "Expiration": "2023-12-31T23:59:59Z"
   }
   ```

2. **常见错误**：
   - `Code` 不是 `Success`
   - 缺少必需字段
   - `Expiration` 格式错误（必须为 ISO 8601 格式：`YYYY-MM-DDTHH:MM:SSZ`）

3. **调试服务端实现**：
   确保凭证服务正确实现了阿里云凭证 URI 协议。

---

#### Q18：Credentials URI 服务无法访问

**问题现象**：
```
CredentialException: error refreshing credentials from http://...,  http_code=404, result: ...
ConnectionError: Failed to establish a new connection
```

**根本原因**：
- URI 地址错误
- 凭证服务未启动
- 网络不可达（防火墙、DNS 解析失败）
- 超时时间过短

**解决方案**：
1. **检查服务可访问性**：
   ```bash
   curl -v http://your-credential-server:8080/credentials
   ping your-credential-server
   ```

2. **调整超时时间**：
   ```python
   from alibabacloud_credentials.http import HttpOptions
   
   config = Config(
       type='credentials_uri',
       credentials_uri='http://...',
       timeout=10000,  # 读超时 10 秒
       connect_timeout=5000  # 连接超时 5 秒
   )
   ```

3. **检查防火墙和安全组**：
   确保目标端口（如 8080）未被阻止。

4. **使用 HTTPS 并配置代理**（如需要）：
   ```python
   config = Config(
       type='credentials_uri',
       credentials_uri='https://...',
       proxy='http://proxy.example.com:8080'
   )
   ```

---

### 4.8 异步操作问题

#### Q19：异步方法调用失败或挂起

**问题现象**：
```python
import asyncio
credential = await client.get_credential_async()  # 一直挂起或报错
```

**根本原因**：
- 异步事件循环未正确运行
- 异步依赖库（如 `aiofiles`）版本不兼容
- 混用同步和异步 API

**解决方案**：
1. **正确使用异步 API**：
   ```python
   import asyncio
   from alibabacloud_credentials.client import Client
   from alibabacloud_credentials.models import Config
   
   async def main():
       config = Config(type='access_key', ...)
       client = Client(config)
       credential = await client.get_credential_async()
       print(credential.access_key_id)
   
   # 运行异步函数
   asyncio.run(main())
   ```

2. **检查依赖版本**：
   ```bash
   pip list | grep aiofiles
   pip install --upgrade aiofiles
   ```

3. **避免在同步上下文中调用异步方法**：
   不要在非异步函数中直接调用 `await`。

---

### 4.9 Python 版本兼容性问题

#### Q20：Python 版本过低导致安装或运行失败

**问题现象**：
```
ERROR: Package 'alibabacloud-credentials' requires a different Python: 3.6.0 not in '>=3.7'
SyntaxError: invalid syntax (f-strings, type hints等)
```

**根本原因**：
从版本 1.0rc1 开始，alibabacloud-credentials 仅支持 Python 3.7 及以上版本。代码使用了 f-string、类型注解等 Python 3.7+ 特性。

**解决方案**：
1. **升级 Python 版本**：
   ```bash
   # Ubuntu/Debian
   sudo apt-get install python3.8 python3.8-venv
   
   # macOS (使用 Homebrew)
   brew install python@3.8
   
   # Windows
   从 python.org 下载安装 Python 3.8+
   ```

2. **使用虚拟环境**：
   ```bash
   python3.8 -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate  # Windows
   pip install alibabacloud-credentials
   ```

3. **检查当前 Python 版本**：
   ```bash
   python --version
   python3 --version
   ```

---

### 4.10 并发与线程安全问题

#### Q21：多线程环境下凭证获取异常

**问题现象**：
多线程同时调用 `client.get_credential()` 时偶发异常或凭证不一致。

**根本原因**：
虽然代码使用了缓存机制，但某些凭证提供者（如配置文件读取）可能在并发场景下存在竞争条件。

**解决方案**：
1. **使用单例模式**（推荐）：
   ```python
   # 全局单例
   _global_client = None
   
   def get_client():
       global _global_client
       if _global_client is None:
           _global_client = Client()
       return _global_client
   
   # 在各个线程中使用
   client = get_client()
   credential = client.get_credential()
   ```

2. **使用线程锁**：
   ```python
   import threading
   
   client_lock = threading.Lock()
   
   def get_credential_safe():
       with client_lock:
           return client.get_credential()
   ```

3. **启用凭证缓存**：
   默认情况下，凭证提供者会缓存凭证并自动刷新，减少并发调用。

---

### 4.11 网络与代理问题

#### Q22：网络请求超时或失败

**问题现象**：
```
ConnectionTimeout: Connection to sts.aliyuncs.com timed out
ReadTimeout: Read timed out
```

**根本原因**：
- 网络延迟高
- STS 服务或元数据服务不可达
- 默认超时时间过短（连接超时 10秒，读超时 5 秒）

**解决方案**：
1. **调整超时时间**：
   ```python
   config = Config(
       type='ram_role_arn',
       ...,
       timeout=30000,  # 读超时 30 秒
       connect_timeout=15000  # 连接超时 15 秒
   )
   ```

2. **检查网络连通性**：
   ```bash
   curl -v https://sts.aliyuncs.com
   ping sts.aliyuncs.com
   ```

3. **使用区域化端点**（提高速度）：
   ```python
   config = Config(
       type='ram_role_arn',
       ...,
       sts_endpoint='sts.cn-hangzhou.aliyuncs.com'  # 杭州区域
   )
   ```

---

#### Q23：需要通过代理访问外网

**问题现象**：
在内网环境中，无法直接访问 `sts.aliyuncs.com` 等公网地址。

**根本原因**：
网络策略要求通过 HTTP/HTTPS 代理访问外网。

**解决方案**：
1. **配置 HTTP 代理**：
   ```python
   config = Config(
       type='ram_role_arn',
       ...,
       proxy='http://proxy.example.com:8080'
   )
   ```

2. **通过环境变量配置代理**：
   ```bash
   export HTTP_PROXY="http://proxy.example.com:8080"
   export HTTPS_PROXY="http://proxy.example.com:8080"
   ```
   注意：代理配置优先使用 `Config` 中的 `proxy` 参数。

3. **代理认证**：
   如果代理需要认证：
   ```python
   config = Config(
       type='ram_role_arn',
       ...,
       proxy='http://username:password@proxy.example.com:8080'
   )
   ```

---

### 4.12 日志与调试问题

#### Q24：如何启用详细日志以排查问题

**问题现象**：
凭证获取失败但不清楚具体原因。

**解决方案**：
1. **启用 Python 日志**：
   ```python
   import logging
   
   logging.basicConfig(
       level=logging.DEBUG,
       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
   )
   
   # 凭证工具会输出日志
   client = Client()
   credential = client.get_credential()
   ```

2. **查看 HTTP 请求详情**（调试 STS 调用）：
   可以在代码中添加请求拦截器查看实际的 HTTP 请求和响应。

3. **分步调试凭证链**：
   ```python
   from alibabacloud_credentials.provider.default import DefaultCredentialsProvider
   
   provider = DefaultCredentialsProvider()
   try:
       cred = provider.get_credentials()
       print(f"成功获取凭证: {cred.get_provider_name()}")
   except Exception as e:
       print(f"凭证链失败: {e}")
       # 查看详细错误消息，其中包含每个提供者的失败原因
   ```

---

### 4.13 凭证刷新与缓存问题

#### Q25：凭证未自动刷新导致过期

**问题现象**：
长时间运行的应用中，临时凭证过期后未自动刷新。

**根本原因**：
- 凭证缓存机制未正确工作
- 异步刷新任务未启动
- 凭证客户端被重复初始化

**解决方案**：
1. **使用单例模式**（避免重复初始化）：
   ```python
   # 错误示例：每次调用都创建新客户端
   def get_cred():
       client = Client()  # 会创建新的缓存
       return client.get_credential()
   
   # 正确示例：全局单例
   global_client = Client()
   
   def get_cred():
       return global_client.get_credential()
   ```

2. **启用异步刷新**（默认已启用）：
   ECS RAM Role 凭证会每分钟检查一次是否需要刷新。

3. **手动触发刷新**：
   如果需要强制刷新：
   ```python
   # 重新获取凭证会触发检查和刷新
   credential = client.get_credential()
   ```

4. **调整刷新提前时间**：
   代码默认在过期前 15 分钟开始刷新（`_get_stale_time`），无法配置。

---

### 4.14 容器与 Kubernetes 环境问题

#### Q26：在 Kubernetes Pod 中使用 OIDC 凭证失败

**问题现象**：
Pod 启动后无法获取 OIDC 凭证，提示文件或环境变量缺失。

**根本原因**：
- ServiceAccount Token 未正确挂载
- 环境变量未注入
- RRSA（RAM Roles for Service Account）未配置

**解决方案**：
1. **检查 ServiceAccount 配置**：
   ```bash
   kubectl get sa <service-account-name> -o yaml
   kubectl describe pod <pod-name>
   ```

2. **确认环境变量已注入**：
   ```bash
   kubectl exec <pod-name> -- env | grep ALIBABA_CLOUD
   ```

3. **检查 Token 文件挂载**：
   ```bash
   kubectl exec <pod-name> -- ls -la /var/run/secrets/tokens/
   kubectl exec <pod-name> -- cat /var/run/secrets/tokens/oidc-token
   ```

4. **参考 ACK RRSA 配置文档**：
   [RAM Roles for Service Account](https://help.aliyun.com/document_detail/420242.html)

---

### 4.15 特殊场景问题

#### Q27：在 Windows 环境下路径问题

**问题现象**：
Windows 系统中配置文件路径不正确，使用了 Linux 风格的路径。

**根本原因**：
代码 `auth_util.py` 中对 Windows 的 HOME 路径处理逻辑：
- 优先使用 `HOME` 环境变量
- 其次使用 `HOMEDRIVE` + `HOMEPATH`
- 最后使用 `os.path.expanduser("~")`

**解决方案**：
1. **检查 HOME 路径**：
   ```powershell
   echo $env:USERPROFILE
   echo $env:HOME
   ```

2. **手动设置配置文件路径**：
   ```python
   from alibabacloud_credentials.provider.profile import ProfileCredentialsProvider
   
   provider = ProfileCredentialsProvider(
       profile_file=r'C:\Users\YourName\.aliyun\config.json'
   )
   ```

3. **使用环境变量指定配置文件**：
   ```powershell
   $env:ALIBABA_CLOUD_CREDENTIALS_FILE="C:\Users\YourName\.aliyun\config.json"
   ```

---

#### Q28：配置文件中使用了注释导致解析失败

**问题现象**：
INI 配置文件中的注释被当作值的一部分。

**根本原因**：
代码 `profile.py` 对 INI 文件注释的处理方式是检查值中是否包含 `#`，并截取 `#` 之前的内容作为实际值。这可能导致如果值本身包含 `#` 时被错误截断。

**解决方案**：
1. **避免在值中使用 `#`**：
   ```ini
   [default]
   # 这是注释，可以正常识别
   type = access_key
   access_key_id = LTAI4G...  # 行尾注释也会被正确处理
   
   # 错误示例（如果密钥本身包含 # 会被截断）
   access_key_secret = abc#def  # 会被截断为 "abc"
   ```

2. **使用 JSON 配置文件**（推荐）：
   JSON 格式更严格，避免注释相关问题：
   ```json
   {
     "current": "default",
     "profiles": [...]
   }
   ```

---

#### Q29：在离线环境中使用凭证工具

**问题现象**：
完全离线环境（无法访问 STS 服务）无法使用 RAM Role ARN 等需要在线刷新的凭证类型。

**根本原因**：
RAM Role ARN、OIDC、RSA Key Pair 等凭证类型需要调用 STS 服务获取临时凭证。

**解决方案**：
1. **使用静态 AccessKey**：
   ```python
   config = Config(
       type='access_key',
       access_key_id='...',
       access_key_secret='...'
   )
   ```

2. **使用预先获取的 STS Token**：
   ```python
   config = Config(
       type='sts',
       access_key_id='STS.xxx',
       access_key_secret='xxx',
       security_token='CAISxxx'
   )
   ```
   注意：STS Token 有过期时间，需要在失效前更新。

3. **部署本地凭证服务**：
   使用 Credentials URI 方式，在内网部署凭证分发服务。

---

## 5. 最佳实践

### 安全建议

1. **不要在代码中硬编码 AccessKey**：使用环境变量或配置文件。
2. **最小权限原则**：使用 RAM 用户或角色，仅授予必要权限。
3. **定期轮换密钥**：定期更新 AccessKey。
4. **敏感文件权限控制**：
   ```bash
   chmod 600 ~/.aliyun/config.json
   ```
5. **使用临时凭证**：优先使用 STS Token、RAM Role 等临时凭证。

### 性能优化

1. **使用单例模式**：避免频繁创建客户端。
2. **启用凭证缓存**：利用自动刷新机制减少 STS 调用。
3. **合理设置会话时长**：根据应用需求调整 `duration_seconds`（默认 3600 秒）。
4. **使用区域化端点**：配置 `sts_region_id` 以减少网络延迟。

### 监控与日志

1. **启用详细日志**：在调试阶段开启 DEBUG 日志。
2. **监控凭证刷新**：关注凭证刷新失败的日志。
3. **设置告警**：对凭证获取失败设置告警。

---

## 6. 参考资源

- [官方文档](https://github.com/aliyun/credentials-python)
- [阿里云 RAM 文档](https://help.aliyun.com/product/28625.html)
- [STS 临时访问凭证](https://help.aliyun.com/document_detail/28756.html)
- [RRSA 功能说明](https://help.aliyun.com/document_detail/420242.html)
- [问题反馈](https://github.com/aliyun/credentials-python/issues)

---

**文档版本**：1.0  
**最后更新**：2025-12-07  
**适用版本**：alibabacloud-credentials >= 1.0rc1

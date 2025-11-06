import os
import json
import threading
import platform
from typing import Any, Dict

import aiofiles

# 跨平台文件锁支持
if platform.system() == 'Windows':
    # Windows平台使用msvcrt
    import msvcrt

    HAS_MSVCRT = True
    HAS_FCNTL = False
else:
    # 其他平台尝试使用fcntl，如果不可用则不设文件锁
    HAS_MSVCRT = False
    try:
        import fcntl

        HAS_FCNTL = True
    except ImportError:
        HAS_FCNTL = False

from .static_ak import StaticAKCredentialsProvider
from .ecs_ram_role import EcsRamRoleCredentialsProvider
from .ram_role_arn import RamRoleArnCredentialsProvider
from .oidc import OIDCRoleArnCredentialsProvider
from .static_sts import StaticSTSCredentialsProvider
from .cloud_sso import CloudSSOCredentialsProvider
from .oauth import OAuthCredentialsProvider, OAuthTokenUpdateCallback, OAuthTokenUpdateCallbackAsync
from .refreshable import Credentials
from alibabacloud_credentials_api import ICredentialsProvider
from alibabacloud_credentials.utils import auth_constant as ac
from alibabacloud_credentials.utils import auth_util as au
from alibabacloud_credentials.exceptions import CredentialException


async def _load_config_async(file_path: str) -> Any:
    async with aiofiles.open(file_path, mode='r') as f:
        content = await f.read()
    return json.loads(content)


def _load_config(file_path: str) -> Any:
    with open(file_path, mode='r') as f:
        content = f.read()
    return json.loads(content)


class CLIProfileCredentialsProvider(ICredentialsProvider):

    def __init__(self, *,
                 profile_name: str = None,
                 profile_file: str = None,
                 allow_config_force_rewrite: bool = False):
        self._profile_file = profile_file or os.path.join(ac.HOME, ".aliyun/config.json")
        self._profile_name = profile_name or au.environment_profile_name
        self._allow_config_force_rewrite = allow_config_force_rewrite
        self.__innerProvider = None
        # 文件锁，用于并发安全
        self._file_lock = threading.RLock()

    def _should_reload_credentials_provider(self) -> bool:
        if self.__innerProvider is None:
            return True
        return False

    def get_credentials(self) -> Credentials:
        if au.environment_cli_profile_disabled.lower() == "true":
            raise CredentialException('cli credentials file is disabled')

        if self._should_reload_credentials_provider():
            if not os.path.exists(self._profile_file) or not os.path.isfile(self._profile_file):
                raise CredentialException(f'unable to open credentials file: {self._profile_file}')
            try:
                config = _load_config(self._profile_file)
            except Exception as e:
                raise CredentialException(
                    f'failed to parse credential form cli credentials file: {self._profile_file}')
            if config is None:
                raise CredentialException(
                    f'failed to parse credential form cli credentials file: {self._profile_file}')

            profile_name = self._profile_name
            if self._profile_name is None or self._profile_name == '':
                profile_name = config.get('current')
            self.__innerProvider = self._get_credentials_provider(config, profile_name)

        cre = self.__innerProvider.get_credentials()
        credentials = Credentials(
            access_key_id=cre.get_access_key_id(),
            access_key_secret=cre.get_access_key_secret(),
            security_token=cre.get_security_token(),
            provider_name=f'{self.get_provider_name()}/{cre.get_provider_name()}'
        )
        return credentials

    async def get_credentials_async(self) -> Credentials:
        if au.environment_cli_profile_disabled.lower() == "true":
            raise CredentialException('cli credentials file is disabled')

        if self._should_reload_credentials_provider():
            if not os.path.exists(self._profile_file) or not os.path.isfile(self._profile_file):
                raise CredentialException(f'unable to open credentials file: {self._profile_file}')
            try:
                config = await _load_config_async(self._profile_file)
            except Exception as e:
                raise CredentialException(
                    f'failed to parse credential form cli credentials file: {self._profile_file}')
            if config is None:
                raise CredentialException(
                    f'failed to parse credential form cli credentials file: {self._profile_file}')

            profile_name = self._profile_name
            if self._profile_name is None or self._profile_name == '':
                profile_name = config.get('current')
            self.__innerProvider = self._get_credentials_provider(config, profile_name)

        cre = await self.__innerProvider.get_credentials_async()
        credentials = Credentials(
            access_key_id=cre.get_access_key_id(),
            access_key_secret=cre.get_access_key_secret(),
            security_token=cre.get_security_token(),
            provider_name=f'{self.get_provider_name()}/{cre.get_provider_name()}'
        )
        return credentials

    def _get_credentials_provider(self, config: Dict, profile_name: str) -> ICredentialsProvider:
        if profile_name is None or profile_name == '':
            raise CredentialException('invalid profile name')

        profiles = config.get('profiles', [])

        if not profiles:
            raise CredentialException(f"unable to get profile with '{profile_name}' form cli credentials file.")

        for profile in profiles:
            if profile.get('name') is not None and profile['name'] == profile_name:
                mode = profile.get('mode')
                if mode == "AK":
                    return StaticAKCredentialsProvider(
                        access_key_id=profile.get('access_key_id'),
                        access_key_secret=profile.get('access_key_secret')
                    )
                elif mode == "StsToken":
                    return StaticSTSCredentialsProvider(
                        access_key_id=profile.get('access_key_id'),
                        access_key_secret=profile.get('access_key_secret'),
                        security_token=profile.get('sts_token')
                    )
                elif mode == "RamRoleArn":
                    pre_provider = StaticAKCredentialsProvider(
                        access_key_id=profile.get('access_key_id'),
                        access_key_secret=profile.get('access_key_secret')
                    )
                    return RamRoleArnCredentialsProvider(
                        credentials_provider=pre_provider,
                        role_arn=profile.get('ram_role_arn'),
                        role_session_name=profile.get('ram_session_name'),
                        duration_seconds=profile.get('expired_seconds'),
                        policy=profile.get('policy'),
                        external_id=profile.get('external_id'),
                        sts_region_id=profile.get('sts_region'),
                        enable_vpc=profile.get('enable_vpc'),
                    )
                elif mode == "EcsRamRole":
                    return EcsRamRoleCredentialsProvider(
                        role_name=profile.get('ram_role_name')
                    )
                elif mode == "OIDC":
                    return OIDCRoleArnCredentialsProvider(
                        role_arn=profile.get('ram_role_arn'),
                        oidc_provider_arn=profile.get('oidc_provider_arn'),
                        oidc_token_file_path=profile.get('oidc_token_file'),
                        role_session_name=profile.get('role_session_name'),
                        duration_seconds=profile.get('expired_seconds'),
                        policy=profile.get('policy'),
                        sts_region_id=profile.get('sts_region'),
                        enable_vpc=profile.get('enable_vpc'),
                    )
                elif mode == "ChainableRamRoleArn":
                    previous_provider = self._get_credentials_provider(config, profile.get('source_profile'))
                    return RamRoleArnCredentialsProvider(
                        credentials_provider=previous_provider,
                        role_arn=profile.get('ram_role_arn'),
                        role_session_name=profile.get('ram_session_name'),
                        duration_seconds=profile.get('expired_seconds'),
                        policy=profile.get('policy'),
                        external_id=profile.get('external_id'),
                        sts_region_id=profile.get('sts_region'),
                        enable_vpc=profile.get('enable_vpc'),
                    )
                elif mode == "CloudSSO":
                    return CloudSSOCredentialsProvider(
                        sign_in_url=profile.get('cloud_sso_sign_in_url'),
                        account_id=profile.get('cloud_sso_account_id'),
                        access_config=profile.get('cloud_sso_access_config'),
                        access_token=profile.get('access_token'),
                        access_token_expire=profile.get('cloud_sso_access_token_expire'),
                    )
                elif mode == "OAuth":
                    # 获取 OAuth 配置
                    site_type = profile.get('oauth_site_type', 'CN')
                    oauth_base_url_map = {
                        'CN': 'https://oauth.aliyun.com',
                        'INTL': 'https://oauth.alibabacloud.com'
                    }
                    sign_in_url = oauth_base_url_map.get(site_type.upper())
                    if not sign_in_url:
                        raise CredentialException('Invalid OAuth site type, support CN or INTL')

                    oauth_client_map = {
                        'CN': '4038181954557748008',
                        'INTL': '4103531455503354461'
                    }
                    client_id = oauth_client_map.get(site_type.upper())
                    if not client_id:
                        raise CredentialException('Invalid OAuth site type, support CN or INTL')

                    return OAuthCredentialsProvider(
                        client_id=client_id,
                        sign_in_url=sign_in_url,
                        access_token=profile.get('oauth_access_token'),
                        access_token_expire=profile.get('oauth_access_token_expire'),
                        refresh_token=profile.get('oauth_refresh_token'),
                        token_update_callback=self._get_oauth_token_update_callback(),
                        token_update_callback_async=self._get_oauth_token_update_callback_async(),
                    )
                else:
                    raise CredentialException(f"unsupported profile mode '{mode}' form cli credentials file.")

        raise CredentialException(f"unable to get profile with '{profile_name}' form cli credentials file.")

    def get_provider_name(self) -> str:
        return 'cli_profile'

    def _update_oauth_tokens(self, refresh_token: str, access_token: str, access_key: str, secret: str,
                             security_token: str, access_token_expire: int, sts_expire: int) -> None:
        """更新 OAuth 令牌并写回配置文件"""

        with self._file_lock:
            try:
                # 读取现有配置
                config = _load_config(self._profile_file)

                # 找到当前 profile 并更新 OAuth 令牌
                profile_name = self._profile_name
                if not profile_name:
                    profile_name = config.get('current')
                profiles = config.get('profiles', [])
                profile_tag = False
                for profile in profiles:
                    if profile.get('name') == profile_name:
                        profile_tag = True
                        # 更新 OAuth 令牌
                        profile['oauth_refresh_token'] = refresh_token
                        profile['oauth_access_token'] = access_token
                        profile['oauth_access_token_expire'] = access_token_expire
                        # 更新 STS 凭据
                        profile['access_key_id'] = access_key
                        profile['access_key_secret'] = secret
                        profile['sts_token'] = security_token
                        profile['sts_expiration'] = sts_expire
                        break

                # 写回配置文件
                if not profile_tag:
                    raise CredentialException(f"unable to get profile with '{profile_name}' form cli credentials file.")

                self._write_configuration_to_file_with_lock(self._profile_file, config)

            except Exception as e:
                raise CredentialException(f"failed to update OAuth tokens in config file: {e}")

    def _write_configuration_to_file(self, config_path: str, config: Dict) -> None:
        """将配置写入文件，使用原子写入确保数据完整性"""
        # 获取原文件权限（如果存在）
        file_mode = 0o644
        if os.path.exists(config_path):
            file_mode = os.stat(config_path).st_mode

        # 创建唯一临时文件
        import time
        temp_file = config_path + '.tmp-' + str(int(time.time() * 1000000))  # 微秒级时间戳
        backup_file = None

        try:
            # 写入临时文件
            self._write_config_file(temp_file, file_mode, config)

            # 原子性重命名，Windows下需要特殊处理
            if platform.system() == 'Windows' and self._allow_config_force_rewrite:
                # Windows下需要先删除目标文件，使用备份机制确保数据安全
                if os.path.exists(config_path):
                    backup_file = config_path + '.backup'
                    # 创建备份
                    import shutil
                    shutil.copy2(config_path, backup_file)
                    # 删除原文件
                    os.remove(config_path)

            os.rename(temp_file, config_path)

            # 成功后删除备份
            if backup_file and os.path.exists(backup_file):
                os.remove(backup_file)

        except Exception as e:
            # 恢复原文件（如果存在备份）
            if backup_file and os.path.exists(backup_file):
                try:
                    if not os.path.exists(config_path):
                        os.rename(backup_file, config_path)
                except Exception as restore_error:
                    raise CredentialException(
                        f"Failed to restore original file after write error: {restore_error}. Original error: {e}")

            raise e

    def _write_config_file(self, filename: str, file_mode: int, config: Dict) -> None:
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)

            # 设置文件权限
            os.chmod(filename, file_mode)

        except Exception as e:
            raise CredentialException(f"Failed to write config file: {e}")

    def _write_configuration_to_file_with_lock(self, config_path: str, config: Dict) -> None:
        """使用操作系统级别的文件锁写入配置文件"""
        # 获取原文件权限（如果存在）
        file_mode = 0o644
        if os.path.exists(config_path):
            file_mode = os.stat(config_path).st_mode

        backup_file = None

        try:
            # 确保文件存在
            if not os.path.exists(config_path):
                # 创建空文件
                with open(config_path, 'w') as f:
                    json.dump({}, f)

            # 在获取文件锁之前创建备份（Windows下需要）
            if platform.system() == 'Windows' and self._allow_config_force_rewrite and os.path.exists(config_path):
                backup_file = config_path + '.backup'
                import shutil
                shutil.copy2(config_path, backup_file)

            # 打开文件用于锁定
            with open(config_path, 'r+') as f:
                # 获取独占锁（阻塞其他进程）
                if HAS_MSVCRT:
                    # Windows使用msvcrt
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                elif HAS_FCNTL:
                    # Unix/Linux使用fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                # 如果都不支持，则跳过文件锁（仅进程内保护）

                try:
                    if platform.system() == 'Windows' and self._allow_config_force_rewrite:
                        # Windows下直接在锁定的文件中写入
                        f.seek(0)
                        f.truncate()  # 清空文件内容
                        json.dump(config, f, indent=4, ensure_ascii=False)
                        f.flush()
                    else:
                        # 其他环境使用临时文件+rename（在文件锁内部进行原子操作）
                        import time
                        temp_file = config_path + '.tmp-' + str(int(time.time() * 1000000))
                        self._write_config_file(temp_file, file_mode, config)
                        # 在文件锁内部进行原子重命名
                        os.rename(temp_file, config_path)

                finally:
                    # 释放锁
                    try:
                        if HAS_MSVCRT:
                            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                        elif HAS_FCNTL:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    except (OSError, PermissionError):
                        # 在Windows下，如果文件被重命名，文件句柄可能已经无效
                        # 这种情况下锁会自动释放，所以忽略错误
                        pass

            # 成功后删除备份
            if backup_file and os.path.exists(backup_file):
                os.remove(backup_file)

        except Exception as e:
            # 恢复原文件（如果存在备份）
            if backup_file and os.path.exists(backup_file):
                try:
                    if not os.path.exists(config_path):
                        os.rename(backup_file, config_path)
                except Exception as restore_error:
                    raise CredentialException(
                        f"Failed to restore original file after write error: {restore_error}. Original error: {e}")

            raise e

    def _get_oauth_token_update_callback(self) -> OAuthTokenUpdateCallback:
        """获取 OAuth 令牌更新回调函数"""
        return lambda refresh_token, access_token, access_key, secret, security_token, access_token_expire, sts_expire: self._update_oauth_tokens(
            refresh_token, access_token, access_key, secret, security_token, access_token_expire, sts_expire
        )

    async def _write_configuration_to_file_async(self, config_path: str, config: Dict) -> None:
        """异步将配置写入文件，使用原子写入确保数据完整性"""
        # 获取原文件权限（如果存在）
        file_mode = 0o644
        if os.path.exists(config_path):
            file_mode = os.stat(config_path).st_mode

        # 创建唯一临时文件
        import time
        temp_file = config_path + '.tmp-' + str(int(time.time() * 1000000))  # 微秒级时间戳
        backup_file = None

        try:
            # 异步写入临时文件
            await self._write_config_file_async(temp_file, file_mode, config)

            # 原子性重命名，Windows下需要特殊处理
            if platform.system() == 'Windows' and self._allow_config_force_rewrite:
                # Windows下需要先删除目标文件，使用备份机制确保数据安全
                if os.path.exists(config_path):
                    backup_file = config_path + '.backup'
                    # 创建备份
                    import shutil
                    shutil.copy2(config_path, backup_file)
                    # 删除原文件
                    os.remove(config_path)

            os.rename(temp_file, config_path)

            # 成功后删除备份
            if backup_file and os.path.exists(backup_file):
                os.remove(backup_file)

        except Exception as e:
            # 恢复原文件（如果存在备份）
            if backup_file and os.path.exists(backup_file):
                try:
                    if not os.path.exists(config_path):
                        os.rename(backup_file, config_path)
                except Exception as restore_error:
                    raise CredentialException(
                        f"Failed to restore original file after write error: {restore_error}. Original error: {e}")

            raise e

    async def _write_config_file_async(self, filename: str, file_mode: int, config: Dict) -> None:
        try:
            async with aiofiles.open(filename, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(config, indent=4, ensure_ascii=False))

            # 设置文件权限
            os.chmod(filename, file_mode)

        except Exception as e:
            raise CredentialException(f"Failed to write config file: {e}")

    async def _write_configuration_to_file_with_lock_async(self, config_path: str, config: Dict) -> None:
        """异步使用操作系统级别的文件锁写入配置文件"""
        # 获取原文件权限（如果存在）
        file_mode = 0o644
        if os.path.exists(config_path):
            file_mode = os.stat(config_path).st_mode

        backup_file = None

        try:
            # 确保文件存在
            if not os.path.exists(config_path):
                # 创建空文件
                with open(config_path, 'w') as f:
                    json.dump({}, f)

            # 在获取文件锁之前创建备份（Windows下需要）
            if platform.system() == 'Windows' and self._allow_config_force_rewrite and os.path.exists(config_path):
                backup_file = config_path + '.backup'
                import shutil
                shutil.copy2(config_path, backup_file)

            # 打开文件用于锁定
            with open(config_path, 'r+') as f:
                # 获取独占锁（阻塞其他进程）
                if HAS_MSVCRT:
                    # Windows使用msvcrt
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                elif HAS_FCNTL:
                    # Unix/Linux使用fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                # 如果都不支持，则跳过文件锁（仅进程内保护）

                try:
                    if platform.system() == 'Windows' and self._allow_config_force_rewrite:
                        # Windows下直接在锁定的文件中写入
                        f.seek(0)
                        f.truncate()  # 清空文件内容
                        json.dump(config, f, indent=4, ensure_ascii=False)
                        f.flush()
                    else:
                        # 其他环境使用临时文件+rename（在文件锁内部进行原子操作）
                        import time
                        temp_file = config_path + '.tmp-' + str(int(time.time() * 1000000))
                        await self._write_config_file_async(temp_file, file_mode, config)
                        # 在文件锁内部进行原子重命名
                        os.rename(temp_file, config_path)

                finally:
                    # 释放锁
                    try:
                        if HAS_MSVCRT:
                            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                        elif HAS_FCNTL:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    except (OSError, PermissionError):
                        # 在Windows下，如果文件被重命名，文件句柄可能已经无效
                        # 这种情况下锁会自动释放，所以忽略错误
                        pass

            # 成功后删除备份
            if backup_file and os.path.exists(backup_file):
                os.remove(backup_file)

        except Exception as e:
            # 恢复原文件（如果存在备份）
            if backup_file and os.path.exists(backup_file):
                try:
                    if not os.path.exists(config_path):
                        os.rename(backup_file, config_path)
                except Exception as restore_error:
                    raise CredentialException(
                        f"Failed to restore original file after write error: {restore_error}. Original error: {e}")

            raise e

    async def _update_oauth_tokens_async(self, refresh_token: str, access_token: str, access_key: str, secret: str,
                                         security_token: str, access_token_expire: int, sts_expire: int) -> None:
        """异步更新 OAuth 令牌并写回配置文件"""

        try:
            with self._file_lock:
                cfg_path = self._profile_file
                conf = await _load_config_async(cfg_path)

                # 找到当前 profile 并更新 OAuth 令牌
                profile_name = self._profile_name
                if not profile_name:
                    profile_name = conf.get('current')
                profiles = conf.get('profiles', [])
                profile_tag = False
                for profile in profiles:
                    if profile.get('name') == profile_name:
                        profile_tag = True
                        # 更新 OAuth 相关字段
                        profile['oauth_refresh_token'] = refresh_token
                        profile['oauth_access_token'] = access_token
                        profile['oauth_access_token_expire'] = access_token_expire
                        # 更新 STS 凭据
                        profile['access_key_id'] = access_key
                        profile['access_key_secret'] = secret
                        profile['sts_token'] = security_token
                        profile['sts_expiration'] = sts_expire
                        break

                if not profile_tag:
                    raise CredentialException(f"Profile '{profile_name}' not found in config file")

                # 异步写回配置文件
                await self._write_configuration_to_file_with_lock_async(cfg_path, conf)

        except Exception as e:
            raise CredentialException(f"failed to update OAuth tokens in config file: {e}")

    def _get_oauth_token_update_callback_async(self) -> OAuthTokenUpdateCallbackAsync:
        """获取异步 OAuth 令牌更新回调函数"""
        return lambda refresh_token, access_token, access_key, secret, security_token, access_token_expire, sts_expire: self._update_oauth_tokens_async(
            refresh_token, access_token, access_key, secret, security_token, access_token_expire, sts_expire
        )

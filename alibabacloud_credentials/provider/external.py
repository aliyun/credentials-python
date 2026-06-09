import asyncio
import calendar
import json
import logging
import os
import shlex
import subprocess
import time
from typing import Callable, Optional

from alibabacloud_credentials.provider.refreshable import Credentials, RefreshResult, RefreshCachedSupplier
from alibabacloud_credentials_api import ICredentialsProvider
from alibabacloud_credentials.exceptions import CredentialException

log = logging.getLogger('credentials')

ExternalCredentialUpdateCallback = Callable[[str, str, str, int], None]
ExternalCredentialUpdateCallbackAsync = Callable[[str, str, str, int], None]


def _parse_expiration(expiration: str) -> int:
    if not expiration:
        return 0
    time_array = time.strptime(expiration, '%Y-%m-%dT%H:%M:%SZ')
    return calendar.timegm(time_array)


def _get_stale_time(expiration: int) -> int:
    if expiration <= 0:
        return int(time.mktime(time.localtime()))
    return expiration - 180


class ExternalCredentialsProvider(ICredentialsProvider):
    DEFAULT_TIMEOUT = 60

    def __init__(self, *,
                 process_command: str = None,
                 timeout: int = None,
                 credential_update_callback: Optional[ExternalCredentialUpdateCallback] = None,
                 credential_update_callback_async: Optional[ExternalCredentialUpdateCallbackAsync] = None):
        if not process_command:
            raise ValueError('process_command is empty')

        self._process_command = process_command
        self._timeout = timeout if timeout and timeout > 0 else ExternalCredentialsProvider.DEFAULT_TIMEOUT
        self._credential_update_callback = credential_update_callback
        self._credential_update_callback_async = credential_update_callback_async
        self._credentials_cache = RefreshCachedSupplier(
            refresh_callable=self._refresh_credentials,
            refresh_callable_async=self._refresh_credentials_async,
        )

    def get_credentials(self) -> Credentials:
        return self._credentials_cache._sync_call()

    async def get_credentials_async(self) -> Credentials:
        return await self._credentials_cache._async_call()

    def _refresh_credentials(self) -> RefreshResult[Credentials]:
        if not self._process_command.strip():
            raise CredentialException('process_command is empty')

        try:
            command = self._process_command if os.name == 'nt' else shlex.split(self._process_command)
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self._timeout,
                check=False,
                text=True,
                shell=os.name == 'nt',
            )
        except subprocess.TimeoutExpired:
            raise CredentialException(f'command process timed out after {self._timeout * 1000} milliseconds')
        except Exception as e:
            raise CredentialException(f'failed to execute external command: {e}')

        if completed.returncode != 0:
            raise CredentialException(
                f'failed to execute external command: exit status {completed.returncode}\nstderr: {completed.stderr}')

        return self._parse_and_build_credentials(completed.stdout, async_callback=False)

    async def _refresh_credentials_async(self) -> RefreshResult[Credentials]:
        if not self._process_command.strip():
            raise CredentialException('process_command is empty')

        try:
            if os.name == 'nt':
                process = await asyncio.create_subprocess_shell(
                    self._process_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                process = await asyncio.create_subprocess_exec(
                    *shlex.split(self._process_command),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self._timeout)
        except asyncio.TimeoutError:
            if 'process' in locals():
                process.kill()
                await process.wait()
            raise CredentialException(f'command process timed out after {self._timeout * 1000} milliseconds')
        except Exception as e:
            raise CredentialException(f'failed to execute external command: {e}')

        if process.returncode != 0:
            raise CredentialException(
                f'failed to execute external command: exit status {process.returncode}\nstderr: {stderr.decode("utf-8")}')

        return await self._parse_and_build_credentials_async(stdout.decode('utf-8'))

    def _parse_and_build_credentials(self, output: str, async_callback: bool) -> RefreshResult[Credentials]:
        try:
            data = json.loads(output)
        except Exception as e:
            raise CredentialException(f'failed to parse external command output: {e}')

        access_key_id = data.get('access_key_id')
        access_key_secret = data.get('access_key_secret')
        security_token = data.get('sts_token')
        if not access_key_id or not access_key_secret:
            raise CredentialException('invalid credential response: access_key_id or access_key_secret is empty')
        if data.get('mode') == 'StsToken' and not security_token:
            raise CredentialException('invalid StsToken credential response: sts_token is empty')

        expiration = _parse_expiration(data.get('expiration'))
        credentials = Credentials(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            security_token=security_token,
            expiration=expiration,
            provider_name=self.get_provider_name(),
        )

        if not async_callback and self._credential_update_callback:
            try:
                self._credential_update_callback(access_key_id, access_key_secret, security_token, expiration)
            except Exception as e:
                log.warning(f'failed to update external credentials in config file: {e}')

        return RefreshResult(value=credentials, stale_time=_get_stale_time(expiration))

    async def _parse_and_build_credentials_async(self, output: str) -> RefreshResult[Credentials]:
        result = self._parse_and_build_credentials(output, async_callback=True)
        credentials = result.value()
        if self._credential_update_callback_async:
            try:
                await self._credential_update_callback_async(
                    credentials.get_access_key_id(),
                    credentials.get_access_key_secret(),
                    credentials.get_security_token(),
                    credentials.get_expiration() or 0,
                )
            except Exception as e:
                log.warning(f'failed to update external credentials in config file: {e}')
        return result

    def get_provider_name(self) -> str:
        return 'external'

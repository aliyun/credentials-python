import random
import asyncio
import threading
import logging
import time
import atexit
from datetime import datetime
from enum import Enum
from typing import Callable, Generic, TypeVar, Coroutine, Any
from threading import Semaphore
from concurrent.futures.thread import ThreadPoolExecutor

from alibabacloud_credentials.exceptions import CredentialException
from alibabacloud_credentials_api import ICredentials

log = logging.getLogger('credentials')
log.setLevel(logging.INFO)
ch = logging.StreamHandler()
log.addHandler(ch)

T = TypeVar('T')
INT64_MAX = 2 ** 63 - 1
MAX_CONCURRENT_REFRESHES = 100
CONCURRENT_REFRESH_LEASES = Semaphore(MAX_CONCURRENT_REFRESHES)
EXECUTOR = ThreadPoolExecutor(max_workers=INT64_MAX, thread_name_prefix='non-blocking-refresh')


def _shutdown_handler():
    log.debug("Shutting down executor...")
    EXECUTOR.shutdown(wait=False)


atexit.register(_shutdown_handler)


def _jitter_time(now: int, jitter_start: int, jitter_end: int) -> int:
    jitter_amount = random.randint(jitter_start, jitter_end)
    return now + jitter_amount


def _max_stale_failure_jitter(num_failures: int) -> int:
    backoff_millis = max(10 * 1000, (1 << num_failures - 1) * 100)
    return backoff_millis


class Credentials(ICredentials):
    def __init__(self, *,
                 access_key_id: str = None,
                 access_key_secret: str = None,
                 security_token: str = None,
                 expiration: int = None,
                 provider_name: str = None):
        self._access_key_id = access_key_id
        self._access_key_secret = access_key_secret
        self._security_token = security_token
        self._expiration = expiration
        self._provider_name = provider_name

    def get_access_key_id(self) -> str:
        return self._access_key_id

    def get_access_key_secret(self) -> str:
        return self._access_key_secret

    def get_security_token(self) -> str:
        return self._security_token

    def get_expiration(self) -> int:
        return self._expiration

    def get_provider_name(self) -> str:
        return self._provider_name


class StaleValueBehavior(Enum):
    """
    Strictly treat the stale time. Never return a stale cached value (except when the supplier returns an expired
    value, in which case the supplier will return the value but only for a very short period of time to prevent
    overloading the underlying supplier).
    """
    STRICT = 0
    """
    Allow stale values to be returned from the cache. Value retrieval will never fail, as long as the cache has
    succeeded when calling the underlying supplier at least once.
    """
    ALLOW = 1


class RefreshResult(Generic[T]):
    def __init__(self, *,
                 value: T,
                 stale_time: int = INT64_MAX,
                 prefetch_time: int = INT64_MAX):
        self._value = value
        self._stale_time = stale_time
        self._prefetch_time = prefetch_time

    def value(self) -> T:
        return self._value

    def stale_time(self) -> int:
        return self._stale_time

    def prefetch_time(self) -> int:
        return self._prefetch_time


class PrefetchStrategy:
    def prefetch(self, action: Callable):
        raise NotImplementedError

    async def prefetch_async(self, action: Callable):
        raise NotImplementedError


class NonBlocking(PrefetchStrategy):

    def prefetch(self, action: Callable):
        if not CONCURRENT_REFRESH_LEASES.acquire(False):
            log.warning('Skipping a background refresh task because there are too many other tasks running.')
            return

        try:
            EXECUTOR.submit(action)
        except KeyboardInterrupt:
            _shutdown_handler()
        except Exception as t:
            log.warning(f'Exception occurred when submitting background task.', exc_info=True)
        finally:
            CONCURRENT_REFRESH_LEASES.release()

    async def prefetch_async(self, action: Callable):
        def run_asyncio_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(action())
            loop.close()

        self.prefetch(run_asyncio_loop)


class OneCallerBlocks(PrefetchStrategy):
    def prefetch(self, action: Callable):
        action()

    async def prefetch_async(self, action: Callable):
        await action()


class RefreshCachedSupplier(Generic[T]):
    STALE_TIME = 15 * 60  # seconds
    REFRESH_BLOCKING_MAX_WAIT = 5  # seconds

    def __init__(self, refresh_callable: Callable[[], RefreshResult[T]],
                 refresh_callable_async: Callable[[], Coroutine[Any, Any, RefreshResult[T]]],
                 stale_value_behavior: StaleValueBehavior = StaleValueBehavior.STRICT,
                 prefetch_strategy: PrefetchStrategy = OneCallerBlocks()):

        self._refresh_callable = refresh_callable
        self._refresh_callable_async = refresh_callable_async
        self._stale_value_behavior = stale_value_behavior
        self._prefetch_strategy = prefetch_strategy
        self._consecutive_refresh_failures = 0
        self._cached_value = None
        self._refresh_lock = threading.Lock()

    def _sync_call(self) -> T:
        if self._cache_is_stale():
            log.debug('Refreshing synchronously')
            self._refresh_cache()
        elif self._should_initiate_cache_prefetch():
            log.debug(f'Prefetching using strategy: {self._prefetch_strategy.__class__.__name__}')
            self._prefetch_cache()
        return self._cached_value.value()

    async def _async_call(self) -> T:
        if self._cache_is_stale():
            log.debug('Refreshing synchronously')
            await self._refresh_cache_async()
        elif self._should_initiate_cache_prefetch():
            log.debug(f'Prefetching using strategy: {self._prefetch_strategy.__class__.__name__}')
            await self._prefetch_cache_async()
        return self._cached_value.value()

    def _cache_is_stale(self) -> bool:
        if self._cached_value is None:
            return True
        return int(time.mktime(time.localtime())) >= self._cached_value.stale_time()

    def _should_initiate_cache_prefetch(self) -> bool:
        if self._cached_value is None:
            return True
        return int(time.mktime(time.localtime())) >= self._cached_value.prefetch_time()

    def _prefetch_cache(self):
        self._prefetch_strategy.prefetch(self._refresh_cache)

    def _refresh_cache(self):
        acquired = self._refresh_lock.acquire(timeout=RefreshCachedSupplier.REFRESH_BLOCKING_MAX_WAIT)
        try:
            if self._cache_is_stale() or self._should_initiate_cache_prefetch():
                try:
                    self._cached_value = self._handle_fetched_success(self._refresh_callable())
                except Exception as ex:
                    self._cached_value = self._handle_fetched_failure(ex)
        finally:
            if acquired:
                self._refresh_lock.release()

    async def _prefetch_cache_async(self):
        await self._prefetch_strategy.prefetch_async(self._refresh_cache_async)

    async def _refresh_cache_async(self):
        acquired = self._refresh_lock.acquire(timeout=RefreshCachedSupplier.REFRESH_BLOCKING_MAX_WAIT)
        try:
            if self._cache_is_stale() or self._should_initiate_cache_prefetch():
                try:
                    self._cached_value = self._handle_fetched_success(await self._refresh_callable_async())
                except Exception as ex:
                    self._cached_value = self._handle_fetched_failure(ex)
        finally:
            if acquired:
                self._refresh_lock.release()

    def _handle_fetched_success(self, value: RefreshResult[T]) -> RefreshResult[T]:
        log.debug(f'Refresh credentials successfully, retrieved value is {value}, cached value is {self._cached_value}')
        self._consecutive_refresh_failures = 0
        now = int(time.mktime(time.localtime()))
        # 过期时间大于15分钟，不用管
        if now < value.stale_time():
            log.debug(
                f'Retrieved value stale time is {datetime.fromtimestamp(value.stale_time())}. Using staleTime of {datetime.fromtimestamp(value.stale_time())}')
            return value
        # 不足或等于15分钟，但未过期，下次会再次刷新
        if now < value.stale_time() + RefreshCachedSupplier.STALE_TIME:
            log.warning(
                f'Retrieved value stale time is in the past ({datetime.fromtimestamp(value.stale_time())}). Using staleTime of {datetime.fromtimestamp(now)}')
            return RefreshResult(value=value.value(), stale_time=now, prefetch_time=value.prefetch_time())

        log.warning(
            f'Retrieved value expiration time of the credential is in the past ({datetime.fromtimestamp(value.stale_time() + RefreshCachedSupplier.STALE_TIME)}). Trying use the cached value.')
        # 已过期，看缓存，缓存若大于15分钟，返回缓存，若小于15分钟，则根据策略判断是立刻重试还是稍后重试
        if self._cached_value is None:
            raise CredentialException('No cached value was found.')
        elif now < self._cached_value.stale_time():
            log.warning(
                f'Cached value staleTime is {datetime.fromtimestamp(self._cached_value.stale_time())}. Using staleTime of {datetime.fromtimestamp(self._cached_value.stale_time())}')
            return self._cached_value
        elif self._stale_value_behavior == StaleValueBehavior.STRICT:
            log.warning(
                f'Cached value expiration is in the past ({datetime.fromtimestamp(self._cached_value.stale_time())}). Using expiration of {datetime.fromtimestamp(now + 1)}')
            return RefreshResult(value=self._cached_value.value(), stale_time=now + 1,
                                 prefetch_time=self._cached_value.prefetch_time())
        else:  # ALLOW
            extended_stale_time = now + int((50 * 1000 + random.randint(0, 20 * 1000 + 1)) / 1000)
            log.warning(
                f'Cached value expiration has been extended to {datetime.fromtimestamp(extended_stale_time)} because the downstream service returned a time in the past: {datetime.fromtimestamp(self._cached_value.stale_time())}')
            return RefreshResult(value=self._cached_value.value(), stale_time=extended_stale_time,
                                 prefetch_time=self._cached_value.prefetch_time())

    def _handle_fetched_failure(self, exception: Exception) -> RefreshResult[T]:
        log.warning(f'Refresh credentials failed, cached value is {self._cached_value}, error: {exception}')
        if not self._cached_value:
            log.exception(exception)
            raise exception
        now = int(time.mktime(time.localtime()))
        if now < self._cached_value.stale_time():
            return self._cached_value

        self._consecutive_refresh_failures += 1
        if self._stale_value_behavior == StaleValueBehavior.STRICT:
            log.exception(exception)
            raise exception
        else:  # ALLOW
            new_stale_time = int(
                _jitter_time(now * 1000, 1000, _max_stale_failure_jitter(self._consecutive_refresh_failures)) / 1000)
            log.warning(
                f'Cached value expiration has been extended to {datetime.fromtimestamp(new_stale_time)} because calling the downstream service failed (consecutive failures: {self._consecutive_refresh_failures}).')
            return RefreshResult(value=self._cached_value.value(), stale_time=new_stale_time,
                                 prefetch_time=self._cached_value.prefetch_time())

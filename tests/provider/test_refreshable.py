import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import time
from alibabacloud_credentials.provider.refreshable import (
    Credentials,
    RefreshResult,
    NonBlocking,
    OneCallerBlocks,
    RefreshCachedSupplier,
    StaleValueBehavior,
    CredentialException
)


class TestCredentials(unittest.TestCase):

    def test_credentials_initialization(self):
        """
        Test case 1: Test initialization of Credentials class
        """
        cred = Credentials(
            access_key_id="test_access_key_id",
            access_key_secret="test_access_key_secret",
            security_token="test_security_token",
            expiration=1672531199,
            provider_name="test_provider"
        )

        self.assertEqual(cred.get_access_key_id(), "test_access_key_id")
        self.assertEqual(cred.get_access_key_secret(), "test_access_key_secret")
        self.assertEqual(cred.get_security_token(), "test_security_token")
        self.assertEqual(cred.get_expiration(), 1672531199)
        self.assertEqual(cred.get_provider_name(), "test_provider")


class TestRefreshResult(unittest.TestCase):

    def test_refresh_result_initialization(self):
        """
        Test case 2: Test initialization of RefreshResult class
        """
        value = Credentials(
            access_key_id="test_access_key_id",
            access_key_secret="test_access_key_secret",
            security_token="test_security_token",
            expiration=1672531199,
            provider_name="test_provider"
        )
        refresh_result = RefreshResult(
            value=value,
            stale_time=1672531199 + 900,
            prefetch_time=1672531199 + 1800
        )

        self.assertEqual(refresh_result.value().get_access_key_id(), "test_access_key_id")
        self.assertEqual(refresh_result.stale_time(), 1672531199 + 900)
        self.assertEqual(refresh_result.prefetch_time(), 1672531199 + 1800)


class TestNonBlocking(unittest.TestCase):

    def setUp(self):
        self.non_blocking = NonBlocking()

    @patch('alibabacloud_credentials.provider.refreshable.EXECUTOR.submit')
    @patch('alibabacloud_credentials.provider.refreshable.CONCURRENT_REFRESH_LEASES.acquire')
    def test_prefetch_success(self, mock_acquire, mock_submit):
        """
        Test case 3: Test prefetch success in NonBlocking class
        """
        mock_acquire.return_value = True
        action = MagicMock()

        self.non_blocking.prefetch(action)

        mock_acquire.assert_called_once()
        mock_submit.assert_called_once_with(action)

    @patch('alibabacloud_credentials.provider.refreshable.EXECUTOR.submit')
    @patch('alibabacloud_credentials.provider.refreshable.CONCURRENT_REFRESH_LEASES.acquire')
    def test_prefetch_failure(self, mock_acquire, mock_submit):
        """
        Test case 4: Test prefetch failure in NonBlocking class
        """
        mock_acquire.return_value = False
        action = MagicMock()

        self.non_blocking.prefetch(action)

        mock_acquire.assert_called_once()
        mock_submit.assert_not_called()

    @patch('alibabacloud_credentials.provider.refreshable.EXECUTOR.submit')
    @patch('alibabacloud_credentials.provider.refreshable.CONCURRENT_REFRESH_LEASES.acquire')
    def test_prefetch_exception(self, mock_acquire, mock_submit):
        """
        Test case 5: Test prefetch exception in NonBlocking class
        """
        mock_acquire.return_value = True
        mock_submit.side_effect = Exception("Test exception")
        action = MagicMock()

        self.non_blocking.prefetch(action)

        mock_acquire.assert_called_once()
        mock_submit.assert_called_once_with(action)

    @patch('alibabacloud_credentials.provider.refreshable.NonBlocking.prefetch')
    def test_prefetch_async(self, mock_prefetch):
        """
        Test case 6: Test prefetch_async in NonBlocking class
        """

        action = AsyncMock()

        loop = asyncio.get_event_loop()
        task = asyncio.ensure_future(
            self.non_blocking.prefetch_async(action)
        )
        loop.run_until_complete(task)

        mock_prefetch.assert_called_once()


class TestOneCallerBlocks(unittest.TestCase):

    def setUp(self):
        self.one_caller_blocks = OneCallerBlocks()

    def test_prefetch(self):
        """
        Test case 7: Test prefetch in OneCallerBlocks class
        """
        action = MagicMock()

        self.one_caller_blocks.prefetch(action)

        action.assert_called_once()

    @patch('alibabacloud_credentials.provider.refreshable.OneCallerBlocks.prefetch')
    def test_prefetch_async(self, mock_prefetch):
        """
        Test case 8: Test prefetch_async in OneCallerBlocks class
        """
        action = AsyncMock()

        loop = asyncio.get_event_loop()
        task = asyncio.ensure_future(
            self.one_caller_blocks.prefetch_async(action)
        )
        loop.run_until_complete(task)

        action.assert_called_once()


class TestRefreshCachedSupplier(unittest.TestCase):

    def setUp(self):
        self.refresh_callable = MagicMock()
        self.refresh_callable_async = AsyncMock()
        self.refresh_result = RefreshResult(
            value=Credentials(
                access_key_id="test_access_key_id",
                access_key_secret="test_access_key_secret",
                security_token="test_security_token",
                expiration=int(time.mktime(time.localtime())) + 3600,
                provider_name="test_provider"
            ),
            stale_time=int(time.mktime(time.localtime())) + 1800,
            prefetch_time=int(time.mktime(time.localtime())) + 3600
        )
        self.refresh_cached_supplier = RefreshCachedSupplier(
            refresh_callable=self.refresh_callable,
            refresh_callable_async=self.refresh_callable_async,
            stale_value_behavior=StaleValueBehavior.STRICT,
            prefetch_strategy=OneCallerBlocks()
        )

    def test_sync_call_cache_not_stale(self):
        """
        Test case 9: Test sync_call when cache is not stale
        """
        self.refresh_cached_supplier._cached_value = self.refresh_result

        result = self.refresh_cached_supplier._sync_call()

        self.assertEqual(result.get_access_key_id(), "test_access_key_id")
        self.refresh_callable.assert_not_called()

    def test_sync_call_cache_stale(self):
        """
        Test case 10: Test sync_call when cache is stale
        """
        self.refresh_cached_supplier._cached_value = self.refresh_result
        self.refresh_cached_supplier._cached_value._stale_time = int(time.mktime(time.localtime())) - 1800
        self.refresh_callable.return_value = self.refresh_result

        result = self.refresh_cached_supplier._sync_call()

        self.assertEqual(result.get_access_key_id(), "test_access_key_id")
        self.refresh_callable.assert_called_once()

    def test_async_call_cache_not_stale(self):
        """
        Test case 11: Test async_call when cache is not stale
        """
        self.refresh_cached_supplier._cached_value = self.refresh_result

        loop = asyncio.get_event_loop()
        task = asyncio.ensure_future(
            self.refresh_cached_supplier._async_call()
        )
        loop.run_until_complete(task)
        result = task.result()

        self.assertEqual(result.get_access_key_id(), "test_access_key_id")
        self.refresh_callable_async.assert_not_called()

    @patch('alibabacloud_credentials.provider.refreshable.RefreshCachedSupplier._refresh_cache_async')
    def test_async_call_cache_stale(self, mock_refresh_cache_async):
        """
        Test case 12: Test async_call when cache is stale
        """
        self.refresh_cached_supplier._cached_value = self.refresh_result
        self.refresh_cached_supplier._cached_value._stale_time = int(time.mktime(time.localtime())) - 1800
        mock_refresh_cache_async.return_value = self.refresh_result

        loop = asyncio.get_event_loop()
        task = asyncio.ensure_future(
            self.refresh_cached_supplier._async_call()
        )
        loop.run_until_complete(task)
        result = task.result()

        self.assertEqual(result.get_access_key_id(), "test_access_key_id")
        mock_refresh_cache_async.assert_called_once()

    def test_cache_is_stale(self):
        """
        Test case 13: Test cache_is_stale method
        """
        self.refresh_cached_supplier._cached_value = None
        self.assertTrue(self.refresh_cached_supplier._cache_is_stale())

        self.refresh_cached_supplier._cached_value = self.refresh_result
        self.refresh_cached_supplier._cached_value._stale_time = int(time.mktime(time.localtime())) + 1800
        self.assertFalse(self.refresh_cached_supplier._cache_is_stale())

        self.refresh_cached_supplier._cached_value._stale_time = int(time.mktime(time.localtime())) - 1800
        self.assertTrue(self.refresh_cached_supplier._cache_is_stale())

    def test_should_initiate_cache_prefetch(self):
        """
        Test case 14: Test should_initiate_cache_prefetch method
        """
        self.refresh_cached_supplier._cached_value = None
        self.assertTrue(self.refresh_cached_supplier._should_initiate_cache_prefetch())

        self.refresh_cached_supplier._cached_value = self.refresh_result
        self.refresh_cached_supplier._cached_value._prefetch_time = int(time.mktime(time.localtime())) + 3600
        self.assertFalse(self.refresh_cached_supplier._should_initiate_cache_prefetch())

        self.refresh_cached_supplier._cached_value._prefetch_time = int(time.mktime(time.localtime())) - 3600
        self.assertTrue(self.refresh_cached_supplier._should_initiate_cache_prefetch())

    def test_prefetch_cache(self):
        """
        Test case 15: Test prefetch_cache method
        """
        self.refresh_cached_supplier._prefetch_strategy.prefetch = MagicMock()

        self.refresh_cached_supplier._prefetch_cache()

        self.refresh_cached_supplier._prefetch_strategy.prefetch.assert_called_once_with(
            self.refresh_cached_supplier._refresh_cache)

    @patch('alibabacloud_credentials.provider.refreshable.RefreshCachedSupplier._refresh_cache_async')
    def test_prefetch_cache_async(self, mock_refresh_cache):
        """
        Test case 16: Test prefetch_cache_async method
        """
        self.refresh_cached_supplier._prefetch_strategy.prefetch_async = AsyncMock()

        loop = asyncio.get_event_loop()
        task = asyncio.ensure_future(
            self.refresh_cached_supplier._prefetch_cache_async()
        )
        loop.run_until_complete(task)

        self.refresh_cached_supplier._prefetch_strategy.prefetch_async.assert_called_once_with(mock_refresh_cache)

    @patch('alibabacloud_credentials.provider.refreshable.RefreshCachedSupplier._handle_fetched_success')
    def test_refresh_cache_success(self, mock_handle_fetched_success):
        """
        Test case 17: Test refresh_cache method on success
        """
        self.refresh_callable.return_value = self.refresh_result
        mock_handle_fetched_success.return_value = self.refresh_result

        self.refresh_cached_supplier._refresh_cache()

        self.refresh_callable.assert_called_once()
        mock_handle_fetched_success.assert_called_once_with(self.refresh_result)
        self.refresh_cached_supplier._refresh_lock.release.assert_called_once()

    @patch('alibabacloud_credentials.provider.refreshable.RefreshCachedSupplier._handle_fetched_failure')
    def test_refresh_cache_failure(self, mock_handle_fetched_failure):
        """
        Test case 18: Test refresh_cache method on failure
        """
        self.refresh_callable.side_effect = Exception("Test exception")
        mock_handle_fetched_failure.return_value = self.refresh_result

        self.refresh_cached_supplier._refresh_cache()

        self.refresh_callable.assert_called_once()
        mock_handle_fetched_failure.assert_called_once()

    @patch('alibabacloud_credentials.provider.refreshable.RefreshCachedSupplier._handle_fetched_success')
    async def test_refresh_cache_async_success(self, mock_handle_fetched_success):
        """
        Test case 19: Test refresh_cache_async method on success
        """
        self.refresh_callable_async.return_value = self.refresh_result
        mock_handle_fetched_success.return_value = self.refresh_result

        loop = asyncio.get_event_loop()
        task = asyncio.ensure_future(
            self.refresh_cached_supplier._prefetch_cache_async()
        )
        loop.run_until_complete(task)

        self.refresh_callable_async.assert_called_once()
        mock_handle_fetched_success.assert_called_once_with(self.refresh_result)

    @patch('alibabacloud_credentials.provider.refreshable.RefreshCachedSupplier._handle_fetched_failure')
    async def test_refresh_cache_async_failure(self, mock_handle_fetched_failure):
        """
        Test case 20: Test refresh_cache_async method on failure
        """
        self.refresh_callable_async.side_effect = Exception("Test exception")
        mock_handle_fetched_failure.return_value = self.refresh_result

        loop = asyncio.get_event_loop()
        task = asyncio.ensure_future(
            self.refresh_cached_supplier._refresh_cache_async()
        )
        loop.run_until_complete(task)

        self.refresh_callable_async.assert_called_once()
        mock_handle_fetched_failure.assert_called_once_with(Exception("Test exception"))
        self.refresh_cached_supplier._refresh_lock.release.assert_called_once()

    def test_handle_fetched_success(self):
        """
        Test case 21: Test handle_fetched_success method
        """
        now = int(time.mktime(time.localtime()))
        self.refresh_result._stale_time = now + 1800

        result = self.refresh_cached_supplier._handle_fetched_success(self.refresh_result)

        self.assertEqual(result.value().get_access_key_id(), "test_access_key_id")
        self.assertEqual(result.stale_time(), now + 1800)
        self.assertEqual(result.prefetch_time(), now + 3600)

    def test_handle_fetched_success_stale_time_in_past(self):
        """
        Test case 22: Test handle_fetched_success method when stale time is in the past
        """
        now = int(time.mktime(time.localtime()))
        self.refresh_result._stale_time = now - 1800
        self.refresh_cached_supplier_stale_value_behavior = StaleValueBehavior.ALLOW

        with self.assertRaises(CredentialException) as context:
            self.refresh_cached_supplier._handle_fetched_success(self.refresh_result)

        self.assertIn("No cached value was found.", str(context.exception))

    def test_handle_fetched_success_expired(self):
        """
        Test case 23: Test handle_fetched_success method when credential is expired
        """
        now = int(time.mktime(time.localtime()))
        self.refresh_result._stale_time = now - 1800
        self.refresh_cached_supplier._cached_value = self.refresh_result

        result = self.refresh_cached_supplier._handle_fetched_success(self.refresh_result)

        self.assertEqual(result.value().get_access_key_id(), "test_access_key_id")
        self.assertGreaterEqual(result.stale_time(), now + 1)
        self.assertGreaterEqual(result.prefetch_time(), now + 3600)

    def test_handle_fetched_success_expired_allow_stale(self):
        """
        Test case 24: Test handle_fetched_success method when credential is expired and stale value behavior is ALLOW
        """
        now = int(time.mktime(time.localtime()))
        self.refresh_result._stale_time = now - 1800
        self.refresh_cached_supplier._cached_value = self.refresh_result
        self.refresh_cached_supplier._stale_value_behavior = StaleValueBehavior.ALLOW

        result = self.refresh_cached_supplier._handle_fetched_success(self.refresh_result)

        self.assertEqual(result.value().get_access_key_id(), "test_access_key_id")
        self.assertGreaterEqual(result.stale_time(), now)
        self.assertGreaterEqual(result.prefetch_time(), now + 3600)

    def test_handle_fetched_failure(self):
        """
        Test case 25: Test handle_fetched_failure method
        """
        now = int(time.mktime(time.localtime()))
        self.refresh_cached_supplier._cached_value = self.refresh_result

        result = self.refresh_cached_supplier._handle_fetched_failure(Exception("Test exception"))

        self.assertEqual(result.value().get_access_key_id(), "test_access_key_id")
        self.assertGreaterEqual(result.stale_time(), now + 1)
        self.assertGreaterEqual(result.prefetch_time(), now + 3600)

    def test_handle_fetched_failure_no_cached_value(self):
        """
        Test case 26: Test handle_fetched_failure method when no cached value is available
        """
        self.refresh_cached_supplier._cached_value = None
        self.refresh_cached_supplier_stale_value_behavior = StaleValueBehavior.ALLOW

        with self.assertRaises(CredentialException) as context:
            self.refresh_cached_supplier._handle_fetched_failure(CredentialException("Test exception"))

        self.assertIn("Test exception", str(context.exception))

    def test_handle_fetched_failure_expired(self):
        """
        Test case 27: Test handle_fetched_failure method when cached value is expired
        """
        now = int(time.mktime(time.localtime()))
        self.refresh_cached_supplier._cached_value = self.refresh_result
        self.refresh_cached_supplier._cached_value._stale_time = now - 1800
        self.refresh_cached_supplier._stale_value_behavior = StaleValueBehavior.ALLOW

        result = self.refresh_cached_supplier._handle_fetched_failure(Exception("Test exception"))

        self.assertEqual(result.value().get_access_key_id(), "test_access_key_id")
        self.assertGreaterEqual(result.stale_time(), now)
        self.assertGreaterEqual(result.prefetch_time(), now + 3600)

    def test_handle_fetched_failure_expired_allow_stale(self):
        """
        Test case 28: Test handle_fetched_failure method when cached value is expired and stale value behavior is ALLOW
        """
        now = int(time.mktime(time.localtime()))
        self.refresh_cached_supplier._cached_value = self.refresh_result
        self.refresh_cached_supplier._cached_value._stale_time = now - 1800
        self.refresh_cached_supplier._stale_value_behavior = StaleValueBehavior.ALLOW

        result = self.refresh_cached_supplier._handle_fetched_failure(Exception("Test exception"))

        self.assertEqual(result.value().get_access_key_id(), "test_access_key_id")
        self.assertGreaterEqual(result.stale_time(), now)
        self.assertGreaterEqual(result.prefetch_time(), now + 3600)

"""
Asynchronous utility helpers for ArticDBM Manager.

Provides utilities for:
- Running synchronous functions in thread pool
- Retrying async functions with exponential backoff
- Concurrent execution with rate limiting
- Timeout management for async operations
"""

import asyncio
import functools
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Awaitable, Callable, List, TypeVar, Optional

logger = logging.getLogger(__name__)

T = TypeVar("T")


async def run_in_executor(
    func: Callable[..., T], *args: Any, **kwargs: Any
) -> T:
    """
    Run a synchronous function in a thread pool executor.

    Allows non-blocking execution of blocking operations within async context.

    Args:
        func: Synchronous function to execute
        *args: Positional arguments for func
        **kwargs: Keyword arguments for func

    Returns:
        Result of func(*args, **kwargs)

    Raises:
        Any exceptions raised by func are propagated

    Example:
        def blocking_io():
            return requests.get('http://example.com')

        result = await run_in_executor(blocking_io)
    """
    loop = asyncio.get_event_loop()
    partial_func = functools.partial(func, *args, **kwargs)
    return await loop.run_in_executor(None, partial_func)


def async_retry(
    max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0
) -> Callable:
    """
    Decorator for async functions with automatic retry on failure.

    Implements exponential backoff between retries.

    Args:
        max_retries: Maximum number of retry attempts (default: 3)
        delay: Initial delay between retries in seconds (default: 1.0)
        backoff: Multiplier for delay after each retry (default: 2.0)

    Returns:
        Decorator function

    Raises:
        The last exception if all retries are exhausted

    Example:
        @async_retry(max_retries=5, delay=0.5)
        async def flaky_operation():
            return await database.query()

        result = await flaky_operation()
    """

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            current_delay = delay
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        logger.warning(
                            f"Attempt {attempt + 1} failed for {func.__name__}: "
                            f"{str(e)}. Retrying in {current_delay}s..."
                        )
                        await asyncio.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logger.error(
                            f"All {max_retries + 1} attempts failed for "
                            f"{func.__name__}: {str(e)}"
                        )

            raise last_exception

        return wrapper

    return decorator


async def gather_with_limit(
    coros: List[Awaitable[T]], limit: int = 5
) -> List[T]:
    """
    Run multiple coroutines with a concurrency limit using a semaphore.

    Prevents resource exhaustion by limiting parallel execution.

    Args:
        coros: List of coroutines to execute
        limit: Maximum concurrent coroutines (default: 5)

    Returns:
        List of results in same order as input coroutines

    Raises:
        Propagates any exceptions from coroutines

    Example:
        tasks = [fetch_data(i) for i in range(100)]
        results = await gather_with_limit(tasks, limit=10)
    """
    semaphore = asyncio.Semaphore(limit)

    async def bounded_coro(coro: Awaitable[T]) -> T:
        async with semaphore:
            return await coro

    return await asyncio.gather(*[bounded_coro(coro) for coro in coros])


async def timeout_wrapper(
    coro: Awaitable[T], timeout_seconds: float = 30
) -> T:
    """
    Wrap a coroutine with a timeout.

    Cancels the coroutine if it exceeds the specified timeout.

    Args:
        coro: Coroutine to execute
        timeout_seconds: Timeout in seconds (default: 30)

    Returns:
        Result of coroutine

    Raises:
        asyncio.TimeoutError: If coroutine exceeds timeout
        Any exceptions raised by the coroutine

    Example:
        try:
            result = await timeout_wrapper(long_operation(), timeout_seconds=10)
        except asyncio.TimeoutError:
            logger.error("Operation timed out")
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.error(
            f"Coroutine exceeded timeout of {timeout_seconds} seconds"
        )
        raise

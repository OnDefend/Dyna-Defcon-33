"""
Robust Plugin Timeout Management
"""

import time
import signal
import logging
import threading
from typing import Callable, Any, Optional
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class TimeoutError(Exception):
    """Custom timeout exception."""
    pass

class RobustPluginTimeout:
    """Manage plugin timeouts robustly across different execution contexts."""
    
    def __init__(self):
        self.default_timeout = 120  # 2 minutes default
        self.max_timeout = 300      # 5 minutes maximum
    
    @contextmanager
    def timeout_context(self, timeout_seconds: int = None):
        """Context manager for plugin execution with timeout."""
        if timeout_seconds is None:
            timeout_seconds = self.default_timeout
        
        timeout_seconds = min(timeout_seconds, self.max_timeout)
        
        # Use threading-based timeout (works in all contexts)
        result = [None]
        exception = [None]
        completed = threading.Event()
        
        def target_wrapper(func, args, kwargs):
            try:
                result[0] = func(*args, **kwargs)
            except Exception as e:
                exception[0] = e
            finally:
                completed.set()
        
        try:
            yield self._create_timeout_wrapper(timeout_seconds, completed, result, exception)
        except Exception as e:
            logger.error(f"Plugin execution failed: {e}")
            raise
    
    def _create_timeout_wrapper(self, timeout_seconds, completed, result, exception):
        """Create a timeout wrapper function."""
        
        def execute_with_timeout(func, *args, **kwargs):
            # Start execution in thread
            thread = threading.Thread(
                target=lambda: self._thread_target(func, args, kwargs, result, exception, completed)
            )
            thread.daemon = True
            thread.start()
            
            # Wait for completion or timeout
            if completed.wait(timeout=timeout_seconds):
                # Completed normally
                if exception[0]:
                    raise exception[0]
                return result[0]
            else:
                # Timed out
                logger.warning(f"Plugin execution timed out after {timeout_seconds}s")
                raise TimeoutError(f"Plugin execution timed out after {timeout_seconds} seconds")
        
        return execute_with_timeout
    
    def _thread_target(self, func, args, kwargs, result, exception, completed):
        """Thread target for plugin execution."""
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            exception[0] = e
        finally:
            completed.set()

# Global timeout manager
plugin_timeout_manager = RobustPluginTimeout()

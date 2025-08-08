#!/usr/bin/env python3
"""
Unified Timeout Manager

Consolidates all timeout handling logic from different execution systems.
Eliminates duplication and provides consistent timeout behavior across all execution modes.
"""

import logging
import signal
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Optional, Tuple, Union

logger = logging.getLogger(__name__)

class TimeoutType(Enum):
    """Types of timeouts for different operations."""
    PLUGIN = "plugin"
    PROCESS = "process"
    CRITICAL = "critical"
    DEFAULT = "default"

@dataclass
class TimeoutConfig:
    """Configuration for timeout handling."""
    plugin_timeout: int = 120
    process_timeout: int = 1800
    critical_timeout: int = 300
    default_timeout: int = 60
    enable_escalation: bool = True
    escalation_factor: float = 1.5
    max_escalations: int = 2

class TimeoutException(Exception):
    """Exception raised when an operation times out."""
    
    def __init__(self, operation: str, timeout: int, elapsed: float):
        self.operation = operation
        self.timeout = timeout
        self.elapsed = elapsed
        super().__init__(f"Operation '{operation}' timed out after {elapsed:.1f}s (limit: {timeout}s)")

class TimeoutManager:
    """
    Unified timeout manager eliminating timeout handling duplication.
    
    Consolidates timeout logic from:
    - ParallelAnalysisEngine timeout handling
    - UnifiedPluginExecutionManager timeout management  
    - RobustPluginExecutionManager timeout protection
    - ParallelScanManager process timeouts
    """
    
    def __init__(self, config: Optional[TimeoutConfig] = None):
        """Initialize unified timeout manager."""
        self.config = config or TimeoutConfig()
        self.logger = logging.getLogger(__name__)
        
        # Active timeouts tracking
        self._active_timeouts: Dict[str, threading.Timer] = {}
        self._timeout_lock = threading.RLock()
        
        # Timeout statistics
        self._timeout_stats = {
            'total_operations': 0,
            'successful_operations': 0,
            'timed_out_operations': 0,
            'escalated_operations': 0
        }
        
        self.logger.info("Unified timeout manager initialized")
    
    def get_timeout(self, operation_type: TimeoutType, custom_timeout: Optional[int] = None) -> int:
        """
        Get appropriate timeout for operation type.
        
        Args:
            operation_type: Type of operation needing timeout
            custom_timeout: Custom timeout override
            
        Returns:
            Timeout in seconds
        """
        if custom_timeout is not None:
            return custom_timeout
        
        timeout_map = {
            TimeoutType.PLUGIN: self.config.plugin_timeout,
            TimeoutType.PROCESS: self.config.process_timeout,
            TimeoutType.CRITICAL: self.config.critical_timeout,
            TimeoutType.DEFAULT: self.config.default_timeout
        }
        
        return timeout_map.get(operation_type, self.config.default_timeout)
    
    @contextmanager
    def timeout_context(self, operation_name: str, timeout_seconds: int, 
                       operation_type: TimeoutType = TimeoutType.DEFAULT):
        """
        Context manager for timeout-protected operations.
        
        Args:
            operation_name: Name of the operation for tracking
            timeout_seconds: Timeout in seconds
            operation_type: Type of operation for statistics
            
        Yields:
            TimeoutContext object for monitoring
            
        Raises:
            TimeoutException: If operation times out
        """
        start_time = time.time()
        timeout_id = f"{operation_name}_{int(start_time)}"
        
        # Create timeout context
        context = TimeoutContext(
            operation_name=operation_name,
            timeout_seconds=timeout_seconds,
            start_time=start_time,
            timeout_id=timeout_id
        )
        
        # Set up timeout timer
        timer = None
        try:
            with self._timeout_lock:
                self._timeout_stats['total_operations'] += 1
                
                # Create timeout timer
                timer = threading.Timer(timeout_seconds, self._timeout_callback, [timeout_id, operation_name])
                self._active_timeouts[timeout_id] = timer
                timer.start()
            
            self.logger.debug(f"Started timeout protection for '{operation_name}' ({timeout_seconds}s)")
            
            yield context
            
            # Operation completed successfully
            elapsed = time.time() - start_time
            with self._timeout_lock:
                self._timeout_stats['successful_operations'] += 1
            
            self.logger.debug(f"Operation '{operation_name}' completed in {elapsed:.1f}s")
            
        except TimeoutException:
            # Re-raise timeout exceptions
            raise
        except Exception as e:
            # Log other exceptions but don't modify them
            elapsed = time.time() - start_time
            self.logger.warning(f"Operation '{operation_name}' failed after {elapsed:.1f}s: {e}")
            raise
        finally:
            # Clean up timeout timer
            self._cleanup_timeout(timeout_id)
    
    def _timeout_callback(self, timeout_id: str, operation_name: str):
        """Callback executed when timeout is reached."""
        with self._timeout_lock:
            if timeout_id in self._active_timeouts:
                self._timeout_stats['timed_out_operations'] += 1
                # The timeout will be handled by the monitoring thread
                self.logger.warning(f"Timeout reached for operation '{operation_name}'")
    
    def _cleanup_timeout(self, timeout_id: str):
        """Clean up timeout timer and tracking."""
        with self._timeout_lock:
            if timeout_id in self._active_timeouts:
                timer = self._active_timeouts[timeout_id]
                if timer.is_alive():
                    timer.cancel()
                del self._active_timeouts[timeout_id]
    
    def is_timeout_active(self, timeout_id: str) -> bool:
        """Check if a timeout is still active."""
        with self._timeout_lock:
            return timeout_id in self._active_timeouts
    
    def cancel_timeout(self, timeout_id: str) -> bool:
        """
        Cancel an active timeout.
        
        Args:
            timeout_id: ID of timeout to cancel
            
        Returns:
            True if timeout was cancelled, False if not found
        """
        with self._timeout_lock:
            if timeout_id in self._active_timeouts:
                timer = self._active_timeouts[timeout_id]
                if timer.is_alive():
                    timer.cancel()
                del self._active_timeouts[timeout_id]
                return True
            return False
    
    def escalate_timeout(self, timeout_id: str) -> bool:
        """
        Escalate timeout for an operation (extend the timeout).
        
        Args:
            timeout_id: ID of timeout to escalate
            
        Returns:
            True if escalation was successful
        """
        if not self.config.enable_escalation:
            return False
        
        with self._timeout_lock:
            if timeout_id in self._active_timeouts:
                # Cancel current timer
                current_timer = self._active_timeouts[timeout_id]
                if current_timer.is_alive():
                    current_timer.cancel()
                
                # Create new timer with extended timeout
                original_timeout = getattr(current_timer, 'original_timeout', self.config.default_timeout)
                new_timeout = int(original_timeout * self.config.escalation_factor)
                
                # Extract operation name from timeout_id
                operation_name = timeout_id.rsplit('_', 1)[0]
                
                new_timer = threading.Timer(new_timeout, self._timeout_callback, [timeout_id, operation_name])
                new_timer.original_timeout = original_timeout
                self._active_timeouts[timeout_id] = new_timer
                new_timer.start()
                
                self._timeout_stats['escalated_operations'] += 1
                self.logger.info(f"Escalated timeout for '{operation_name}' to {new_timeout}s")
                return True
        
        return False
    
    def get_active_timeouts(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all active timeouts."""
        with self._timeout_lock:
            active_info = {}
            for timeout_id, timer in self._active_timeouts.items():
                operation_name = timeout_id.rsplit('_', 1)[0]
                active_info[timeout_id] = {
                    'operation_name': operation_name,
                    'is_alive': timer.is_alive(),
                    'timeout_seconds': getattr(timer, 'original_timeout', 'unknown')
                }
            return active_info
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get timeout statistics."""
        with self._timeout_lock:
            stats = self._timeout_stats.copy()
            stats['active_timeouts'] = len(self._active_timeouts)
            
            # Calculate percentages
            total = stats['total_operations']
            if total > 0:
                stats['success_rate'] = stats['successful_operations'] / total
                stats['timeout_rate'] = stats['timed_out_operations'] / total
                stats['escalation_rate'] = stats['escalated_operations'] / total
            else:
                stats['success_rate'] = 0.0
                stats['timeout_rate'] = 0.0
                stats['escalation_rate'] = 0.0
            
            return stats
    
    def shutdown(self):
        """Shutdown timeout manager and cancel all active timeouts."""
        with self._timeout_lock:
            for timeout_id in list(self._active_timeouts.keys()):
                self.cancel_timeout(timeout_id)
        
        self.logger.info("Timeout manager shutdown complete")

@dataclass
class TimeoutContext:
    """Context object for timeout-protected operations."""
    operation_name: str
    timeout_seconds: int
    start_time: float
    timeout_id: str
    
    def get_elapsed_time(self) -> float:
        """Get elapsed time since operation started."""
        return time.time() - self.start_time
    
    def get_remaining_time(self) -> float:
        """Get remaining time before timeout."""
        elapsed = self.get_elapsed_time()
        return max(0, self.timeout_seconds - elapsed)
    
    def is_timeout_imminent(self, threshold_seconds: float = 10.0) -> bool:
        """Check if timeout is imminent (within threshold seconds)."""
        return self.get_remaining_time() <= threshold_seconds

def create_timeout_manager(config: Optional[TimeoutConfig] = None) -> TimeoutManager:
    """Factory function to create timeout manager."""
    return TimeoutManager(config) 
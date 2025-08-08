#!/usr/bin/env python3
"""
Performance Optimizer for AODS Plugin Modularization

This module provides performance optimization utilities that can be shared
across all plugins to improve analysis speed and resource utilization.

Features:
- Memory usage optimization
- CPU usage optimization
- I/O operation optimization
- Caching strategies
- Parallel processing coordination
- Performance monitoring and metrics
"""

import logging
import time
import psutil
import threading
import gc
from typing import Dict, List, Optional, Any, Callable, TypeVar, Union
from dataclasses import dataclass, field
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from functools import wraps, lru_cache
import weakref

logger = logging.getLogger(__name__)

T = TypeVar('T')
R = TypeVar('R')

@dataclass
class PerformanceMetrics:
    """Performance metrics tracking."""
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration: float = 0.0
    memory_usage_start: float = 0.0
    memory_usage_end: float = 0.0
    memory_peak: float = 0.0
    cpu_usage_avg: float = 0.0
    io_operations: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    
    def __post_init__(self):
        """Initialize performance metrics."""
        self.memory_usage_start = self._get_memory_usage()
    
    def finalize(self):
        """Finalize performance metrics."""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        self.memory_usage_end = self._get_memory_usage()
        self.memory_peak = max(self.memory_usage_start, self.memory_usage_end)
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            process = psutil.Process()
            return process.memory_info().rss / (1024 * 1024)  # MB
        except:
            return 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'duration': self.duration,
            'memory_usage_start': self.memory_usage_start,
            'memory_usage_end': self.memory_usage_end,
            'memory_peak': self.memory_peak,
            'cpu_usage_avg': self.cpu_usage_avg,
            'io_operations': self.io_operations,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses
        }

@dataclass
class OptimizationConfig:
    """Configuration for performance optimization."""
    enable_memory_optimization: bool = True
    enable_cpu_optimization: bool = True
    enable_io_optimization: bool = True
    enable_caching: bool = True
    max_memory_usage_mb: int = 1024
    max_cpu_usage_percent: float = 80.0
    cache_size_limit: int = 1000
    parallel_processing_threshold: int = 10
    gc_frequency: int = 100  # Operations between garbage collection
    
    def __post_init__(self):
        """Validate configuration."""
        if self.max_memory_usage_mb <= 0:
            raise ValueError("Max memory usage must be positive")
        if not 0 < self.max_cpu_usage_percent <= 100:
            raise ValueError("Max CPU usage must be between 0 and 100")

class PerformanceOptimizer:
    """
    Performance optimizer providing shared optimization utilities
    for all AODS analysis plugins.
    """
    
    def __init__(self, config: OptimizationConfig):
        """
        Initialize performance optimizer.
        
        Args:
            config: Optimization configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Performance monitoring
        self.metrics = PerformanceMetrics()
        self.operation_count = 0
        self.last_gc_time = time.time()
        
        # Caching
        self.cache: Dict[str, Any] = {}
        self.cache_timestamps: Dict[str, float] = {}
        self.cache_lock = threading.Lock()
        
        # Resource monitoring
        self.resource_monitor = ResourceMonitor()
        
        # Thread pool for parallel operations
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
        self.logger.info("Performance optimizer initialized")
    
    def monitor_performance(self, func: Callable) -> Callable:
        """
        Decorator to monitor function performance.
        
        Args:
            func: Function to monitor
            
        Returns:
            Decorated function with performance monitoring
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            metrics = PerformanceMetrics()
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Update metrics
                metrics.finalize()
                self._update_performance_metrics(metrics)
                
                return result
                
            except Exception as e:
                metrics.finalize()
                self._update_performance_metrics(metrics)
                raise e
        
        return wrapper
    
    def optimize_memory(self, func: Callable) -> Callable:
        """
        Decorator to optimize memory usage.
        
        Args:
            func: Function to optimize
            
        Returns:
            Memory-optimized function
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not self.config.enable_memory_optimization:
                return func(*args, **kwargs)
            
            # Check memory usage before execution
            current_memory = self._get_memory_usage()
            
            if current_memory > self.config.max_memory_usage_mb:
                self._force_garbage_collection()
                self.logger.warning(f"Memory usage high: {current_memory:.2f}MB, forced GC")
            
            try:
                result = func(*args, **kwargs)
                
                # Periodic garbage collection
                self.operation_count += 1
                if self.operation_count % self.config.gc_frequency == 0:
                    self._force_garbage_collection()
                
                return result
                
            except MemoryError:
                self.logger.error("Memory error occurred, forcing garbage collection")
                self._force_garbage_collection()
                raise
        
        return wrapper
    
    def cache_result(self, cache_key: str, ttl: int = 3600) -> Callable:
        """
        Decorator to cache function results.
        
        Args:
            cache_key: Key for caching
            ttl: Time-to-live in seconds
            
        Returns:
            Cached function
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not self.config.enable_caching:
                    return func(*args, **kwargs)
                
                # Generate cache key
                key = self._generate_cache_key(cache_key, args, kwargs)
                
                # Check cache
                cached_result = self._get_cached_result(key, ttl)
                if cached_result is not None:
                    self.metrics.cache_hits += 1
                    return cached_result
                
                # Execute function and cache result
                result = func(*args, **kwargs)
                self._cache_result(key, result)
                self.metrics.cache_misses += 1
                
                return result
            
            return wrapper
        
        return decorator
    
    def parallelize_operation(self, 
                            items: List[T],
                            operation: Callable[[T], R],
                            max_workers: Optional[int] = None) -> List[R]:
        """
        Parallelize operation over a list of items.
        
        Args:
            items: List of items to process
            operation: Operation to perform on each item
            max_workers: Maximum number of worker threads
            
        Returns:
            List of results
        """
        if len(items) < self.config.parallel_processing_threshold:
            # Sequential processing for small datasets
            return [operation(item) for item in items]
        
        max_workers = max_workers or min(len(items), 4)
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_item = {
                executor.submit(operation, item): item 
                for item in items
            }
            
            # Collect results
            for future in as_completed(future_to_item):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Error in parallel operation: {e}")
                    # Continue processing other items
        
        return results
    
    def batch_process(self, 
                     items: List[T],
                     operation: Callable[[List[T]], List[R]],
                     batch_size: int = 100) -> List[R]:
        """
        Process items in batches for better performance.
        
        Args:
            items: List of items to process
            operation: Batch operation function
            batch_size: Size of each batch
            
        Returns:
            List of results
        """
        results = []
        
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            try:
                batch_results = operation(batch)
                results.extend(batch_results)
            except Exception as e:
                self.logger.error(f"Error in batch processing: {e}")
                # Continue with next batch
        
        return results
    
    def optimize_file_operations(self, file_paths: List[Path]) -> List[Path]:
        """
        Optimize file operations by sorting and filtering.
        
        Args:
            file_paths: List of file paths
            
        Returns:
            Optimized list of file paths
        """
        if not self.config.enable_io_optimization:
            return file_paths
        
        # Filter out non-existent files
        valid_paths = [path for path in file_paths if path.exists()]
        
        # Sort by directory to optimize disk I/O
        valid_paths.sort(key=lambda p: (p.parent, p.name))
        
        self.logger.debug(f"Optimized {len(file_paths)} paths to {len(valid_paths)} valid paths")
        return valid_paths
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            process = psutil.Process()
            return process.memory_info().rss / (1024 * 1024)  # MB
        except:
            return 0.0
    
    def _force_garbage_collection(self) -> None:
        """Force garbage collection."""
        try:
            gc.collect()
            self.last_gc_time = time.time()
            self.logger.debug("Forced garbage collection")
        except Exception as e:
            self.logger.error(f"Error during garbage collection: {e}")
    
    def _generate_cache_key(self, base_key: str, args: tuple, kwargs: dict) -> str:
        """Generate cache key from function arguments."""
        import hashlib
        
        # Create a string representation of arguments
        args_str = str(args) + str(sorted(kwargs.items()))
        args_hash = hashlib.md5(args_str.encode()).hexdigest()
        
        return f"{base_key}_{args_hash}"
    
    def _get_cached_result(self, key: str, ttl: int) -> Optional[Any]:
        """Get cached result if valid."""
        with self.cache_lock:
            if key in self.cache:
                timestamp = self.cache_timestamps.get(key, 0)
                if time.time() - timestamp < ttl:
                    return self.cache[key]
                else:
                    # Remove expired entry
                    del self.cache[key]
                    del self.cache_timestamps[key]
        
        return None
    
    def _cache_result(self, key: str, result: Any) -> None:
        """Cache function result."""
        with self.cache_lock:
            # Check cache size limit
            if len(self.cache) >= self.config.cache_size_limit:
                self._cleanup_cache()
            
            self.cache[key] = result
            self.cache_timestamps[key] = time.time()
    
    def _cleanup_cache(self) -> None:
        """Cleanup old cache entries."""
        current_time = time.time()
        keys_to_remove = []
        
        # Find expired entries
        for key, timestamp in self.cache_timestamps.items():
            if current_time - timestamp > 3600:  # 1 hour TTL
                keys_to_remove.append(key)
        
        # Remove expired entries
        for key in keys_to_remove:
            if key in self.cache:
                del self.cache[key]
            if key in self.cache_timestamps:
                del self.cache_timestamps[key]
        
        # If still over limit, remove oldest entries
        if len(self.cache) >= self.config.cache_size_limit:
            sorted_keys = sorted(
                self.cache_timestamps.keys(),
                key=lambda k: self.cache_timestamps[k]
            )
            
            excess_count = len(self.cache) - self.config.cache_size_limit + 10
            for key in sorted_keys[:excess_count]:
                if key in self.cache:
                    del self.cache[key]
                if key in self.cache_timestamps:
                    del self.cache_timestamps[key]
    
    def _update_performance_metrics(self, metrics: PerformanceMetrics) -> None:
        """Update global performance metrics."""
        self.metrics.duration += metrics.duration
        self.metrics.memory_peak = max(self.metrics.memory_peak, metrics.memory_peak)
        self.metrics.io_operations += metrics.io_operations
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get performance optimization report."""
        return {
            'metrics': self.metrics.to_dict(),
            'operation_count': self.operation_count,
            'cache_size': len(self.cache),
            'memory_usage_mb': self._get_memory_usage(),
            'resource_monitor': self.resource_monitor.get_status(),
            'config': {
                'enable_memory_optimization': self.config.enable_memory_optimization,
                'enable_cpu_optimization': self.config.enable_cpu_optimization,
                'enable_io_optimization': self.config.enable_io_optimization,
                'enable_caching': self.config.enable_caching,
                'max_memory_usage_mb': self.config.max_memory_usage_mb,
                'cache_size_limit': self.config.cache_size_limit
            }
        }
    
    def clear_cache(self) -> None:
        """Clear all cached results."""
        with self.cache_lock:
            self.cache.clear()
            self.cache_timestamps.clear()
        
        self.logger.info("Performance cache cleared")
    
    def shutdown(self) -> None:
        """Shutdown performance optimizer."""
        try:
            self.thread_pool.shutdown(wait=True)
            self.clear_cache()
            self.logger.info("Performance optimizer shut down")
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")

class ResourceMonitor:
    """Monitor system resources during analysis."""
    
    def __init__(self):
        """Initialize resource monitor."""
        self.logger = logging.getLogger(__name__)
        self.start_time = time.time()
        self.cpu_samples = []
        self.memory_samples = []
        self.monitoring = False
        self.monitor_thread = None
        self.lock = threading.Lock()
    
    def start_monitoring(self, interval: float = 1.0) -> None:
        """Start resource monitoring."""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        self.logger.debug("Resource monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop resource monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
        self.logger.debug("Resource monitoring stopped")
    
    def _monitor_loop(self, interval: float) -> None:
        """Resource monitoring loop."""
        while self.monitoring:
            try:
                # Get CPU usage
                cpu_percent = psutil.cpu_percent(interval=None)
                
                # Get memory usage
                memory_info = psutil.virtual_memory()
                memory_percent = memory_info.percent
                
                with self.lock:
                    self.cpu_samples.append(cpu_percent)
                    self.memory_samples.append(memory_percent)
                    
                    # Keep only recent samples (last 100)
                    if len(self.cpu_samples) > 100:
                        self.cpu_samples = self.cpu_samples[-100:]
                    if len(self.memory_samples) > 100:
                        self.memory_samples = self.memory_samples[-100:]
                
                time.sleep(interval)
                
            except Exception as e:
                self.logger.error(f"Error in resource monitoring: {e}")
                time.sleep(interval)
    
    def get_status(self) -> Dict[str, Any]:
        """Get current resource status."""
        with self.lock:
            if not self.cpu_samples or not self.memory_samples:
                return {
                    'cpu_usage_avg': 0.0,
                    'cpu_usage_peak': 0.0,
                    'memory_usage_avg': 0.0,
                    'memory_usage_peak': 0.0,
                    'monitoring_duration': time.time() - self.start_time
                }
            
            return {
                'cpu_usage_avg': sum(self.cpu_samples) / len(self.cpu_samples),
                'cpu_usage_peak': max(self.cpu_samples),
                'memory_usage_avg': sum(self.memory_samples) / len(self.memory_samples),
                'memory_usage_peak': max(self.memory_samples),
                'monitoring_duration': time.time() - self.start_time
            }

# Utility functions for common optimizations
def optimize_string_operations(text: str) -> str:
    """Optimize string operations."""
    if not text:
        return text
    
    # Use more efficient string operations
    lines = text.splitlines()
    return '\n'.join(line.strip() for line in lines if line.strip())

def optimize_list_operations(items: List[Any]) -> List[Any]:
    """Optimize list operations."""
    if not items:
        return items
    
    # Remove duplicates while preserving order
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    
    return result

def optimize_dict_operations(data: Dict[str, Any]) -> Dict[str, Any]:
    """Optimize dictionary operations."""
    if not data:
        return data
    
    # Remove None values and empty containers
    return {
        key: value for key, value in data.items()
        if value is not None and (
            not isinstance(value, (list, dict, str)) or len(value) > 0
        )
    } 
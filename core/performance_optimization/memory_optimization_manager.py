"""
Memory Optimization Manager for AODS Phase 3
Optimize memory usage for large APKs and constrained environments
"""

import gc
import os
import psutil
import logging
import threading
import time
from typing import Dict, List, Any, Optional, Callable, Generator
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
from contextlib import contextmanager
import mmap
import weakref

logger = logging.getLogger(__name__)

@dataclass
class MemoryProfile:
    """Memory usage profile for analysis."""
    peak_memory_mb: float
    average_memory_mb: float
    memory_efficiency: float
    gc_collections: int
    large_object_count: int
    memory_pressure_events: int

@dataclass
class MemoryThresholds:
    """Memory threshold configuration."""
    warning_threshold_mb: int
    critical_threshold_mb: int
    emergency_threshold_mb: int
    gc_trigger_threshold_mb: int

class MemoryMonitor:
    """Monitor memory usage and trigger optimization actions."""
    
    def __init__(self):
        self.process = psutil.Process()
        self.monitoring_active = False
        self.memory_history = []
        self.memory_events = []
        self.callbacks = {
            'warning': [],
            'critical': [],
            'emergency': []
        }
        
        # Default thresholds (can be adjusted based on system)
        total_memory = psutil.virtual_memory().total // (1024 * 1024)  # MB
        self.thresholds = MemoryThresholds(
            warning_threshold_mb=int(total_memory * 0.6),      # 60% of system memory
            critical_threshold_mb=int(total_memory * 0.8),     # 80% of system memory
            emergency_threshold_mb=int(total_memory * 0.9),    # 90% of system memory
            gc_trigger_threshold_mb=min(2048, int(total_memory * 0.3))  # 2GB or 30%
        )
        
    def get_current_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage statistics."""
        memory_info = self.process.memory_info()
        system_memory = psutil.virtual_memory()
        
        return {
            "rss_mb": memory_info.rss / (1024 * 1024),
            "vms_mb": memory_info.vms / (1024 * 1024),
            "percent": self.process.memory_percent(),
            "available_mb": system_memory.available / (1024 * 1024),
            "system_percent": system_memory.percent,
            "timestamp": datetime.now().isoformat()
        }
    
    def start_monitoring(self, interval: float = 5.0):
        """Start continuous memory monitoring."""
        self.monitoring_active = True
        
        def monitor_loop():
            while self.monitoring_active:
                try:
                    memory_usage = self.get_current_memory_usage()
                    self.memory_history.append(memory_usage)
                    
                    # Keep only recent history (last 10 minutes)
                    if len(self.memory_history) > 120:  # 5s intervals = 120 for 10 minutes
                        self.memory_history = self.memory_history[-120:]
                    
                    # Check thresholds and trigger callbacks
                    self._check_thresholds(memory_usage)
                    
                    time.sleep(interval)
                    
                except Exception as e:
                    logger.error(f"Memory monitoring error: {e}")
                    time.sleep(interval)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("Memory monitoring started")
    
    def stop_monitoring(self):
        """Stop memory monitoring."""
        self.monitoring_active = False
        logger.info("Memory monitoring stopped")
    
    def _check_thresholds(self, memory_usage: Dict[str, float]):
        """Check memory thresholds and trigger callbacks."""
        rss_mb = memory_usage["rss_mb"]
        
        if rss_mb > self.thresholds.emergency_threshold_mb:
            self._trigger_callbacks('emergency', memory_usage)
            self.memory_events.append({
                "type": "emergency",
                "memory_mb": rss_mb,
                "timestamp": memory_usage["timestamp"]
            })
        elif rss_mb > self.thresholds.critical_threshold_mb:
            self._trigger_callbacks('critical', memory_usage)
            self.memory_events.append({
                "type": "critical",
                "memory_mb": rss_mb,
                "timestamp": memory_usage["timestamp"]
            })
        elif rss_mb > self.thresholds.warning_threshold_mb:
            self._trigger_callbacks('warning', memory_usage)
    
    def _trigger_callbacks(self, event_type: str, memory_usage: Dict[str, float]):
        """Trigger registered callbacks for memory events."""
        for callback in self.callbacks[event_type]:
            try:
                callback(memory_usage)
            except Exception as e:
                logger.error(f"Memory callback error: {e}")
    
    def register_callback(self, event_type: str, callback: Callable):
        """Register callback for memory events."""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
            logger.debug(f"Registered {event_type} memory callback")
    
    def get_memory_profile(self) -> MemoryProfile:
        """Get comprehensive memory profile."""
        if not self.memory_history:
            return MemoryProfile(0, 0, 0, 0, 0, 0)
        
        recent_memory = [m["rss_mb"] for m in self.memory_history[-20:]]  # Last 20 measurements
        
        return MemoryProfile(
            peak_memory_mb=max(recent_memory),
            average_memory_mb=sum(recent_memory) / len(recent_memory),
            memory_efficiency=1.0 - (max(recent_memory) - min(recent_memory)) / max(recent_memory, 1),
            gc_collections=len([e for e in self.memory_events if e["type"] == "gc_triggered"]),
            large_object_count=len(gc.get_objects()) // 1000,  # Approximate large objects
            memory_pressure_events=len(self.memory_events)
        )

class StreamingFileProcessor:
    """Process large files in streaming fashion to minimize memory usage."""
    
    @staticmethod
    def read_file_chunks(file_path: str, chunk_size: int = 8192) -> Generator[bytes, None, None]:
        """Read file in chunks to minimize memory usage."""
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
    
    @staticmethod
    def process_large_text_file(file_path: str, processor: Callable[[str], Any], 
                               chunk_size: int = 1024 * 1024) -> List[Any]:
        """Process large text file line by line to minimize memory usage."""
        results = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                buffer = ""
                for chunk in iter(lambda: f.read(chunk_size), ''):
                    buffer += chunk
                    lines = buffer.split('\n')
                    buffer = lines[-1]  # Keep incomplete line
                    
                    for line in lines[:-1]:
                        if line.strip():
                            result = processor(line)
                            if result is not None:
                                results.append(result)
                
                # Process final line
                if buffer.strip():
                    result = processor(buffer)
                    if result is not None:
                        results.append(result)
                        
        except Exception as e:
            logger.error(f"Error processing large text file {file_path}: {e}")
        
        return results
    
    @staticmethod
    @contextmanager
    def memory_mapped_file(file_path: str):
        """Use memory mapping for efficient large file access."""
        try:
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    yield mm
        except Exception as e:
            logger.error(f"Error memory mapping file {file_path}: {e}")
            yield None

class ObjectPool:
    """Object pool for reusing expensive objects."""
    
    def __init__(self, factory: Callable, max_size: int = 100):
        self.factory = factory
        self.max_size = max_size
        self.pool = []
        self.active_objects = weakref.WeakSet()
        self._lock = threading.Lock()
    
    def get_object(self):
        """Get object from pool or create new one."""
        with self._lock:
            if self.pool:
                obj = self.pool.pop()
                self.active_objects.add(obj)
                return obj
            else:
                obj = self.factory()
                self.active_objects.add(obj)
                return obj
    
    def return_object(self, obj):
        """Return object to pool."""
        with self._lock:
            if len(self.pool) < self.max_size:
                # Reset object state if it has a reset method
                if hasattr(obj, 'reset'):
                    obj.reset()
                self.pool.append(obj)
                
            # Remove from active objects
            self.active_objects.discard(obj)
    
    @contextmanager
    def get_pooled_object(self):
        """Context manager for automatic object return."""
        obj = self.get_object()
        try:
            yield obj
        finally:
            self.return_object(obj)
    
    def get_pool_stats(self) -> Dict[str, int]:
        """Get pool statistics."""
        with self._lock:
            return {
                "available_objects": len(self.pool),
                "active_objects": len(self.active_objects),
                "max_size": self.max_size
            }

class MemoryOptimizationManager:
    """Main memory optimization manager."""
    
    def __init__(self):
        self.monitor = MemoryMonitor()
        self.object_pools = {}
        self.optimization_strategies = {}
        self.gc_stats = {
            "manual_collections": 0,
            "memory_freed_mb": 0,
            "optimization_events": 0
        }
        
        # Register default memory callbacks
        self._register_default_callbacks()
        
        # Start monitoring
        self.monitor.start_monitoring()
    
    def _register_default_callbacks(self):
        """Register default memory optimization callbacks."""
        
        def warning_callback(memory_usage):
            logger.warning(f"Memory warning: {memory_usage['rss_mb']:.1f}MB")
            self._trigger_soft_cleanup()
        
        def critical_callback(memory_usage):
            logger.error(f"Critical memory usage: {memory_usage['rss_mb']:.1f}MB")
            self._trigger_aggressive_cleanup()
        
        def emergency_callback(memory_usage):
            logger.critical(f"Emergency memory usage: {memory_usage['rss_mb']:.1f}MB")
            self._trigger_emergency_cleanup()
        
        self.monitor.register_callback('warning', warning_callback)
        self.monitor.register_callback('critical', critical_callback)
        self.monitor.register_callback('emergency', emergency_callback)
    
    def _trigger_soft_cleanup(self):
        """Trigger soft memory cleanup."""
        logger.info("Triggering soft memory cleanup")
        
        # Force garbage collection
        freed_objects = gc.collect()
        self.gc_stats["manual_collections"] += 1
        
        logger.info(f"Soft cleanup freed {freed_objects} objects")
    
    def _trigger_aggressive_cleanup(self):
        """Trigger aggressive memory cleanup."""
        logger.info("Triggering aggressive memory cleanup")
        
        # Force garbage collection with all generations
        memory_before = self.monitor.get_current_memory_usage()["rss_mb"]
        
        for generation in range(3):
            freed_objects = gc.collect(generation)
            
        # Clear object pools partially
        for pool_name, pool in self.object_pools.items():
            if hasattr(pool, 'pool'):
                cleared = len(pool.pool) // 2
                pool.pool = pool.pool[:cleared]
                logger.debug(f"Cleared {cleared} objects from {pool_name} pool")
        
        memory_after = self.monitor.get_current_memory_usage()["rss_mb"]
        memory_freed = memory_before - memory_after
        
        self.gc_stats["manual_collections"] += 1
        self.gc_stats["memory_freed_mb"] += max(0, memory_freed)
        self.gc_stats["optimization_events"] += 1
        
        logger.info(f"Aggressive cleanup freed {memory_freed:.1f}MB")
    
    def _trigger_emergency_cleanup(self):
        """Trigger emergency memory cleanup."""
        logger.critical("Triggering emergency memory cleanup")
        
        memory_before = self.monitor.get_current_memory_usage()["rss_mb"]
        
        # Clear all object pools
        for pool_name, pool in self.object_pools.items():
            if hasattr(pool, 'pool'):
                cleared = len(pool.pool)
                pool.pool.clear()
                logger.warning(f"Emergency: Cleared all {cleared} objects from {pool_name} pool")
        
        # Force comprehensive garbage collection
        for _ in range(3):
            gc.collect()
        
        # Clear internal caches if available
        try:
            # Clear any internal caches
            import sys
            if hasattr(sys, 'intern'):
                # This is not directly accessible, but we can trigger intern cleanup
                pass
        except:
            pass
        
        memory_after = self.monitor.get_current_memory_usage()["rss_mb"]
        memory_freed = memory_before - memory_after
        
        self.gc_stats["manual_collections"] += 3
        self.gc_stats["memory_freed_mb"] += max(0, memory_freed)
        self.gc_stats["optimization_events"] += 1
        
        logger.critical(f"Emergency cleanup freed {memory_freed:.1f}MB")
    
    @contextmanager
    def memory_optimized_processing(self, operation_name: str):
        """Context manager for memory-optimized processing."""
        logger.debug(f"Starting memory-optimized processing: {operation_name}")
        
        # Record initial memory state
        initial_memory = self.monitor.get_current_memory_usage()
        
        # Set up memory tracking
        gc_before = gc.get_count()
        
        try:
            yield
        finally:
            # Cleanup after processing
            gc_after = gc.get_count()
            
            # Force cleanup if significant allocations occurred
            if sum(gc_after) - sum(gc_before) > 1000:
                freed = gc.collect()
                logger.debug(f"Post-processing cleanup freed {freed} objects")
            
            # Record final memory state
            final_memory = self.monitor.get_current_memory_usage()
            memory_delta = final_memory["rss_mb"] - initial_memory["rss_mb"]
            
            logger.debug(f"Completed {operation_name}: {memory_delta:+.1f}MB memory change")
    
    def create_object_pool(self, pool_name: str, factory: Callable, max_size: int = 100) -> ObjectPool:
        """Create a new object pool."""
        pool = ObjectPool(factory, max_size)
        self.object_pools[pool_name] = pool
        logger.info(f"Created object pool: {pool_name} (max_size: {max_size})")
        return pool
    
    def get_object_pool(self, pool_name: str) -> Optional[ObjectPool]:
        """Get existing object pool."""
        return self.object_pools.get(pool_name)
    
    def optimize_for_large_apk(self, apk_size_mb: float) -> Dict[str, Any]:
        """Optimize memory settings for large APK processing."""
        logger.info(f"Optimizing for large APK: {apk_size_mb:.1f}MB")
        
        optimizations = {
            "gc_frequency": "increased",
            "object_pooling": "enabled",
            "streaming_processing": "enabled",
            "memory_mapping": "enabled"
        }
        
        # Adjust thresholds based on APK size
        if apk_size_mb > 500:  # 500MB+
            # Very large APK - aggressive optimization
            self.monitor.thresholds.gc_trigger_threshold_mb = max(1024, int(apk_size_mb * 0.5))
            optimizations["strategy"] = "aggressive"
            optimizations["chunk_size"] = 4096  # Smaller chunks
        elif apk_size_mb > 100:  # 100-500MB
            # Large APK - moderate optimization
            self.monitor.thresholds.gc_trigger_threshold_mb = max(512, int(apk_size_mb * 0.8))
            optimizations["strategy"] = "moderate"
            optimizations["chunk_size"] = 8192
        else:
            # Normal APK - standard optimization
            optimizations["strategy"] = "standard"
            optimizations["chunk_size"] = 16384
        
        logger.info(f"Applied {optimizations['strategy']} optimization strategy")
        return optimizations
    
    def get_memory_statistics(self) -> Dict[str, Any]:
        """Get comprehensive memory statistics."""
        current_memory = self.monitor.get_current_memory_usage()
        memory_profile = self.monitor.get_memory_profile()
        
        # Object pool statistics
        pool_stats = {}
        for pool_name, pool in self.object_pools.items():
            pool_stats[pool_name] = pool.get_pool_stats()
        
        return {
            "current_memory": current_memory,
            "memory_profile": {
                "peak_memory_mb": memory_profile.peak_memory_mb,
                "average_memory_mb": memory_profile.average_memory_mb,
                "memory_efficiency": memory_profile.memory_efficiency,
                "gc_collections": memory_profile.gc_collections,
                "large_object_count": memory_profile.large_object_count,
                "memory_pressure_events": memory_profile.memory_pressure_events
            },
            "gc_statistics": self.gc_stats,
            "object_pools": pool_stats,
            "memory_thresholds": {
                "warning_mb": self.monitor.thresholds.warning_threshold_mb,
                "critical_mb": self.monitor.thresholds.critical_threshold_mb,
                "emergency_mb": self.monitor.thresholds.emergency_threshold_mb,
                "gc_trigger_mb": self.monitor.thresholds.gc_trigger_threshold_mb
            },
            "optimization_recommendations": self._get_optimization_recommendations(current_memory)
        }
    
    def _get_optimization_recommendations(self, current_memory: Dict[str, float]) -> List[str]:
        """Get memory optimization recommendations."""
        recommendations = []
        
        if current_memory["rss_mb"] > self.monitor.thresholds.warning_threshold_mb:
            recommendations.append("Consider increasing garbage collection frequency")
            recommendations.append("Enable object pooling for frequently created objects")
        
        if current_memory["system_percent"] > 80:
            recommendations.append("System memory usage is high - consider reducing concurrent operations")
        
        if self.gc_stats["optimization_events"] > 5:
            recommendations.append("Frequent memory pressure detected - consider increasing memory limits")
        
        if not self.object_pools:
            recommendations.append("Consider creating object pools for better memory management")
        
        return recommendations
    
    def shutdown(self):
        """Shutdown memory optimization manager."""
        logger.info("Shutting down memory optimization manager")
        
        self.monitor.stop_monitoring()
        
        # Clear all object pools
        for pool_name, pool in self.object_pools.items():
            if hasattr(pool, 'pool'):
                pool.pool.clear()
        
        self.object_pools.clear()
        
        # Final garbage collection
        gc.collect()
        
        logger.info("Memory optimization manager shutdown completed")

# Global memory optimization manager
memory_optimizer = MemoryOptimizationManager()

def optimize_memory_for_operation(operation_name: str):
    """Decorator for memory-optimized operations."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with memory_optimizer.memory_optimized_processing(operation_name):
                return func(*args, **kwargs)
        return wrapper
    return decorator

@contextmanager
def optimized_large_file_processing(file_path: str):
    """Context manager for optimized large file processing."""
    file_size_mb = Path(file_path).stat().st_size / (1024 * 1024)
    optimizations = memory_optimizer.optimize_for_large_apk(file_size_mb)
    
    logger.info(f"Optimizing for file processing: {file_size_mb:.1f}MB")
    
    try:
        yield optimizations
    finally:
        # Cleanup after processing
        gc.collect()
        logger.debug("Completed optimized large file processing") 
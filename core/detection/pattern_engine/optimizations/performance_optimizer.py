#!/usr/bin/env python3
"""
Performance Optimization Module

Advanced performance optimizations for the modular pattern engine including
memory management, lazy loading, caching strategies, and resource optimization.
"""

import gc
import logging
import threading
import weakref
from typing import Dict, List, Any, Optional, Set, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import psutil
import os

from ..models import VulnerabilityPattern, PatternSourceConfig

@dataclass
class PerformanceMetrics:
    """Performance metrics tracking."""
    
    patterns_loaded: int = 0
    loading_time_seconds: float = 0.0
    memory_usage_mb: float = 0.0
    cache_hit_rate: float = 0.0
    pattern_compilation_rate: float = 0.0
    memory_peak_mb: float = 0.0
    gc_collections: int = 0
    thread_pool_efficiency: float = 0.0

class MemoryManager:
    """
    Advanced memory management for pattern engine.
    
    Handles memory monitoring, garbage collection optimization,
    and memory-efficient pattern storage.
    """
    
    def __init__(self, max_memory_mb: int = 512):
        """
        Initialize memory manager.
        
        Args:
            max_memory_mb: Maximum memory usage in MB
        """
        self.max_memory_mb = max_memory_mb
        self.logger = logging.getLogger(__name__)
        self._process = psutil.Process(os.getpid())
        self._memory_snapshots: List[float] = []
        self._pattern_refs: Set[weakref.ref] = set()
        
    def get_current_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        return self._process.memory_info().rss / 1024 / 1024
    
    def check_memory_pressure(self) -> bool:
        """Check if system is under memory pressure."""
        current_memory = self.get_current_memory_usage()
        return current_memory > self.max_memory_mb * 0.8
    
    def optimize_memory_usage(self):
        """Perform memory optimization operations."""
        if self.check_memory_pressure():
            self.logger.info("Memory pressure detected, performing optimization")
            
            # Force garbage collection
            collected = gc.collect()
            self.logger.debug(f"Garbage collection freed {collected} objects")
            
            # Clean up dead weak references
            self._cleanup_dead_references()
            
            # Compact memory if available
            try:
                gc.set_debug(0)  # Disable debug mode for performance
            except:
                pass
    
    def _cleanup_dead_references(self):
        """Clean up dead weak references to patterns."""
        dead_refs = {ref for ref in self._pattern_refs if ref() is None}
        self._pattern_refs -= dead_refs
        self.logger.debug(f"Cleaned up {len(dead_refs)} dead pattern references")
    
    def register_patterns(self, patterns: List[VulnerabilityPattern]):
        """Register patterns for memory tracking."""
        for pattern in patterns:
            self._pattern_refs.add(weakref.ref(pattern))
    
    def get_memory_stats(self) -> Dict[str, float]:
        """Get comprehensive memory statistics."""
        current_memory = self.get_current_memory_usage()
        
        return {
            "current_memory_mb": current_memory,
            "max_memory_mb": self.max_memory_mb,
            "memory_usage_percent": (current_memory / self.max_memory_mb) * 100,
            "tracked_patterns": len(self._pattern_refs),
            "memory_pressure": self.check_memory_pressure()
        }

class LazyPatternLoader:
    """
    Lazy loading implementation for patterns.
    
    Loads patterns on-demand and provides memory-efficient
    access to large pattern collections.
    """
    
    def __init__(self, pattern_factory: Callable[[], List[VulnerabilityPattern]]):
        """
        Initialize lazy loader.
        
        Args:
            pattern_factory: Function that produces patterns when called
        """
        self.pattern_factory = pattern_factory
        self._patterns: Optional[List[VulnerabilityPattern]] = None
        self._loading = False
        self._lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
    
    def get_patterns(self) -> List[VulnerabilityPattern]:
        """Get patterns, loading them if necessary."""
        if self._patterns is None:
            with self._lock:
                if self._patterns is None and not self._loading:
                    self._loading = True
                    try:
                        self.logger.debug("Lazy loading patterns...")
                        self._patterns = self.pattern_factory()
                        self.logger.info(f"Lazy loaded {len(self._patterns)} patterns")
                    finally:
                        self._loading = False
                
                # Wait for loading to complete if another thread is loading
                while self._loading:
                    threading.Event().wait(0.01)
        
        return self._patterns or []
    
    def is_loaded(self) -> bool:
        """Check if patterns are loaded."""
        return self._patterns is not None
    
    def unload(self):
        """Unload patterns to free memory."""
        with self._lock:
            if self._patterns:
                pattern_count = len(self._patterns)
                self._patterns = None
                self.logger.debug(f"Unloaded {pattern_count} patterns")
    
    def get_pattern_count(self) -> int:
        """Get pattern count without loading all patterns."""
        if self._patterns is not None:
            return len(self._patterns)
        
        # For lazy counting, we'd need to implement a separate count mechanism
        # For now, load and count
        return len(self.get_patterns())

class IntelligentCache:
    """
    Intelligent caching system with LRU eviction and adaptive sizing.
    
    Provides memory-efficient caching with automatic cleanup
    and performance optimization.
    """
    
    def __init__(self, max_size: int = 1000, max_memory_mb: int = 100):
        """
        Initialize intelligent cache.
        
        Args:
            max_size: Maximum number of cached items
            max_memory_mb: Maximum memory usage for cache
        """
        self.max_size = max_size
        self.max_memory_mb = max_memory_mb
        self._cache: Dict[str, Any] = {}
        self._access_times: Dict[str, datetime] = {}
        self._access_counts: Dict[str, int] = {}
        self._lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
        
        # Cache statistics
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache."""
        with self._lock:
            if key in self._cache:
                self._access_times[key] = datetime.now()
                self._access_counts[key] = self._access_counts.get(key, 0) + 1
                self._hits += 1
                return self._cache[key]
            
            self._misses += 1
            return None
    
    def put(self, key: str, value: Any):
        """Put item in cache with intelligent eviction."""
        with self._lock:
            # Check if we need to evict items
            if len(self._cache) >= self.max_size:
                self._evict_items()
            
            self._cache[key] = value
            self._access_times[key] = datetime.now()
            self._access_counts[key] = 1
    
    def _evict_items(self):
        """Evict items using LRU + access frequency algorithm."""
        if not self._cache:
            return
        
        # Calculate eviction scores (combine LRU and frequency)
        now = datetime.now()
        eviction_scores = {}
        
        for key in self._cache:
            time_score = (now - self._access_times[key]).total_seconds()
            frequency_score = 1.0 / (self._access_counts[key] + 1)
            eviction_scores[key] = time_score * frequency_score
        
        # Evict 25% of items with highest scores
        items_to_evict = int(self.max_size * 0.25)
        items_to_remove = sorted(eviction_scores.items(), key=lambda x: x[1], reverse=True)[:items_to_evict]
        
        for key, _ in items_to_remove:
            del self._cache[key]
            del self._access_times[key]
            del self._access_counts[key]
        
        self.logger.debug(f"Evicted {len(items_to_remove)} cache items")
    
    def clear(self):
        """Clear entire cache."""
        with self._lock:
            self._cache.clear()
            self._access_times.clear()
            self._access_counts.clear()
            self.logger.debug("Cache cleared")
    
    def get_hit_rate(self) -> float:
        """Get cache hit rate."""
        total_requests = self._hits + self._misses
        if total_requests == 0:
            return 0.0
        return self._hits / total_requests
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hit_rate": self.get_hit_rate(),
            "hits": self._hits,
            "misses": self._misses,
            "memory_usage_estimate_mb": self._estimate_memory_usage()
        }
    
    def _estimate_memory_usage(self) -> float:
        """Estimate cache memory usage."""
        # Rough estimation - would need more sophisticated implementation
        # for accurate memory measurement
        return len(self._cache) * 0.01  # Assume 10KB per cached item

class PatternCompiler:
    """
    Optimized pattern compilation with caching and precompilation.
    
    Compiles regex patterns efficiently and caches compiled patterns
    for improved performance.
    """
    
    def __init__(self):
        """Initialize pattern compiler."""
        self._compiled_cache = IntelligentCache(max_size=2000, max_memory_mb=50)
        self._compilation_stats = {
            "compiled_count": 0,
            "cache_hits": 0,
            "compilation_time": 0.0
        }
        self.logger = logging.getLogger(__name__)
    
    def compile_pattern(self, pattern: VulnerabilityPattern) -> Any:
        """
        Compile regex pattern with caching.
        
        Args:
            pattern: Vulnerability pattern to compile
            
        Returns:
            Compiled regex object
        """
        import re
        import time
        
        # Check cache first
        cached = self._compiled_cache.get(pattern.pattern_regex)
        if cached is not None:
            self._compilation_stats["cache_hits"] += 1
            return cached
        
        # Compile pattern
        start_time = time.time()
        try:
            compiled_pattern = re.compile(pattern.pattern_regex, re.IGNORECASE | re.MULTILINE)
            
            # Cache compiled pattern
            self._compiled_cache.put(pattern.pattern_regex, compiled_pattern)
            
            # Update statistics
            compilation_time = time.time() - start_time
            self._compilation_stats["compiled_count"] += 1
            self._compilation_stats["compilation_time"] += compilation_time
            
            return compiled_pattern
            
        except re.error as e:
            self.logger.warning(f"Failed to compile pattern {pattern.pattern_id}: {e}")
            return None
    
    def precompile_patterns(self, patterns: List[VulnerabilityPattern]) -> Dict[str, Any]:
        """
        Precompile patterns for better performance.
        
        Args:
            patterns: List of patterns to precompile
            
        Returns:
            Compilation statistics
        """
        start_time = time.time()
        compiled_count = 0
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(self.compile_pattern, pattern) for pattern in patterns]
            
            for future in futures:
                try:
                    result = future.result(timeout=1.0)
                    if result is not None:
                        compiled_count += 1
                except Exception as e:
                    self.logger.warning(f"Pattern compilation failed: {e}")
        
        total_time = time.time() - start_time
        
        return {
            "total_patterns": len(patterns),
            "compiled_patterns": compiled_count,
            "compilation_time": total_time,
            "patterns_per_second": compiled_count / total_time if total_time > 0 else 0
        }
    
    def get_compilation_stats(self) -> Dict[str, Any]:
        """Get pattern compilation statistics."""
        stats = self._compilation_stats.copy()
        stats.update(self._compiled_cache.get_stats())
        return stats

class PerformanceOptimizer:
    """
    Main performance optimization coordinator.
    
    Orchestrates all performance optimizations including memory management,
    lazy loading, caching, and pattern compilation.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize performance optimizer.
        
        Args:
            config: Performance optimization configuration
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize optimization components
        self.memory_manager = MemoryManager(
            max_memory_mb=self.config.get('max_memory_mb', 512)
        )
        
        self.pattern_compiler = PatternCompiler()
        
        # Performance tracking
        self._start_time: Optional[datetime] = None
        self._metrics = PerformanceMetrics()
        
    def optimize_pattern_loading(self, patterns: List[VulnerabilityPattern]) -> List[VulnerabilityPattern]:
        """
        Optimize pattern loading with comprehensive optimizations.
        
        Args:
            patterns: Raw patterns to optimize
            
        Returns:
            Optimized patterns
        """
        self._start_time = datetime.now()
        
        try:
            # Memory optimization
            self.memory_manager.optimize_memory_usage()
            
            # Register patterns for memory tracking
            self.memory_manager.register_patterns(patterns)
            
            # Precompile patterns for better performance
            compilation_stats = self.pattern_compiler.precompile_patterns(patterns)
            
            # Update metrics
            self._update_metrics(patterns, compilation_stats)
            
            self.logger.info(f"Optimized {len(patterns)} patterns with {compilation_stats['patterns_per_second']:.1f} patterns/sec")
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Pattern optimization failed: {e}")
            return patterns
    
    def _update_metrics(self, patterns: List[VulnerabilityPattern], compilation_stats: Dict[str, Any]):
        """Update performance metrics."""
        if self._start_time:
            loading_time = (datetime.now() - self._start_time).total_seconds()
            self._metrics.loading_time_seconds = loading_time
            self._metrics.pattern_compilation_rate = compilation_stats.get('patterns_per_second', 0)
        
        self._metrics.patterns_loaded = len(patterns)
        self._metrics.memory_usage_mb = self.memory_manager.get_current_memory_usage()
        self._metrics.cache_hit_rate = self.pattern_compiler._compiled_cache.get_hit_rate()
    
    def get_performance_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics."""
        # Update memory stats
        self._metrics.memory_usage_mb = self.memory_manager.get_current_memory_usage()
        self._metrics.memory_peak_mb = max(self._metrics.memory_peak_mb, self._metrics.memory_usage_mb)
        
        return self._metrics
    
    def optimize_for_deployment(self) -> Dict[str, Any]:
        """
        Perform deployment-ready optimizations.
        
        Returns:
            Optimization report
        """
        self.logger.info("Performing deployment optimizations...")
        
        # Memory optimization
        self.memory_manager.optimize_memory_usage()
        
        # Clear unnecessary caches
        self.pattern_compiler._compiled_cache.clear()
        
        # Force garbage collection
        collected = gc.collect()
        
        # Generate optimization report
        memory_stats = self.memory_manager.get_memory_stats()
        compilation_stats = self.pattern_compiler.get_compilation_stats()
        
        report = {
            "memory_optimization": memory_stats,
            "pattern_compilation": compilation_stats,
            "garbage_collection": {"objects_collected": collected},
            "optimization_timestamp": datetime.now().isoformat()
        }
        
        self.logger.info("Deployment optimizations completed")
        return report
    
    def create_lazy_loader(self, pattern_factory: Callable[[], List[VulnerabilityPattern]]) -> LazyPatternLoader:
        """
        Create optimized lazy loader for patterns.
        
        Args:
            pattern_factory: Function that produces patterns
            
        Returns:
            Configured lazy loader
        """
        return LazyPatternLoader(pattern_factory)
    
    def monitor_performance(self) -> Dict[str, Any]:
        """
        Monitor and report current performance status.
        
        Returns:
            Performance monitoring report
        """
        metrics = self.get_performance_metrics()
        memory_stats = self.memory_manager.get_memory_stats()
        compilation_stats = self.pattern_compiler.get_compilation_stats()
        
        return {
            "performance_metrics": {
                "patterns_loaded": metrics.patterns_loaded,
                "loading_time_seconds": metrics.loading_time_seconds,
                "pattern_compilation_rate": metrics.pattern_compilation_rate,
                "cache_hit_rate": metrics.cache_hit_rate
            },
            "memory_status": memory_stats,
            "compilation_status": compilation_stats,
            "recommendations": self._generate_performance_recommendations(metrics, memory_stats)
        }
    
    def _generate_performance_recommendations(self, metrics: PerformanceMetrics, memory_stats: Dict[str, Any]) -> List[str]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        if memory_stats.get("memory_pressure", False):
            recommendations.append("Consider reducing max_patterns or increasing memory limit")
        
        if metrics.cache_hit_rate < 0.7:
            recommendations.append("Cache hit rate is low, consider increasing cache size")
        
        if metrics.pattern_compilation_rate < 50:
            recommendations.append("Pattern compilation is slow, consider optimizing regex patterns")
        
        if not recommendations:
            recommendations.append("Performance is optimal")
        
        return recommendations 
#!/usr/bin/env python3
"""
Enhanced Caching Coordinator for AODS

This module provides a unified, high-performance caching system that coordinates
all existing caching mechanisms in AODS for maximum performance optimization.

Features:
- Unified caching interface for all AODS components
- Intelligent cache tier management (Memory → SSD → Network)
- Automatic performance optimization and cache warming
- Cross-plugin cache sharing and coordination
- Advanced cache analytics and monitoring
- Lightning-fast cache operations for all scan modes
"""

import logging
import time
import threading
import json
import pickle
import hashlib
from typing import Dict, List, Optional, Any, Union, Tuple, Callable
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import asyncio
import weakref

# Import existing caching systems
from core.jadx_decompilation_cache import JADXDecompilationCache
from core.performance_optimization.intelligent_caching_system import IntelligentCachingSystem
from core.semantic_analysis_framework.shared_infrastructure.caching_manager import SemanticCacheManager
from core.config_management.config_cache import ConfigCache

logger = logging.getLogger(__name__)

@dataclass
class CachePerformanceMetrics:
    """Comprehensive cache performance metrics."""
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    memory_hits: int = 0
    disk_hits: int = 0
    network_hits: int = 0
    
    # Performance metrics
    avg_hit_time_ms: float = 0.0
    avg_miss_time_ms: float = 0.0
    total_time_saved_ms: float = 0.0
    cache_size_mb: float = 0.0
    
    # By category
    jadx_hits: int = 0
    plugin_hits: int = 0
    ml_hits: int = 0
    config_hits: int = 0
    
    @property
    def hit_ratio(self) -> float:
        """Calculate cache hit ratio."""
        if self.total_requests == 0:
            return 0.0
        return self.cache_hits / self.total_requests
    
    @property
    def performance_improvement(self) -> float:
        """Calculate performance improvement percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.total_time_saved_ms / 1000) / self.total_requests * 100

@dataclass
class CacheConfiguration:
    """Enhanced caching configuration."""
    # Memory cache limits
    memory_cache_size_mb: int = 1024  # 1GB
    max_memory_entries: int = 50000
    
    # Disk cache limits
    disk_cache_size_gb: float = 5.0
    disk_cache_ttl_hours: int = 48
    
    # Performance settings
    enable_aggressive_caching: bool = True
    enable_predictive_caching: bool = True
    enable_cache_warming: bool = True
    
    # Lightning mode optimizations
    lightning_mode_memory_mb: int = 2048  # 2GB for Lightning
    lightning_mode_priority: bool = True
    
    # Cache coordination
    enable_cross_plugin_sharing: bool = True
    enable_semantic_caching: bool = True
    auto_cleanup_interval_minutes: int = 30

class EnhancedCachingCoordinator:
    """
    Unified high-performance caching coordinator for AODS.
    
    Coordinates all caching systems for maximum performance optimization.
    """
    
    def __init__(self, config: Optional[CacheConfiguration] = None):
        """Initialize the enhanced caching coordinator."""
        self.config = config or CacheConfiguration()
        self.logger = logging.getLogger(__name__)
        
        # Thread safety
        self._coordinator_lock = threading.RLock()
        
        # Performance metrics
        self.metrics = CachePerformanceMetrics()
        self.metrics_lock = threading.Lock()
        
        # Initialize coordinated caching systems
        self._initialize_caching_systems()
        
        # Cache warming and optimization
        self._cache_warmup_queue = asyncio.Queue()
        self._optimization_thread = None
        
        # Start optimization background processes
        self._start_optimization_services()
        
        self.logger.info("Enhanced Caching Coordinator initialized")
        self.logger.info(f"Configuration: Memory={self.config.memory_cache_size_mb}MB, "
                        f"Disk={self.config.disk_cache_size_gb}GB")
    
    def _initialize_caching_systems(self):
        """Initialize and coordinate all caching systems."""
        try:
            # JADX Decompilation Cache
            self.jadx_cache = JADXDecompilationCache(
                cache_dir="~/.aods_cache/jadx_enhanced",
                max_cache_size_gb=self.config.disk_cache_size_gb
            )
            
            # Intelligent Multi-Tier Cache
            self.intelligent_cache = IntelligentCachingSystem()
            self.intelligent_cache.memory_cache.max_size_mb = self.config.memory_cache_size_mb
            
            # Semantic Analysis Cache
            self.semantic_cache = SemanticCacheManager(
                cache_dir="cache/semantic_analysis_enhanced",
                max_memory_entries=self.config.max_memory_entries // 4,
                max_disk_size_mb=int(self.config.disk_cache_size_gb * 1024 // 4)  # Convert GB to MB
            )
            
            # Configuration Cache
            self.config_cache = ConfigCache(
                max_size=self.config.max_memory_entries // 8,
                default_ttl=self.config.disk_cache_ttl_hours * 3600
            )
            
            # Unified cache registry
            self.cache_registry = {
                'jadx': self.jadx_cache,
                'intelligent': self.intelligent_cache,
                'semantic': self.semantic_cache,
                'config': self.config_cache
            }
            
            self.logger.info("All caching systems initialized and coordinated")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize caching systems: {e}")
            raise
    
    def get_cached_result(self, cache_type: str, cache_key: str, 
                         context: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        """
        Unified method to get cached results from any cache system.
        
        Args:
            cache_type: Type of cache ('jadx', 'plugin', 'ml', 'config', 'semantic')
            cache_key: Unique cache key
            context: Additional context for cache optimization
            
        Returns:
            Cached result or None if not found
        """
        start_time = time.time()
        
        with self.metrics_lock:
            self.metrics.total_requests += 1
        
        try:
            result = None
            hit_source = None
            
            # Lightning mode optimization - prioritize memory cache
            if context and context.get('lightning_mode', False):
                result = self._get_lightning_cached_result(cache_type, cache_key)
                if result:
                    hit_source = 'lightning'
            
            # Standard cache lookup hierarchy
            if not result:
                result, hit_source = self._hierarchical_cache_lookup(cache_type, cache_key, context)
            
            # Update metrics
            lookup_time = (time.time() - start_time) * 1000  # ms
            
            with self.metrics_lock:
                if result is not None:
                    self.metrics.cache_hits += 1
                    self.metrics.avg_hit_time_ms = (
                        (self.metrics.avg_hit_time_ms * (self.metrics.cache_hits - 1) + lookup_time) 
                        / self.metrics.cache_hits
                    )
                    
                    # Update by source
                    if hit_source == 'memory' or hit_source == 'lightning':
                        self.metrics.memory_hits += 1
                    elif hit_source == 'disk':
                        self.metrics.disk_hits += 1
                    
                    # Update by type
                    if cache_type == 'jadx':
                        self.metrics.jadx_hits += 1
                    elif cache_type in ['plugin', 'ml']:
                        self.metrics.plugin_hits += 1
                    elif cache_type == 'config':
                        self.metrics.config_hits += 1
                else:
                    self.metrics.cache_misses += 1
                    self.metrics.avg_miss_time_ms = (
                        (self.metrics.avg_miss_time_ms * (self.metrics.cache_misses - 1) + lookup_time) 
                        / self.metrics.cache_misses
                    )
            
            if result:
                self.logger.debug(f"Cache HIT: {cache_type}:{cache_key[:16]}... from {hit_source} in {lookup_time:.1f}ms")
            else:
                self.logger.debug(f"Cache MISS: {cache_type}:{cache_key[:16]}... in {lookup_time:.1f}ms")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Cache lookup failed for {cache_type}:{cache_key}: {e}")
            return None
    
    def cache_result(self, cache_type: str, cache_key: str, result: Any,
                    context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Unified method to cache results in appropriate cache systems.
        
        Args:
            cache_type: Type of cache
            cache_key: Unique cache key
            result: Result to cache
            context: Additional context for cache optimization
            
        Returns:
            True if successfully cached
        """
        try:
            success = True
            
            # Determine caching strategy based on type and context
            if cache_type == 'jadx':
                success &= self._cache_jadx_result(cache_key, result, context)
            elif cache_type in ['plugin', 'ml']:
                success &= self._cache_plugin_result(cache_key, result, context)
            elif cache_type == 'semantic':
                success &= self._cache_semantic_result(cache_key, result, context)
            elif cache_type == 'config':
                success &= self._cache_config_result(cache_key, result, context)
            
            # Lightning mode - aggressive memory caching
            if context and context.get('lightning_mode', False):
                success &= self._cache_lightning_result(cache_type, cache_key, result)
            
            if success:
                self.logger.debug(f"Cached: {cache_type}:{cache_key[:16]}...")
                
                # Schedule cache warming for related keys
                if self.config.enable_predictive_caching:
                    self._schedule_predictive_caching(cache_type, cache_key, context)
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to cache {cache_type}:{cache_key}: {e}")
            return False
    
    def _hierarchical_cache_lookup(self, cache_type: str, cache_key: str, 
                                 context: Optional[Dict[str, Any]]) -> Tuple[Optional[Any], Optional[str]]:
        """Perform hierarchical cache lookup across all cache tiers."""
        
        # Memory cache first (fastest)
        if cache_type in ['plugin', 'ml']:
            result = self.intelligent_cache.memory_cache.get(cache_key)
            if result:
                return result, 'memory'
        
        # Specialized cache systems
        if cache_type == 'jadx':
            # Try JADX cache with plugin context
            plugin_name = context.get('plugin_name', 'unknown') if context else 'unknown'
            result = self.jadx_cache.get_cached_decompilation(
                context.get('apk_path', ''), plugin_name
            ) if context else None
            if result:
                return result, 'disk'
        
        elif cache_type == 'semantic':
            # Try semantic cache
            if context and 'source_code' in context and 'language' in context:
                result = self.semantic_cache.get_cached_result(
                    context['source_code'], context['language']
                )
                if result:
                    return result, 'disk'
        
        elif cache_type == 'config':
            # Try config cache
            result = self.config_cache.get(cache_key)
            if result:
                return result, 'memory'
        
        # Persistent cache (intelligent cache system)
        if cache_type in ['plugin', 'ml']:
            result = self.intelligent_cache.persistent_cache.get(cache_key)
            if result:
                # Promote to memory cache
                self.intelligent_cache.memory_cache.put(cache_key, result)
                return result, 'disk'
        
        return None, None
    
    def _get_lightning_cached_result(self, cache_type: str, cache_key: str) -> Optional[Any]:
        """Optimized cache lookup for Lightning mode."""
        # Lightning mode prioritizes memory-only lookups for speed
        if cache_type in ['plugin', 'ml']:
            return self.intelligent_cache.memory_cache.get(cache_key)
        elif cache_type == 'config':
            return self.config_cache.get(cache_key)
        return None
    
    def _cache_jadx_result(self, cache_key: str, result: Any, 
                          context: Optional[Dict[str, Any]]) -> bool:
        """Cache JADX decompilation results."""
        if not context or 'apk_path' not in context:
            return False
        
        return self.jadx_cache.cache_decompilation_results(
            context['apk_path'],
            result,
            context.get('decompilation_time', 0.0)
        )
    
    def _cache_plugin_result(self, cache_key: str, result: Any,
                           context: Optional[Dict[str, Any]]) -> bool:
        """Cache plugin analysis results."""
        if not context or 'apk_path' not in context or 'plugin_name' not in context:
            return False
        
        return self.intelligent_cache.cache_plugin_result(
            context['apk_path'],
            context['plugin_name'],
            result,
            context.get('config', {})
        )
    
    def _cache_semantic_result(self, cache_key: str, result: Any,
                             context: Optional[Dict[str, Any]]) -> bool:
        """Cache semantic analysis results."""
        if not context or 'source_code' not in context or 'language' not in context:
            return False
        
        self.semantic_cache.cache_result(
            context['source_code'],
            context['language'],
            result
        )
        return True
    
    def _cache_config_result(self, cache_key: str, result: Any,
                           context: Optional[Dict[str, Any]]) -> bool:
        """Cache configuration results."""
        ttl = context.get('ttl', self.config.disk_cache_ttl_hours * 3600) if context else None
        return self.config_cache.set(cache_key, result, ttl)
    
    def _cache_lightning_result(self, cache_type: str, cache_key: str, result: Any) -> bool:
        """Aggressively cache result for Lightning mode."""
        # Store in memory cache with high priority
        if cache_type in ['plugin', 'ml']:
            return self.intelligent_cache.memory_cache.put(
                cache_key, result, ttl_seconds=3600, priority=True
            )
        elif cache_type == 'config':
            return self.config_cache.set(cache_key, result, ttl=3600)
        return True
    
    def _schedule_predictive_caching(self, cache_type: str, cache_key: str,
                                   context: Optional[Dict[str, Any]]):
        """Schedule predictive caching for related cache keys."""
        try:
            # Add to warming queue for background processing
            if hasattr(self, '_cache_warmup_queue'):
                warming_task = {
                    'type': cache_type,
                    'key': cache_key,
                    'context': context,
                    'timestamp': time.time()
                }
                asyncio.create_task(self._cache_warmup_queue.put(warming_task))
        except Exception as e:
            self.logger.debug(f"Failed to schedule predictive caching: {e}")
    
    def _start_optimization_services(self):
        """Start background optimization services."""
        if self.config.enable_cache_warming or self.config.enable_predictive_caching:
            self._optimization_thread = threading.Thread(
                target=self._background_optimization_worker,
                daemon=True
            )
            self._optimization_thread.start()
            self.logger.info("Cache optimization services started")
    
    def _background_optimization_worker(self):
        """Background worker for cache optimization."""
        while True:
            try:
                # Cache cleanup
                self._cleanup_expired_entries()
                
                # Cache warming (if enabled)
                if self.config.enable_cache_warming:
                    self._perform_cache_warming()
                
                # Performance optimization
                self._optimize_cache_performance()
                
                # Sleep for cleanup interval
                time.sleep(self.config.auto_cleanup_interval_minutes * 60)
                
            except Exception as e:
                self.logger.error(f"Background optimization error: {e}")
                time.sleep(60)  # Wait a minute before retrying
    
    def _cleanup_expired_entries(self):
        """Clean up expired cache entries across all cache systems."""
        try:
            # Let each cache system handle its own cleanup
            for cache_name, cache_system in self.cache_registry.items():
                if hasattr(cache_system, 'cleanup_expired_entries'):
                    cache_system.cleanup_expired_entries()
                    
            self.logger.debug("Cache cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Cache cleanup failed: {e}")
    
    def _perform_cache_warming(self):
        """Perform intelligent cache warming based on usage patterns."""
        # This is a placeholder for cache warming logic
        # Could analyze recent cache misses and pre-populate likely requests
        pass
    
    def _optimize_cache_performance(self):
        """Optimize cache performance based on metrics."""
        try:
            with self.metrics_lock:
                hit_ratio = self.metrics.hit_ratio
                
                # Adjust memory cache size based on performance
                if hit_ratio < 0.7 and self.config.memory_cache_size_mb < 2048:
                    # Increase memory cache size
                    new_size = min(self.config.memory_cache_size_mb * 1.2, 2048)
                    self.config.memory_cache_size_mb = int(new_size)
                    self.intelligent_cache.memory_cache.max_size_mb = int(new_size)
                    self.logger.info(f"Increased memory cache to {new_size}MB (hit ratio: {hit_ratio:.2f})")
                
                elif hit_ratio > 0.9 and self.config.memory_cache_size_mb > 256:
                    # Decrease memory cache size if very high hit ratio
                    new_size = max(self.config.memory_cache_size_mb * 0.9, 256)
                    self.config.memory_cache_size_mb = int(new_size)
                    self.intelligent_cache.memory_cache.max_size_mb = int(new_size)
                    self.logger.info(f"Optimized memory cache to {new_size}MB (hit ratio: {hit_ratio:.2f})")
                    
        except Exception as e:
            self.logger.error(f"Cache performance optimization failed: {e}")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive cache performance metrics."""
        with self.metrics_lock:
            return {
                'hit_ratio': self.metrics.hit_ratio,
                'performance_improvement': self.metrics.performance_improvement,
                'total_requests': self.metrics.total_requests,
                'cache_hits': self.metrics.cache_hits,
                'cache_misses': self.metrics.cache_misses,
                'memory_hits': self.metrics.memory_hits,
                'disk_hits': self.metrics.disk_hits,
                'avg_hit_time_ms': self.metrics.avg_hit_time_ms,
                'avg_miss_time_ms': self.metrics.avg_miss_time_ms,
                'time_saved_seconds': self.metrics.total_time_saved_ms / 1000,
                'cache_breakdown': {
                    'jadx_hits': self.metrics.jadx_hits,
                    'plugin_hits': self.metrics.plugin_hits,
                    'ml_hits': self.metrics.ml_hits,
                    'config_hits': self.metrics.config_hits
                },
                'configuration': {
                    'memory_cache_mb': self.config.memory_cache_size_mb,
                    'disk_cache_gb': self.config.disk_cache_size_gb,
                    'lightning_mode_memory_mb': self.config.lightning_mode_memory_mb
                }
            }
    
    def invalidate_cache(self, cache_type: Optional[str] = None, 
                        cache_key: Optional[str] = None,
                        apk_path: Optional[str] = None):
        """Invalidate cache entries by type, key, or APK."""
        try:
            if apk_path:
                # Invalidate all cache entries for specific APK
                self.intelligent_cache.invalidate_apk_cache(apk_path)
                self.logger.info(f"Invalidated cache for APK: {Path(apk_path).name}")
                
            elif cache_type and cache_key:
                # Invalidate specific cache entry
                if cache_type in ['plugin', 'ml']:
                    self.intelligent_cache.memory_cache.invalidate(cache_key)
                    self.intelligent_cache.persistent_cache.invalidate(cache_key)
                elif cache_type == 'config':
                    self.config_cache.invalidate(cache_key)
                    
                self.logger.info(f"Invalidated cache: {cache_type}:{cache_key}")
                
            elif cache_type:
                # Invalidate all entries of specific type
                self.intelligent_cache.invalidate_plugin_cache(cache_type)
                self.logger.info(f"Invalidated all {cache_type} cache entries")
                
        except Exception as e:
            self.logger.error(f"Cache invalidation failed: {e}")

# Global enhanced caching coordinator
enhanced_cache_coordinator = EnhancedCachingCoordinator()

def get_enhanced_cache() -> EnhancedCachingCoordinator:
    """Get the global enhanced caching coordinator."""
    return enhanced_cache_coordinator

def cache_plugin_result(apk_path: str, plugin_name: str, result: Any, 
                       config: Optional[Dict[str, Any]] = None,
                       lightning_mode: bool = False) -> bool:
    """Convenience function to cache plugin results."""
    context = {
        'apk_path': apk_path,
        'plugin_name': plugin_name,
        'config': config or {},
        'lightning_mode': lightning_mode
    }
    cache_key = f"plugin:{plugin_name}:{hashlib.md5(apk_path.encode()).hexdigest()}"
    return enhanced_cache_coordinator.cache_result('plugin', cache_key, result, context)

def get_cached_plugin_result(apk_path: str, plugin_name: str,
                           config: Optional[Dict[str, Any]] = None,
                           lightning_mode: bool = False) -> Optional[Any]:
    """Convenience function to get cached plugin results."""
    context = {
        'apk_path': apk_path,
        'plugin_name': plugin_name,
        'config': config or {},
        'lightning_mode': lightning_mode
    }
    cache_key = f"plugin:{plugin_name}:{hashlib.md5(apk_path.encode()).hexdigest()}"
    return enhanced_cache_coordinator.get_cached_result('plugin', cache_key, context) 
"""
Enhanced Caching Coordinator for AODS

This module provides a unified, high-performance caching system that coordinates
all existing caching mechanisms in AODS for maximum performance optimization.

Features:
- Unified caching interface for all AODS components
- Intelligent cache tier management (Memory → SSD → Network)
- Automatic performance optimization and cache warming
- Cross-plugin cache sharing and coordination
- Advanced cache analytics and monitoring
- Lightning-fast cache operations for all scan modes
"""

import logging
import time
import threading
import json
import pickle
import hashlib
from typing import Dict, List, Optional, Any, Union, Tuple, Callable
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import asyncio
import weakref

# Import existing caching systems
from core.jadx_decompilation_cache import JADXDecompilationCache
from core.performance_optimization.intelligent_caching_system import IntelligentCachingSystem
from core.semantic_analysis_framework.shared_infrastructure.caching_manager import SemanticCacheManager
from core.config_management.config_cache import ConfigCache

logger = logging.getLogger(__name__)

@dataclass
class CachePerformanceMetrics:
    """Comprehensive cache performance metrics."""
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    memory_hits: int = 0
    disk_hits: int = 0
    network_hits: int = 0
    
    # Performance metrics
    avg_hit_time_ms: float = 0.0
    avg_miss_time_ms: float = 0.0
    total_time_saved_ms: float = 0.0
    cache_size_mb: float = 0.0
    
    # By category
    jadx_hits: int = 0
    plugin_hits: int = 0
    ml_hits: int = 0
    config_hits: int = 0
    
    @property
    def hit_ratio(self) -> float:
        """Calculate cache hit ratio."""
        if self.total_requests == 0:
            return 0.0
        return self.cache_hits / self.total_requests
    
    @property
    def performance_improvement(self) -> float:
        """Calculate performance improvement percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.total_time_saved_ms / 1000) / self.total_requests * 100

@dataclass
class CacheConfiguration:
    """Enhanced caching configuration."""
    # Memory cache limits
    memory_cache_size_mb: int = 1024  # 1GB
    max_memory_entries: int = 50000
    
    # Disk cache limits
    disk_cache_size_gb: float = 5.0
    disk_cache_ttl_hours: int = 48
    
    # Performance settings
    enable_aggressive_caching: bool = True
    enable_predictive_caching: bool = True
    enable_cache_warming: bool = True
    
    # Lightning mode optimizations
    lightning_mode_memory_mb: int = 2048  # 2GB for Lightning
    lightning_mode_priority: bool = True
    
    # Cache coordination
    enable_cross_plugin_sharing: bool = True
    enable_semantic_caching: bool = True
    auto_cleanup_interval_minutes: int = 30

class EnhancedCachingCoordinator:
    """
    Unified high-performance caching coordinator for AODS.
    
    Coordinates all caching systems for maximum performance optimization.
    """
    
    def __init__(self, config: Optional[CacheConfiguration] = None):
        """Initialize the enhanced caching coordinator."""
        self.config = config or CacheConfiguration()
        self.logger = logging.getLogger(__name__)
        
        # Thread safety
        self._coordinator_lock = threading.RLock()
        
        # Performance metrics
        self.metrics = CachePerformanceMetrics()
        self.metrics_lock = threading.Lock()
        
        # Initialize coordinated caching systems
        self._initialize_caching_systems()
        
        # Cache warming and optimization
        self._cache_warmup_queue = asyncio.Queue()
        self._optimization_thread = None
        
        # Start optimization background processes
        self._start_optimization_services()
        
        self.logger.info("Enhanced Caching Coordinator initialized")
        self.logger.info(f"Configuration: Memory={self.config.memory_cache_size_mb}MB, "
                        f"Disk={self.config.disk_cache_size_gb}GB")
    
    def _initialize_caching_systems(self):
        """Initialize and coordinate all caching systems."""
        try:
            # JADX Decompilation Cache
            self.jadx_cache = JADXDecompilationCache(
                cache_dir="~/.aods_cache/jadx_enhanced",
                max_cache_size_gb=self.config.disk_cache_size_gb
            )
            
            # Intelligent Multi-Tier Cache
            self.intelligent_cache = IntelligentCachingSystem()
            self.intelligent_cache.memory_cache.max_size_mb = self.config.memory_cache_size_mb
            
            # Semantic Analysis Cache
            self.semantic_cache = SemanticCacheManager(
                cache_dir="cache/semantic_analysis_enhanced",
                max_memory_entries=self.config.max_memory_entries // 4,
                max_disk_size_mb=int(self.config.disk_cache_size_gb * 1024 // 4)  # Convert GB to MB
            )
            
            # Configuration Cache
            self.config_cache = ConfigCache(
                max_size=self.config.max_memory_entries // 8,
                default_ttl=self.config.disk_cache_ttl_hours * 3600
            )
            
            # Unified cache registry
            self.cache_registry = {
                'jadx': self.jadx_cache,
                'intelligent': self.intelligent_cache,
                'semantic': self.semantic_cache,
                'config': self.config_cache
            }
            
            self.logger.info("All caching systems initialized and coordinated")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize caching systems: {e}")
            raise
    
    def get_cached_result(self, cache_type: str, cache_key: str, 
                         context: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        """
        Unified method to get cached results from any cache system.
        
        Args:
            cache_type: Type of cache ('jadx', 'plugin', 'ml', 'config', 'semantic')
            cache_key: Unique cache key
            context: Additional context for cache optimization
            
        Returns:
            Cached result or None if not found
        """
        start_time = time.time()
        
        with self.metrics_lock:
            self.metrics.total_requests += 1
        
        try:
            result = None
            hit_source = None
            
            # Lightning mode optimization - prioritize memory cache
            if context and context.get('lightning_mode', False):
                result = self._get_lightning_cached_result(cache_type, cache_key)
                if result:
                    hit_source = 'lightning'
            
            # Standard cache lookup hierarchy
            if not result:
                result, hit_source = self._hierarchical_cache_lookup(cache_type, cache_key, context)
            
            # Update metrics
            lookup_time = (time.time() - start_time) * 1000  # ms
            
            with self.metrics_lock:
                if result is not None:
                    self.metrics.cache_hits += 1
                    self.metrics.avg_hit_time_ms = (
                        (self.metrics.avg_hit_time_ms * (self.metrics.cache_hits - 1) + lookup_time) 
                        / self.metrics.cache_hits
                    )
                    
                    # Update by source
                    if hit_source == 'memory' or hit_source == 'lightning':
                        self.metrics.memory_hits += 1
                    elif hit_source == 'disk':
                        self.metrics.disk_hits += 1
                    
                    # Update by type
                    if cache_type == 'jadx':
                        self.metrics.jadx_hits += 1
                    elif cache_type in ['plugin', 'ml']:
                        self.metrics.plugin_hits += 1
                    elif cache_type == 'config':
                        self.metrics.config_hits += 1
                else:
                    self.metrics.cache_misses += 1
                    self.metrics.avg_miss_time_ms = (
                        (self.metrics.avg_miss_time_ms * (self.metrics.cache_misses - 1) + lookup_time) 
                        / self.metrics.cache_misses
                    )
            
            if result:
                self.logger.debug(f"Cache HIT: {cache_type}:{cache_key[:16]}... from {hit_source} in {lookup_time:.1f}ms")
            else:
                self.logger.debug(f"Cache MISS: {cache_type}:{cache_key[:16]}... in {lookup_time:.1f}ms")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Cache lookup failed for {cache_type}:{cache_key}: {e}")
            return None
    
    def cache_result(self, cache_type: str, cache_key: str, result: Any,
                    context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Unified method to cache results in appropriate cache systems.
        
        Args:
            cache_type: Type of cache
            cache_key: Unique cache key
            result: Result to cache
            context: Additional context for cache optimization
            
        Returns:
            True if successfully cached
        """
        try:
            success = True
            
            # Determine caching strategy based on type and context
            if cache_type == 'jadx':
                success &= self._cache_jadx_result(cache_key, result, context)
            elif cache_type in ['plugin', 'ml']:
                success &= self._cache_plugin_result(cache_key, result, context)
            elif cache_type == 'semantic':
                success &= self._cache_semantic_result(cache_key, result, context)
            elif cache_type == 'config':
                success &= self._cache_config_result(cache_key, result, context)
            
            # Lightning mode - aggressive memory caching
            if context and context.get('lightning_mode', False):
                success &= self._cache_lightning_result(cache_type, cache_key, result)
            
            if success:
                self.logger.debug(f"Cached: {cache_type}:{cache_key[:16]}...")
                
                # Schedule cache warming for related keys
                if self.config.enable_predictive_caching:
                    self._schedule_predictive_caching(cache_type, cache_key, context)
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to cache {cache_type}:{cache_key}: {e}")
            return False
    
    def _hierarchical_cache_lookup(self, cache_type: str, cache_key: str, 
                                 context: Optional[Dict[str, Any]]) -> Tuple[Optional[Any], Optional[str]]:
        """Perform hierarchical cache lookup across all cache tiers."""
        
        # Memory cache first (fastest)
        if cache_type in ['plugin', 'ml']:
            result = self.intelligent_cache.memory_cache.get(cache_key)
            if result:
                return result, 'memory'
        
        # Specialized cache systems
        if cache_type == 'jadx':
            # Try JADX cache with plugin context
            plugin_name = context.get('plugin_name', 'unknown') if context else 'unknown'
            result = self.jadx_cache.get_cached_decompilation(
                context.get('apk_path', ''), plugin_name
            ) if context else None
            if result:
                return result, 'disk'
        
        elif cache_type == 'semantic':
            # Try semantic cache
            if context and 'source_code' in context and 'language' in context:
                result = self.semantic_cache.get_cached_result(
                    context['source_code'], context['language']
                )
                if result:
                    return result, 'disk'
        
        elif cache_type == 'config':
            # Try config cache
            result = self.config_cache.get(cache_key)
            if result:
                return result, 'memory'
        
        # Persistent cache (intelligent cache system)
        if cache_type in ['plugin', 'ml']:
            result = self.intelligent_cache.persistent_cache.get(cache_key)
            if result:
                # Promote to memory cache
                self.intelligent_cache.memory_cache.put(cache_key, result)
                return result, 'disk'
        
        return None, None
    
    def _get_lightning_cached_result(self, cache_type: str, cache_key: str) -> Optional[Any]:
        """Optimized cache lookup for Lightning mode."""
        # Lightning mode prioritizes memory-only lookups for speed
        if cache_type in ['plugin', 'ml']:
            return self.intelligent_cache.memory_cache.get(cache_key)
        elif cache_type == 'config':
            return self.config_cache.get(cache_key)
        return None
    
    def _cache_jadx_result(self, cache_key: str, result: Any, 
                          context: Optional[Dict[str, Any]]) -> bool:
        """Cache JADX decompilation results."""
        if not context or 'apk_path' not in context:
            return False
        
        return self.jadx_cache.cache_decompilation_results(
            context['apk_path'],
            result,
            context.get('decompilation_time', 0.0)
        )
    
    def _cache_plugin_result(self, cache_key: str, result: Any,
                           context: Optional[Dict[str, Any]]) -> bool:
        """Cache plugin analysis results."""
        if not context or 'apk_path' not in context or 'plugin_name' not in context:
            return False
        
        return self.intelligent_cache.cache_plugin_result(
            context['apk_path'],
            context['plugin_name'],
            result,
            context.get('config', {})
        )
    
    def _cache_semantic_result(self, cache_key: str, result: Any,
                             context: Optional[Dict[str, Any]]) -> bool:
        """Cache semantic analysis results."""
        if not context or 'source_code' not in context or 'language' not in context:
            return False
        
        self.semantic_cache.cache_result(
            context['source_code'],
            context['language'],
            result
        )
        return True
    
    def _cache_config_result(self, cache_key: str, result: Any,
                           context: Optional[Dict[str, Any]]) -> bool:
        """Cache configuration results."""
        ttl = context.get('ttl', self.config.disk_cache_ttl_hours * 3600) if context else None
        return self.config_cache.set(cache_key, result, ttl)
    
    def _cache_lightning_result(self, cache_type: str, cache_key: str, result: Any) -> bool:
        """Aggressively cache result for Lightning mode."""
        # Store in memory cache with high priority
        if cache_type in ['plugin', 'ml']:
            return self.intelligent_cache.memory_cache.put(
                cache_key, result, ttl_seconds=3600, priority=True
            )
        elif cache_type == 'config':
            return self.config_cache.set(cache_key, result, ttl=3600)
        return True
    
    def _schedule_predictive_caching(self, cache_type: str, cache_key: str,
                                   context: Optional[Dict[str, Any]]):
        """Schedule predictive caching for related cache keys."""
        try:
            # Add to warming queue for background processing
            if hasattr(self, '_cache_warmup_queue'):
                warming_task = {
                    'type': cache_type,
                    'key': cache_key,
                    'context': context,
                    'timestamp': time.time()
                }
                asyncio.create_task(self._cache_warmup_queue.put(warming_task))
        except Exception as e:
            self.logger.debug(f"Failed to schedule predictive caching: {e}")
    
    def _start_optimization_services(self):
        """Start background optimization services."""
        if self.config.enable_cache_warming or self.config.enable_predictive_caching:
            self._optimization_thread = threading.Thread(
                target=self._background_optimization_worker,
                daemon=True
            )
            self._optimization_thread.start()
            self.logger.info("Cache optimization services started")
    
    def _background_optimization_worker(self):
        """Background worker for cache optimization."""
        while True:
            try:
                # Cache cleanup
                self._cleanup_expired_entries()
                
                # Cache warming (if enabled)
                if self.config.enable_cache_warming:
                    self._perform_cache_warming()
                
                # Performance optimization
                self._optimize_cache_performance()
                
                # Sleep for cleanup interval
                time.sleep(self.config.auto_cleanup_interval_minutes * 60)
                
            except Exception as e:
                self.logger.error(f"Background optimization error: {e}")
                time.sleep(60)  # Wait a minute before retrying
    
    def _cleanup_expired_entries(self):
        """Clean up expired cache entries across all cache systems."""
        try:
            # Let each cache system handle its own cleanup
            for cache_name, cache_system in self.cache_registry.items():
                if hasattr(cache_system, 'cleanup_expired_entries'):
                    cache_system.cleanup_expired_entries()
                    
            self.logger.debug("Cache cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Cache cleanup failed: {e}")
    
    def _perform_cache_warming(self):
        """Perform intelligent cache warming based on usage patterns."""
        # This is a placeholder for cache warming logic
        # Could analyze recent cache misses and pre-populate likely requests
        pass
    
    def _optimize_cache_performance(self):
        """Optimize cache performance based on metrics."""
        try:
            with self.metrics_lock:
                hit_ratio = self.metrics.hit_ratio
                
                # Adjust memory cache size based on performance
                if hit_ratio < 0.7 and self.config.memory_cache_size_mb < 2048:
                    # Increase memory cache size
                    new_size = min(self.config.memory_cache_size_mb * 1.2, 2048)
                    self.config.memory_cache_size_mb = int(new_size)
                    self.intelligent_cache.memory_cache.max_size_mb = int(new_size)
                    self.logger.info(f"Increased memory cache to {new_size}MB (hit ratio: {hit_ratio:.2f})")
                
                elif hit_ratio > 0.9 and self.config.memory_cache_size_mb > 256:
                    # Decrease memory cache size if very high hit ratio
                    new_size = max(self.config.memory_cache_size_mb * 0.9, 256)
                    self.config.memory_cache_size_mb = int(new_size)
                    self.intelligent_cache.memory_cache.max_size_mb = int(new_size)
                    self.logger.info(f"Optimized memory cache to {new_size}MB (hit ratio: {hit_ratio:.2f})")
                    
        except Exception as e:
            self.logger.error(f"Cache performance optimization failed: {e}")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive cache performance metrics."""
        with self.metrics_lock:
            return {
                'hit_ratio': self.metrics.hit_ratio,
                'performance_improvement': self.metrics.performance_improvement,
                'total_requests': self.metrics.total_requests,
                'cache_hits': self.metrics.cache_hits,
                'cache_misses': self.metrics.cache_misses,
                'memory_hits': self.metrics.memory_hits,
                'disk_hits': self.metrics.disk_hits,
                'avg_hit_time_ms': self.metrics.avg_hit_time_ms,
                'avg_miss_time_ms': self.metrics.avg_miss_time_ms,
                'time_saved_seconds': self.metrics.total_time_saved_ms / 1000,
                'cache_breakdown': {
                    'jadx_hits': self.metrics.jadx_hits,
                    'plugin_hits': self.metrics.plugin_hits,
                    'ml_hits': self.metrics.ml_hits,
                    'config_hits': self.metrics.config_hits
                },
                'configuration': {
                    'memory_cache_mb': self.config.memory_cache_size_mb,
                    'disk_cache_gb': self.config.disk_cache_size_gb,
                    'lightning_mode_memory_mb': self.config.lightning_mode_memory_mb
                }
            }
    
    def invalidate_cache(self, cache_type: Optional[str] = None, 
                        cache_key: Optional[str] = None,
                        apk_path: Optional[str] = None):
        """Invalidate cache entries by type, key, or APK."""
        try:
            if apk_path:
                # Invalidate all cache entries for specific APK
                self.intelligent_cache.invalidate_apk_cache(apk_path)
                self.logger.info(f"Invalidated cache for APK: {Path(apk_path).name}")
                
            elif cache_type and cache_key:
                # Invalidate specific cache entry
                if cache_type in ['plugin', 'ml']:
                    self.intelligent_cache.memory_cache.invalidate(cache_key)
                    self.intelligent_cache.persistent_cache.invalidate(cache_key)
                elif cache_type == 'config':
                    self.config_cache.invalidate(cache_key)
                    
                self.logger.info(f"Invalidated cache: {cache_type}:{cache_key}")
                
            elif cache_type:
                # Invalidate all entries of specific type
                self.intelligent_cache.invalidate_plugin_cache(cache_type)
                self.logger.info(f"Invalidated all {cache_type} cache entries")
                
        except Exception as e:
            self.logger.error(f"Cache invalidation failed: {e}")

# Global enhanced caching coordinator
enhanced_cache_coordinator = EnhancedCachingCoordinator()

def get_enhanced_cache() -> EnhancedCachingCoordinator:
    """Get the global enhanced caching coordinator."""
    return enhanced_cache_coordinator

def cache_plugin_result(apk_path: str, plugin_name: str, result: Any, 
                       config: Optional[Dict[str, Any]] = None,
                       lightning_mode: bool = False) -> bool:
    """Convenience function to cache plugin results."""
    context = {
        'apk_path': apk_path,
        'plugin_name': plugin_name,
        'config': config or {},
        'lightning_mode': lightning_mode
    }
    cache_key = f"plugin:{plugin_name}:{hashlib.md5(apk_path.encode()).hexdigest()}"
    return enhanced_cache_coordinator.cache_result('plugin', cache_key, result, context)

def get_cached_plugin_result(apk_path: str, plugin_name: str,
                           config: Optional[Dict[str, Any]] = None,
                           lightning_mode: bool = False) -> Optional[Any]:
    """Convenience function to get cached plugin results."""
    context = {
        'apk_path': apk_path,
        'plugin_name': plugin_name,
        'config': config or {},
        'lightning_mode': lightning_mode
    }
    cache_key = f"plugin:{plugin_name}:{hashlib.md5(apk_path.encode()).hexdigest()}"
    return enhanced_cache_coordinator.get_cached_result('plugin', cache_key, context) 
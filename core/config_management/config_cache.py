#!/usr/bin/env python3
"""
Configuration Cache System for AODS Plugin Modularization

This module provides efficient caching for configuration data, patterns,
and settings to improve performance and reduce I/O operations.

Features:
- In-memory configuration caching with TTL
- LRU eviction policy for memory management
- Thread-safe operations
- Cache invalidation strategies
- Performance metrics and statistics
"""

import logging
import time
import threading
from typing import Dict, List, Optional, Any, Union, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from collections import OrderedDict
import hashlib
import json
import weakref

logger = logging.getLogger(__name__)

@dataclass
class CacheEntry:
    """Represents a cache entry with metadata."""
    key: str
    value: Any
    timestamp: float
    ttl: float
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    
    @property
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        return time.time() - self.timestamp > self.ttl
    
    @property
    def age(self) -> float:
        """Get age of cache entry in seconds."""
        return time.time() - self.timestamp
    
    def touch(self):
        """Update last accessed time and increment access count."""
        self.last_accessed = time.time()
        self.access_count += 1

@dataclass
class CacheStats:
    """Cache statistics and metrics."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    invalidations: int = 0
    total_entries: int = 0
    memory_usage_bytes: int = 0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total_requests = self.hits + self.misses
        return self.hits / total_requests if total_requests > 0 else 0.0
    
    @property
    def miss_rate(self) -> float:
        """Calculate cache miss rate."""
        return 1.0 - self.hit_rate
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            'hits': self.hits,
            'misses': self.misses,
            'evictions': self.evictions,
            'invalidations': self.invalidations,
            'total_entries': self.total_entries,
            'memory_usage_bytes': self.memory_usage_bytes,
            'hit_rate': self.hit_rate,
            'miss_rate': self.miss_rate
        }

class ConfigCache:
    """
    Thread-safe configuration cache with LRU eviction and TTL expiration.
    
    Features:
    - Configurable cache size and TTL
    - LRU eviction policy
    - Thread-safe operations
    - Cache statistics
    - Memory usage tracking
    """
    
    def __init__(self, 
                 max_size: int = 1000,
                 default_ttl: float = 3600.0,
                 cleanup_interval: float = 300.0):
        """
        Initialize configuration cache.
        
        Args:
            max_size: Maximum number of cache entries
            default_ttl: Default TTL for cache entries in seconds
            cleanup_interval: Interval for automatic cleanup in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cleanup_interval = cleanup_interval
        
        # Cache storage
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.stats = CacheStats()
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Cleanup thread
        self.cleanup_thread = None
        self.cleanup_running = False
        
        # Start cleanup thread
        self._start_cleanup_thread()
        
        logger.info(f"ConfigCache initialized: max_size={max_size}, default_ttl={default_ttl}s")
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        with self.lock:
            if key not in self.cache:
                self.stats.misses += 1
                return None
            
            entry = self.cache[key]
            
            # Check if expired
            if entry.is_expired:
                self._remove_entry(key)
                self.stats.misses += 1
                return None
            
            # Update access statistics
            entry.touch()
            
            # Move to end (LRU)
            self.cache.move_to_end(key)
            
            self.stats.hits += 1
            return entry.value
    
    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """
        Put value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        with self.lock:
            if ttl is None:
                ttl = self.default_ttl
            
            # Create cache entry
            entry = CacheEntry(
                key=key,
                value=value,
                timestamp=time.time(),
                ttl=ttl
            )
            
            # Remove existing entry if present
            if key in self.cache:
                self._remove_entry(key)
            
            # Add new entry
            self.cache[key] = entry
            self.stats.total_entries += 1
            
            # Evict if over capacity
            while len(self.cache) > self.max_size:
                self._evict_lru()
    
    def remove(self, key: str) -> bool:
        """
        Remove entry from cache.
        
        Args:
            key: Cache key to remove
            
        Returns:
            True if entry was removed, False if not found
        """
        with self.lock:
            if key in self.cache:
                self._remove_entry(key)
                self.stats.invalidations += 1
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            self.stats.invalidations += self.stats.total_entries
            self.stats.total_entries = 0
            self.stats.memory_usage_bytes = 0
    
    def contains(self, key: str) -> bool:
        """Check if key exists in cache and is not expired."""
        with self.lock:
            if key not in self.cache:
                return False
            
            entry = self.cache[key]
            if entry.is_expired:
                self._remove_entry(key)
                return False
            
            return True
    
    def keys(self) -> List[str]:
        """Get all cache keys."""
        with self.lock:
            return list(self.cache.keys())
    
    def size(self) -> int:
        """Get current cache size."""
        with self.lock:
            return len(self.cache)
    
    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        with self.lock:
            # Update current stats
            self.stats.total_entries = len(self.cache)
            self.stats.memory_usage_bytes = self._calculate_memory_usage()
            return self.stats
    
    def cleanup_expired(self) -> int:
        """
        Remove expired entries.
        
        Returns:
            Number of entries removed
        """
        with self.lock:
            expired_keys = []
            
            for key, entry in self.cache.items():
                if entry.is_expired:
                    expired_keys.append(key)
            
            for key in expired_keys:
                self._remove_entry(key)
            
            return len(expired_keys)
    
    def _remove_entry(self, key: str) -> None:
        """Remove cache entry (internal method)."""
        if key in self.cache:
            del self.cache[key]
            self.stats.total_entries -= 1
    
    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if self.cache:
            # Remove oldest entry (first in OrderedDict)
            oldest_key = next(iter(self.cache))
            self._remove_entry(oldest_key)
            self.stats.evictions += 1
    
    def _calculate_memory_usage(self) -> int:
        """Calculate approximate memory usage in bytes."""
        total_size = 0
        
        for entry in self.cache.values():
            # Rough estimate of memory usage
            try:
                total_size += len(json.dumps(entry.value, default=str))
            except (TypeError, ValueError):
                # Fallback for non-serializable objects
                total_size += len(str(entry.value))
        
        return total_size
    
    def _start_cleanup_thread(self) -> None:
        """Start background cleanup thread."""
        if self.cleanup_thread is None or not self.cleanup_thread.is_alive():
            self.cleanup_running = True
            self.cleanup_thread = threading.Thread(
                target=self._cleanup_loop,
                daemon=True
            )
            self.cleanup_thread.start()
    
    def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while self.cleanup_running:
            try:
                time.sleep(self.cleanup_interval)
                if self.cleanup_running:
                    removed = self.cleanup_expired()
                    if removed > 0:
                        logger.debug(f"Cleaned up {removed} expired cache entries")
            except Exception as e:
                logger.error(f"Error in cache cleanup loop: {e}")
    
    def stop_cleanup(self) -> None:
        """Stop background cleanup thread."""
        self.cleanup_running = False
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=1.0)
    
    def __del__(self):
        """Cleanup on destruction."""
        self.stop_cleanup()

class CacheManager:
    """
    Global cache manager for configuration data.
    
    Manages multiple cache instances for different types of configuration data.
    """
    
    def __init__(self):
        """Initialize cache manager."""
        self.caches: Dict[str, ConfigCache] = {}
        self.default_config = {
            'max_size': 1000,
            'default_ttl': 3600.0,
            'cleanup_interval': 300.0
        }
        
        # Create default caches
        self.caches['patterns'] = ConfigCache(**self.default_config)
        self.caches['plugins'] = ConfigCache(**self.default_config)
        self.caches['analysis'] = ConfigCache(**self.default_config)
        self.caches['general'] = ConfigCache(**self.default_config)
        
        logger.info("CacheManager initialized with default caches")
    
    def get_cache(self, cache_name: str) -> Optional[ConfigCache]:
        """Get cache instance by name."""
        return self.caches.get(cache_name)
    
    def create_cache(self, 
                    cache_name: str,
                    max_size: int = 1000,
                    default_ttl: float = 3600.0,
                    cleanup_interval: float = 300.0) -> ConfigCache:
        """
        Create a new cache instance.
        
        Args:
            cache_name: Name of the cache
            max_size: Maximum cache size
            default_ttl: Default TTL in seconds
            cleanup_interval: Cleanup interval in seconds
            
        Returns:
            New ConfigCache instance
        """
        cache = ConfigCache(
            max_size=max_size,
            default_ttl=default_ttl,
            cleanup_interval=cleanup_interval
        )
        
        self.caches[cache_name] = cache
        return cache
    
    def remove_cache(self, cache_name: str) -> bool:
        """Remove cache instance."""
        if cache_name in self.caches:
            cache = self.caches[cache_name]
            cache.stop_cleanup()
            del self.caches[cache_name]
            return True
        return False
    
    def clear_all_caches(self) -> None:
        """Clear all cache instances."""
        for cache in self.caches.values():
            cache.clear()
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all caches."""
        return {
            name: cache.get_stats().to_dict()
            for name, cache in self.caches.items()
        }
    
    def cleanup_all_caches(self) -> Dict[str, int]:
        """Cleanup expired entries in all caches."""
        results = {}
        for name, cache in self.caches.items():
            results[name] = cache.cleanup_expired()
        return results
    
    def shutdown(self) -> None:
        """Shutdown all caches."""
        for cache in self.caches.values():
            cache.stop_cleanup()
        self.caches.clear()

# Global cache manager instance
_cache_manager = None

def get_cache_manager() -> CacheManager:
    """Get global cache manager instance."""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager

def get_cache(cache_name: str) -> Optional[ConfigCache]:
    """Get cache instance by name."""
    return get_cache_manager().get_cache(cache_name)

def cache_config(cache_name: str, key: str, value: Any, ttl: Optional[float] = None) -> None:
    """Cache configuration value."""
    cache = get_cache(cache_name)
    if cache:
        cache.put(key, value, ttl)

def get_cached_config(cache_name: str, key: str) -> Optional[Any]:
    """Get cached configuration value."""
    cache = get_cache(cache_name)
    if cache:
        return cache.get(key)
    return None

def invalidate_cache(cache_name: str, key: str) -> bool:
    """Invalidate cached configuration value."""
    cache = get_cache(cache_name)
    if cache:
        return cache.remove(key)
    return False

def clear_cache(cache_name: str) -> None:
    """Clear entire cache."""
    cache = get_cache(cache_name)
    if cache:
        cache.clear()

# Cache key generators
def generate_file_cache_key(file_path: Path) -> str:
    """Generate cache key for file-based configuration."""
    # Include file path and modification time
    try:
        mtime = file_path.stat().st_mtime
        path_str = str(file_path.resolve())
        return f"file:{hashlib.md5(path_str.encode()).hexdigest()}:{mtime}"
    except (OSError, AttributeError):
        return f"file:{hashlib.md5(str(file_path).encode()).hexdigest()}"

def generate_config_cache_key(config_type: str, identifier: str) -> str:
    """Generate cache key for configuration data."""
    return f"{config_type}:{identifier}"

def generate_pattern_cache_key(pattern_file: Path, category: str) -> str:
    """Generate cache key for pattern configuration."""
    file_key = generate_file_cache_key(pattern_file)
    return f"pattern:{file_key}:{category}" 
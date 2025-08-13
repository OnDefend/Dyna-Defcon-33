#!/usr/bin/env python3
"""
Performance Optimizer - Intelligent Cache

caching system with SQLite persistence, LRU eviction,
and content-based cache keys for maximum performance optimization.
"""

import logging
import time
import hashlib
import pickle
import sqlite3
import threading
import json
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from functools import wraps

from .data_structures import CacheMetrics, CacheStrategy

class IntelligentCache:
    """
    intelligent caching system for AODS accuracy pipeline
    
    Features:
    - SQLite-based persistent cache with ACID compliance
    - Multiple eviction strategies (LRU, LFU, FIFO, Adaptive)
    - Content-based cache key generation
    - Automatic cache invalidation with TTL support
    - Thread-safe operations with proper locking
    - Comprehensive metrics and monitoring
    """
    
    def __init__(self, cache_dir: str = "cache", max_size_mb: int = 512, 
                 ttl_hours: int = 24, strategy: CacheStrategy = CacheStrategy.ADAPTIVE):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.max_size_mb = max_size_mb
        self.ttl_seconds = ttl_hours * 3600
        self.strategy = strategy
        
        # Initialize database
        self.db_path = self.cache_dir / "cache.db"
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
        
        # Metrics tracking
        self.metrics = CacheMetrics()
        
        # Initialize cache database
        self._initialize_database()
        
        # Cleanup expired entries on startup
        self._cleanup_expired_entries()
        
        self.logger.info(f"Intelligent cache initialized with {strategy.value} strategy")
        self.logger.info(f"Cache directory: {self.cache_dir}")
        self.logger.info(f"Max size: {max_size_mb}MB, TTL: {ttl_hours}h")
    
    def _initialize_database(self):
        """Initialize SQLite database for persistent caching."""
        with self.lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS cache_entries (
                        key TEXT PRIMARY KEY,
                        value BLOB,
                        created_at REAL,
                        last_accessed REAL,
                        access_count INTEGER DEFAULT 1,
                        size_bytes INTEGER,
                        content_hash TEXT
                    )
                """)
                
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_last_accessed 
                    ON cache_entries(last_accessed)
                """)
                
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_created_at 
                    ON cache_entries(created_at)
                """)
                
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_access_count 
                    ON cache_entries(access_count)
                """)
                
                conn.commit()
                self.logger.info("Cache database initialized successfully")
                
            except Exception as e:
                self.logger.error(f"Failed to initialize cache database: {e}")
                raise
            finally:
                conn.close()
    
    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve item from cache with professional error handling and metrics tracking.
        """
        start_time = time.time()
        
        with self.lock:
            try:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()
                
                # Check if entry exists and is not expired
                cursor.execute("""
                    SELECT value, created_at, last_accessed, access_count 
                    FROM cache_entries 
                    WHERE key = ? AND (? - created_at) < ?
                """, (key, time.time(), self.ttl_seconds))
                
                result = cursor.fetchone()
                
                if result:
                    # Update access statistics
                    current_time = time.time()
                    cursor.execute("""
                        UPDATE cache_entries 
                        SET last_accessed = ?, access_count = access_count + 1
                        WHERE key = ?
                    """, (current_time, key))
                    
                    conn.commit()
                    
                    # Deserialize value
                    value = pickle.loads(result[0])
                    
                    # Update metrics
                    self.metrics.cache_hits += 1
                    self.metrics.total_requests += 1
                    self.metrics.hit_rate_percentage = (
                        self.metrics.cache_hits / self.metrics.total_requests * 100
                    )
                    
                    lookup_time = (time.time() - start_time) * 1000
                    self.metrics.average_lookup_time_ms = (
                        (self.metrics.average_lookup_time_ms * (self.metrics.total_requests - 1) + lookup_time) /
                        self.metrics.total_requests
                    )
                    
                    self.logger.debug(f"Cache hit for key: {key[:16]}...")
                    return value
                else:
                    # Cache miss
                    self.metrics.cache_misses += 1
                    self.metrics.total_requests += 1
                    self.metrics.miss_rate_percentage = (
                        self.metrics.cache_misses / self.metrics.total_requests * 100
                    )
                    
                    self.logger.debug(f"Cache miss for key: {key[:16]}...")
                    return None
                    
            except Exception as e:
                self.logger.error(f"Cache retrieval error for key {key[:16]}...: {e}")
                return None
            finally:
                conn.close()
    
    def put(self, key: str, value: Any, ttl_override: Optional[int] = None) -> bool:
        """
        Store item in cache with intelligent eviction and size management.
        """
        with self.lock:
            try:
                # Serialize value and calculate size
                serialized_value = pickle.dumps(value)
                value_size = len(serialized_value)
                content_hash = hashlib.md5(serialized_value).hexdigest()
                
                # Check if we need to make space
                if not self._ensure_cache_space(value_size):
                    self.logger.warning(f"Failed to make space for cache entry: {key[:16]}...")
                    return False
                
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()
                
                current_time = time.time()
                
                # Insert or replace cache entry
                cursor.execute("""
                    INSERT OR REPLACE INTO cache_entries 
                    (key, value, created_at, last_accessed, access_count, size_bytes, content_hash)
                    VALUES (?, ?, ?, ?, 1, ?, ?)
                """, (key, serialized_value, current_time, current_time, value_size, content_hash))
                
                conn.commit()
                
                self.logger.debug(f"Cached entry for key: {key[:16]}... (size: {value_size} bytes)")
                return True
                
            except Exception as e:
                self.logger.error(f"Cache storage error for key {key[:16]}...: {e}")
                return False
            finally:
                conn.close()
    
    def _ensure_cache_space(self, required_bytes: int) -> bool:
        """
        Ensure sufficient cache space using intelligent eviction strategies.
        """
        current_size = self._get_cache_size_bytes()
        max_size_bytes = self.max_size_mb * 1024 * 1024
        
        if current_size + required_bytes <= max_size_bytes:
            return True
        
        # Calculate how much space we need to free
        space_to_free = (current_size + required_bytes) - max_size_bytes
        
        return self._evict_entries(space_to_free)
    
    def _evict_entries(self, space_to_free: int) -> bool:
        """
        Evict cache entries based on the configured strategy.
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            if self.strategy == CacheStrategy.LRU:
                # Evict least recently used entries
                cursor.execute("""
                    SELECT key, size_bytes FROM cache_entries 
                    ORDER BY last_accessed ASC
                """)
            elif self.strategy == CacheStrategy.LFU:
                # Evict least frequently used entries
                cursor.execute("""
                    SELECT key, size_bytes FROM cache_entries 
                    ORDER BY access_count ASC, last_accessed ASC
                """)
            elif self.strategy == CacheStrategy.FIFO:
                # Evict oldest entries first
                cursor.execute("""
                    SELECT key, size_bytes FROM cache_entries 
                    ORDER BY created_at ASC
                """)
            else:  # ADAPTIVE
                # Use adaptive strategy based on access patterns
                cursor.execute("""
                    SELECT key, size_bytes, access_count, last_accessed, created_at 
                    FROM cache_entries 
                    ORDER BY (access_count * 0.5 + (? - last_accessed) * 0.3 + (? - created_at) * 0.2) ASC
                """, (time.time(), time.time()))
            
            entries_to_evict = []
            freed_space = 0
            
            for row in cursor.fetchall():
                entries_to_evict.append(row[0])  # key
                freed_space += row[1]  # size_bytes
                
                if freed_space >= space_to_free:
                    break
            
            # Remove selected entries
            for key in entries_to_evict:
                cursor.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                self.metrics.eviction_count += 1
            
            conn.commit()
            
            self.logger.info(f"Evicted {len(entries_to_evict)} entries, freed {freed_space} bytes")
            return True
            
        except Exception as e:
            self.logger.error(f"Cache eviction error: {e}")
            return False
        finally:
            conn.close()
    
    def _get_cache_size_bytes(self) -> int:
        """Get current cache size in bytes."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT SUM(size_bytes) FROM cache_entries")
            result = cursor.fetchone()
            return result[0] if result[0] else 0
        except Exception as e:
            self.logger.error(f"Error getting cache size: {e}")
            return 0
        finally:
            conn.close()
    
    def _cleanup_expired_entries(self):
        """Remove expired cache entries."""
        with self.lock:
            try:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()
                
                current_time = time.time()
                cursor.execute("""
                    DELETE FROM cache_entries 
                    WHERE (? - created_at) > ?
                """, (current_time, self.ttl_seconds))
                
                deleted_count = cursor.rowcount
                conn.commit()
                
                if deleted_count > 0:
                    self.logger.info(f"Cleaned up {deleted_count} expired cache entries")
                    
            except Exception as e:
                self.logger.error(f"Cache cleanup error: {e}")
            finally:
                conn.close()
    
    def _generate_cache_key(self, data: Dict[str, Any], prefix: str = "cache") -> str:
        """
        Generate content-based cache key with collision resistance.
        """
        # Create stable string representation
        stable_data = json.dumps(data, sort_keys=True, default=str)
        
        # Generate hash-based key
        content_hash = hashlib.sha256(stable_data.encode()).hexdigest()
        
        return f"{prefix}_{content_hash[:32]}"
    
    def clear(self):
        """Clear all cache entries."""
        with self.lock:
            try:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()
                cursor.execute("DELETE FROM cache_entries")
                conn.commit()
                
                # Reset metrics
                self.metrics = CacheMetrics()
                
                self.logger.info("Cache cleared successfully")
                
            except Exception as e:
                self.logger.error(f"Cache clear error: {e}")
            finally:
                conn.close()
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics and metrics."""
        with self.lock:
            try:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()
                
                # Get entry count and total size
                cursor.execute("SELECT COUNT(*), SUM(size_bytes) FROM cache_entries")
                count_result = cursor.fetchone()
                entry_count = count_result[0] if count_result[0] else 0
                total_size_bytes = count_result[1] if count_result[1] else 0
                
                # Update metrics
                self.metrics.cache_size_mb = total_size_bytes / (1024 * 1024)
                self.metrics.utilization_percentage = (
                    (total_size_bytes / (self.max_size_mb * 1024 * 1024)) * 100
                    if self.max_size_mb > 0 else 0
                )
                
                # Calculate efficiency metrics
                if self.metrics.total_requests > 0:
                    self.metrics.hit_rate_percentage = (
                        self.metrics.cache_hits / self.metrics.total_requests * 100
                    )
                    self.metrics.miss_rate_percentage = (
                        self.metrics.cache_misses / self.metrics.total_requests * 100
                    )
                
                return {
                    'entry_count': entry_count,
                    'total_size_mb': self.metrics.cache_size_mb,
                    'utilization_percentage': self.metrics.utilization_percentage,
                    'hit_rate_percentage': self.metrics.hit_rate_percentage,
                    'miss_rate_percentage': self.metrics.miss_rate_percentage,
                    'total_requests': self.metrics.total_requests,
                    'cache_hits': self.metrics.cache_hits,
                    'cache_misses': self.metrics.cache_misses,
                    'eviction_count': self.metrics.eviction_count,
                    'average_lookup_time_ms': self.metrics.average_lookup_time_ms,
                    'strategy': self.strategy.value,
                    'max_size_mb': self.max_size_mb,
                    'ttl_hours': self.ttl_seconds / 3600
                }
                
            except Exception as e:
                self.logger.error(f"Error getting cache statistics: {e}")
                return {}
            finally:
                conn.close()

# Decorator for automatic caching
def cache_result(cache_instance: IntelligentCache, key_prefix: str = "func", ttl_hours: Optional[int] = None):
    """
    Decorator for automatic function result caching.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key from function arguments
            cache_key_data = {
                'func_name': func.__name__,
                'args': args,
                'kwargs': kwargs
            }
            cache_key = cache_instance._generate_cache_key(cache_key_data, key_prefix)
            
            # Try to get from cache first
            cached_result = cache_instance.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache_instance.put(cache_key, result, ttl_hours)
            
            return result
        
        return wrapper
    return decorator 
"""
Semantic Cache Manager for AODS Semantic Analysis Framework

This module provides intelligent caching capabilities for semantic parsing results,
integrating with existing AODS shared infrastructure for optimal performance.
"""

import hashlib
import pickle
import time
import sqlite3
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import threading

from ..data_structures import SemanticParsingResult, LanguageType

# Integration with existing AODS infrastructure
try:
    from core.shared_infrastructure.universal_pattern_matcher import CacheManager as AODSCacheManager
    AODS_CACHE_AVAILABLE = True
except ImportError:
    AODS_CACHE_AVAILABLE = False

logger = logging.getLogger(__name__)


class SemanticCacheManager:
    """
    Intelligent cache manager for semantic parsing results.
    
    This cache manager integrates with existing AODS shared infrastructure
    while providing specialized caching for semantic analysis results.
    
    Features:
    - SQLite-based persistent storage
    - Content-based cache keys using SHA-256
    - TTL (Time To Live) for cache entries
    - Memory and disk size limits
    - Integration with AODS cache infrastructure
    - Thread-safe operations
    """
    
    def __init__(self, 
                 cache_dir: str = "cache/semantic_analysis",
                 max_memory_entries: int = 1000,
                 max_disk_size_mb: int = 500,
                 default_ttl_hours: int = 24):
        """
        Initialize the semantic cache manager.
        
        Args:
            cache_dir: Directory for cache storage
            max_memory_entries: Maximum entries in memory cache
            max_disk_size_mb: Maximum disk cache size in MB
            default_ttl_hours: Default TTL for cache entries in hours
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.max_memory_entries = max_memory_entries
        self.max_disk_size_mb = max_disk_size_mb
        self.default_ttl_seconds = default_ttl_hours * 3600
        
        # Memory cache for fast access
        self.memory_cache: Dict[str, Tuple[SemanticParsingResult, float]] = {}
        self.cache_lock = threading.RLock()
        
        # Database for persistent storage
        self.db_path = self.cache_dir / "semantic_cache.db"
        self._init_database()
        
        # Integration with AODS cache infrastructure
        self.aods_cache = None
        if AODS_CACHE_AVAILABLE:
            try:
                self.aods_cache = AODSCacheManager()
                logger.info("AODS cache integration enabled")
            except Exception as e:
                logger.warning(f"AODS cache integration failed: {e}")
        
        # Statistics tracking
        self.stats = {
            'hits': 0,
            'misses': 0,
            'stores': 0,
            'evictions': 0,
            'errors': 0
        }
        
        logger.info(f"SemanticCacheManager initialized: {cache_dir}, "
                   f"memory_limit={max_memory_entries}, disk_limit={max_disk_size_mb}MB")
    
    def _init_database(self):
        """Initialize the SQLite database for persistent caching."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS semantic_cache (
                        cache_key TEXT PRIMARY KEY,
                        language TEXT NOT NULL,
                        source_hash TEXT NOT NULL,
                        result_data BLOB NOT NULL,
                        created_time REAL NOT NULL,
                        access_time REAL NOT NULL,
                        access_count INTEGER DEFAULT 1,
                        file_size INTEGER NOT NULL
                    )
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_created_time 
                    ON semantic_cache(created_time)
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_language 
                    ON semantic_cache(language)
                """)
                
                conn.commit()
                logger.debug("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def get_cached_result(self, 
                         source_code: str, 
                         language: LanguageType) -> Optional[SemanticParsingResult]:
        """
        Retrieve a cached parsing result.
        
        Args:
            source_code: Source code content
            language: Programming language
            
        Returns:
            Cached parsing result or None if not found
        """
        cache_key = self._generate_cache_key(source_code, language)
        
        with self.cache_lock:
            try:
                # Check memory cache first
                if cache_key in self.memory_cache:
                    result, created_time = self.memory_cache[cache_key]
                    
                    # Check TTL
                    if time.time() - created_time < self.default_ttl_seconds:
                        self.stats['hits'] += 1
                        logger.debug(f"Memory cache hit: {cache_key[:16]}...")
                        return result
                    else:
                        # Expired, remove from memory cache
                        del self.memory_cache[cache_key]
                
                # Check disk cache
                result = self._get_from_disk(cache_key)
                if result:
                    # Add to memory cache for faster access
                    self._add_to_memory_cache(cache_key, result)
                    self.stats['hits'] += 1
                    logger.debug(f"Disk cache hit: {cache_key[:16]}...")
                    return result
                
                # Check AODS cache if available
                if self.aods_cache:
                    aods_result = self.aods_cache.get(cache_key)
                    if aods_result:
                        logger.debug(f"AODS cache hit: {cache_key[:16]}...")
                        self.stats['hits'] += 1
                        return aods_result
                
                # Cache miss
                self.stats['misses'] += 1
                return None
                
            except Exception as e:
                logger.error(f"Cache retrieval error: {e}")
                self.stats['errors'] += 1
                return None
    
    def cache_result(self, 
                    source_code: str, 
                    language: LanguageType, 
                    result: SemanticParsingResult):
        """
        Cache a parsing result.
        
        Args:
            source_code: Source code content
            language: Programming language
            result: Parsing result to cache
        """
        if not result.success:
            return  # Don't cache failed results
        
        cache_key = self._generate_cache_key(source_code, language)
        
        with self.cache_lock:
            try:
                # Add to memory cache
                self._add_to_memory_cache(cache_key, result)
                
                # Add to disk cache
                self._store_to_disk(cache_key, source_code, language, result)
                
                # Add to AODS cache if available
                if self.aods_cache:
                    self.aods_cache.set(cache_key, result)
                
                self.stats['stores'] += 1
                logger.debug(f"Cached result: {cache_key[:16]}...")
                
            except Exception as e:
                logger.error(f"Cache storage error: {e}")
                self.stats['errors'] += 1
    
    def _generate_cache_key(self, source_code: str, language: LanguageType) -> str:
        """
        Generate a unique cache key based on content and language.
        
        Args:
            source_code: Source code content
            language: Programming language
            
        Returns:
            SHA-256 based cache key
        """
        content = f"{language.value}:{source_code}"
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def _add_to_memory_cache(self, cache_key: str, result: SemanticParsingResult):
        """Add result to memory cache with eviction if needed."""
        # Check memory limit and evict if necessary
        if len(self.memory_cache) >= self.max_memory_entries:
            self._evict_memory_cache()
        
        self.memory_cache[cache_key] = (result, time.time())
    
    def _evict_memory_cache(self):
        """Evict least recently used entries from memory cache."""
        if not self.memory_cache:
            return
        
        # Remove 20% of entries (LRU eviction)
        evict_count = max(1, len(self.memory_cache) // 5)
        
        # Sort by creation time and remove oldest
        sorted_items = sorted(
            self.memory_cache.items(), 
            key=lambda x: x[1][1]  # Sort by timestamp
        )
        
        for i in range(evict_count):
            cache_key = sorted_items[i][0]
            del self.memory_cache[cache_key]
            self.stats['evictions'] += 1
        
        logger.debug(f"Evicted {evict_count} entries from memory cache")
    
    def _store_to_disk(self, 
                      cache_key: str, 
                      source_code: str, 
                      language: LanguageType, 
                      result: SemanticParsingResult):
        """Store result to disk cache."""
        try:
            # Serialize result
            result_data = pickle.dumps(result)
            source_hash = hashlib.sha256(source_code.encode('utf-8')).hexdigest()
            current_time = time.time()
            
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO semantic_cache 
                    (cache_key, language, source_hash, result_data, 
                     created_time, access_time, access_count, file_size)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """, (
                    cache_key, language.value, source_hash, result_data,
                    current_time, current_time, len(result_data)
                ))
                conn.commit()
            
            # Check disk size limit
            self._cleanup_disk_cache()
            
        except Exception as e:
            logger.error(f"Disk storage error: {e}")
            raise
    
    def _get_from_disk(self, cache_key: str) -> Optional[SemanticParsingResult]:
        """Retrieve result from disk cache."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute("""
                    SELECT result_data, created_time, access_count 
                    FROM semantic_cache 
                    WHERE cache_key = ?
                """, (cache_key,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                result_data, created_time, access_count = row
                
                # Check TTL
                if time.time() - created_time > self.default_ttl_seconds:
                    # Expired, remove from disk
                    conn.execute("DELETE FROM semantic_cache WHERE cache_key = ?", (cache_key,))
                    conn.commit()
                    return None
                
                # Update access statistics
                conn.execute("""
                    UPDATE semantic_cache 
                    SET access_time = ?, access_count = ?
                    WHERE cache_key = ?
                """, (time.time(), access_count + 1, cache_key))
                conn.commit()
                
                # Deserialize and return result
                return pickle.loads(result_data)
                
        except Exception as e:
            logger.error(f"Disk retrieval error: {e}")
            return None
    
    def _cleanup_disk_cache(self):
        """Clean up disk cache to stay within size limits."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Calculate current cache size
                cursor = conn.execute("SELECT SUM(file_size) FROM semantic_cache")
                total_size = cursor.fetchone()[0] or 0
                
                max_size_bytes = self.max_disk_size_mb * 1024 * 1024
                
                if total_size > max_size_bytes:
                    # Remove oldest entries until under limit
                    cursor = conn.execute("""
                        SELECT cache_key, file_size 
                        FROM semantic_cache 
                        ORDER BY access_time ASC
                    """)
                    
                    removed_size = 0
                    target_removal = total_size - max_size_bytes + (max_size_bytes * 0.1)  # Remove extra 10%
                    
                    for cache_key, file_size in cursor:
                        if removed_size >= target_removal:
                            break
                        
                        conn.execute("DELETE FROM semantic_cache WHERE cache_key = ?", (cache_key,))
                        removed_size += file_size
                        self.stats['evictions'] += 1
                    
                    conn.commit()
                    logger.info(f"Cleaned up disk cache: removed {removed_size / 1024 / 1024:.1f}MB")
                    
        except Exception as e:
            logger.error(f"Disk cleanup error: {e}")
    
    def clear_cache(self):
        """Clear all cached data."""
        with self.cache_lock:
            try:
                # Clear memory cache
                self.memory_cache.clear()
                
                # Clear disk cache
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.execute("DELETE FROM semantic_cache")
                    conn.commit()
                
                # Clear AODS cache if available
                if self.aods_cache:
                    # AODS cache doesn't have a clear method, so we skip this
                    pass
                
                # Reset statistics
                self.stats = {key: 0 for key in self.stats}
                
                logger.info("All caches cleared")
                
            except Exception as e:
                logger.error(f"Cache clearing error: {e}")
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive cache statistics.
        
        Returns:
            Dictionary with cache performance metrics
        """
        with self.cache_lock:
            try:
                # Memory cache stats
                memory_size = len(self.memory_cache)
                
                # Disk cache stats
                with sqlite3.connect(str(self.db_path)) as conn:
                    cursor = conn.execute("""
                        SELECT COUNT(*), SUM(file_size), AVG(access_count)
                        FROM semantic_cache
                    """)
                    disk_count, disk_size, avg_access = cursor.fetchone()
                    
                    cursor = conn.execute("""
                        SELECT language, COUNT(*) 
                        FROM semantic_cache 
                        GROUP BY language
                    """)
                    language_distribution = dict(cursor.fetchall())
                
                # Calculate hit rate
                total_requests = self.stats['hits'] + self.stats['misses']
                hit_rate = self.stats['hits'] / max(1, total_requests)
                
                return {
                    'memory_cache_size': memory_size,
                    'memory_cache_limit': self.max_memory_entries,
                    'disk_cache_entries': disk_count or 0,
                    'disk_cache_size_mb': (disk_size or 0) / 1024 / 1024,
                    'disk_cache_limit_mb': self.max_disk_size_mb,
                    'average_access_count': avg_access or 0,
                    'language_distribution': language_distribution or {},
                    'hit_rate': hit_rate,
                    'total_hits': self.stats['hits'],
                    'total_misses': self.stats['misses'],
                    'total_stores': self.stats['stores'],
                    'total_evictions': self.stats['evictions'],
                    'total_errors': self.stats['errors'],
                    'aods_integration': self.aods_cache is not None
                }
                
            except Exception as e:
                logger.error(f"Statistics error: {e}")
                return {'error': str(e)}
    
    def cleanup_expired_entries(self):
        """Remove expired entries from all caches."""
        with self.cache_lock:
            try:
                current_time = time.time()
                
                # Clean memory cache
                expired_keys = [
                    key for key, (_, created_time) in self.memory_cache.items()
                    if current_time - created_time > self.default_ttl_seconds
                ]
                
                for key in expired_keys:
                    del self.memory_cache[key]
                
                # Clean disk cache
                with sqlite3.connect(str(self.db_path)) as conn:
                    cursor = conn.execute("""
                        DELETE FROM semantic_cache 
                        WHERE created_time < ?
                    """, (current_time - self.default_ttl_seconds,))
                    
                    deleted_count = cursor.rowcount
                    conn.commit()
                
                if expired_keys or deleted_count:
                    logger.info(f"Cleaned up expired entries: "
                               f"{len(expired_keys)} from memory, {deleted_count} from disk")
                
            except Exception as e:
                logger.error(f"Expired entry cleanup error: {e}")
    
    def __del__(self):
        """Cleanup on object destruction."""
        try:
            # Perform final cleanup
            self.cleanup_expired_entries()
        except:
            pass  # Ignore errors during cleanup 
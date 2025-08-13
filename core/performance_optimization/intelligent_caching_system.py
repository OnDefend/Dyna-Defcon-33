"""
Intelligent Caching System for AODS Phase 3
Advanced caching strategies to reduce redundant processing and improve performance
"""

import os
import json
import time
import hashlib
import sqlite3
import logging
import pickle
import zlib
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading
from collections import OrderedDict

logger = logging.getLogger(__name__)

@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    key: str
    value: Any
    created_at: str
    last_accessed: str
    access_count: int
    size_bytes: int
    ttl_seconds: Optional[int]
    tags: List[str]
    compression_ratio: float

@dataclass
class CacheStats:
    """Cache performance statistics."""
    total_requests: int
    cache_hits: int
    cache_misses: int
    hit_ratio: float
    total_size_bytes: int
    entry_count: int
    eviction_count: int
    compression_savings: int

class CacheKeyGenerator:
    """Generate intelligent cache keys for different types of AODS analysis."""
    
    @staticmethod
    def generate_apk_hash(apk_path: str) -> str:
        """Generate hash for APK file."""
        try:
            with open(apk_path, 'rb') as f:
                # Read file in chunks to handle large APKs
                hash_md5 = hashlib.md5()
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
                return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"Failed to generate APK hash: {e}")
            return hashlib.md5(apk_path.encode()).hexdigest()
    
    @staticmethod
    def generate_plugin_key(apk_path: str, plugin_name: str, config: Dict[str, Any] = None) -> str:
        """Generate cache key for plugin analysis results."""
        apk_hash = CacheKeyGenerator.generate_apk_hash(apk_path)
        config_hash = hashlib.md5(json.dumps(config or {}, sort_keys=True).encode()).hexdigest()[:8]
        return f"plugin:{plugin_name}:{apk_hash}:{config_hash}"
    
    @staticmethod
    def generate_ml_key(features: Dict[str, Any], model_version: str) -> str:
        """Generate cache key for ML model predictions."""
        features_hash = hashlib.md5(json.dumps(features, sort_keys=True).encode()).hexdigest()
        return f"ml:{model_version}:{features_hash}"
    
    @staticmethod
    def generate_decompilation_key(apk_path: str, decompiler: str, options: Dict[str, Any] = None) -> str:
        """Generate cache key for decompilation results."""
        apk_hash = CacheKeyGenerator.generate_apk_hash(apk_path)
        options_hash = hashlib.md5(json.dumps(options or {}, sort_keys=True).encode()).hexdigest()[:8]
        return f"decompile:{decompiler}:{apk_hash}:{options_hash}"
    
    @staticmethod
    def generate_signature_key(apk_path: str) -> str:
        """Generate cache key for APK signature analysis."""
        apk_hash = CacheKeyGenerator.generate_apk_hash(apk_path)
        return f"signature:{apk_hash}"

class CompressionManager:
    """Manage data compression for cache entries."""
    
    @staticmethod
    def compress_data(data: Any) -> Tuple[bytes, float]:
        """Compress data and return compressed bytes with compression ratio."""
        try:
            # Serialize data
            serialized = pickle.dumps(data)
            original_size = len(serialized)
            
            # Compress using zlib
            compressed = zlib.compress(serialized, level=6)
            compressed_size = len(compressed)
            
            compression_ratio = compressed_size / original_size if original_size > 0 else 1.0
            
            return compressed, compression_ratio
            
        except Exception as e:
            logger.error(f"Compression failed: {e}")
            # Fallback to uncompressed
            return pickle.dumps(data), 1.0
    
    @staticmethod
    def decompress_data(compressed_data: bytes) -> Any:
        """Decompress data and return original object."""
        try:
            # Decompress
            decompressed = zlib.decompress(compressed_data)
            
            # Deserialize
            return pickle.loads(decompressed)
            
        except Exception as e:
            logger.error(f"Decompression failed: {e}")
            # Try direct deserialization (uncompressed fallback)
            return pickle.loads(compressed_data)

class InMemoryCache:
    """High-performance in-memory cache with LRU eviction."""
    
    def __init__(self, max_size_mb: int = 512, max_entries: int = 10000):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_entries = max_entries
        self.cache = OrderedDict()
        self.stats = CacheStats(0, 0, 0, 0.0, 0, 0, 0, 0)
        self._lock = threading.RLock()
        
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self._lock:
            self.stats.total_requests += 1
            
            if key in self.cache:
                # Move to end (most recently used)
                entry = self.cache.pop(key)
                self.cache[key] = entry
                
                # Update access metadata
                entry.last_accessed = datetime.now().isoformat()
                entry.access_count += 1
                
                self.stats.cache_hits += 1
                self._update_hit_ratio()
                
                return entry.value
            else:
                self.stats.cache_misses += 1
                self._update_hit_ratio()
                return None
    
    def put(self, key: str, value: Any, ttl_seconds: Optional[int] = None, tags: List[str] = None) -> bool:
        """Put value in cache."""
        with self._lock:
            try:
                # Compress the value
                compressed_data, compression_ratio = CompressionManager.compress_data(value)
                entry_size = len(compressed_data)
                
                # Check if entry is too large
                if entry_size > self.max_size_bytes // 2:
                    logger.warning(f"Entry too large for cache: {entry_size} bytes")
                    return False
                
                # Create cache entry
                entry = CacheEntry(
                    key=key,
                    value=compressed_data,
                    created_at=datetime.now().isoformat(),
                    last_accessed=datetime.now().isoformat(),
                    access_count=0,
                    size_bytes=entry_size,
                    ttl_seconds=ttl_seconds,
                    tags=tags or [],
                    compression_ratio=compression_ratio
                )
                
                # Evict if necessary
                self._evict_if_necessary(entry_size)
                
                # Add to cache
                if key in self.cache:
                    # Update existing entry
                    old_entry = self.cache[key]
                    self.stats.total_size_bytes -= old_entry.size_bytes
                
                self.cache[key] = entry
                self.stats.total_size_bytes += entry_size
                self.stats.entry_count = len(self.cache)
                
                # Update compression savings
                original_size = entry_size / compression_ratio
                self.stats.compression_savings += int(original_size - entry_size)
                
                return True
                
            except Exception as e:
                logger.error(f"Failed to cache entry: {e}")
                return False
    
    def _evict_if_necessary(self, new_entry_size: int):
        """Evict entries if necessary to make room."""
        # Check size limit
        while (self.stats.total_size_bytes + new_entry_size > self.max_size_bytes and 
               len(self.cache) > 0):
            self._evict_lru()
        
        # Check entry count limit
        while len(self.cache) >= self.max_entries:
            self._evict_lru()
    
    def _evict_lru(self):
        """Evict least recently used entry."""
        if self.cache:
            key, entry = self.cache.popitem(last=False)  # Remove first (oldest)
            self.stats.total_size_bytes -= entry.size_bytes
            self.stats.eviction_count += 1
            logger.debug(f"Evicted cache entry: {key}")
    
    def _update_hit_ratio(self):
        """Update cache hit ratio."""
        if self.stats.total_requests > 0:
            self.stats.hit_ratio = self.stats.cache_hits / self.stats.total_requests
    
    def invalidate_by_tags(self, tags: List[str]):
        """Invalidate all entries with specified tags."""
        with self._lock:
            keys_to_remove = []
            for key, entry in self.cache.items():
                if any(tag in entry.tags for tag in tags):
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                entry = self.cache.pop(key)
                self.stats.total_size_bytes -= entry.size_bytes
                logger.debug(f"Invalidated cache entry by tag: {key}")
    
    def clear(self):
        """Clear all cache entries."""
        with self._lock:
            self.cache.clear()
            self.stats = CacheStats(0, 0, 0, 0.0, 0, 0, 0, 0)
    
    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        with self._lock:
            self.stats.entry_count = len(self.cache)
            return self.stats

class PersistentCache:
    """Persistent cache using SQLite for long-term storage."""
    
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "cache.db"
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database for persistent cache."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache_entries (
                key TEXT PRIMARY KEY,
                value BLOB,
                created_at TEXT,
                last_accessed TEXT,
                access_count INTEGER,
                size_bytes INTEGER,
                ttl_seconds INTEGER,
                tags TEXT,
                compression_ratio REAL,
                expires_at TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_expires_at ON cache_entries(expires_at)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_tags ON cache_entries(tags)
        ''')
        
        conn.commit()
        conn.close()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from persistent cache."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT value, ttl_seconds, created_at, access_count 
                FROM cache_entries 
                WHERE key = ?
            ''', (key,))
            
            result = cursor.fetchone()
            
            if result:
                value_blob, ttl_seconds, created_at, access_count = result
                
                # Check TTL
                if ttl_seconds:
                    created_time = datetime.fromisoformat(created_at)
                    if datetime.now() > created_time + timedelta(seconds=ttl_seconds):
                        # Entry expired, remove it
                        cursor.execute('DELETE FROM cache_entries WHERE key = ?', (key,))
                        conn.commit()
                        conn.close()
                        return None
                
                # Update access metadata
                cursor.execute('''
                    UPDATE cache_entries 
                    SET last_accessed = ?, access_count = ? 
                    WHERE key = ?
                ''', (datetime.now().isoformat(), access_count + 1, key))
                
                conn.commit()
                conn.close()
                
                # Decompress and return value
                return CompressionManager.decompress_data(value_blob)
            
            conn.close()
            return None
            
        except Exception as e:
            logger.error(f"Failed to get from persistent cache: {e}")
            return None
    
    def put(self, key: str, value: Any, ttl_seconds: Optional[int] = None, tags: List[str] = None) -> bool:
        """Put value in persistent cache."""
        try:
            # Compress the value
            compressed_data, compression_ratio = CompressionManager.compress_data(value)
            
            # Calculate expiration
            expires_at = None
            if ttl_seconds:
                expires_at = (datetime.now() + timedelta(seconds=ttl_seconds)).isoformat()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO cache_entries 
                (key, value, created_at, last_accessed, access_count, size_bytes, 
                 ttl_seconds, tags, compression_ratio, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                key, compressed_data, datetime.now().isoformat(), 
                datetime.now().isoformat(), 0, len(compressed_data),
                ttl_seconds, json.dumps(tags or []), compression_ratio, expires_at
            ))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to put in persistent cache: {e}")
            return False
    
    def cleanup_expired(self) -> int:
        """Clean up expired entries."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM cache_entries 
                WHERE expires_at IS NOT NULL AND expires_at < ?
            ''', (datetime.now().isoformat(),))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} expired cache entries")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired entries: {e}")
            return 0

class IntelligentCachingSystem:
    """Main intelligent caching system with multi-tier caching."""
    
    def __init__(self, base_dir: Path = None):
        self.base_dir = base_dir or Path(".")
        self.cache_dir = self.base_dir / "cache" / "intelligent_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize cache tiers
        self.memory_cache = InMemoryCache(max_size_mb=512, max_entries=10000)
        self.persistent_cache = PersistentCache(self.cache_dir)
        
        # Cache configuration
        self.config = {
            "memory_cache_enabled": True,
            "persistent_cache_enabled": True,
            "default_ttl_seconds": 3600,  # 1 hour
            "apk_analysis_ttl": 7200,     # 2 hours
            "ml_prediction_ttl": 1800,    # 30 minutes
            "decompilation_ttl": 14400,   # 4 hours
            "auto_cleanup_interval": 3600  # 1 hour
        }
        
        # Start background cleanup
        self._start_cleanup_thread()
        
    def get_cached_plugin_result(self, apk_path: str, plugin_name: str, 
                                config: Dict[str, Any] = None) -> Optional[Any]:
        """Get cached plugin analysis result."""
        cache_key = CacheKeyGenerator.generate_plugin_key(apk_path, plugin_name, config)
        
        # Try memory cache first
        if self.config["memory_cache_enabled"]:
            result = self.memory_cache.get(cache_key)
            if result is not None:
                logger.debug(f"Memory cache hit for plugin {plugin_name}")
                return CompressionManager.decompress_data(result)
        
        # Try persistent cache
        if self.config["persistent_cache_enabled"]:
            result = self.persistent_cache.get(cache_key)
            if result is not None:
                logger.debug(f"Persistent cache hit for plugin {plugin_name}")
                # Promote to memory cache
                self.memory_cache.put(
                    cache_key, result, 
                    ttl_seconds=self.config["apk_analysis_ttl"],
                    tags=[f"plugin:{plugin_name}", f"apk:{Path(apk_path).stem}"]
                )
                return result
        
        logger.debug(f"Cache miss for plugin {plugin_name}")
        return None
    
    def cache_plugin_result(self, apk_path: str, plugin_name: str, result: Any, 
                           config: Dict[str, Any] = None) -> bool:
        """Cache plugin analysis result."""
        cache_key = CacheKeyGenerator.generate_plugin_key(apk_path, plugin_name, config)
        tags = [f"plugin:{plugin_name}", f"apk:{Path(apk_path).stem}"]
        
        success = True
        
        # Cache in memory
        if self.config["memory_cache_enabled"]:
            success &= self.memory_cache.put(
                cache_key, result,
                ttl_seconds=self.config["apk_analysis_ttl"],
                tags=tags
            )
        
        # Cache persistently
        if self.config["persistent_cache_enabled"]:
            success &= self.persistent_cache.put(
                cache_key, result,
                ttl_seconds=self.config["apk_analysis_ttl"],
                tags=tags
            )
        
        if success:
            logger.debug(f"Cached result for plugin {plugin_name}")
        
        return success
    
    def get_cached_ml_prediction(self, features: Dict[str, Any], model_version: str) -> Optional[Any]:
        """Get cached ML model prediction."""
        cache_key = CacheKeyGenerator.generate_ml_key(features, model_version)
        
        # Try memory cache first
        if self.config["memory_cache_enabled"]:
            result = self.memory_cache.get(cache_key)
            if result is not None:
                logger.debug(f"Memory cache hit for ML prediction")
                return CompressionManager.decompress_data(result)
        
        # Try persistent cache
        if self.config["persistent_cache_enabled"]:
            result = self.persistent_cache.get(cache_key)
            if result is not None:
                logger.debug(f"Persistent cache hit for ML prediction")
                # Promote to memory cache
                self.memory_cache.put(
                    cache_key, result,
                    ttl_seconds=self.config["ml_prediction_ttl"],
                    tags=[f"ml:{model_version}"]
                )
                return result
        
        return None
    
    def cache_ml_prediction(self, features: Dict[str, Any], model_version: str, 
                           prediction: Any) -> bool:
        """Cache ML model prediction."""
        cache_key = CacheKeyGenerator.generate_ml_key(features, model_version)
        tags = [f"ml:{model_version}"]
        
        success = True
        
        # Cache in memory
        if self.config["memory_cache_enabled"]:
            success &= self.memory_cache.put(
                cache_key, prediction,
                ttl_seconds=self.config["ml_prediction_ttl"],
                tags=tags
            )
        
        # Cache persistently
        if self.config["persistent_cache_enabled"]:
            success &= self.persistent_cache.put(
                cache_key, prediction,
                ttl_seconds=self.config["ml_prediction_ttl"],
                tags=tags
            )
        
        return success
    
    def get_cached_decompilation(self, apk_path: str, decompiler: str, 
                                options: Dict[str, Any] = None) -> Optional[Any]:
        """Get cached decompilation result."""
        cache_key = CacheKeyGenerator.generate_decompilation_key(apk_path, decompiler, options)
        
        # Try memory cache first
        if self.config["memory_cache_enabled"]:
            result = self.memory_cache.get(cache_key)
            if result is not None:
                logger.debug(f"Memory cache hit for decompilation")
                return CompressionManager.decompress_data(result)
        
        # Try persistent cache (decompilation results are large, good for persistent storage)
        if self.config["persistent_cache_enabled"]:
            result = self.persistent_cache.get(cache_key)
            if result is not None:
                logger.debug(f"Persistent cache hit for decompilation")
                return result
        
        return None
    
    def cache_decompilation(self, apk_path: str, decompiler: str, result: Any,
                           options: Dict[str, Any] = None) -> bool:
        """Cache decompilation result."""
        cache_key = CacheKeyGenerator.generate_decompilation_key(apk_path, decompiler, options)
        tags = [f"decompile:{decompiler}", f"apk:{Path(apk_path).stem}"]
        
        # Decompilation results are typically large, so prioritize persistent cache
        success = True
        
        if self.config["persistent_cache_enabled"]:
            success &= self.persistent_cache.put(
                cache_key, result,
                ttl_seconds=self.config["decompilation_ttl"],
                tags=tags
            )
        
        # Only cache in memory if result is reasonably sized
        if self.config["memory_cache_enabled"]:
            try:
                # Estimate size
                test_data, _ = CompressionManager.compress_data(result)
                if len(test_data) < 50 * 1024 * 1024:  # Less than 50MB compressed
                    success &= self.memory_cache.put(
                        cache_key, result,
                        ttl_seconds=self.config["decompilation_ttl"],
                        tags=tags
                    )
            except:
                pass  # Skip memory caching if size estimation fails
        
        return success
    
    def invalidate_apk_cache(self, apk_path: str):
        """Invalidate all cache entries for a specific APK."""
        apk_tag = f"apk:{Path(apk_path).stem}"
        
        self.memory_cache.invalidate_by_tags([apk_tag])
        logger.info(f"Invalidated cache for APK: {Path(apk_path).name}")
    
    def invalidate_plugin_cache(self, plugin_name: str):
        """Invalidate all cache entries for a specific plugin."""
        plugin_tag = f"plugin:{plugin_name}"
        
        self.memory_cache.invalidate_by_tags([plugin_tag])
        logger.info(f"Invalidated cache for plugin: {plugin_name}")
    
    def _start_cleanup_thread(self):
        """Start background thread for cache cleanup."""
        def cleanup_loop():
            while True:
                try:
                    time.sleep(self.config["auto_cleanup_interval"])
                    
                    # Cleanup expired persistent cache entries
                    if self.config["persistent_cache_enabled"]:
                        self.persistent_cache.cleanup_expired()
                    
                except Exception as e:
                    logger.error(f"Cache cleanup error: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
        logger.info("Cache cleanup thread started")
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        memory_stats = self.memory_cache.get_stats()
        
        return {
            "memory_cache": {
                "enabled": self.config["memory_cache_enabled"],
                "total_requests": memory_stats.total_requests,
                "cache_hits": memory_stats.cache_hits,
                "cache_misses": memory_stats.cache_misses,
                "hit_ratio": memory_stats.hit_ratio,
                "total_size_mb": memory_stats.total_size_bytes / (1024 * 1024),
                "entry_count": memory_stats.entry_count,
                "eviction_count": memory_stats.eviction_count,
                "compression_savings_mb": memory_stats.compression_savings / (1024 * 1024)
            },
            "persistent_cache": {
                "enabled": self.config["persistent_cache_enabled"],
                "database_path": str(self.persistent_cache.db_path),
                "database_size_mb": self.persistent_cache.db_path.stat().st_size / (1024 * 1024) 
                                   if self.persistent_cache.db_path.exists() else 0
            },
            "configuration": self.config,
            "cache_effectiveness": {
                "overall_hit_ratio": memory_stats.hit_ratio,
                "performance_impact": "significant" if memory_stats.hit_ratio > 0.3 else "moderate",
                "storage_efficiency": memory_stats.compression_savings / max(memory_stats.total_size_bytes, 1)
            }
        }

# Global intelligent caching system
intelligent_cache = IntelligentCachingSystem()

def get_cached_result(cache_type: str, **kwargs) -> Optional[Any]:
    """Global function to get cached results."""
    if cache_type == "plugin":
        return intelligent_cache.get_cached_plugin_result(
            kwargs["apk_path"], kwargs["plugin_name"], kwargs.get("config")
        )
    elif cache_type == "ml":
        return intelligent_cache.get_cached_ml_prediction(
            kwargs["features"], kwargs["model_version"]
        )
    elif cache_type == "decompilation":
        return intelligent_cache.get_cached_decompilation(
            kwargs["apk_path"], kwargs["decompiler"], kwargs.get("options")
        )
    else:
        return None

def cache_result(cache_type: str, result: Any, **kwargs) -> bool:
    """Global function to cache results."""
    if cache_type == "plugin":
        return intelligent_cache.cache_plugin_result(
            kwargs["apk_path"], kwargs["plugin_name"], result, kwargs.get("config")
        )
    elif cache_type == "ml":
        return intelligent_cache.cache_ml_prediction(
            kwargs["features"], kwargs["model_version"], result
        )
    elif cache_type == "decompilation":
        return intelligent_cache.cache_decompilation(
            kwargs["apk_path"], kwargs["decompiler"], result, kwargs.get("options")
        )
    else:
        return False 
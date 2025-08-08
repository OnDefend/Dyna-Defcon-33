#!/usr/bin/env python3
"""
JADX Decompilation Cache

This module implements intelligent caching for JADX decompilation results with:
- Decompilation result caching with APK fingerprinting (SHA-256 + size + metadata)
- Cache hit rate optimization targeting 70%+ for repeated APK analysis
- Intelligent cache invalidation based on APK changes and analysis updates
- Storage space management with configurable cache size limits (1-10GB)
- Cache sharing between plugins to avoid redundant decompilation
- Performance monitoring and cache effectiveness reporting

"""

import os
import sys
import time
import hashlib
import json
import shutil
import logging
import threading
import zipfile
from typing import Dict, Any, Optional, Tuple, List, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import sqlite3

logger = logging.getLogger(__name__)

@dataclass
class APKFingerprint:
    """APK fingerprint for cache identification."""
    sha256_hash: str
    file_size: int
    package_name: str
    version_code: str
    version_name: str
    min_sdk_version: str
    target_sdk_version: str
    creation_timestamp: datetime
    file_path: str
    
    @property
    def cache_key(self) -> str:
        """Generate unique cache key from fingerprint."""
        return f"{self.sha256_hash}_{self.file_size}_{self.package_name}_{self.version_code}"

@dataclass
class CacheEntry:
    """Cache entry containing decompilation results and metadata."""
    cache_key: str
    apk_fingerprint: APKFingerprint
    decompilation_output_path: str
    cache_creation_time: datetime
    last_access_time: datetime
    access_count: int
    cache_size_bytes: int
    decompilation_time_seconds: float
    plugin_usage_count: Dict[str, int] = field(default_factory=dict)
    invalidated: bool = False
    
    @property
    def age_hours(self) -> float:
        """Age of cache entry in hours."""
        return (datetime.now() - self.cache_creation_time).total_seconds() / 3600
    
    @property
    def size_mb(self) -> float:
        """Cache size in MB."""
        return self.cache_size_bytes / (1024 * 1024)

@dataclass
class CacheStatistics:
    """Cache performance statistics."""
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    cache_invalidations: int = 0
    total_cache_size_bytes: int = 0
    average_decompilation_time_saved: float = 0.0
    hit_rate_percentage: float = 0.0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        if self.total_requests == 0:
            return 0.0
        return (self.cache_hits / self.total_requests) * 100
    
    @property
    def miss_rate(self) -> float:
        """Calculate cache miss rate."""
        return 100.0 - self.hit_rate
    
    @property
    def total_size_mb(self) -> float:
        """Total cache size in MB."""
        return self.total_cache_size_bytes / (1024 * 1024)

class APKFingerprintGenerator:
    """Generates comprehensive APK fingerprints for cache identification."""
    
    def __init__(self):
        """Initialize the fingerprint generator."""
        self._cache = {}
        self._lock = threading.Lock()
    
    def generate_fingerprint(self, apk_path: str) -> APKFingerprint:
        """Generate comprehensive APK fingerprint for caching."""
        apk_path = Path(apk_path).resolve()
        
        with self._lock:
            # Check if already cached
            if str(apk_path) in self._cache:
                return self._cache[str(apk_path)]
            
            # Calculate SHA-256 hash
            sha256_hash = self._calculate_sha256(apk_path)
            
            # Get file size
            file_size = apk_path.stat().st_size
            
            # Extract APK metadata
            metadata = self._extract_apk_metadata(apk_path)
            
            fingerprint = APKFingerprint(
                sha256_hash=sha256_hash,
                file_size=file_size,
                package_name=metadata.get('package_name', 'unknown'),
                version_code=metadata.get('version_code', '0'),
                version_name=metadata.get('version_name', '1.0'),
                min_sdk_version=metadata.get('min_sdk_version', '1'),
                target_sdk_version=metadata.get('target_sdk_version', '28'),
                creation_timestamp=datetime.now(),
                file_path=str(apk_path)
            )
            
            # Cache the fingerprint
            self._cache[str(apk_path)] = fingerprint
            
            logger.debug(f"Generated fingerprint for {apk_path.name}: {fingerprint.cache_key}")
            return fingerprint
    
    def _calculate_sha256(self, apk_path: Path) -> str:
        """Calculate SHA-256 hash of APK file."""
        sha256_hash = hashlib.sha256()
        with open(apk_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _extract_apk_metadata(self, apk_path: Path) -> Dict[str, str]:
        """Extract metadata from APK for fingerprinting."""
        metadata = {}
        
        try:
            # Use aapt2 if available for proper manifest parsing
            import subprocess
            result = subprocess.run([
                'aapt2', 'dump', 'badging', str(apk_path)
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                metadata = self._parse_aapt_output(result.stdout)
            else:
                # Fallback to basic ZIP extraction
                metadata = self._extract_basic_metadata(apk_path)
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fallback to basic ZIP extraction
            metadata = self._extract_basic_metadata(apk_path)
        
        return metadata
    
    def _parse_aapt_output(self, aapt_output: str) -> Dict[str, str]:
        """Parse aapt2 output for APK metadata."""
        metadata = {}
        
        for line in aapt_output.split('\n'):
            if line.startswith('package:'):
                # Extract package info: package: name='com.example' versionCode='1' versionName='1.0'
                parts = line.split()
                for part in parts:
                    if part.startswith('name='):
                        metadata['package_name'] = part.split('=')[1].strip("'\"")
                    elif part.startswith('versionCode='):
                        metadata['version_code'] = part.split('=')[1].strip("'\"")
                    elif part.startswith('versionName='):
                        metadata['version_name'] = part.split('=')[1].strip("'\"")
            elif line.startswith('sdkVersion:'):
                metadata['min_sdk_version'] = line.split(':')[1].strip().strip("'\"")
            elif line.startswith('targetSdkVersion:'):
                metadata['target_sdk_version'] = line.split(':')[1].strip().strip("'\"")
        
        return metadata
    
    def _extract_basic_metadata(self, apk_path: Path) -> Dict[str, str]:
        """Extract basic metadata using ZIP file access.""" 
        metadata = {}
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Try to extract package name from file names
                for filename in apk_zip.namelist():
                    if filename.startswith('META-INF/') and filename.endswith('.SF'):
                        # Try to infer package from signing file
                        package_hint = filename.replace('META-INF/', '').replace('.SF', '')
                        if '.' in package_hint:
                            metadata['package_name'] = package_hint
                            break
                
                # Default values if extraction fails
                metadata.setdefault('package_name', f"unknown_{apk_path.stem}")
                metadata.setdefault('version_code', '1')
                metadata.setdefault('version_name', '1.0')
                metadata.setdefault('min_sdk_version', '21')
                metadata.setdefault('target_sdk_version', '28')
        
        except Exception as e:
            logger.warning(f"Failed to extract APK metadata: {e}")
            # Minimal fallback metadata
            metadata = {
                'package_name': f"unknown_{apk_path.stem}",
                'version_code': '1',
                'version_name': '1.0',
                'min_sdk_version': '21',
                'target_sdk_version': '28'
            }
        
        return metadata

class CacheStorageManager:
    """Manages cache storage, cleanup, and space optimization."""
    
    def __init__(self, cache_dir: str, max_cache_size_gb: float = 5.0):
        """Initialize cache storage manager."""
        self.cache_dir = Path(cache_dir)
        self.max_cache_size_bytes = int(max_cache_size_gb * 1024 * 1024 * 1024)
        self.db_path = self.cache_dir / "cache_metadata.db"
        
        # Create cache directory
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize metadata database
        self._init_database()
        
        logger.info(f"Cache storage initialized: {self.cache_dir} (max {max_cache_size_gb}GB)")
    
    def _init_database(self):
        """Initialize SQLite database for cache metadata."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_entries (
                    cache_key TEXT PRIMARY KEY,
                    apk_fingerprint TEXT NOT NULL,
                    decompilation_output_path TEXT NOT NULL,
                    cache_creation_time TEXT NOT NULL,
                    last_access_time TEXT NOT NULL,
                    access_count INTEGER DEFAULT 0,
                    cache_size_bytes INTEGER NOT NULL,
                    decompilation_time_seconds REAL NOT NULL,
                    plugin_usage_count TEXT DEFAULT '{}',
                    invalidated BOOLEAN DEFAULT FALSE
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_statistics (
                    id INTEGER PRIMARY KEY,
                    total_requests INTEGER DEFAULT 0,
                    cache_hits INTEGER DEFAULT 0,
                    cache_misses INTEGER DEFAULT 0,
                    cache_invalidations INTEGER DEFAULT 0,
                    total_cache_size_bytes INTEGER DEFAULT 0,
                    average_decompilation_time_saved REAL DEFAULT 0.0,
                    last_updated TEXT
                )
            """)
            
            # Insert initial statistics if not exists
            conn.execute("""
                INSERT OR IGNORE INTO cache_statistics (id, last_updated) 
                VALUES (1, ?)
            """, (datetime.now().isoformat(),))
            
            conn.commit()
    
    def store_cache_entry(self, entry: CacheEntry) -> bool:
        """Store cache entry in database and filesystem."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO cache_entries (
                        cache_key, apk_fingerprint, decompilation_output_path,
                        cache_creation_time, last_access_time, access_count,
                        cache_size_bytes, decompilation_time_seconds, plugin_usage_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.cache_key,
                    json.dumps(asdict(entry.apk_fingerprint), default=str),
                    entry.decompilation_output_path,
                    entry.cache_creation_time.isoformat(),
                    entry.last_access_time.isoformat(),
                    entry.access_count,
                    entry.cache_size_bytes,
                    entry.decompilation_time_seconds,
                    json.dumps(entry.plugin_usage_count)
                ))
                conn.commit()
            
            logger.debug(f"Stored cache entry: {entry.cache_key}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store cache entry {entry.cache_key}: {e}")
            return False
    
    def get_cache_entry(self, cache_key: str) -> Optional[CacheEntry]:
        """Retrieve cache entry from database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT * FROM cache_entries WHERE cache_key = ? AND invalidated = FALSE
                """, (cache_key,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Parse the row data
                apk_fingerprint_data = json.loads(row[1])
                apk_fingerprint_data['creation_timestamp'] = datetime.fromisoformat(apk_fingerprint_data['creation_timestamp'])
                apk_fingerprint = APKFingerprint(**apk_fingerprint_data)
                
                entry = CacheEntry(
                    cache_key=row[0],
                    apk_fingerprint=apk_fingerprint,
                    decompilation_output_path=row[2],
                    cache_creation_time=datetime.fromisoformat(row[3]),
                    last_access_time=datetime.fromisoformat(row[4]),
                    access_count=row[5],
                    cache_size_bytes=row[6],
                    decompilation_time_seconds=row[7],
                    plugin_usage_count=json.loads(row[8] or '{}'),
                    invalidated=bool(row[9])
                )
                
                return entry
                
        except Exception as e:
            logger.error(f"Failed to retrieve cache entry {cache_key}: {e}")
            return None
    
    def update_access_stats(self, cache_key: str, plugin_name: str = "unknown"):
        """Update access statistics for cache entry."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get current plugin usage count
                cursor = conn.execute("""
                    SELECT plugin_usage_count FROM cache_entries WHERE cache_key = ?
                """, (cache_key,))
                
                row = cursor.fetchone()
                if row:
                    plugin_usage = json.loads(row[0] or '{}')
                    plugin_usage[plugin_name] = plugin_usage.get(plugin_name, 0) + 1
                    
                    # Update entry
                    conn.execute("""
                        UPDATE cache_entries SET 
                        last_access_time = ?, 
                        access_count = access_count + 1,
                        plugin_usage_count = ?
                        WHERE cache_key = ?
                    """, (datetime.now().isoformat(), json.dumps(plugin_usage), cache_key))
                    
                    conn.commit()
        
        except Exception as e:
            logger.error(f"Failed to update access stats for {cache_key}: {e}")
    
    def cleanup_old_entries(self, max_age_days: int = 30):
        """Clean up old cache entries to manage storage space."""
        cutoff_time = datetime.now() - timedelta(days=max_age_days)
        entries_cleaned = 0
        bytes_freed = 0
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get old entries
                cursor = conn.execute("""
                    SELECT cache_key, decompilation_output_path, cache_size_bytes 
                    FROM cache_entries 
                    WHERE cache_creation_time < ?
                """, (cutoff_time.isoformat(),))
                
                old_entries = cursor.fetchall()
                
                for cache_key, output_path, size_bytes in old_entries:
                    try:
                        # Remove from filesystem
                        if Path(output_path).exists():
                            shutil.rmtree(output_path)
                        
                        # Remove from database
                        conn.execute("DELETE FROM cache_entries WHERE cache_key = ?", (cache_key,))
                        
                        entries_cleaned += 1
                        bytes_freed += size_bytes
                        
                    except Exception as e:
                        logger.warning(f"Failed to clean cache entry {cache_key}: {e}")
                
                conn.commit()
        
        except Exception as e:
            logger.error(f"Failed to cleanup old entries: {e}")
        
        if entries_cleaned > 0:
            logger.info(f"Cleaned {entries_cleaned} old cache entries, freed {bytes_freed / (1024*1024):.1f} MB")
        
        return entries_cleaned, bytes_freed
    
    def enforce_size_limit(self):
        """Enforce cache size limit by removing least recently used entries."""
        current_size = self.get_total_cache_size()
        
        if current_size <= self.max_cache_size_bytes:
            return
        
        entries_removed = 0
        bytes_freed = 0
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get entries ordered by last access (LRU)
                cursor = conn.execute("""
                    SELECT cache_key, decompilation_output_path, cache_size_bytes 
                    FROM cache_entries 
                    ORDER BY last_access_time ASC
                """)
                
                entries = cursor.fetchall()
                
                for cache_key, output_path, size_bytes in entries:
                    if current_size - bytes_freed <= self.max_cache_size_bytes:
                        break
                    
                    try:
                        # Remove from filesystem
                        if Path(output_path).exists():
                            shutil.rmtree(output_path)
                        
                        # Remove from database
                        conn.execute("DELETE FROM cache_entries WHERE cache_key = ?", (cache_key,))
                        
                        entries_removed += 1
                        bytes_freed += size_bytes
                        
                    except Exception as e:
                        logger.warning(f"Failed to remove cache entry {cache_key}: {e}")
                
                conn.commit()
        
        except Exception as e:
            logger.error(f"Failed to enforce size limit: {e}")
        
        if entries_removed > 0:
            logger.info(f"Enforced size limit: removed {entries_removed} entries, freed {bytes_freed / (1024*1024):.1f} MB")
    
    def get_total_cache_size(self) -> int:
        """Get total cache size in bytes."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT SUM(cache_size_bytes) FROM cache_entries WHERE invalidated = FALSE")
                result = cursor.fetchone()
                return result[0] or 0
        except Exception:
            return 0
    
    def get_cache_statistics(self) -> CacheStatistics:
        """Get comprehensive cache statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT * FROM cache_statistics WHERE id = 1")
                row = cursor.fetchone()
                
                if row:
                    stats = CacheStatistics(
                        total_requests=row[1],
                        cache_hits=row[2],
                        cache_misses=row[3],
                        cache_invalidations=row[4],
                        total_cache_size_bytes=row[5],
                        average_decompilation_time_saved=row[6]
                    )
                    stats.hit_rate_percentage = stats.hit_rate
                    return stats
                else:
                    return CacheStatistics()
        
        except Exception as e:
            logger.error(f"Failed to get cache statistics: {e}")
            return CacheStatistics()
    
    def update_statistics(self, hit: bool, time_saved: float = 0.0):
        """Update cache performance statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                if hit:
                    conn.execute("""
                        UPDATE cache_statistics SET 
                        total_requests = total_requests + 1,
                        cache_hits = cache_hits + 1,
                        average_decompilation_time_saved = 
                            (average_decompilation_time_saved * cache_hits + ?) / (cache_hits + 1),
                        total_cache_size_bytes = ?,
                        last_updated = ?
                        WHERE id = 1
                    """, (time_saved, self.get_total_cache_size(), datetime.now().isoformat()))
                else:
                    conn.execute("""
                        UPDATE cache_statistics SET 
                        total_requests = total_requests + 1,
                        cache_misses = cache_misses + 1,
                        total_cache_size_bytes = ?,
                        last_updated = ?
                        WHERE id = 1
                    """, (self.get_total_cache_size(), datetime.now().isoformat()))
                
                conn.commit()
        
        except Exception as e:
            logger.error(f"Failed to update statistics: {e}")

class JADXDecompilationCache:
    """
    Intelligent JADX Decompilation Cache for Task SO.4
    
    Provides comprehensive caching functionality with APK fingerprinting,
    intelligent cache management, and performance monitoring.
    """
    
    def __init__(self, cache_dir: str = "~/.aods_cache/jadx", max_cache_size_gb: float = 5.0):
        """Initialize JADX decompilation cache."""
        self.cache_dir = Path(cache_dir).expanduser()
        self.fingerprint_generator = APKFingerprintGenerator()
        self.storage_manager = CacheStorageManager(str(self.cache_dir), max_cache_size_gb)
        
        # Thread safety
        self._cache_lock = threading.Lock()
        
        # Performance tracking
        self._decompilation_times = {}
        
        logger.info(f"JADX Decompilation Cache initialized: {self.cache_dir}")
    
    def get_cached_decompilation(self, apk_path: str, plugin_name: str = "unknown") -> Optional[str]:
        """
        Get cached decompilation results for APK.
        
        Returns the output directory path if cached, None if cache miss.
        """
        with self._cache_lock:
            try:
                # Generate APK fingerprint
                fingerprint = self.fingerprint_generator.generate_fingerprint(apk_path)
                cache_key = fingerprint.cache_key
                
                # Check cache
                cache_entry = self.storage_manager.get_cache_entry(cache_key)
                
                if cache_entry and Path(cache_entry.decompilation_output_path).exists():
                    # Cache hit - update access stats
                    self.storage_manager.update_access_stats(cache_key, plugin_name)
                    self.storage_manager.update_statistics(hit=True, time_saved=cache_entry.decompilation_time_seconds)
                    
                    logger.info(f"Cache HIT for {Path(apk_path).name} (plugin: {plugin_name})")
                    logger.debug(f"   Cache key: {cache_key}")
                    logger.debug(f"   Output path: {cache_entry.decompilation_output_path}")
                    logger.debug(f"   Age: {cache_entry.age_hours:.1f} hours")
                    logger.debug(f"   Size: {cache_entry.size_mb:.1f} MB")
                    
                    return cache_entry.decompilation_output_path
                else:
                    # Cache miss
                    self.storage_manager.update_statistics(hit=False)
                    
                    logger.info(f"Cache MISS for {Path(apk_path).name} (plugin: {plugin_name})")
                    logger.debug(f"   Cache key: {cache_key}")
                    
                    return None
            
            except Exception as e:
                logger.error(f"Failed to check cache for {apk_path}: {e}")
                self.storage_manager.update_statistics(hit=False)
                return None
    
    def cache_decompilation_results(self, apk_path: str, output_dir: str, decompilation_time: float) -> bool:
        """
        Cache decompilation results for future use.
        
        Args:
            apk_path: Path to the APK file
            output_dir: Path to decompilation output directory
            decompilation_time: Time taken for decompilation in seconds
            
        Returns:
            True if successfully cached, False otherwise
        """
        with self._cache_lock:
            try:
                # Generate APK fingerprint
                fingerprint = self.fingerprint_generator.generate_fingerprint(apk_path)
                cache_key = fingerprint.cache_key
                
                # Calculate cache size
                cache_size = self._calculate_directory_size(output_dir)
                
                # Create cache entry
                cache_entry = CacheEntry(
                    cache_key=cache_key,
                    apk_fingerprint=fingerprint,
                    decompilation_output_path=output_dir,
                    cache_creation_time=datetime.now(),
                    last_access_time=datetime.now(),
                    access_count=1,
                    cache_size_bytes=cache_size,
                    decompilation_time_seconds=decompilation_time
                )
                
                # Store cache entry
                success = self.storage_manager.store_cache_entry(cache_entry)
                
                if success:
                    logger.info(f"Cached decompilation for {Path(apk_path).name}")
                    logger.debug(f"   Cache key: {cache_key}")
                    logger.debug(f"   Output path: {output_dir}")
                    logger.debug(f"   Size: {cache_size / (1024*1024):.1f} MB")
                    logger.debug(f"   Decompilation time: {decompilation_time:.1f}s")
                    
                    # Enforce cache size limits
                    self.storage_manager.enforce_size_limit()
                    
                    return True
                else:
                    logger.error(f"Failed to cache decompilation for {Path(apk_path).name}")
                    return False
            
            except Exception as e:
                logger.error(f"Failed to cache decompilation results for {apk_path}: {e}")
                return False
    
    def invalidate_cache(self, apk_path: str) -> bool:
        """
        Invalidate cache for specific APK.
        
        This is useful when APK changes or analysis updates require fresh decompilation.
        """
        with self._cache_lock:
            try:
                # Generate APK fingerprint
                fingerprint = self.fingerprint_generator.generate_fingerprint(apk_path)
                cache_key = fingerprint.cache_key
                
                # Mark as invalidated in database
                with sqlite3.connect(self.storage_manager.db_path) as conn:
                    conn.execute("""
                        UPDATE cache_entries SET invalidated = TRUE WHERE cache_key = ?
                    """, (cache_key,))
                    conn.commit()
                
                # Update invalidation statistics
                with sqlite3.connect(self.storage_manager.db_path) as conn:
                    conn.execute("""
                        UPDATE cache_statistics SET 
                        cache_invalidations = cache_invalidations + 1,
                        last_updated = ?
                        WHERE id = 1
                    """, (datetime.now().isoformat(),))
                    conn.commit()
                
                logger.info(f"Invalidated cache for {Path(apk_path).name}")
                logger.debug(f"   Cache key: {cache_key}")
                
                return True
            
            except Exception as e:
                logger.error(f"Failed to invalidate cache for {apk_path}: {e}")
                return False
    
    def cleanup_cache(self, max_age_days: int = 30) -> Tuple[int, int]:
        """
        Clean up old cache entries.
        
        Args:
            max_age_days: Maximum age of cache entries in days
            
        Returns:
            Tuple of (entries_cleaned, bytes_freed)
        """
        logger.info(f"Starting cache cleanup (max age: {max_age_days} days)")
        
        entries_cleaned, bytes_freed = self.storage_manager.cleanup_old_entries(max_age_days)
        
        # Also enforce size limits
        self.storage_manager.enforce_size_limit()
        
        logger.info(f"Cache cleanup completed: {entries_cleaned} entries, {bytes_freed / (1024*1024):.1f} MB freed")
        
        return entries_cleaned, bytes_freed
    
    def get_cache_statistics(self) -> CacheStatistics:
        """Get comprehensive cache performance statistics."""
        return self.storage_manager.get_cache_statistics()
    
    def get_cache_report(self) -> Dict[str, Any]:
        """Generate comprehensive cache effectiveness report."""
        stats = self.get_cache_statistics()
        
        report = {
            "cache_performance": {
                "hit_rate_percentage": round(stats.hit_rate, 2),
                "miss_rate_percentage": round(stats.miss_rate, 2),
                "total_requests": stats.total_requests,
                "cache_hits": stats.cache_hits,
                "cache_misses": stats.cache_misses,
                "cache_invalidations": stats.cache_invalidations,
                "target_hit_rate": 70.0,
                "hit_rate_status": "✅ EXCELLENT" if stats.hit_rate >= 70 else "⚠️ NEEDS IMPROVEMENT"
            },
            "storage_utilization": {
                "total_cache_size_mb": round(stats.total_size_mb, 2),
                "max_cache_size_mb": round(self.storage_manager.max_cache_size_bytes / (1024*1024), 2),
                "utilization_percentage": round((stats.total_cache_size_bytes / self.storage_manager.max_cache_size_bytes) * 100, 2),
                "average_cache_size_per_apk_mb": round(stats.total_size_mb / max(stats.cache_hits, 1), 2)
            },
            "performance_impact": {
                "average_time_saved_seconds": round(stats.average_decompilation_time_saved, 2),
                "total_time_saved_seconds": round(stats.average_decompilation_time_saved * stats.cache_hits, 2),
                "decompilation_speed_improvement": "40-significant reduction in repeated analysis time"
            },
            "cache_directory": str(self.cache_dir),
            "last_updated": datetime.now().isoformat()
        }
        
        return report
    
    def _calculate_directory_size(self, directory: str) -> int:
        """Calculate total size of directory in bytes."""
        total_size = 0
        
        try:
            for dirpath, dirnames, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    if os.path.exists(filepath):
                        total_size += os.path.getsize(filepath)
        except Exception as e:
            logger.warning(f"Failed to calculate directory size for {directory}: {e}")
        
        return total_size

#!/usr/bin/env python3
"""
Enhanced Configuration Manager for AODS

Advanced configuration management system providing intelligent configuration
handling, validation, and optimization for Android security analysis.
"""

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional, Union
from functools import lru_cache
import hashlib

class EnhancedConfigManager:
    """
    Enhanced configuration manager with:
    - Thread-safe caching
    - Hot reload capabilities
    - Graceful error handling
    - Edge case management
    - Performance optimization
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Singleton pattern with thread safety"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
            
        self.logger = logging.getLogger(__name__)
        self.config_cache = {}
        self.cache_lock = threading.RLock()
        self.file_timestamps = {}
        self.config_dir = Path(__file__).parent.parent / "config"
        
        # Pattern configuration mappings
        self.pattern_configs = {
            'crypto_patterns': 'crypto_patterns.json',
            'cloud_patterns': 'cloud_service_patterns.json',
            'database_patterns': 'database_patterns.json',
            'vulnerability_patterns': 'vulnerability_patterns.json'
        }
        
        # Default patterns fallback
        self.default_patterns = self._initialize_default_patterns()
        
        # Performance tracking
        self.load_stats = {
            'cache_hits': 0,
            'cache_misses': 0,
            'reload_count': 0,
            'error_count': 0
        }
        
        # Ensure config directory exists
        self._ensure_config_directory()
        
        self._initialized = True
        self.logger.info("Enhanced configuration manager initialized")
    
    def _ensure_config_directory(self):
        """Ensure configuration directory exists with proper permissions"""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            # Set appropriate permissions (readable by owner and group)
            if os.name != 'nt':  # Unix-like systems
                os.chmod(self.config_dir, 0o755)
                
            self.logger.debug(f"Configuration directory ensured: {self.config_dir}")
            
        except Exception as e:
            self.logger.error(f"Failed to create config directory {self.config_dir}: {e}")
            # Continue with default patterns
    
    def _initialize_default_patterns(self) -> Dict[str, Dict]:
        """Initialize minimal default patterns for fallback"""
        return {
            'crypto_patterns': {
                'weak_encryption_algorithms': {
                    'DES': {
                        'patterns': ['DES\\.getInstance\\(', 'Cipher\\.getInstance\\(["\']DES["\']'],
                        'severity': 'CRITICAL',
                        'reason': 'DES encryption is deprecated and vulnerable',
                        'recommendation': 'Use AES-256 encryption instead',
                        'cwe_id': 'CWE-327',
                        'confidence': 0.95
                    }
                }
            },
            'cloud_patterns': {
                'aws': {
                    'access_keys': {
                        'pattern': 'AKIA[0-9A-Z]{16}',
                        'severity': 'CRITICAL',
                        'reason': 'AWS access keys detected',
                        'recommendation': 'Remove hardcoded AWS credentials',
                        'cwe_id': 'CWE-798',
                        'confidence': 0.95
                    }
                }
            },
            'database_patterns': {
                'sensitive_column_patterns': {
                    'authentication_data': {
                        'patterns': ['password', 'secret', 'token', 'key'],
                        'severity': 'HIGH',
                        'reason': 'Sensitive authentication data detected',
                        'recommendation': 'Ensure proper encryption and access controls'
                    }
                }
            }
        }
    
    def load_pattern_config(self, pattern_type: str, force_reload: bool = False) -> Dict[str, Any]:
        """
        Load pattern configuration with caching and error handling
        
        Args:
            pattern_type: Type of pattern configuration to load
            force_reload: Force reload from disk ignoring cache
            
        Returns:
            Dictionary containing pattern configuration
        """
        start_time = time.time()
        
        try:
            # Check if pattern type is valid
            if pattern_type not in self.pattern_configs:
                self.logger.error(f"Unknown pattern type: {pattern_type}")
                self.load_stats['error_count'] += 1
                return self.default_patterns.get(pattern_type, {})
            
            with self.cache_lock:
                # Check cache first (unless force reload)
                if not force_reload and pattern_type in self.config_cache:
                    # Check if file has been modified
                    config_file = self.pattern_configs[pattern_type]
                    config_path = self.config_dir / config_file
                    
                    if self._is_cache_valid(config_path, pattern_type):
                        self.load_stats['cache_hits'] += 1
                        load_time = (time.time() - start_time) * 1000
                        self.logger.debug(f"Cache hit for {pattern_type} ({load_time:.2f}ms)")
                        return self.config_cache[pattern_type]
                
                # Load from file
                self.load_stats['cache_misses'] += 1
                config_data = self._load_config_file(pattern_type)
                
                # Cache the loaded data
                self.config_cache[pattern_type] = config_data
                self._update_file_timestamp(pattern_type)
                
                load_time = (time.time() - start_time) * 1000
                self.logger.debug(f"Loaded {pattern_type} from file ({load_time:.2f}ms)")
                
                return config_data
                
        except Exception as e:
            self.logger.error(f"Error loading pattern config {pattern_type}: {e}")
            self.load_stats['error_count'] += 1
            
            # Return cached version if available
            if pattern_type in self.config_cache:
                self.logger.warning(f"Returning cached version of {pattern_type}")
                return self.config_cache[pattern_type]
            
            # Return default patterns as last resort
            self.logger.warning(f"Returning default patterns for {pattern_type}")
            return self.default_patterns.get(pattern_type, {})
    
    def _is_cache_valid(self, config_path: Path, pattern_type: str) -> bool:
        """Check if cached configuration is still valid"""
        try:
            if not config_path.exists():
                return False
                
            current_mtime = config_path.stat().st_mtime
            cached_mtime = self.file_timestamps.get(pattern_type, 0)
            
            return current_mtime <= cached_mtime
            
        except (OSError, IOError) as e:
            self.logger.warning(f"Error checking file timestamp for {config_path}: {e}")
            return True  # Assume cache is valid if we can't check
    
    def _update_file_timestamp(self, pattern_type: str):
        """Update cached file timestamp"""
        try:
            config_file = self.pattern_configs[pattern_type]
            config_path = self.config_dir / config_file
            
            if config_path.exists():
                self.file_timestamps[pattern_type] = config_path.stat().st_mtime
                
        except (OSError, IOError) as e:
            self.logger.debug(f"Could not update timestamp for {pattern_type}: {e}")
    
    def _load_config_file(self, pattern_type: str) -> Dict[str, Any]:
        """Load configuration file with comprehensive error handling"""
        config_file = self.pattern_configs[pattern_type]
        config_path = self.config_dir / config_file
        
        try:
            # Check file exists and is readable
            if not config_path.exists():
                self.logger.warning(f"Config file not found: {config_path}")
                return self.default_patterns.get(pattern_type, {})
            
            # Check file size (protect against extremely large files)
            file_size = config_path.stat().st_size
            if file_size > 50 * 1024 * 1024:  # 50MB limit
                self.logger.error(f"Config file too large ({file_size} bytes): {config_path}")
                return self.default_patterns.get(pattern_type, {})
            
            # Check file permissions
            if not os.access(config_path, os.R_OK):
                self.logger.error(f"No read permission for config file: {config_path}")
                return self.default_patterns.get(pattern_type, {})
            
            # Read and parse JSON
            with open(config_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                
                # Validate JSON structure
                if not content.strip():
                    self.logger.warning(f"Empty config file: {config_path}")
                    return self.default_patterns.get(pattern_type, {})
                
                try:
                    config_data = json.loads(content)
                except json.JSONDecodeError as json_error:
                    self.logger.error(f"Invalid JSON in {config_path}: {json_error}")
                    
                    # Attempt to recover by removing problematic lines
                    config_data = self._attempt_json_recovery(content, config_path)
                    if not config_data:
                        return self.default_patterns.get(pattern_type, {})
                
                # Validate configuration structure
                validated_config = self._validate_config_structure(config_data, pattern_type)
                
                self.logger.info(f"Successfully loaded {pattern_type} from {config_path}")
                return validated_config
                
        except UnicodeDecodeError as e:
            self.logger.error(f"Encoding error in config file {config_path}: {e}")
            return self.default_patterns.get(pattern_type, {})
            
        except (OSError, IOError) as e:
            self.logger.error(f"File I/O error loading {config_path}: {e}")
            return self.default_patterns.get(pattern_type, {})
            
        except Exception as e:
            self.logger.error(f"Unexpected error loading {config_path}: {e}")
            return self.default_patterns.get(pattern_type, {})
    
    def _attempt_json_recovery(self, content: str, config_path: Path) -> Dict[str, Any]:
        """Attempt to recover from malformed JSON"""
        try:
            self.logger.info(f"Attempting JSON recovery for {config_path}")
            
            # Try to find and fix common JSON issues
            lines = content.split('\n')
            cleaned_lines = []
            
            for line in lines:
                # Skip lines that look like comments
                if line.strip().startswith('//') or line.strip().startswith('#'):
                    continue
                    
                # Remove trailing commas before closing braces/brackets
                line = line.rstrip(',')
                cleaned_lines.append(line)
            
            cleaned_content = '\n'.join(cleaned_lines)
            
            # Try parsing the cleaned content
            recovery_data = json.loads(cleaned_content)
            self.logger.info(f"Successfully recovered JSON for {config_path}")
            return recovery_data
            
        except Exception as recovery_error:
            self.logger.error(f"JSON recovery failed for {config_path}: {recovery_error}")
            return {}
    
    def _validate_config_structure(self, config_data: Dict[str, Any], pattern_type: str) -> Dict[str, Any]:
        """Validate and sanitize configuration structure"""
        if not isinstance(config_data, dict):
            self.logger.error(f"Config data for {pattern_type} is not a dictionary")
            return self.default_patterns.get(pattern_type, {})
        
        validated_config = {}
        
        # Basic validation - ensure required fields exist
        for category, category_data in config_data.items():
            if isinstance(category_data, dict):
                validated_category = {}
                
                for item_name, item_data in category_data.items():
                    if isinstance(item_data, dict):
                        # Validate required fields based on pattern type
                        if self._validate_pattern_item(item_data, pattern_type):
                            validated_category[item_name] = item_data
                        else:
                            self.logger.warning(f"Invalid pattern item {item_name} in {category}")
                    else:
                        validated_category[item_name] = item_data
                
                if validated_category:
                    validated_config[category] = validated_category
            else:
                validated_config[category] = category_data
        
        return validated_config
    
    def _validate_pattern_item(self, item_data: Dict[str, Any], pattern_type: str) -> bool:
        """Validate individual pattern item structure"""
        required_fields = {
            'crypto_patterns': ['patterns', 'severity', 'reason'],
            'cloud_patterns': ['pattern', 'severity', 'reason'],
            'database_patterns': ['severity', 'reason']
        }
        
        required = required_fields.get(pattern_type, [])
        
        for field in required:
            if field not in item_data:
                return False
                
        # Validate severity levels
        valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO']
        severity = item_data.get('severity', '').upper()
        if severity not in valid_severities:
            return False
            
        return True
    
    def reload_pattern_config(self, pattern_type: str) -> Dict[str, Any]:
        """Force reload of pattern configuration"""
        self.logger.info(f"Force reloading configuration for {pattern_type}")
        self.load_stats['reload_count'] += 1
        
        with self.cache_lock:
            # Clear cached data
            if pattern_type in self.config_cache:
                del self.config_cache[pattern_type]
            if pattern_type in self.file_timestamps:
                del self.file_timestamps[pattern_type]
        
        return self.load_pattern_config(pattern_type, force_reload=True)
    
    def reload_all_configs(self) -> Dict[str, Dict[str, Any]]:
        """Reload all pattern configurations"""
        self.logger.info("Reloading all pattern configurations")
        
        reloaded_configs = {}
        for pattern_type in self.pattern_configs.keys():
            reloaded_configs[pattern_type] = self.reload_pattern_config(pattern_type)
        
        return reloaded_configs
    
    def clear_cache(self):
        """Clear all cached configurations"""
        with self.cache_lock:
            self.config_cache.clear()
            self.file_timestamps.clear()
            self.load_stats['cache_hits'] = 0
            self.load_stats['cache_misses'] = 0
        
        self.logger.info("Configuration cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics"""
        with self.cache_lock:
            total_requests = self.load_stats['cache_hits'] + self.load_stats['cache_misses']
            hit_rate = (self.load_stats['cache_hits'] / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'cache_hits': self.load_stats['cache_hits'],
                'cache_misses': self.load_stats['cache_misses'],
                'hit_rate_percent': round(hit_rate, 2),
                'reload_count': self.load_stats['reload_count'],
                'error_count': self.load_stats['error_count'],
                'cached_configs': list(self.config_cache.keys())
            }
    
    def validate_config_files(self) -> Dict[str, bool]:
        """Validate all configuration files without loading them into cache"""
        validation_results = {}
        
        for pattern_type, config_file in self.pattern_configs.items():
            config_path = self.config_dir / config_file
            
            try:
                if not config_path.exists():
                    validation_results[pattern_type] = False
                    continue
                
                with open(config_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    json.loads(content)  # Just validate JSON syntax
                    
                validation_results[pattern_type] = True
                
            except Exception as e:
                self.logger.error(f"Validation failed for {pattern_type}: {e}")
                validation_results[pattern_type] = False
        
        return validation_results
    
    @lru_cache(maxsize=128)
    def get_config_hash(self, pattern_type: str) -> str:
        """Get hash of configuration for change detection"""
        try:
            config_file = self.pattern_configs.get(pattern_type)
            if not config_file:
                return ""
                
            config_path = self.config_dir / config_file
            if not config_path.exists():
                return ""
            
            with open(config_path, 'rb') as f:
                content = f.read()
                return hashlib.md5(content).hexdigest()
                
        except Exception as e:
            self.logger.debug(f"Error calculating config hash for {pattern_type}: {e}")
            return ""
    
    def __str__(self) -> str:
        """String representation for debugging"""
        stats = self.get_cache_stats()
        return f"EnhancedConfigManager(cached_configs={len(stats['cached_configs'])}, hit_rate={stats['hit_rate_percent']}%)"
    
    def __repr__(self) -> str:
        return self.__str__()

# Global instance for easy access
config_manager = EnhancedConfigManager()

# Convenience functions
def load_crypto_patterns() -> Dict[str, Any]:
    """Load cryptographic vulnerability patterns"""
    return config_manager.load_pattern_config('crypto_patterns')

def load_cloud_patterns() -> Dict[str, Any]:
    """Load cloud service patterns"""
    return config_manager.load_pattern_config('cloud_patterns')

def load_database_patterns() -> Dict[str, Any]:
    """Load database security patterns"""
    return config_manager.load_pattern_config('database_patterns')

def reload_all_patterns() -> Dict[str, Dict[str, Any]]:
    """Reload all pattern configurations"""
    return config_manager.reload_all_configs()

if __name__ == "__main__":
    # Test the configuration manager
    import sys
    
    logging.basicConfig(level=logging.DEBUG)
    
    manager = EnhancedConfigManager()
    
    print("Testing configuration manager...")
    
    # Test loading patterns
    crypto_patterns = manager.load_pattern_config('crypto_patterns')
    print(f"Loaded crypto patterns: {len(crypto_patterns)} categories")
    
    cloud_patterns = manager.load_pattern_config('cloud_patterns')
    print(f"Loaded cloud patterns: {len(cloud_patterns)} services")
    
    db_patterns = manager.load_pattern_config('database_patterns')
    print(f"Loaded database patterns: {len(db_patterns)} categories")
    
    # Test cache performance
    print("\nCache performance test...")
    start_time = time.time()
    for _ in range(100):
        manager.load_pattern_config('crypto_patterns')
    cache_time = time.time() - start_time
    print(f"100 cached loads took {cache_time:.4f} seconds")
    
    # Print statistics
    stats = manager.get_cache_stats()
    print(f"\nCache statistics: {stats}")
    
    # Validate configurations
    validation = manager.validate_config_files()
    print(f"\nConfiguration validation: {validation}")
    
    print("\nConfiguration manager test completed successfully!") 
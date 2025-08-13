#!/usr/bin/env python3
"""
Multi-Format Configuration Loader for AODS Shared Infrastructure

Provides comprehensive configuration loading capabilities supporting multiple
formats, validation, hot-reload, and intelligent merging of configuration sources.

Features:
- Multi-format support (YAML, JSON, TOML, INI)
- Configuration validation and schema checking
- Hot-reload capabilities with file watching
- Environment variable interpolation
- Configuration merging and inheritance
- Caching for performance optimization
- Error handling with detailed reporting
- Plugin-specific configuration loading
- Security pattern loading and validation

This component serves as the central configuration loading system for all
AODS components, providing consistent and reliable configuration management.
"""

import os
import json
import logging
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
import time
import threading

# Optional imports for extended format support
try:
    import toml
    TOML_AVAILABLE = True
except ImportError:
    TOML_AVAILABLE = False
    toml = None

try:
    import configparser
    INI_AVAILABLE = True
except ImportError:
    INI_AVAILABLE = False
    configparser = None

from .system_detection import get_system_detector
from ..analysis_exceptions import ConfigurationError

logger = logging.getLogger(__name__)

class ConfigFormat(Enum):
    """Supported configuration formats."""
    YAML = "yaml"
    JSON = "json"
    TOML = "toml"
    INI = "ini"
    AUTO = "auto"

class ConfigMergeStrategy(Enum):
    """Configuration merging strategies."""
    REPLACE = "replace"      # Replace values completely
    MERGE = "merge"          # Merge dictionaries, replace lists
    APPEND = "append"        # Append to lists, merge dictionaries
    DEEP_MERGE = "deep_merge"  # Deep merge all structures

@dataclass
class ConfigSource:
    """Configuration source definition."""
    path: Path
    format: ConfigFormat
    priority: int = 0
    required: bool = True
    watch: bool = True
    environment_specific: bool = False
    
    def __post_init__(self):
        """Validate configuration source."""
        if self.format == ConfigFormat.AUTO:
            self.format = self._detect_format()
    
    def _detect_format(self) -> ConfigFormat:
        """Auto-detect configuration format from file extension."""
        suffix = self.path.suffix.lower()
        if suffix in ['.yaml', '.yml']:
            return ConfigFormat.YAML
        elif suffix == '.json':
            return ConfigFormat.JSON
        elif suffix == '.toml':
            return ConfigFormat.TOML
        elif suffix in ['.ini', '.cfg']:
            return ConfigFormat.INI
        else:
            return ConfigFormat.YAML  # Default fallback

@dataclass
class LoadedConfiguration:
    """Container for loaded configuration data."""
    data: Dict[str, Any]
    sources: List[ConfigSource]
    load_time: float
    validation_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def is_valid(self) -> bool:
        """Check if configuration is valid."""
        return len(self.validation_errors) == 0
    
    def get_nested(self, key_path: str, default: Any = None) -> Any:
        """Get nested configuration value using dot notation."""
        keys = key_path.split('.')
        current = self.data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        
        return current
    
    def set_nested(self, key_path: str, value: Any) -> None:
        """Set nested configuration value using dot notation."""
        keys = key_path.split('.')
        current = self.data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value

class ConfigurationLoader:
    """
    Multi-format configuration loader with validation and hot-reload.
    
    Provides centralized configuration loading for all AODS components
    with support for multiple formats, validation, and real-time updates.
    """
    
    def __init__(self, 
                 base_path: Optional[Path] = None,
                 enable_hot_reload: bool = True,
                 enable_caching: bool = True,
                 cache_ttl: float = 300.0):
        """
        Initialize configuration loader.
        
        Args:
            base_path: Base directory for configuration files
            enable_hot_reload: Enable file watching and hot reload
            enable_caching: Enable configuration caching
            cache_ttl: Cache time-to-live in seconds
        """
        self.base_path = base_path or Path.cwd() / 'config'
        self.enable_hot_reload = enable_hot_reload
        self.enable_caching = enable_caching
        self.cache_ttl = cache_ttl
        
        # Configuration cache
        self._cache: Dict[str, LoadedConfiguration] = {}
        self._cache_timestamps: Dict[str, float] = {}
        
        # File watching and reload
        self._watched_sources: Dict[str, List[ConfigSource]] = {}
        self._reload_callbacks: Dict[str, List[Callable]] = {}
        self._reload_lock = threading.RLock()
        
        # Environment variable pattern
        self._env_var_pattern = re.compile(r'\$\{([^}]+)\}')
        
        # Format loaders
        self._format_loaders = {
            ConfigFormat.YAML: self._load_yaml,
            ConfigFormat.JSON: self._load_json,
            ConfigFormat.TOML: self._load_toml,
            ConfigFormat.INI: self._load_ini
        }
        
        # Merge strategies
        self._merge_strategies = {
            ConfigMergeStrategy.REPLACE: self._merge_replace,
            ConfigMergeStrategy.MERGE: self._merge_standard,
            ConfigMergeStrategy.APPEND: self._merge_append,
            ConfigMergeStrategy.DEEP_MERGE: self._merge_deep
        }
        
        logger.info(f"Configuration loader initialized - base_path: {self.base_path}")
    
    def load_configuration(self, 
                          sources: List[Union[str, Path, ConfigSource]],
                          merge_strategy: ConfigMergeStrategy = ConfigMergeStrategy.DEEP_MERGE,
                          environment: Optional[str] = None,
                          validate_schema: bool = True) -> LoadedConfiguration:
        """
        Load configuration from multiple sources.
        
        Args:
            sources: List of configuration sources
            merge_strategy: Strategy for merging multiple sources
            environment: Environment name for environment-specific configs
            validate_schema: Whether to validate configuration schema
            
        Returns:
            LoadedConfiguration with merged data
        """
        # Normalize sources
        config_sources = self._normalize_sources(sources)
        
        # Generate cache key
        cache_key = self._generate_cache_key(config_sources, merge_strategy, environment)
        
        # Check cache
        if self.enable_caching and self._is_cached(cache_key):
            logger.debug(f"Loading configuration from cache: {cache_key}")
            return self._get_cached(cache_key)
        
        try:
            # Load individual configurations
            loaded_configs = []
            for source in config_sources:
                config_data = self._load_single_source(source, environment)
                if config_data is not None:
                    loaded_configs.append((source, config_data))
            
            if not loaded_configs:
                raise ConfigurationError("No valid configuration sources found")
            
            # Merge configurations
            merged_data = self._merge_configurations(loaded_configs, merge_strategy)
            
            # Environment variable interpolation
            merged_data = self._interpolate_environment_variables(merged_data)
            
            # Create loaded configuration
            loaded_config = LoadedConfiguration(
                data=merged_data,
                sources=config_sources,
                load_time=time.time()
            )
            
            # Validation
            if validate_schema:
                self._validate_configuration(loaded_config)
            
            # Cache result
            if self.enable_caching:
                self._cache_configuration(cache_key, loaded_config)
            
            # Set up file watching
            if self.enable_hot_reload:
                self._setup_file_watching(cache_key, config_sources)
            
            logger.info(f"Configuration loaded successfully from {len(config_sources)} sources")
            return loaded_config
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise ConfigurationError(f"Configuration loading failed: {e}")
    
    def load_plugin_configuration(self, 
                                 plugin_name: str,
                                 additional_sources: Optional[List[Union[str, Path]]] = None) -> LoadedConfiguration:
        """
        Load configuration for a specific plugin.
        
        Args:
            plugin_name: Name of the plugin
            additional_sources: Additional configuration sources
            
        Returns:
            LoadedConfiguration for the plugin
        """
        sources = []
        
        # Standard plugin configuration paths
        standard_paths = [
            self.base_path / 'plugins' / f'{plugin_name}.yaml',
            self.base_path / 'plugins' / f'{plugin_name}.yml',
            self.base_path / 'plugins' / f'{plugin_name}.json',
            Path(f'plugins/{plugin_name}/config.yaml'),
            Path(f'plugins/{plugin_name}/config.yml'),
            Path(f'plugins/{plugin_name}/config.json')
        ]
        
        # Add existing paths as sources
        for path in standard_paths:
            if path.exists():
                sources.append(ConfigSource(
                    path=path,
                    format=ConfigFormat.AUTO,
                    priority=1,
                    required=False
                ))
        
        # Add additional sources
        if additional_sources:
            for source in additional_sources:
                if isinstance(source, (str, Path)):
                    source_path = Path(source)
                    if source_path.exists():
                        sources.append(ConfigSource(
                            path=source_path,
                            format=ConfigFormat.AUTO,
                            priority=2
                        ))
        
        if not sources:
            logger.warning(f"No configuration found for plugin: {plugin_name}")
            return LoadedConfiguration(
                data={},
                sources=[],
                load_time=time.time()
            )
        
        return self.load_configuration(sources)
    
    def load_security_patterns(self, 
                              pattern_files: List[Union[str, Path]],
                              pattern_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Load security patterns from configuration files.
        
        Args:
            pattern_files: List of pattern configuration files
            pattern_type: Type of patterns to load (optional filter)
            
        Returns:
            Dictionary of loaded security patterns
        """
        all_patterns = {}
        
        for pattern_file in pattern_files:
            try:
                pattern_path = Path(pattern_file)
                if not pattern_path.exists():
                    logger.warning(f"Pattern file not found: {pattern_path}")
                    continue
                
                # Load pattern configuration
                config = self.load_configuration([
                    ConfigSource(
                        path=pattern_path,
                        format=ConfigFormat.AUTO,
                        required=False
                    )
                ])
                
                # Extract patterns
                patterns = config.data
                
                # Filter by pattern type if specified
                if pattern_type and pattern_type in patterns:
                    patterns = {pattern_type: patterns[pattern_type]}
                
                # Merge patterns
                all_patterns = self._merge_deep(all_patterns, patterns)
                
                logger.debug(f"Loaded patterns from: {pattern_path}")
                
            except Exception as e:
                logger.error(f"Failed to load patterns from {pattern_file}: {e}")
                continue
        
        return all_patterns
    
    def register_reload_callback(self, 
                               cache_key: str, 
                               callback: Callable[[LoadedConfiguration], None]) -> None:
        """Register callback for configuration reload events."""
        with self._reload_lock:
            if cache_key not in self._reload_callbacks:
                self._reload_callbacks[cache_key] = []
            self._reload_callbacks[cache_key].append(callback)
    
    def reload_configuration(self, cache_key: str) -> Optional[LoadedConfiguration]:
        """Manually reload configuration."""
        with self._reload_lock:
            if cache_key not in self._watched_sources:
                logger.warning(f"No watched sources for cache key: {cache_key}")
                return None
            
            try:
                # Clear cache
                if cache_key in self._cache:
                    del self._cache[cache_key]
                if cache_key in self._cache_timestamps:
                    del self._cache_timestamps[cache_key]
                
                # Reload configuration
                sources = self._watched_sources[cache_key]
                config = self.load_configuration(sources)
                
                # Trigger callbacks
                callbacks = self._reload_callbacks.get(cache_key, [])
                for callback in callbacks:
                    try:
                        callback(config)
                    except Exception as e:
                        logger.error(f"Error in reload callback: {e}")
                
                logger.info(f"Configuration reloaded: {cache_key}")
                return config
                
            except Exception as e:
                logger.error(f"Failed to reload configuration {cache_key}: {e}")
                return None
    
    def _normalize_sources(self, sources: List[Union[str, Path, ConfigSource]]) -> List[ConfigSource]:
        """Normalize configuration sources."""
        normalized = []
        
        for i, source in enumerate(sources):
            if isinstance(source, ConfigSource):
                normalized.append(source)
            elif isinstance(source, (str, Path)):
                source_path = Path(source)
                
                # Make relative paths relative to base_path
                if not source_path.is_absolute():
                    source_path = self.base_path / source_path
                
                normalized.append(ConfigSource(
                    path=source_path,
                    format=ConfigFormat.AUTO,
                    priority=i,
                    required=True
                ))
            else:
                logger.warning(f"Invalid configuration source type: {type(source)}")
        
        # Sort by priority
        normalized.sort(key=lambda x: x.priority)
        return normalized
    
    def _load_single_source(self, source: ConfigSource, environment: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Load configuration from a single source."""
        try:
            if not source.path.exists():
                if source.required:
                    raise ConfigurationError(f"Required configuration file not found: {source.path}")
                else:
                    logger.debug(f"Optional configuration file not found: {source.path}")
                    return None
            
            # Check for environment-specific variant
            if environment and source.environment_specific:
                env_path = source.path.parent / f"{source.path.stem}.{environment}{source.path.suffix}"
                if env_path.exists():
                    logger.debug(f"Using environment-specific config: {env_path}")
                    source = ConfigSource(
                        path=env_path,
                        format=source.format,
                        priority=source.priority,
                        required=source.required
                    )
            
            # Load configuration data
            loader = self._format_loaders.get(source.format)
            if not loader:
                raise ConfigurationError(f"Unsupported configuration format: {source.format}")
            
            data = loader(source.path)
            
            logger.debug(f"Loaded configuration from: {source.path}")
            return data
            
        except Exception as e:
            if source.required:
                raise ConfigurationError(f"Failed to load required configuration {source.path}: {e}")
            else:
                logger.warning(f"Failed to load optional configuration {source.path}: {e}")
                return None
    
    def _load_yaml(self, path: Path) -> Dict[str, Any]:
        """Load YAML configuration file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in {path}: {e}")
    
    def _load_json(self, path: Path) -> Dict[str, Any]:
        """Load JSON configuration file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f) or {}
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in {path}: {e}")
    
    def _load_toml(self, path: Path) -> Dict[str, Any]:
        """Load TOML configuration file."""
        if not TOML_AVAILABLE:
            raise ConfigurationError("TOML support not available (install 'toml' package)")
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return toml.load(f) or {}
        except Exception as e:
            raise ConfigurationError(f"Invalid TOML in {path}: {e}")
    
    def _load_ini(self, path: Path) -> Dict[str, Any]:
        """Load INI configuration file."""
        if not INI_AVAILABLE:
            raise ConfigurationError("INI support not available")
        
        try:
            config = configparser.ConfigParser()
            config.read(path)
            
            # Convert to nested dictionary
            result = {}
            for section_name in config.sections():
                result[section_name] = dict(config[section_name])
            
            return result
        except Exception as e:
            raise ConfigurationError(f"Invalid INI in {path}: {e}")
    
    def _merge_configurations(self, 
                            loaded_configs: List[Tuple[ConfigSource, Dict[str, Any]]], 
                            strategy: ConfigMergeStrategy) -> Dict[str, Any]:
        """Merge multiple configurations using specified strategy."""
        if not loaded_configs:
            return {}
        
        # Start with the first configuration
        merged = loaded_configs[0][1].copy()
        
        # Merge remaining configurations
        merge_func = self._merge_strategies[strategy]
        for source, config_data in loaded_configs[1:]:
            merged = merge_func(merged, config_data)
        
        return merged
    
    def _merge_replace(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """Replace merge strategy - overlay replaces base completely."""
        result = base.copy()
        result.update(overlay)
        return result
    
    def _merge_standard(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """Standard merge strategy - merge dicts, replace lists."""
        result = base.copy()
        
        for key, value in overlay.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_standard(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _merge_append(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """Append merge strategy - append lists, merge dicts."""
        result = base.copy()
        
        for key, value in overlay.items():
            if key in result:
                if isinstance(result[key], list) and isinstance(value, list):
                    result[key] = result[key] + value
                elif isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = self._merge_append(result[key], value)
                else:
                    result[key] = value
            else:
                result[key] = value
        
        return result
    
    def _merge_deep(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge strategy - recursively merge all structures."""
        result = base.copy()
        
        for key, value in overlay.items():
            if key in result:
                if isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = self._merge_deep(result[key], value)
                elif isinstance(result[key], list) and isinstance(value, list):
                    # For lists, extend with unique items
                    for item in value:
                        if item not in result[key]:
                            result[key].append(item)
                else:
                    result[key] = value
            else:
                result[key] = value
        
        return result
    
    def _interpolate_environment_variables(self, data: Any) -> Any:
        """Recursively interpolate environment variables in configuration."""
        if isinstance(data, dict):
            return {key: self._interpolate_environment_variables(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self._interpolate_environment_variables(item) for item in data]
        elif isinstance(data, str):
            return self._env_var_pattern.sub(self._replace_env_var, data)
        else:
            return data
    
    def _replace_env_var(self, match) -> str:
        """Replace environment variable with its value."""
        var_name = match.group(1)
        
        # Support default values: ${VAR_NAME:default_value}
        if ':' in var_name:
            var_name, default_value = var_name.split(':', 1)
        else:
            default_value = None
        
        # Get environment variable value
        value = os.environ.get(var_name)
        
        if value is None:
            if default_value is not None:
                return default_value
            else:
                logger.warning(f"Environment variable not found: {var_name}")
                return match.group(0)  # Return original if not found
        
        return value
    
    def _validate_configuration(self, config: LoadedConfiguration) -> None:
        """Validate loaded configuration."""
        try:
            # Basic validation
            if not isinstance(config.data, dict):
                config.validation_errors.append("Configuration root must be a dictionary")
                return
            
            # Plugin-specific validation
            if 'plugin_name' in config.data:
                self._validate_plugin_configuration(config)
            
            # Pattern validation
            if any(key.endswith('_patterns') for key in config.data.keys()):
                self._validate_pattern_configuration(config)
            
        except Exception as e:
            config.validation_errors.append(f"Validation error: {e}")
    
    def _validate_plugin_configuration(self, config: LoadedConfiguration) -> None:
        """Validate plugin-specific configuration."""
        required_fields = ['plugin_name', 'version']
        
        for field in required_fields:
            if field not in config.data:
                config.validation_errors.append(f"Missing required field: {field}")
    
    def _validate_pattern_configuration(self, config: LoadedConfiguration) -> None:
        """Validate security pattern configuration."""
        for key, patterns in config.data.items():
            if not key.endswith('_patterns'):
                continue
            
            if not isinstance(patterns, (dict, list)):
                config.validation_errors.append(f"Invalid pattern format for {key}")
                continue
            
            # Validate individual patterns
            pattern_list = patterns if isinstance(patterns, list) else patterns.values()
            for i, pattern in enumerate(pattern_list):
                if isinstance(pattern, dict):
                    if 'pattern' not in pattern:
                        config.validation_errors.append(f"Pattern {i} in {key} missing 'pattern' field")
                    if 'name' not in pattern:
                        config.warnings.append(f"Pattern {i} in {key} missing 'name' field")
    
    def _generate_cache_key(self, 
                          sources: List[ConfigSource], 
                          merge_strategy: ConfigMergeStrategy,
                          environment: Optional[str]) -> str:
        """Generate cache key for configuration."""
        source_paths = [str(source.path) for source in sources]
        key_parts = [
            ','.join(sorted(source_paths)),
            merge_strategy.value,
            environment or 'default'
        ]
        return '|'.join(key_parts)
    
    def _is_cached(self, cache_key: str) -> bool:
        """Check if configuration is cached and not expired."""
        if cache_key not in self._cache:
            return False
        
        timestamp = self._cache_timestamps.get(cache_key, 0)
        return time.time() - timestamp < self.cache_ttl
    
    def _get_cached(self, cache_key: str) -> LoadedConfiguration:
        """Get cached configuration."""
        return self._cache[cache_key]
    
    def _cache_configuration(self, cache_key: str, config: LoadedConfiguration) -> None:
        """Cache configuration."""
        self._cache[cache_key] = config
        self._cache_timestamps[cache_key] = time.time()
    
    def _setup_file_watching(self, cache_key: str, sources: List[ConfigSource]) -> None:
        """Set up file watching for hot reload."""
        # Store sources for reload
        self._watched_sources[cache_key] = sources
        
        # Note: Actual file watching implementation would require
        # integration with the hot reload manager from config_management

# Global configuration loader instance
_config_loader = None

def get_config_loader() -> ConfigurationLoader:
    """Get global configuration loader instance."""
    global _config_loader
    if _config_loader is None:
        _config_loader = ConfigurationLoader()
    return _config_loader

def load_configuration(sources: List[Union[str, Path, ConfigSource]], **kwargs) -> LoadedConfiguration:
    """Load configuration using global loader."""
    return get_config_loader().load_configuration(sources, **kwargs)

def load_plugin_configuration(plugin_name: str, **kwargs) -> LoadedConfiguration:
    """Load plugin configuration using global loader."""
    return get_config_loader().load_plugin_configuration(plugin_name, **kwargs) 
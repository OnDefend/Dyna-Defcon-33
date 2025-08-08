#!/usr/bin/env python3
"""
Configuration Management for Modular Pattern Engine

Handles loading, validation, and management of YAML configuration files.
Provides centralized configuration access with validation and defaults.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from ..models import PatternEngineConfig, PatternSourceConfig

class ConfigurationError(Exception):
    """Exception raised for configuration-related errors."""
    pass

@dataclass
class ConfigPaths:
    """Configuration file paths."""
    engine_config: str = "default_engine_config.yaml"
    template_config: str = "pattern_source_templates.yaml"
    custom_config: Optional[str] = None

class ConfigManager:
    """
    Centralized configuration manager for the pattern engine.
    
    Loads and validates YAML configurations, provides typed access to settings,
    and supports configuration overlays and environment-specific overrides.
    """
    
    def __init__(self, config_dir: Optional[str] = None, custom_config: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_dir: Directory containing configuration files
            custom_config: Path to custom configuration file for overrides
        """
        self.logger = logging.getLogger(__name__)
        
        # Set default config directory
        if config_dir is None:
            config_dir = Path(__file__).parent
        self.config_dir = Path(config_dir)
        
        # Configuration file paths
        self.paths = ConfigPaths(
            engine_config=str(self.config_dir / "default_engine_config.yaml"),
            template_config=str(self.config_dir / "pattern_source_templates.yaml"),
            custom_config=custom_config
        )
        
        # Loaded configurations
        self._engine_config: Optional[Dict[str, Any]] = None
        self._template_config: Optional[Dict[str, Any]] = None
        self._merged_config: Optional[Dict[str, Any]] = None
        
        # Load configurations
        self._load_configurations()
    
    def _load_configurations(self):
        """Load all configuration files."""
        try:
            # Load main engine configuration
            self._engine_config = self._load_yaml_file(self.paths.engine_config)
            self.logger.info(f"Loaded engine configuration from {self.paths.engine_config}")
            
            # Load template configuration
            self._template_config = self._load_yaml_file(self.paths.template_config)
            self.logger.info(f"Loaded template configuration from {self.paths.template_config}")
            
            # Load custom configuration if provided
            custom_overrides = {}
            if self.paths.custom_config and os.path.exists(self.paths.custom_config):
                custom_overrides = self._load_yaml_file(self.paths.custom_config)
                self.logger.info(f"Loaded custom configuration from {self.paths.custom_config}")
            
            # Merge configurations (custom overrides take precedence)
            self._merged_config = self._merge_configs(self._engine_config, custom_overrides)
            
            # Validate configuration
            self._validate_configuration()
            
        except Exception as e:
            self.logger.error(f"Failed to load configurations: {e}")
            raise ConfigurationError(f"Configuration loading failed: {e}") from e
    
    def _load_yaml_file(self, file_path: str) -> Dict[str, Any]:
        """Load and parse a YAML file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return yaml.safe_load(file) or {}
        except FileNotFoundError:
            self.logger.warning(f"Configuration file not found: {file_path}")
            return {}
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in {file_path}: {e}") from e
    
    def _merge_configs(self, base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge configuration dictionaries."""
        merged = base_config.copy()
        
        for key, value in override_config.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value
        
        return merged
    
    def _validate_configuration(self):
        """Validate the merged configuration for required fields and types."""
        if not self._merged_config:
            raise ConfigurationError("No configuration loaded")
        
        # Validate engine section
        engine_config = self._merged_config.get('engine', {})
        required_engine_fields = ['max_workers', 'enable_parallel_loading', 'log_level']
        
        for field in required_engine_fields:
            if field not in engine_config:
                raise ConfigurationError(f"Missing required engine configuration: {field}")
        
        # Validate pattern sources
        pattern_sources = self._merged_config.get('pattern_sources', {})
        if not pattern_sources:
            self.logger.warning("No pattern sources configured")
        
        # Validate each enabled source
        for source_id, source_config in pattern_sources.items():
            if source_config.get('enabled', False):
                self._validate_source_config(source_id, source_config)
        
        self.logger.info("Configuration validation passed")
    
    def _validate_source_config(self, source_id: str, config: Dict[str, Any]):
        """Validate configuration for a specific pattern source."""
        required_fields = ['enabled', 'priority', 'timeout_seconds']
        
        for field in required_fields:
            if field not in config:
                raise ConfigurationError(f"Missing required field '{field}' in source '{source_id}'")
        
        # Validate data types
        if not isinstance(config['priority'], int) or config['priority'] < 1:
            raise ConfigurationError(f"Invalid priority for source '{source_id}': must be positive integer")
        
        if not isinstance(config['timeout_seconds'], int) or config['timeout_seconds'] < 1:
            raise ConfigurationError(f"Invalid timeout for source '{source_id}': must be positive integer")
    
    def get_engine_config(self) -> PatternEngineConfig:
        """
        Get typed engine configuration.
        
        Returns:
            Validated PatternEngineConfig instance
        """
        if not self._merged_config:
            raise ConfigurationError("Configuration not loaded")
        
        engine_config = self._merged_config.get('engine', {})
        
        # Create pattern source configurations
        pattern_sources = []
        sources_config = self._merged_config.get('pattern_sources', {})
        
        for source_id, source_config in sources_config.items():
            if source_config.get('enabled', False):
                pattern_sources.append(PatternSourceConfig(
                    source_id=source_id,
                    source_name=source_config.get('name', source_id.replace('_', ' ').title()),
                    enabled=source_config['enabled'],
                    priority=source_config.get('priority', 5),
                    max_patterns=source_config.get('max_patterns'),
                    timeout_seconds=source_config.get('timeout_seconds', 30),
                    retry_count=source_config.get('retry_count', 3),
                    cache_duration_hours=source_config.get('cache_duration_hours', 24),
                    config_data=source_config
                ))
        
        return PatternEngineConfig(
            max_workers=engine_config.get('max_workers', 4),
            enable_parallel_loading=engine_config.get('enable_parallel_loading', True),
            enable_semantic_analysis=engine_config.get('enable_semantic_analysis', True),
            match_timeout_seconds=engine_config.get('match_timeout_seconds', 30),
            enable_caching=engine_config.get('enable_caching', True),
            cache_size_limit=engine_config.get('cache_size_limit', 10000),
            log_level=engine_config.get('log_level', 'INFO'),
            pattern_sources=pattern_sources
        )
    
    def get_source_config(self, source_id: str) -> Optional[Dict[str, Any]]:
        """
        Get configuration for a specific pattern source.
        
        Args:
            source_id: Identifier of the pattern source
            
        Returns:
            Source configuration dictionary or None if not found
        """
        if not self._merged_config:
            return None
        
        return self._merged_config.get('pattern_sources', {}).get(source_id)
    
    def get_template_config(self) -> Dict[str, Any]:
        """
        Get template configuration.
        
        Returns:
            Template configuration dictionary
        """
        return self._template_config or {}
    
    def get_templates_for_category(self, category: str) -> List[Dict[str, Any]]:
        """
        Get templates for a specific category.
        
        Args:
            category: Template category name
            
        Returns:
            List of template configurations
        """
        template_config = self.get_template_config()
        templates = template_config.get('templates', {})
        categories = template_config.get('categories', {})
        
        category_templates = categories.get(category, [])
        
        result = []
        for template_type in category_templates:
            if template_type in templates:
                result.extend(templates[template_type])
        
        return result
    
    def get_validation_config(self) -> Dict[str, Any]:
        """Get validation and quality control configuration."""
        if not self._merged_config:
            return {}
        
        return self._merged_config.get('validation', {})
    
    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring and metrics configuration."""
        if not self._merged_config:
            return {}
        
        return self._merged_config.get('monitoring', {})
    
    def get_advanced_config(self) -> Dict[str, Any]:
        """Get advanced features configuration."""
        if not self._merged_config:
            return {}
        
        return self._merged_config.get('advanced', {})
    
    def is_debug_mode(self) -> bool:
        """Check if debug mode is enabled."""
        if not self._merged_config:
            return False
        
        return self._merged_config.get('development', {}).get('debug_mode', False)
    
    def reload_configuration(self):
        """Reload configuration from files."""
        self.logger.info("Reloading configuration...")
        self._load_configurations()
    
    def update_config(self, key_path: str, value: Any):
        """
        Update a configuration value at runtime.
        
        Args:
            key_path: Dot-separated path to the configuration key (e.g., 'engine.max_workers')
            value: New value to set
        """
        if not self._merged_config:
            raise ConfigurationError("Configuration not loaded")
        
        keys = key_path.split('.')
        config = self._merged_config
        
        # Navigate to the parent of the target key
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
        
        self.logger.info(f"Updated configuration: {key_path} = {value}")
    
    def get_config_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current configuration.
        
        Returns:
            Configuration summary for monitoring and debugging
        """
        if not self._merged_config:
            return {"status": "not_loaded"}
        
        engine_config = self._merged_config.get('engine', {})
        pattern_sources = self._merged_config.get('pattern_sources', {})
        enabled_sources = [s for s, c in pattern_sources.items() if c.get('enabled', False)]
        
        return {
            "status": "loaded",
            "engine": {
                "max_workers": engine_config.get('max_workers'),
                "parallel_loading": engine_config.get('enable_parallel_loading'),
                "log_level": engine_config.get('log_level')
            },
            "pattern_sources": {
                "total": len(pattern_sources),
                "enabled": len(enabled_sources),
                "enabled_sources": enabled_sources
            },
            "templates": {
                "categories": len(self._template_config.get('categories', {})),
                "total_templates": sum(len(templates) for templates in self._template_config.get('templates', {}).values())
            }
        }

# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None

def get_config_manager(config_dir: Optional[str] = None, custom_config: Optional[str] = None) -> ConfigManager:
    """
    Get or create the global configuration manager instance.
    
    Args:
        config_dir: Directory containing configuration files
        custom_config: Path to custom configuration file
        
    Returns:
        ConfigManager instance
    """
    global _config_manager
    
    if _config_manager is None or config_dir is not None or custom_config is not None:
        _config_manager = ConfigManager(config_dir, custom_config)
    
    return _config_manager

def reload_config():
    """Reload the global configuration."""
    global _config_manager
    if _config_manager:
        _config_manager.reload_configuration() 
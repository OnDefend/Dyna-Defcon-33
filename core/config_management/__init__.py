#!/usr/bin/env python3
"""
Configuration Management Module for AODS Plugin Modularization

This module provides centralized configuration management for patterns,
plugin settings, and external YAML configuration files. It enables
hot-reload capabilities and maintains clean separation between code
and configuration data.

Components:
- PatternLoader: Loads and validates security patterns from YAML files
- ConfigValidator: Validates configuration files and data structures
- ConfigCache: Provides caching for improved performance
- HotReloadManager: Enables runtime configuration updates
"""

from .pattern_loader import PatternLoader, PatternLoadError
from .config_validator import ConfigValidator, ValidationError
from .config_cache import ConfigCache, CacheManager
from .hot_reload_manager import HotReloadManager

__version__ = "1.0.0"
__author__ = "AODS Development Team"

__all__ = [
    "PatternLoader",
    "PatternLoadError",
    "ConfigValidator", 
    "ValidationError",
    "ConfigCache",
    "CacheManager",
    "HotReloadManager"
] 
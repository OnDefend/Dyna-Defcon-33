#!/usr/bin/env python3
"""
Performance Optimizer - Configuration Manager

Configuration management for performance optimization with intelligent defaults.
This module provides compatibility layer for enterprise configuration management.
"""

import logging
from typing import Dict, Any, Optional

# Import the actual configuration manager from enterprise integration
from ..enterprise_performance_integration.configuration_manager import ConfigurationManager

class PerformanceConfigurationManager(ConfigurationManager):
    """
    Performance-specific configuration manager that extends the enterprise
    configuration manager with performance optimization specific settings.
    """
    
    def __init__(self):
        """Initialize performance configuration manager."""
        super().__init__()
        self.logger = logging.getLogger(__name__)
        
        # Performance-specific configuration defaults
        self.performance_defaults = {
            'optimization_level': 'balanced',
            'memory_limit_mb': 2048,
            'cpu_threads': None,  # Auto-detect
            'cache_size_mb': 512,
            'timeout_seconds': 300,
            'parallel_processing': True,
            'chunked_processing': True,
            'progress_reporting': True
        }
        
    def get_performance_config(self) -> Dict[str, Any]:
        """Get performance optimization configuration."""
        try:
            # Base configuration from system detection
            base_config = {
                'system_capabilities': self.system_capabilities,
                'optimization_level': self.performance_defaults['optimization_level']
            }
            
            # Add performance-specific settings
            base_config.update(self.performance_defaults)
            
            # Adjust based on system capabilities
            if hasattr(self.system_capabilities, 'cpu_count'):
                base_config['cpu_threads'] = min(
                    self.system_capabilities.cpu_count,
                    8  # Cap at 8 threads for performance optimization
                )
            
            if hasattr(self.system_capabilities, 'memory_gb'):
                # Scale memory limit based on available memory
                available_memory_mb = getattr(self.system_capabilities, 'memory_gb', 4) * 1024
                base_config['memory_limit_mb'] = min(
                    int(available_memory_mb * 0.4),  # Use 40% of available memory
                    4096  # Cap at 4GB
                )
                
                # Scale cache size based on memory
                base_config['cache_size_mb'] = min(
                    int(available_memory_mb * 0.1),  # Use 10% for cache
                    1024  # Cap at 1GB
                )
            
            return base_config
            
        except Exception as e:
            self.logger.error(f"Error generating performance config: {e}")
            return self.performance_defaults
    
    def get_optimization_settings(self, optimization_level: str = 'balanced') -> Dict[str, Any]:
        """Get optimization settings for specific optimization level."""
        optimization_settings = {
            'minimal': {
                'parallel_workers': 2,
                'chunk_size': 100,
                'cache_enabled': False,
                'timeout_multiplier': 1.0
            },
            'balanced': {
                'parallel_workers': 4,
                'chunk_size': 50,
                'cache_enabled': True,
                'timeout_multiplier': 1.5
            },
            'aggressive': {
                'parallel_workers': 8,
                'chunk_size': 20,
                'cache_enabled': True,
                'timeout_multiplier': 2.0
            },
            'enterprise': {
                'parallel_workers': 12,
                'chunk_size': 10,
                'cache_enabled': True,
                'timeout_multiplier': 3.0
            }
        }
        
        return optimization_settings.get(optimization_level, optimization_settings['balanced'])

# Backward compatibility alias
PerformanceConfigManager = PerformanceConfigurationManager 
#!/usr/bin/env python3
"""
Analysis Configuration Data Structures

This module provides standardized configuration data structures used across
all AODS plugins for consistent analysis configuration and settings management.

Features:
- Standardized configuration classes
- Type-safe configuration validation
- Performance and resource management settings
- Plugin-specific configuration interfaces
- Scan execution configuration
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

class AnalysisMode(Enum):
    """Analysis execution modes."""
    SAFE = "safe"
    DEEP = "deep"
    COMPREHENSIVE = "comprehensive"
    FAST = "fast"
    CUSTOM = "custom"

class OutputFormat(Enum):
    """Output format options."""
    JSON = "json"
    CSV = "csv"
    TXT = "txt"
    XML = "xml"
    CONSOLE = "console"
    RICH = "rich"

@dataclass
class PerformanceConfiguration:
    """Performance and resource management configuration."""
    
    # Processing limits
    max_memory_usage_mb: int = 2048
    max_cpu_usage_percent: float = 80.0
    max_execution_time_seconds: int = 600
    
    # Parallel processing
    enable_parallel_processing: bool = True
    max_worker_threads: int = 4
    parallel_processing_threshold: int = 10
    
    # I/O optimization
    enable_io_optimization: bool = True
    max_file_size_mb: int = 50
    max_files_to_analyze: int = 10000
    
    # Memory optimization
    enable_memory_optimization: bool = True
    memory_cleanup_interval: int = 100
    enable_garbage_collection: bool = True
    
    # Caching
    enable_caching: bool = True
    cache_size_limit: int = 1000
    cache_ttl_seconds: int = 3600
    
    def __post_init__(self):
        """Validate performance configuration."""
        if self.max_memory_usage_mb <= 0:
            raise ValueError("Max memory usage must be positive")
        if not 0 < self.max_cpu_usage_percent <= 100:
            raise ValueError("Max CPU usage must be between 0 and 100")
        if self.max_execution_time_seconds <= 0:
            raise ValueError("Max execution time must be positive")
        if self.max_worker_threads <= 0:
            raise ValueError("Max worker threads must be positive")

@dataclass
class ScanConfiguration:
    """Scan execution configuration."""
    
    # Scan mode and behavior
    analysis_mode: AnalysisMode = AnalysisMode.SAFE
    enable_deep_analysis: bool = False
    enable_dynamic_analysis: bool = False
    enable_static_analysis: bool = True
    
    # Output configuration
    output_formats: List[OutputFormat] = field(default_factory=lambda: [OutputFormat.CONSOLE])
    output_directory: Optional[Path] = None
    enable_rich_formatting: bool = True
    
    # Confidence and filtering
    min_confidence_threshold: float = 0.1
    max_confidence_threshold: float = 1.0
    include_low_confidence_findings: bool = True
    max_vulnerabilities_per_type: int = 100
    
    # Analysis scope
    enable_manifest_analysis: bool = True
    enable_code_analysis: bool = True
    enable_resource_analysis: bool = True
    enable_binary_analysis: bool = True
    
    # Compliance and standards
    enable_masvs_mapping: bool = True
    enable_mstg_mapping: bool = True
    enable_cwe_mapping: bool = True
    compliance_standards: List[str] = field(default_factory=lambda: ["MASVS", "MSTG"])
    
    # Advanced features
    enable_machine_learning: bool = False
    enable_pattern_learning: bool = True
    enable_historical_analysis: bool = True
    
    def __post_init__(self):
        """Validate scan configuration."""
        if not 0.0 <= self.min_confidence_threshold <= 1.0:
            raise ValueError("Min confidence threshold must be between 0.0 and 1.0")
        if not 0.0 <= self.max_confidence_threshold <= 1.0:
            raise ValueError("Max confidence threshold must be between 0.0 and 1.0")
        if self.min_confidence_threshold > self.max_confidence_threshold:
            raise ValueError("Min confidence threshold cannot be greater than max")
        if self.max_vulnerabilities_per_type <= 0:
            raise ValueError("Max vulnerabilities per type must be positive")
        if self.output_directory and not self.output_directory.exists():
            self.output_directory.mkdir(parents=True, exist_ok=True)

@dataclass
class PluginConfiguration:
    """Plugin-specific configuration."""
    
    # Plugin identification
    plugin_name: str
    plugin_description: str = ""
    
    # Plugin behavior
    enabled: bool = True
    priority: int = 50  # 0-100, higher = higher priority
    timeout_seconds: int = 300
    
    # Plugin-specific settings
    custom_settings: Dict[str, Any] = field(default_factory=dict)
    pattern_files: List[Path] = field(default_factory=list)
    external_tools: List[str] = field(default_factory=list)
    
    # Dependencies
    required_plugins: List[str] = field(default_factory=list)
    optional_plugins: List[str] = field(default_factory=list)
    
    # Resource requirements
    min_memory_mb: int = 100
    max_memory_mb: int = 500
    requires_network: bool = False
    requires_root: bool = False
    
    def __post_init__(self):
        """Validate plugin configuration."""
        if not self.plugin_name:
            raise ValueError("Plugin name cannot be empty")
        if not 0 <= self.priority <= 100:
            raise ValueError("Plugin priority must be between 0 and 100")
        if self.timeout_seconds <= 0:
            raise ValueError("Plugin timeout must be positive")
        if self.min_memory_mb <= 0:
            raise ValueError("Min memory must be positive")
        if self.max_memory_mb < self.min_memory_mb:
            raise ValueError("Max memory cannot be less than min memory")

@dataclass
class AnalysisConfiguration:
    """Main analysis configuration container."""
    
    # Core configuration
    scan_config: ScanConfiguration = field(default_factory=ScanConfiguration)
    performance_config: PerformanceConfiguration = field(default_factory=PerformanceConfiguration)
    
    # Plugin configurations
    plugin_configs: Dict[str, PluginConfiguration] = field(default_factory=dict)
    
    # Global settings
    debug_mode: bool = False
    verbose_logging: bool = False
    log_level: str = "INFO"
    log_file: Optional[Path] = None
    
    # Analysis context
    apk_path: Optional[Path] = None
    package_name: Optional[str] = None
    analysis_id: Optional[str] = None
    
    # External dependencies
    external_tools_path: Optional[Path] = None
    temp_directory: Optional[Path] = None
    
    # Security settings
    enable_sandbox: bool = True
    sandbox_timeout: int = 300
    allow_network_access: bool = False
    
    def __post_init__(self):
        """Validate analysis configuration."""
        if self.apk_path and not self.apk_path.exists():
            raise ValueError(f"APK path does not exist: {self.apk_path}")
        if self.log_file and not self.log_file.parent.exists():
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
        if self.temp_directory and not self.temp_directory.exists():
            self.temp_directory.mkdir(parents=True, exist_ok=True)
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level not in valid_log_levels:
            raise ValueError(f"Invalid log level: {self.log_level}")
    
    def get_plugin_config(self, plugin_name: str) -> Optional[PluginConfiguration]:
        """Get configuration for a specific plugin."""
        return self.plugin_configs.get(plugin_name)
    
    def add_plugin_config(self, plugin_config: PluginConfiguration):
        """Add plugin configuration."""
        self.plugin_configs[plugin_config.plugin_name] = plugin_config
    
    def remove_plugin_config(self, plugin_name: str):
        """Remove plugin configuration."""
        if plugin_name in self.plugin_configs:
            del self.plugin_configs[plugin_name]
    
    def get_enabled_plugins(self) -> List[str]:
        """Get list of enabled plugin names."""
        return [
            name for name, config in self.plugin_configs.items()
            if config.enabled
        ]
    
    def get_plugins_by_priority(self) -> List[str]:
        """Get plugins ordered by priority (highest first)."""
        return sorted(
            self.plugin_configs.keys(),
            key=lambda name: self.plugin_configs[name].priority,
            reverse=True
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'scan_config': {
                'analysis_mode': self.scan_config.analysis_mode.value,
                'enable_deep_analysis': self.scan_config.enable_deep_analysis,
                'enable_dynamic_analysis': self.scan_config.enable_dynamic_analysis,
                'enable_static_analysis': self.scan_config.enable_static_analysis,
                'output_formats': [fmt.value for fmt in self.scan_config.output_formats],
                'min_confidence_threshold': self.scan_config.min_confidence_threshold,
                'max_confidence_threshold': self.scan_config.max_confidence_threshold,
                'include_low_confidence_findings': self.scan_config.include_low_confidence_findings,
                'max_vulnerabilities_per_type': self.scan_config.max_vulnerabilities_per_type,
                'enable_masvs_mapping': self.scan_config.enable_masvs_mapping,
                'enable_mstg_mapping': self.scan_config.enable_mstg_mapping,
                'compliance_standards': self.scan_config.compliance_standards
            },
            'performance_config': {
                'max_memory_usage_mb': self.performance_config.max_memory_usage_mb,
                'max_cpu_usage_percent': self.performance_config.max_cpu_usage_percent,
                'max_execution_time_seconds': self.performance_config.max_execution_time_seconds,
                'enable_parallel_processing': self.performance_config.enable_parallel_processing,
                'max_worker_threads': self.performance_config.max_worker_threads,
                'enable_caching': self.performance_config.enable_caching,
                'cache_size_limit': self.performance_config.cache_size_limit
            },
            'plugin_configs': {
                name: {
                    'plugin_name': config.plugin_name,
                    'plugin_version': config.plugin_version,
                    'enabled': config.enabled,
                    'priority': config.priority,
                    'timeout_seconds': config.timeout_seconds,
                    'custom_settings': config.custom_settings,
                    'required_plugins': config.required_plugins,
                    'optional_plugins': config.optional_plugins,
                    'min_memory_mb': config.min_memory_mb,
                    'max_memory_mb': config.max_memory_mb,
                    'requires_network': config.requires_network,
                    'requires_root': config.requires_root
                }
                for name, config in self.plugin_configs.items()
            },
            'global_settings': {
                'debug_mode': self.debug_mode,
                'verbose_logging': self.verbose_logging,
                'log_level': self.log_level,
                'log_file': str(self.log_file) if self.log_file else None,
                'analysis_id': self.analysis_id,
                'package_name': self.package_name,
                'enable_sandbox': self.enable_sandbox,
                'sandbox_timeout': self.sandbox_timeout,
                'allow_network_access': self.allow_network_access
            }
        }
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'AnalysisConfiguration':
        """Create configuration from dictionary."""
        config = cls()
        
        # Load scan configuration
        if 'scan_config' in config_dict:
            scan_data = config_dict['scan_config']
            config.scan_config = ScanConfiguration(
                analysis_mode=AnalysisMode(scan_data.get('analysis_mode', 'safe')),
                enable_deep_analysis=scan_data.get('enable_deep_analysis', False),
                enable_dynamic_analysis=scan_data.get('enable_dynamic_analysis', False),
                enable_static_analysis=scan_data.get('enable_static_analysis', True),
                output_formats=[OutputFormat(fmt) for fmt in scan_data.get('output_formats', ['console'])],
                min_confidence_threshold=scan_data.get('min_confidence_threshold', 0.1),
                max_confidence_threshold=scan_data.get('max_confidence_threshold', 1.0),
                include_low_confidence_findings=scan_data.get('include_low_confidence_findings', True),
                max_vulnerabilities_per_type=scan_data.get('max_vulnerabilities_per_type', 100),
                enable_masvs_mapping=scan_data.get('enable_masvs_mapping', True),
                enable_mstg_mapping=scan_data.get('enable_mstg_mapping', True),
                compliance_standards=scan_data.get('compliance_standards', ['MASVS', 'MSTG'])
            )
        
        # Load performance configuration
        if 'performance_config' in config_dict:
            perf_data = config_dict['performance_config']
            config.performance_config = PerformanceConfiguration(
                max_memory_usage_mb=perf_data.get('max_memory_usage_mb', 2048),
                max_cpu_usage_percent=perf_data.get('max_cpu_usage_percent', 80.0),
                max_execution_time_seconds=perf_data.get('max_execution_time_seconds', 600),
                enable_parallel_processing=perf_data.get('enable_parallel_processing', True),
                max_worker_threads=perf_data.get('max_worker_threads', 4),
                enable_caching=perf_data.get('enable_caching', True),
                cache_size_limit=perf_data.get('cache_size_limit', 1000)
            )
        
        # Load plugin configurations
        if 'plugin_configs' in config_dict:
            for plugin_name, plugin_data in config_dict['plugin_configs'].items():
                plugin_config = PluginConfiguration(
                    plugin_name=plugin_data.get('plugin_name', plugin_name),
                    plugin_version=plugin_data.get('plugin_version', '1.0.0'),
                    enabled=plugin_data.get('enabled', True),
                    priority=plugin_data.get('priority', 50),
                    timeout_seconds=plugin_data.get('timeout_seconds', 300),
                    custom_settings=plugin_data.get('custom_settings', {}),
                    required_plugins=plugin_data.get('required_plugins', []),
                    optional_plugins=plugin_data.get('optional_plugins', []),
                    min_memory_mb=plugin_data.get('min_memory_mb', 100),
                    max_memory_mb=plugin_data.get('max_memory_mb', 500),
                    requires_network=plugin_data.get('requires_network', False),
                    requires_root=plugin_data.get('requires_root', False)
                )
                config.plugin_configs[plugin_name] = plugin_config
        
        # Load global settings
        if 'global_settings' in config_dict:
            global_data = config_dict['global_settings']
            config.debug_mode = global_data.get('debug_mode', False)
            config.verbose_logging = global_data.get('verbose_logging', False)
            config.log_level = global_data.get('log_level', 'INFO')
            config.analysis_id = global_data.get('analysis_id')
            config.package_name = global_data.get('package_name')
            config.enable_sandbox = global_data.get('enable_sandbox', True)
            config.sandbox_timeout = global_data.get('sandbox_timeout', 300)
            config.allow_network_access = global_data.get('allow_network_access', False)
            
            if global_data.get('log_file'):
                config.log_file = Path(global_data['log_file'])
        
        return config

# Factory functions for common configurations
def create_safe_analysis_config() -> AnalysisConfiguration:
    """Create configuration for safe analysis mode."""
    config = AnalysisConfiguration()
    config.scan_config.analysis_mode = AnalysisMode.SAFE
    config.scan_config.enable_deep_analysis = False
    config.scan_config.enable_dynamic_analysis = False
    config.performance_config.max_execution_time_seconds = 300
    config.performance_config.max_memory_usage_mb = 1024
    return config

def create_deep_analysis_config() -> AnalysisConfiguration:
    """Create configuration for deep analysis mode."""
    config = AnalysisConfiguration()
    config.scan_config.analysis_mode = AnalysisMode.DEEP
    config.scan_config.enable_deep_analysis = True
    config.scan_config.enable_dynamic_analysis = True
    config.performance_config.max_execution_time_seconds = 1800
    config.performance_config.max_memory_usage_mb = 4096
    return config

def create_fast_analysis_config() -> AnalysisConfiguration:
    """Create configuration for fast analysis mode."""
    config = AnalysisConfiguration()
    config.scan_config.analysis_mode = AnalysisMode.FAST
    config.scan_config.enable_deep_analysis = False
    config.scan_config.include_low_confidence_findings = False
    config.scan_config.max_vulnerabilities_per_type = 50
    config.performance_config.max_execution_time_seconds = 120
    config.performance_config.max_memory_usage_mb = 512
    return config

def create_comprehensive_analysis_config() -> AnalysisConfiguration:
    """Create configuration for comprehensive analysis mode."""
    config = AnalysisConfiguration()
    config.scan_config.analysis_mode = AnalysisMode.COMPREHENSIVE
    config.scan_config.enable_deep_analysis = True
    config.scan_config.enable_dynamic_analysis = True
    config.scan_config.enable_machine_learning = True
    config.scan_config.enable_pattern_learning = True
    config.scan_config.enable_historical_analysis = True
    config.performance_config.max_execution_time_seconds = 3600
    config.performance_config.max_memory_usage_mb = 8192
    config.performance_config.max_worker_threads = 8
    return config 
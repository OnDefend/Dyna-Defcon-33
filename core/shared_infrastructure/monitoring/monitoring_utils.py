#!/usr/bin/env python3
"""
Monitoring Utilities for AODS Monitoring Framework

Common utilities, configuration management, and helper functions
for the monitoring framework components.

Features:
- Monitoring configuration management
- Custom exception classes
- Metric formatting and calculation utilities
- System baseline establishment
- Common constants and enums
- Helper functions for monitoring operations

This module provides shared utilities used across all
monitoring framework components.
"""

import logging
import os
import json
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import psutil

logger = logging.getLogger(__name__)

class MonitoringException(Exception):
    """Base exception class for monitoring framework."""
    
    def __init__(self, message: str, component: str = "monitoring",
                 error_code: Optional[str] = None, context: Optional[Dict] = None):
        super().__init__(message)
        self.message = message
        self.component = component
        self.error_code = error_code
        self.context = context or {}
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary format."""
        return {
            'message': self.message,
            'component': self.component,
            'error_code': self.error_code,
            'context': self.context,
            'timestamp': self.timestamp.isoformat(),
            'exception_type': self.__class__.__name__
        }

class MonitoringConfigError(MonitoringException):
    """Configuration-related monitoring error."""
    pass

class MonitoringDataError(MonitoringException):
    """Data processing-related monitoring error."""
    pass

class MonitoringConnectionError(MonitoringException):
    """Connection-related monitoring error."""
    pass

@dataclass
class MonitoringConfiguration:
    """Configuration settings for monitoring framework."""
    
    # Collection settings
    collection_interval: float = 30.0
    retention_days: int = 30
    max_metrics_per_collection: int = 1000
    
    # Performance settings
    enable_parallel_collection: bool = True
    max_collection_workers: int = 5
    collection_timeout_seconds: float = 60.0
    
    # Storage settings
    storage_path: str = "monitoring_data"
    database_url: Optional[str] = None
    compress_historical_data: bool = True
    
    # Alert settings
    enable_alerting: bool = True
    alert_channels: List[str] = field(default_factory=lambda: ["console", "file"])
    alert_aggregation_window_minutes: int = 5
    
    # Analysis settings
    enable_trend_analysis: bool = True
    trend_analysis_window_hours: int = 24
    anomaly_detection_sensitivity: float = 0.1
    
    # Resource thresholds
    cpu_warning_threshold: float = 75.0
    cpu_critical_threshold: float = 90.0
    memory_warning_threshold: float = 80.0
    memory_critical_threshold: float = 95.0
    disk_warning_threshold: float = 85.0
    disk_critical_threshold: float = 95.0
    
    # Health check settings
    health_check_interval: float = 60.0
    health_check_timeout: float = 30.0
    enable_external_health_checks: bool = True
    
    # Advanced settings
    enable_ml_features: bool = True
    enable_predictive_analysis: bool = True
    debug_mode: bool = False
    
    @classmethod
    def from_file(cls, config_path: str) -> 'MonitoringConfiguration':
        """Load configuration from file."""
        try:
            config_file = Path(config_path)
            if not config_file.exists():
                logger.warning(f"Configuration file not found: {config_path}, using defaults")
                return cls()
            
            with open(config_file, 'r') as f:
                if config_path.endswith('.json'):
                    config_data = json.load(f)
                else:
                    # Assume YAML
                    try:
                        import yaml
                        config_data = yaml.safe_load(f)
                    except ImportError:
                        logger.error("YAML support not available, please install PyYAML")
                        return cls()
            
            # Create configuration with loaded data
            return cls(**{k: v for k, v in config_data.items() 
                         if hasattr(cls, k)})
                         
        except Exception as e:
            logger.error(f"Failed to load configuration from {config_path}: {e}")
            return cls()
    
    def to_file(self, config_path: str) -> None:
        """Save configuration to file."""
        try:
            config_file = Path(config_path)
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            config_data = {
                k: v for k, v in self.__dict__.items()
                if not k.startswith('_')
            }
            
            with open(config_file, 'w') as f:
                if config_path.endswith('.json'):
                    json.dump(config_data, f, indent=2, default=str)
                else:
                    # Assume YAML
                    try:
                        import yaml
                        yaml.dump(config_data, f, default_flow_style=False)
                    except ImportError:
                        logger.error("YAML support not available, saving as JSON")
                        json.dump(config_data, f, indent=2, default=str)
                        
        except Exception as e:
            logger.error(f"Failed to save configuration to {config_path}: {e}")
    
    def validate(self) -> List[str]:
        """Validate configuration settings."""
        errors = []
        
        # Validate intervals
        if self.collection_interval <= 0:
            errors.append("collection_interval must be positive")
        
        if self.retention_days <= 0:
            errors.append("retention_days must be positive")
        
        if self.health_check_interval <= 0:
            errors.append("health_check_interval must be positive")
        
        # Validate thresholds
        if not (0 <= self.cpu_warning_threshold <= 100):
            errors.append("cpu_warning_threshold must be between 0 and 100")
        
        if not (0 <= self.memory_warning_threshold <= 100):
            errors.append("memory_warning_threshold must be between 0 and 100")
        
        if self.cpu_critical_threshold <= self.cpu_warning_threshold:
            errors.append("cpu_critical_threshold must be greater than cpu_warning_threshold")
        
        # Validate paths
        try:
            Path(self.storage_path).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Invalid storage_path: {e}")
        
        # Validate worker counts
        if self.max_collection_workers <= 0:
            errors.append("max_collection_workers must be positive")
        
        return errors

class SystemBaseline:
    """System performance baseline for comparison."""
    
    def __init__(self):
        self.cpu_baseline = 0.0
        self.memory_baseline = 0.0
        self.disk_baseline = 0.0
        self.network_baseline = 0.0
        self.process_count_baseline = 0
        self.established = False
        self.sample_count = 0
        self.baseline_timestamp = None
        
    def establish_baseline(self, duration_minutes: int = 10) -> bool:
        """Establish system baseline by sampling for specified duration."""
        try:
            logger.info(f"Establishing system baseline over {duration_minutes} minutes...")
            
            samples = []
            sample_interval = 30  # 30 seconds between samples
            total_samples = (duration_minutes * 60) // sample_interval
            
            for i in range(total_samples):
                sample = self._collect_baseline_sample()
                if sample:
                    samples.append(sample)
                
                if i < total_samples - 1:  # Don't sleep after last sample
                    import time
                    time.sleep(sample_interval)
            
            if len(samples) < 5:
                logger.error("Insufficient samples for baseline establishment")
                return False
            
            # Calculate baseline values
            self.cpu_baseline = statistics.median([s['cpu'] for s in samples])
            self.memory_baseline = statistics.median([s['memory'] for s in samples])
            self.disk_baseline = statistics.median([s['disk'] for s in samples])
            self.network_baseline = statistics.median([s['network'] for s in samples])
            self.process_count_baseline = int(statistics.median([s['processes'] for s in samples]))
            
            self.sample_count = len(samples)
            self.established = True
            self.baseline_timestamp = datetime.now()
            
            logger.info(f"Baseline established with {self.sample_count} samples")
            logger.info(f"CPU: {self.cpu_baseline:.1f}%, Memory: {self.memory_baseline:.1f}%, "
                       f"Disk: {self.disk_baseline:.1f}%, Processes: {self.process_count_baseline}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to establish baseline: {e}")
            return False
    
    def _collect_baseline_sample(self) -> Optional[Dict[str, float]]:
        """Collect a single baseline sample."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1.0)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Network activity (simplified)
            network = psutil.net_io_counters()
            network_activity = (network.bytes_sent + network.bytes_recv) / (1024 * 1024)  # MB
            
            # Process count
            process_count = len(psutil.pids())
            
            return {
                'cpu': cpu_percent,
                'memory': memory_percent,
                'disk': disk_percent,
                'network': network_activity,
                'processes': process_count
            }
            
        except Exception as e:
            logger.warning(f"Failed to collect baseline sample: {e}")
            return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert baseline to dictionary format."""
        return {
            'cpu_baseline': self.cpu_baseline,
            'memory_baseline': self.memory_baseline,
            'disk_baseline': self.disk_baseline,
            'network_baseline': self.network_baseline,
            'process_count_baseline': self.process_count_baseline,
            'established': self.established,
            'sample_count': self.sample_count,
            'baseline_timestamp': self.baseline_timestamp.isoformat() if self.baseline_timestamp else None
        }

def format_metric_value(value: Union[float, int], metric_type: str, 
                       precision: int = 2) -> str:
    """Format metric value for display."""
    try:
        if isinstance(value, (int, float)):
            if metric_type in ['percentage', 'percent']:
                return f"{value:.{precision}f}%"
            elif metric_type in ['bytes', 'memory']:
                return format_bytes(value)
            elif metric_type in ['seconds', 'time']:
                return format_duration(value)
            elif metric_type in ['rate', 'frequency']:
                return f"{value:.{precision}f}/s"
            elif metric_type == 'count':
                return f"{int(value):,}"
            else:
                return f"{value:.{precision}f}"
        else:
            return str(value)
            
    except Exception:
        return str(value)

def format_bytes(bytes_value: Union[float, int]) -> str:
    """Format byte values with appropriate units."""
    try:
        bytes_value = float(bytes_value)
        
        if bytes_value < 1024:
            return f"{bytes_value:.1f} B"
        elif bytes_value < 1024**2:
            return f"{bytes_value/1024:.1f} KB"
        elif bytes_value < 1024**3:
            return f"{bytes_value/(1024**2):.1f} MB"
        elif bytes_value < 1024**4:
            return f"{bytes_value/(1024**3):.1f} GB"
        else:
            return f"{bytes_value/(1024**4):.1f} TB"
            
    except Exception:
        return str(bytes_value)

def format_duration(seconds: Union[float, int]) -> str:
    """Format duration in seconds to human-readable format."""
    try:
        seconds = float(seconds)
        
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.1f}h"
        else:
            days = seconds / 86400
            return f"{days:.1f}d"
            
    except Exception:
        return str(seconds)

def calculate_metric_percentile(values: List[Union[float, int]], 
                              percentile: float) -> float:
    """Calculate percentile for a list of metric values."""
    try:
        if not values:
            return 0.0
        
        numeric_values = [float(v) for v in values if isinstance(v, (int, float))]
        if not numeric_values:
            return 0.0
        
        sorted_values = sorted(numeric_values)
        n = len(sorted_values)
        
        if percentile <= 0:
            return sorted_values[0]
        elif percentile >= 100:
            return sorted_values[-1]
        
        # Calculate percentile index
        index = (percentile / 100) * (n - 1)
        lower_index = int(index)
        upper_index = min(lower_index + 1, n - 1)
        
        # Interpolate if needed
        if lower_index == upper_index:
            return sorted_values[lower_index]
        else:
            weight = index - lower_index
            return sorted_values[lower_index] * (1 - weight) + sorted_values[upper_index] * weight
            
    except Exception as e:
        logger.error(f"Failed to calculate percentile: {e}")
        return 0.0

def calculate_metric_statistics(values: List[Union[float, int]]) -> Dict[str, float]:
    """Calculate comprehensive statistics for metric values."""
    try:
        if not values:
            return {}
        
        numeric_values = [float(v) for v in values if isinstance(v, (int, float))]
        if not numeric_values:
            return {}
        
        stats = {
            'count': len(numeric_values),
            'mean': statistics.mean(numeric_values),
            'median': statistics.median(numeric_values),
            'min': min(numeric_values),
            'max': max(numeric_values),
            'p25': calculate_metric_percentile(numeric_values, 25),
            'p75': calculate_metric_percentile(numeric_values, 75),
            'p90': calculate_metric_percentile(numeric_values, 90),
            'p95': calculate_metric_percentile(numeric_values, 95),
            'p99': calculate_metric_percentile(numeric_values, 99)
        }
        
        # Calculate standard deviation if we have enough values
        if len(numeric_values) > 1:
            stats['std'] = statistics.stdev(numeric_values)
            stats['variance'] = statistics.variance(numeric_values)
        else:
            stats['std'] = 0.0
            stats['variance'] = 0.0
        
        # Calculate range and IQR
        stats['range'] = stats['max'] - stats['min']
        stats['iqr'] = stats['p75'] - stats['p25']
        
        return stats
        
    except Exception as e:
        logger.error(f"Failed to calculate statistics: {e}")
        return {}

def validate_metric_name(metric_name: str) -> bool:
    """Validate metric name format."""
    if not metric_name or not isinstance(metric_name, str):
        return False
    
    # Basic validation rules
    if len(metric_name) > 255:
        return False
    
    # Allow alphanumeric, dots, underscores, and hyphens
    import re
    pattern = r'^[a-zA-Z][a-zA-Z0-9._-]*$'
    return bool(re.match(pattern, metric_name))

def normalize_metric_labels(labels: Dict[str, str]) -> Dict[str, str]:
    """Normalize metric labels for consistency."""
    if not labels:
        return {}
    
    normalized = {}
    for key, value in labels.items():
        # Normalize key: lowercase, replace spaces with underscores
        normalized_key = str(key).lower().replace(' ', '_').replace('-', '_')
        
        # Normalize value: string representation, limited length
        normalized_value = str(value)[:100]  # Limit to 100 characters
        
        normalized[normalized_key] = normalized_value
    
    return normalized

def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system information."""
    try:
        import platform
        
        system_info = {
            'hostname': platform.node(),
            'platform': platform.platform(),
            'processor': platform.processor(),
            'architecture': platform.architecture(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'cpu_count_logical': psutil.cpu_count(logical=True),
            'memory_total_gb': psutil.virtual_memory().total / (1024**3),
            'disk_total_gb': psutil.disk_usage('/').total / (1024**3),
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            'timezone': str(datetime.now().astimezone().tzinfo)
        }
        
        # Add network interfaces
        network_info = {}
        for interface, addresses in psutil.net_if_addrs().items():
            network_info[interface] = [addr.address for addr in addresses]
        system_info['network_interfaces'] = network_info
        
        return system_info
        
    except Exception as e:
        logger.error(f"Failed to get system info: {e}")
        return {}

# Global system baseline instance
_system_baseline: Optional[SystemBaseline] = None

def get_system_baseline() -> SystemBaseline:
    """Get the global system baseline instance."""
    global _system_baseline
    if _system_baseline is None:
        _system_baseline = SystemBaseline()
    return _system_baseline

# Common constants
DEFAULT_METRIC_RETENTION_DAYS = 30
DEFAULT_COLLECTION_INTERVAL = 30.0
DEFAULT_HEALTH_CHECK_INTERVAL = 60.0
MAX_METRIC_NAME_LENGTH = 255
MAX_LABEL_VALUE_LENGTH = 100

# Load configuration from environment or file
def load_monitoring_config() -> MonitoringConfiguration:
    """Load monitoring configuration from environment or default file."""
    # Check for config file path in environment
    config_path = os.getenv('AODS_MONITORING_CONFIG', 'config/monitoring.yaml')
    
    if os.path.exists(config_path):
        return MonitoringConfiguration.from_file(config_path)
    else:
        # Use environment variables if available
        config = MonitoringConfiguration()
        
        # Override with environment variables
        if os.getenv('MONITORING_COLLECTION_INTERVAL'):
            config.collection_interval = float(os.getenv('MONITORING_COLLECTION_INTERVAL'))
        
        if os.getenv('MONITORING_RETENTION_DAYS'):
            config.retention_days = int(os.getenv('MONITORING_RETENTION_DAYS'))
        
        if os.getenv('MONITORING_STORAGE_PATH'):
            config.storage_path = os.getenv('MONITORING_STORAGE_PATH')
        
        if os.getenv('MONITORING_DEBUG'):
            config.debug_mode = os.getenv('MONITORING_DEBUG').lower() in ('true', '1', 'yes')
        
        return config 
#!/usr/bin/env python3
"""
Configuration Manager

Unified configuration management for execution framework with intelligent
auto-tuning and production-ready defaults.
"""

import logging
import psutil
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ExecutionMode(Enum):
    """Execution mode enumeration."""
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    PROCESS_SEPARATED = "process_separated"
    ADAPTIVE = "adaptive"

@dataclass
class ExecutionConfig:
    """
    Unified execution configuration with intelligent defaults.
    
    Automatically optimizes settings based on system capabilities
    while allowing manual overrides for specific requirements.
    """
    # Execution strategy
    execution_mode: ExecutionMode = ExecutionMode.ADAPTIVE
    
    # Resource management - auto-optimized by default
    max_workers: Optional[int] = None
    timeout_seconds: int = 300
    memory_limit_gb: Optional[float] = None
    
    # Feature toggles
    enable_parallel_execution: bool = True
    enable_process_separation: bool = True
    enable_resource_monitoring: bool = True
    enable_adaptive_optimization: bool = True
    
    # Performance tuning
    parallel_threshold_plugins: int = 3
    process_timeout_seconds: int = 1800
    plugin_execution_timeout: int = 300
    
    # Advanced settings
    enable_performance_learning: bool = True
    enable_intelligent_fallback: bool = True
    enable_context_awareness: bool = True
    
    # System resource thresholds
    max_memory_usage_percent: float = 80.0
    max_cpu_usage_percent: float = 90.0
    
    # Debugging and monitoring
    enable_detailed_logging: bool = False
    enable_execution_profiling: bool = False
    
    def __post_init__(self):
        """Auto-optimize configuration after initialization."""
        self._auto_optimize_settings()
    
    def _auto_optimize_settings(self):
        """Automatically optimize settings based on system capabilities."""
        try:
            # Auto-optimize worker count
            if self.max_workers is None:
                cpu_count = psutil.cpu_count() or 4
                # Use 75% of available cores, minimum 2, maximum 8 for stability
                self.max_workers = max(2, min(8, int(cpu_count * 0.75)))
                logger.debug(f"Auto-optimized max_workers: {self.max_workers} (based on {cpu_count} CPUs)")
            
            # Auto-optimize memory limit
            if self.memory_limit_gb is None:
                memory_gb = psutil.virtual_memory().total / (1024**3)
                # Use 60% of available memory, minimum 2GB, maximum 16GB
                self.memory_limit_gb = max(2.0, min(16.0, memory_gb * 0.6))
                logger.debug(f"Auto-optimized memory_limit_gb: {self.memory_limit_gb:.1f}GB (based on {memory_gb:.1f}GB total)")
            
            # Adjust timeouts based on system performance
            system_performance = self._assess_system_performance()
            if system_performance == "high":
                # High-performance system - reduce timeouts for faster feedback
                self.timeout_seconds = min(self.timeout_seconds, 180)
                self.plugin_execution_timeout = min(self.plugin_execution_timeout, 120)
            elif system_performance == "low":
                # Low-performance system - increase timeouts for stability
                self.timeout_seconds = max(self.timeout_seconds, 600)
                self.plugin_execution_timeout = max(self.plugin_execution_timeout, 480)
            
            logger.info(f"Auto-optimized config: {self.max_workers} workers, {self.memory_limit_gb:.1f}GB memory limit")
            
        except Exception as e:
            logger.warning(f"Failed to auto-optimize configuration: {e}")
    
    def _assess_system_performance(self) -> str:
        """Assess system performance level."""
        try:
            cpu_count = psutil.cpu_count() or 4
            memory_gb = psutil.virtual_memory().total / (1024**3)
            
            # High performance: 8+ cores, 16+ GB RAM
            if cpu_count >= 8 and memory_gb >= 16:
                return "high"
            # Low performance: <4 cores or <8 GB RAM
            elif cpu_count < 4 or memory_gb < 8:
                return "low"
            else:
                return "medium"
        except:
            return "medium"  # Safe default
    
    def optimize_for_apk_size(self, apk_size_mb: float):
        """Optimize configuration based on APK size."""
        if apk_size_mb > 500:  # Large APK
            self.timeout_seconds = max(self.timeout_seconds, 600)
            self.plugin_execution_timeout = max(self.plugin_execution_timeout, 480)
            self.parallel_threshold_plugins = 2  # Lower threshold for large APKs
            logger.info(f"Optimized for large APK ({apk_size_mb:.1f}MB): increased timeouts")
        elif apk_size_mb < 50:  # Small APK
            self.timeout_seconds = min(self.timeout_seconds, 180)
            self.plugin_execution_timeout = min(self.plugin_execution_timeout, 120)
            self.parallel_threshold_plugins = 5  # Higher threshold for small APKs
            logger.info(f"Optimized for small APK ({apk_size_mb:.1f}MB): reduced timeouts")
    
    def optimize_for_plugin_count(self, plugin_count: int):
        """Optimize configuration based on number of plugins."""
        if plugin_count > 50:  # Many plugins
            self.max_workers = min(self.max_workers, 6)  # Limit workers to prevent resource exhaustion
            self.parallel_threshold_plugins = 3
            logger.info(f"Optimized for many plugins ({plugin_count}): limited workers")
        elif plugin_count < 10:  # Few plugins
            self.parallel_threshold_plugins = 2  # Lower threshold
            logger.info(f"Optimized for few plugins ({plugin_count}): lowered parallel threshold")
    
    def enable_debug_mode(self):
        """Enable debug mode with enhanced logging and profiling."""
        self.enable_detailed_logging = True
        self.enable_execution_profiling = True
        self.timeout_seconds = max(self.timeout_seconds, 600)  # Longer timeouts for debugging
        logger.info("Debug mode enabled: detailed logging and profiling active")
    
    def enable_production_mode(self):
        """Enable production mode with optimized settings."""
        self.enable_detailed_logging = False
        self.enable_execution_profiling = False
        self.enable_performance_learning = True
        self.enable_intelligent_fallback = True
        logger.info("Production mode enabled: optimized for performance and reliability")

class ConfigurationManager:
    """
    Manages execution configuration with environment-aware optimization.
    """
    
    def __init__(self, config: Optional[ExecutionConfig] = None):
        """Initialize configuration manager."""
        self.config = config or ExecutionConfig()
        self.logger = logging.getLogger(__name__)
        
        # Apply environment-specific optimizations
        self._apply_environment_optimizations()
        
        self.logger.info("Unified configuration manager initialized")
    
    def _apply_environment_optimizations(self):
        """Apply optimizations based on detected environment."""
        try:
            # Check if running in CI/testing environment
            import os
            if any(env in os.environ for env in ['CI', 'GITHUB_ACTIONS', 'JENKINS_URL', 'GITLAB_CI']):
                self._optimize_for_ci_environment()
            
            # Check if running in containerized environment
            if os.path.exists('/.dockerenv') or os.environ.get('KUBERNETES_SERVICE_HOST'):
                self._optimize_for_container_environment()
            
            # Check available system resources
            self._optimize_for_system_resources()
            
        except Exception as e:
            self.logger.warning(f"Failed to apply environment optimizations: {e}")
    
    def _optimize_for_ci_environment(self):
        """Optimize configuration for CI/testing environments."""
        self.config.timeout_seconds = min(self.config.timeout_seconds, 300)
        self.config.enable_detailed_logging = True
        self.config.max_workers = min(self.config.max_workers, 4)
        self.logger.info("Optimized configuration for CI environment")
    
    def _optimize_for_container_environment(self):
        """Optimize configuration for containerized environments."""
        # More conservative resource usage in containers
        self.config.max_workers = min(self.config.max_workers, 4)
        self.config.memory_limit_gb = min(self.config.memory_limit_gb, 8.0)
        self.config.max_memory_usage_percent = 70.0  # More conservative in containers
        self.logger.info("Optimized configuration for container environment")
    
    def _optimize_for_system_resources(self):
        """Optimize configuration based on current system resources."""
        try:
            # Check current memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 80:
                # High memory usage - be more conservative
                self.config.max_workers = max(1, self.config.max_workers - 2)
                self.config.memory_limit_gb = self.config.memory_limit_gb * 0.8
                self.logger.info("Optimized for high memory usage environment")
            
            # Check CPU load - NON-BLOCKING VERSION
            try:
                # Use non-blocking CPU check (interval=None for immediate reading)
                cpu_percent = psutil.cpu_percent(interval=None)  # Non-blocking
                if cpu_percent > 80:
                    # High CPU usage - reduce workers
                    self.config.max_workers = max(1, self.config.max_workers - 1)
                    self.logger.info(f"Optimized for high CPU usage environment ({cpu_percent:.1f}%)")
            except Exception as e:
                # Fallback: Skip CPU optimization if psutil fails
                self.logger.debug(f"CPU optimization skipped: {e}")
                pass
                
        except Exception as e:
            self.logger.debug(f"Failed to check system resources: {e}")
    
    def get_config(self) -> ExecutionConfig:
        """Get the current configuration."""
        return self.config
    
    def update_config(self, **kwargs):
        """Update configuration with new values."""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                self.logger.debug(f"Updated config: {key} = {value}")
            else:
                self.logger.warning(f"Unknown config parameter: {key}")
    
    def get_optimization_recommendations(self) -> Dict[str, Any]:
        """Get recommendations for configuration optimization."""
        recommendations = {}
        
        try:
            # Analyze current system state
            cpu_count = psutil.cpu_count()
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Worker count recommendations
            optimal_workers = max(2, min(8, int(cpu_count * 0.75)))
            if self.config.max_workers != optimal_workers:
                recommendations['max_workers'] = {
                    'current': self.config.max_workers,
                    'recommended': optimal_workers,
                    'reason': f'Based on {cpu_count} CPU cores'
                }
            
            # Memory recommendations
            optimal_memory = max(2.0, min(16.0, memory.total / (1024**3) * 0.6))
            if abs(self.config.memory_limit_gb - optimal_memory) > 1.0:
                recommendations['memory_limit_gb'] = {
                    'current': self.config.memory_limit_gb,
                    'recommended': round(optimal_memory, 1),
                    'reason': f'Based on {memory.total / (1024**3):.1f}GB total memory'
                }
            
            # Timeout recommendations based on system performance
            if cpu_percent > 80 or memory.percent > 80:
                recommended_timeout = max(self.config.timeout_seconds, 450)
                if self.config.timeout_seconds < recommended_timeout:
                    recommendations['timeout_seconds'] = {
                        'current': self.config.timeout_seconds,
                        'recommended': recommended_timeout,
                        'reason': 'High system load detected'
                    }
            
        except Exception as e:
            self.logger.warning(f"Failed to generate optimization recommendations: {e}")
        
        return recommendations
    
    def apply_recommendations(self):
        """Apply optimization recommendations."""
        recommendations = self.get_optimization_recommendations()
        
        for param, rec in recommendations.items():
            setattr(self.config, param, rec['recommended'])
            self.logger.info(f"Applied recommendation: {param} = {rec['recommended']} ({rec['reason']})")
        
        return len(recommendations) 
#!/usr/bin/env python3
"""
Enterprise Performance Integration - Configuration Manager

System-aware configuration management with intelligent defaults
based on hardware capabilities and optimization requirements.
"""

import psutil
import logging
from typing import Dict, Any, Optional
from pathlib import Path

from .data_structures import SystemCapabilities

class ConfigurationManager:
    """
    Manages configuration for enterprise performance integration with
    intelligent system-aware defaults and hardware optimization.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.system_capabilities = self._detect_system_capabilities()
        
    def _detect_system_capabilities(self) -> SystemCapabilities:
        """Detect system capabilities for intelligent configuration."""
        try:
            cpu_count = psutil.cpu_count()
            memory_gb = psutil.virtual_memory().total / (1024**3)
            
            # Calculate recommended values based on system capabilities
            recommended_max_workers = min(cpu_count, 12)  # Max 12 workers
            recommended_cache_size_mb = min(int(memory_gb * 1024 * 0.2), 2048)  # 20% of memory, max 2GB
            recommended_max_memory_mb = min(int(memory_gb * 1024 * 0.7), 8192)  # 70% of available, max 8GB
            
            supports_parallel_processing = cpu_count >= 2
            supports_large_apk_analysis = memory_gb >= 4.0  # Minimum 4GB for large APK analysis
            
            return SystemCapabilities(
                cpu_count=cpu_count,
                memory_gb=memory_gb,
                recommended_max_workers=recommended_max_workers,
                recommended_cache_size_mb=recommended_cache_size_mb,
                recommended_max_memory_mb=recommended_max_memory_mb,
                supports_parallel_processing=supports_parallel_processing,
                supports_large_apk_analysis=supports_large_apk_analysis
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to detect system capabilities: {e}")
            # Return safe defaults
            return SystemCapabilities(
                cpu_count=4,
                memory_gb=8.0,
                recommended_max_workers=4,
                recommended_cache_size_mb=1024,
                recommended_max_memory_mb=4096,
                supports_parallel_processing=True,
                supports_large_apk_analysis=True
            )
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get intelligent default configuration based on system capabilities."""
        capabilities = self.system_capabilities
        
        config = {
            # Memory management
            'max_memory_mb': capabilities.recommended_max_memory_mb,
            'memory_threshold_percent': 80,
            'enable_memory_monitoring': True,
            
            # Parallel processing
            'max_workers': capabilities.recommended_max_workers,
            'enable_parallel_processing': capabilities.supports_parallel_processing,
            'parallel_threshold_findings': 100,  # Use parallel for >100 findings
            
            # Caching
            'cache_enabled': True,
            'cache_size_mb': capabilities.recommended_cache_size_mb,
            'cache_ttl_hours': 24,
            'cache_directory': 'enterprise_cache',
            
            # Enterprise features
            'enable_batch_processing': True,
            'enable_streaming_analysis': capabilities.supports_large_apk_analysis,
            'enable_progressive_analysis': capabilities.supports_large_apk_analysis,
            'large_apk_threshold_mb': 100,
            
            # Performance monitoring
            'enable_performance_monitoring': True,
            'enable_benchmarking': True,
            'performance_reporting': True,
            
            # System capabilities
            'system_capabilities': capabilities.__dict__
        }
        
        self.logger.info(f"Generated configuration for {capabilities.cpu_count} CPU cores, {capabilities.memory_gb:.1f}GB RAM")
        return config
    
    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and adjust configuration based on system capabilities."""
        validated_config = config.copy()
        capabilities = self.system_capabilities
        
        # Validate memory settings
        if validated_config.get('max_memory_mb', 0) > capabilities.recommended_max_memory_mb:
            self.logger.warning(f"Reducing max_memory_mb from {validated_config['max_memory_mb']} to {capabilities.recommended_max_memory_mb}")
            validated_config['max_memory_mb'] = capabilities.recommended_max_memory_mb
        
        # Validate worker count
        if validated_config.get('max_workers', 0) > capabilities.recommended_max_workers:
            self.logger.warning(f"Reducing max_workers from {validated_config['max_workers']} to {capabilities.recommended_max_workers}")
            validated_config['max_workers'] = capabilities.recommended_max_workers
        
        # Validate cache size
        if validated_config.get('cache_size_mb', 0) > capabilities.recommended_cache_size_mb:
            self.logger.warning(f"Reducing cache_size_mb from {validated_config['cache_size_mb']} to {capabilities.recommended_cache_size_mb}")
            validated_config['cache_size_mb'] = capabilities.recommended_cache_size_mb
        
        # Disable features if not supported
        if not capabilities.supports_parallel_processing:
            validated_config['enable_parallel_processing'] = False
            self.logger.warning("Disabling parallel processing due to insufficient CPU cores")
        
        if not capabilities.supports_large_apk_analysis:
            validated_config['enable_streaming_analysis'] = False
            validated_config['enable_progressive_analysis'] = False
            self.logger.warning("Disabling large APK features due to insufficient memory")
        
        return validated_config
    
    def create_cache_directory(self, cache_dir: str) -> bool:
        """Create cache directory if it doesn't exist."""
        try:
            Path(cache_dir).mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            self.logger.error(f"Failed to create cache directory {cache_dir}: {e}")
            return False
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information for diagnostics."""
        return {
            'capabilities': self.system_capabilities.__dict__,
            'current_memory_usage': self._get_current_memory_usage(),
            'current_cpu_usage': self._get_current_cpu_usage(),
            'disk_space': self._get_disk_space()
        }
    
    def _get_current_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage statistics."""
        try:
            memory = psutil.virtual_memory()
            return {
                'total_gb': memory.total / (1024**3),
                'available_gb': memory.available / (1024**3),
                'used_gb': memory.used / (1024**3),
                'percent_used': memory.percent
            }
        except Exception:
            return {'error': 'Unable to get memory usage'}
    
    def _get_current_cpu_usage(self) -> Dict[str, float]:
        """Get current CPU usage statistics."""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'cpu_count': psutil.cpu_count(),
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
            }
        except Exception:
            return {'error': 'Unable to get CPU usage'}
    
    def _get_disk_space(self) -> Dict[str, float]:
        """Get disk space information."""
        try:
            disk = psutil.disk_usage('.')
            return {
                'total_gb': disk.total / (1024**3),
                'free_gb': disk.free / (1024**3),
                'used_gb': disk.used / (1024**3),
                'percent_used': (disk.used / disk.total) * 100
            }
        except Exception:
            return {'error': 'Unable to get disk space'} 
"""
Enterprise Performance Integration - Configuration Manager

System-aware configuration management with intelligent defaults
based on hardware capabilities and optimization requirements.
"""

import psutil
import logging
from typing import Dict, Any, Optional
from pathlib import Path

from .data_structures import SystemCapabilities

class ConfigurationManager:
    """
    Manages configuration for enterprise performance integration with
    intelligent system-aware defaults and hardware optimization.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.system_capabilities = self._detect_system_capabilities()
        
    def _detect_system_capabilities(self) -> SystemCapabilities:
        """Detect system capabilities for intelligent configuration."""
        try:
            cpu_count = psutil.cpu_count()
            memory_gb = psutil.virtual_memory().total / (1024**3)
            
            # Calculate recommended values based on system capabilities
            recommended_max_workers = min(cpu_count, 12)  # Max 12 workers
            recommended_cache_size_mb = min(int(memory_gb * 1024 * 0.2), 2048)  # 20% of memory, max 2GB
            recommended_max_memory_mb = min(int(memory_gb * 1024 * 0.7), 8192)  # 70% of available, max 8GB
            
            supports_parallel_processing = cpu_count >= 2
            supports_large_apk_analysis = memory_gb >= 4.0  # Minimum 4GB for large APK analysis
            
            return SystemCapabilities(
                cpu_count=cpu_count,
                memory_gb=memory_gb,
                recommended_max_workers=recommended_max_workers,
                recommended_cache_size_mb=recommended_cache_size_mb,
                recommended_max_memory_mb=recommended_max_memory_mb,
                supports_parallel_processing=supports_parallel_processing,
                supports_large_apk_analysis=supports_large_apk_analysis
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to detect system capabilities: {e}")
            # Return safe defaults
            return SystemCapabilities(
                cpu_count=4,
                memory_gb=8.0,
                recommended_max_workers=4,
                recommended_cache_size_mb=1024,
                recommended_max_memory_mb=4096,
                supports_parallel_processing=True,
                supports_large_apk_analysis=True
            )
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get intelligent default configuration based on system capabilities."""
        capabilities = self.system_capabilities
        
        config = {
            # Memory management
            'max_memory_mb': capabilities.recommended_max_memory_mb,
            'memory_threshold_percent': 80,
            'enable_memory_monitoring': True,
            
            # Parallel processing
            'max_workers': capabilities.recommended_max_workers,
            'enable_parallel_processing': capabilities.supports_parallel_processing,
            'parallel_threshold_findings': 100,  # Use parallel for >100 findings
            
            # Caching
            'cache_enabled': True,
            'cache_size_mb': capabilities.recommended_cache_size_mb,
            'cache_ttl_hours': 24,
            'cache_directory': 'enterprise_cache',
            
            # Enterprise features
            'enable_batch_processing': True,
            'enable_streaming_analysis': capabilities.supports_large_apk_analysis,
            'enable_progressive_analysis': capabilities.supports_large_apk_analysis,
            'large_apk_threshold_mb': 100,
            
            # Performance monitoring
            'enable_performance_monitoring': True,
            'enable_benchmarking': True,
            'performance_reporting': True,
            
            # System capabilities
            'system_capabilities': capabilities.__dict__
        }
        
        self.logger.info(f"Generated configuration for {capabilities.cpu_count} CPU cores, {capabilities.memory_gb:.1f}GB RAM")
        return config
    
    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and adjust configuration based on system capabilities."""
        validated_config = config.copy()
        capabilities = self.system_capabilities
        
        # Validate memory settings
        if validated_config.get('max_memory_mb', 0) > capabilities.recommended_max_memory_mb:
            self.logger.warning(f"Reducing max_memory_mb from {validated_config['max_memory_mb']} to {capabilities.recommended_max_memory_mb}")
            validated_config['max_memory_mb'] = capabilities.recommended_max_memory_mb
        
        # Validate worker count
        if validated_config.get('max_workers', 0) > capabilities.recommended_max_workers:
            self.logger.warning(f"Reducing max_workers from {validated_config['max_workers']} to {capabilities.recommended_max_workers}")
            validated_config['max_workers'] = capabilities.recommended_max_workers
        
        # Validate cache size
        if validated_config.get('cache_size_mb', 0) > capabilities.recommended_cache_size_mb:
            self.logger.warning(f"Reducing cache_size_mb from {validated_config['cache_size_mb']} to {capabilities.recommended_cache_size_mb}")
            validated_config['cache_size_mb'] = capabilities.recommended_cache_size_mb
        
        # Disable features if not supported
        if not capabilities.supports_parallel_processing:
            validated_config['enable_parallel_processing'] = False
            self.logger.warning("Disabling parallel processing due to insufficient CPU cores")
        
        if not capabilities.supports_large_apk_analysis:
            validated_config['enable_streaming_analysis'] = False
            validated_config['enable_progressive_analysis'] = False
            self.logger.warning("Disabling large APK features due to insufficient memory")
        
        return validated_config
    
    def create_cache_directory(self, cache_dir: str) -> bool:
        """Create cache directory if it doesn't exist."""
        try:
            Path(cache_dir).mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            self.logger.error(f"Failed to create cache directory {cache_dir}: {e}")
            return False
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information for diagnostics."""
        return {
            'capabilities': self.system_capabilities.__dict__,
            'current_memory_usage': self._get_current_memory_usage(),
            'current_cpu_usage': self._get_current_cpu_usage(),
            'disk_space': self._get_disk_space()
        }
    
    def _get_current_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage statistics."""
        try:
            memory = psutil.virtual_memory()
            return {
                'total_gb': memory.total / (1024**3),
                'available_gb': memory.available / (1024**3),
                'used_gb': memory.used / (1024**3),
                'percent_used': memory.percent
            }
        except Exception:
            return {'error': 'Unable to get memory usage'}
    
    def _get_current_cpu_usage(self) -> Dict[str, float]:
        """Get current CPU usage statistics."""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'cpu_count': psutil.cpu_count(),
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
            }
        except Exception:
            return {'error': 'Unable to get CPU usage'}
    
    def _get_disk_space(self) -> Dict[str, float]:
        """Get disk space information."""
        try:
            disk = psutil.disk_usage('.')
            return {
                'total_gb': disk.total / (1024**3),
                'free_gb': disk.free / (1024**3),
                'used_gb': disk.used / (1024**3),
                'percent_used': (disk.used / disk.total) * 100
            }
        except Exception:
            return {'error': 'Unable to get disk space'} 
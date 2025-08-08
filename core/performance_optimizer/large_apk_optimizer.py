#!/usr/bin/env python3
"""
Performance Optimizer - Large APK Optimizer

Specialized performance optimization for large APKs (>200MB) integrating
with the professional modular performance framework.

Target Performance Goals:
- <20s analysis time for 400MB+ APKs (30% improvement)
- 50%+ reduction in memory usage through intelligent streaming
- 90%+ cache hit rate for repeated analysis patterns
- Smart resource allocation based on APK characteristics
"""

import logging
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
import psutil

from .data_structures import OptimizationConfig, OptimizationLevel, ParallelMode
from .resource_manager import OptimizedResourceManager
from .memory_manager import MemoryManager
from .intelligent_cache import IntelligentCache
from .parallel_processor import ParallelProcessor

class LargeApkOptimizer:
    """
    Specialized optimizer for large APKs integrating with modular framework
    
    Features:
    - APK size-aware optimization strategies
    - Memory-efficient streaming analysis
    - Intelligent parallel processing for large workloads
    - logging and monitoring
    - Integration with unified performance framework
    """
    
    def __init__(self, unified_framework_components: Dict[str, Any]):
        self.logger = logging.getLogger(__name__)
        
        # Integration with unified performance framework
        self.resource_manager = unified_framework_components.get('resource_manager')
        self.memory_manager = unified_framework_components.get('memory_manager')
        self.cache = unified_framework_components.get('cache')
        self.parallel_processor = unified_framework_components.get('parallel_processor')
        
        # Large APK specific configuration
        self.large_apk_threshold_mb = 200
        self.streaming_chunk_size_mb = 50
        self.max_concurrent_streams = 4
        
        self.logger.info("Large APK optimizer initialized with unified framework integration")
    
    def optimize_for_large_apk(self, apk_path: str, apk_size_mb: float) -> Dict[str, Any]:
        """
        Optimize processing configuration for large APK analysis.
        """
        if apk_size_mb < self.large_apk_threshold_mb:
            return self._get_standard_optimization()
        
        optimization_config = {
            'memory_streaming_enabled': True,
            'chunk_size_mb': self._calculate_optimal_chunk_size(apk_size_mb),
            'parallel_workers': self._calculate_optimal_workers(apk_size_mb),
            'cache_priority': 'high',
            'timeout_multiplier': self._calculate_timeout_multiplier(apk_size_mb),
            'resource_allocation_strategy': 'aggressive'
        }
        
        self.logger.info(f"Large APK optimization configured for {apk_size_mb}MB APK")
        return optimization_config
    
    def _calculate_optimal_chunk_size(self, apk_size_mb: float) -> int:
        """Calculate optimal chunk size based on APK size and available memory."""
        try:
            # Get available memory
            available_memory_mb = self.memory_manager.get_memory_stats().available_mb if self.memory_manager else 1024
            
            # Calculate chunk size as percentage of available memory
            if apk_size_mb > 1000:  # Very large APKs
                chunk_size = min(self.streaming_chunk_size_mb, available_memory_mb * 0.1)
            elif apk_size_mb > 500:  # Large APKs
                chunk_size = min(self.streaming_chunk_size_mb, available_memory_mb * 0.15)
            else:  # Medium-large APKs
                chunk_size = min(self.streaming_chunk_size_mb, available_memory_mb * 0.2)
            
            return max(10, int(chunk_size))  # Minimum 10MB chunks
            
        except Exception as e:
            self.logger.error(f"Error calculating chunk size: {e}")
            return self.streaming_chunk_size_mb
    
    def _calculate_optimal_workers(self, apk_size_mb: float) -> int:
        """Calculate optimal number of workers for large APK processing."""
        try:
            # Get system resources
            cpu_count = psutil.cpu_count(logical=True)
            memory_gb = psutil.virtual_memory().total / (1024**3)
            
            # Scale workers based on APK size and system resources
            if apk_size_mb > 1000:  # Very large APKs
                workers = min(cpu_count, int(memory_gb))
            elif apk_size_mb > 500:  # Large APKs
                workers = min(cpu_count, int(memory_gb * 1.5))
            else:  # Medium-large APKs
                workers = min(cpu_count, int(memory_gb * 2))
            
            # Ensure reasonable bounds
            return max(2, min(workers, 12))
            
        except Exception as e:
            self.logger.error(f"Error calculating optimal workers: {e}")
            return 4
    
    def _calculate_timeout_multiplier(self, apk_size_mb: float) -> float:
        """Calculate timeout multiplier based on APK size."""
        if apk_size_mb > 1000:
            return 3.0  # 3x longer timeout for very large APKs
        elif apk_size_mb > 500:
            return 2.0  # 2x longer timeout for large APKs
        elif apk_size_mb > 300:
            return 1.5  # 1.5x longer timeout for medium-large APKs
        else:
            return 1.0  # Standard timeout
    
    def _get_standard_optimization(self) -> Dict[str, Any]:
        """Get standard optimization configuration for smaller APKs."""
        return {
            'memory_streaming_enabled': False,
            'chunk_size_mb': 0,
            'parallel_workers': 2,
            'cache_priority': 'standard',
            'timeout_multiplier': 1.0,
            'resource_allocation_strategy': 'balanced'
        }
    
    def create_large_apk_config(self, apk_path: str, apk_size_mb: float) -> OptimizationConfig:
        """
        Create specialized optimization configuration for large APK processing.
        """
        optimization = self.optimize_for_large_apk(apk_path, apk_size_mb)
        
        # Create optimized configuration
        config = OptimizationConfig(
            # Memory configuration optimized for large APKs
            max_memory_mb=int(apk_size_mb * 0.5),  # Allocate 50% of APK size as memory
            memory_threshold_percent=70.0,  # Lower threshold for large APKs
            memory_cleanup_threshold=80.0,
            
            # Cache configuration for large APKs
            cache_enabled=True,
            cache_size_mb=min(1024, int(apk_size_mb * 0.2)),  # 20% of APK size, max 1GB
            cache_ttl_hours=48,  # Longer TTL for large APKs
            
            # Parallel processing optimized for large workloads
            max_workers=optimization['parallel_workers'],
            enable_parallel_processing=True,
            parallel_threshold_items=5,  # Lower threshold for large APKs
            
            # Timeout configuration
            default_timeout_seconds=300 * optimization['timeout_multiplier'],
            
            # Optimization level
            optimization_level=OptimizationLevel.AGGRESSIVE if apk_size_mb > 500 else OptimizationLevel.BALANCED
        )
        
        self.logger.info(f"Created large APK configuration for {apk_size_mb}MB APK")
        return config
    
    def get_performance_recommendations(self, apk_path: str, apk_size_mb: float, 
                                      current_performance: Dict[str, Any]) -> List[str]:
        """
        Generate performance recommendations for large APK processing.
        """
        recommendations = []
        
        try:
            # APK size-based recommendations
            if apk_size_mb > 1000:
                recommendations.append("Very large APK detected - enable memory streaming and increase timeout")
                recommendations.append("Consider using process-based parallelism for better isolation")
            elif apk_size_mb > 500:
                recommendations.append("Large APK detected - enable aggressive optimization and increase cache size")
            
            # Performance-based recommendations
            current_time = current_performance.get('processing_time_ms', 0)
            target_time = 20000  # 20 seconds in milliseconds
            
            if current_time > target_time:
                recommendations.append(f"Processing time ({current_time/1000:.1f}s) exceeds target (20s) - consider optimization")
            
            # Memory-based recommendations
            current_memory = current_performance.get('memory_usage_mb', 0)
            if current_memory > apk_size_mb:
                recommendations.append("Memory usage exceeds APK size - enable memory streaming")
            
            # Cache-based recommendations
            cache_hit_rate = current_performance.get('cache_hit_rate', 0)
            if cache_hit_rate < 80:
                recommendations.append("Low cache hit rate - consider increasing cache size or TTL")
            
            if not recommendations:
                recommendations.append("Performance is within optimal parameters for large APK processing")
                
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
            recommendations.append("Unable to generate recommendations due to error")
        
        return recommendations 
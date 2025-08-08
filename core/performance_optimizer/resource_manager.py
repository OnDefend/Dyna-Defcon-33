#!/usr/bin/env python3
"""
Performance Optimizer - Optimized Resource Manager

resource allocation and management for enterprise-scale
vulnerability analysis with intelligent resource optimization.
"""

import logging
import psutil
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

from .data_structures import OptimizationLevel

@dataclass
class SystemResources:
    """System resource information."""
    cpu_count: int
    memory_total_gb: float
    memory_available_gb: float
    disk_free_gb: float
    cpu_percent: float
    memory_percent: float

@dataclass
class ResourceAllocation:
    """Resource allocation configuration."""
    max_workers: int
    memory_limit_mb: int
    cache_size_mb: int
    temp_space_mb: int
    optimization_level: OptimizationLevel

class OptimizedResourceManager:
    """
    resource manager for enterprise-scale vulnerability analysis
    
    Features:
    - Dynamic system resource detection and monitoring
    - Intelligent resource allocation based on workload
    - Automatic optimization level adjustment
    - Resource usage prediction and planning
    - logging and monitoring
    """
    
    def __init__(self, optimization_level: OptimizationLevel = OptimizationLevel.BALANCED):
        self.optimization_level = optimization_level
        self.logger = logging.getLogger(__name__)
        
        # Resource monitoring
        self._system_resources = self._detect_system_resources()
        self._last_resource_check = time.time()
        self._resource_check_interval = 30  # seconds
        
        # Resource allocation
        self._current_allocation = self._calculate_initial_allocation()
        
        # Performance tracking
        self._allocation_history: List[Dict[str, Any]] = []
        
        self.logger.info(f"Resource manager initialized - Level: {optimization_level.value}")
        self.logger.info(f"System resources - CPU: {self._system_resources.cpu_count}, Memory: {self._system_resources.memory_total_gb:.1f}GB")
    
    def _detect_system_resources(self) -> SystemResources:
        """Detect and analyze current system resources."""
        try:
            cpu_count = psutil.cpu_count(logical=True)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            cpu_percent = psutil.cpu_percent(interval=1)
            
            return SystemResources(
                cpu_count=cpu_count,
                memory_total_gb=memory.total / (1024 ** 3),
                memory_available_gb=memory.available / (1024 ** 3),
                disk_free_gb=disk.free / (1024 ** 3),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent
            )
            
        except Exception as e:
            self.logger.error(f"Failed to detect system resources: {e}")
            # Return conservative defaults
            return SystemResources(
                cpu_count=4,
                memory_total_gb=8.0,
                memory_available_gb=4.0,
                disk_free_gb=10.0,
                cpu_percent=50.0,
                memory_percent=50.0
            )
    
    def _calculate_initial_allocation(self) -> ResourceAllocation:
        """Calculate initial resource allocation based on system capabilities."""
        resources = self._system_resources
        
        # Base allocation factors by optimization level
        allocation_factors = {
            OptimizationLevel.MINIMAL: {'cpu': 0.25, 'memory': 0.25, 'cache': 0.10},
            OptimizationLevel.BALANCED: {'cpu': 0.50, 'memory': 0.40, 'cache': 0.20},
            OptimizationLevel.AGGRESSIVE: {'cpu': 0.75, 'memory': 0.60, 'cache': 0.30},
            OptimizationLevel.ENTERPRISE: {'cpu': 0.85, 'memory': 0.70, 'cache': 0.40}
        }
        
        factors = allocation_factors[self.optimization_level]
        
        # Calculate allocations
        max_workers = max(1, int(resources.cpu_count * factors['cpu']))
        memory_limit_mb = int(resources.memory_available_gb * 1024 * factors['memory'])
        cache_size_mb = int(memory_limit_mb * factors['cache'])
        temp_space_mb = min(1024, int(resources.disk_free_gb * 1024 * 0.10))  # 10% of free space, max 1GB
        
        allocation = ResourceAllocation(
            max_workers=max_workers,
            memory_limit_mb=memory_limit_mb,
            cache_size_mb=cache_size_mb,
            temp_space_mb=temp_space_mb,
            optimization_level=self.optimization_level
        )
        
        self.logger.info(f"Initial allocation - Workers: {max_workers}, Memory: {memory_limit_mb}MB, Cache: {cache_size_mb}MB")
        return allocation
    
    def get_optimal_allocation(self, workload_size: int) -> ResourceAllocation:
        """
        Get optimal resource allocation for a specific workload size.
        """
        # Update system resources if enough time has passed
        if time.time() - self._last_resource_check > self._resource_check_interval:
            self._system_resources = self._detect_system_resources()
            self._last_resource_check = time.time()
        
        # Adjust allocation based on workload size
        base_allocation = self._current_allocation
        
        # Scale workers based on workload
        if workload_size < 10:
            # Small workload - use minimal resources
            adjusted_workers = max(1, base_allocation.max_workers // 4)
        elif workload_size < 100:
            # Medium workload - use half resources
            adjusted_workers = max(1, base_allocation.max_workers // 2)
        else:
            # Large workload - use full allocation
            adjusted_workers = base_allocation.max_workers
        
        # Adjust memory based on system pressure
        memory_pressure = self._system_resources.memory_percent
        if memory_pressure > 80:
            # High memory pressure - reduce allocation
            memory_factor = 0.6
        elif memory_pressure > 60:
            # Moderate memory pressure - slightly reduce
            memory_factor = 0.8
        else:
            # Low memory pressure - use full allocation
            memory_factor = 1.0
        
        adjusted_memory = int(base_allocation.memory_limit_mb * memory_factor)
        adjusted_cache = int(base_allocation.cache_size_mb * memory_factor)
        
        return ResourceAllocation(
            max_workers=adjusted_workers,
            memory_limit_mb=adjusted_memory,
            cache_size_mb=adjusted_cache,
            temp_space_mb=base_allocation.temp_space_mb,
            optimization_level=self.optimization_level
        )
    
    def monitor_resource_usage(self) -> Dict[str, Any]:
        """
        Monitor current resource usage and return metrics.
        """
        current_resources = self._detect_system_resources()
        
        # Calculate resource utilization
        cpu_utilization = current_resources.cpu_percent
        memory_utilization = current_resources.memory_percent
        memory_used_gb = current_resources.memory_total_gb - current_resources.memory_available_gb
        
        # Determine resource pressure levels
        cpu_pressure = self._categorize_pressure(cpu_utilization)
        memory_pressure = self._categorize_pressure(memory_utilization)
        
        usage_metrics = {
            'timestamp': time.time(),
            'cpu_percent': cpu_utilization,
            'memory_percent': memory_utilization,
            'memory_used_gb': memory_used_gb,
            'memory_available_gb': current_resources.memory_available_gb,
            'disk_free_gb': current_resources.disk_free_gb,
            'cpu_pressure': cpu_pressure,
            'memory_pressure': memory_pressure,
            'overall_pressure': max(cpu_utilization, memory_utilization)
        }
        
        # Log warnings for high resource usage
        if cpu_utilization > 90:
            self.logger.warning(f"High CPU usage detected: {cpu_utilization:.1f}%")
        if memory_utilization > 90:
            self.logger.warning(f"High memory usage detected: {memory_utilization:.1f}%")
        
        return usage_metrics
    
    def _categorize_pressure(self, utilization_percent: float) -> str:
        """Categorize resource pressure level."""
        if utilization_percent < 50:
            return "low"
        elif utilization_percent < 70:
            return "moderate"
        elif utilization_percent < 90:
            return "high"
        else:
            return "critical"
    
    def optimize_allocation(self, performance_history: List[Dict[str, Any]]) -> ResourceAllocation:
        """
        Optimize resource allocation based on performance history.
        """
        if not performance_history:
            return self._current_allocation
        
        # Analyze recent performance
        recent_performance = performance_history[-10:]
        avg_efficiency = sum(perf.get('efficiency_percent', 50) for perf in recent_performance) / len(recent_performance)
        avg_memory_usage = sum(perf.get('memory_usage_mb', 0) for perf in recent_performance) / len(recent_performance)
        
        current_allocation = self._current_allocation
        
        # Optimization decisions based on performance
        if avg_efficiency < 60:
            # Low efficiency - reduce resource allocation
            optimized_workers = max(1, int(current_allocation.max_workers * 0.8))
            optimized_memory = int(current_allocation.memory_limit_mb * 0.9)
            self.logger.info(f"Reducing allocation due to low efficiency ({avg_efficiency:.1f}%)")
            
        elif avg_efficiency > 85 and avg_memory_usage < current_allocation.memory_limit_mb * 0.7:
            # High efficiency with low memory usage - increase allocation
            optimized_workers = min(self._system_resources.cpu_count, current_allocation.max_workers + 1)
            optimized_memory = int(current_allocation.memory_limit_mb * 1.1)
            self.logger.info(f"Increasing allocation due to high efficiency ({avg_efficiency:.1f}%)")
            
        else:
            # Maintain current allocation
            optimized_workers = current_allocation.max_workers
            optimized_memory = current_allocation.memory_limit_mb
        
        # Ensure allocations don't exceed system limits
        max_memory_mb = int(self._system_resources.memory_available_gb * 1024 * 0.8)
        optimized_memory = min(optimized_memory, max_memory_mb)
        
        optimized_allocation = ResourceAllocation(
            max_workers=optimized_workers,
            memory_limit_mb=optimized_memory,
            cache_size_mb=int(optimized_memory * 0.3),
            temp_space_mb=current_allocation.temp_space_mb,
            optimization_level=self.optimization_level
        )
        
        # Record allocation change
        self._record_allocation_change(current_allocation, optimized_allocation, avg_efficiency)
        
        self._current_allocation = optimized_allocation
        return optimized_allocation
    
    def _record_allocation_change(self, old_allocation: ResourceAllocation, new_allocation: ResourceAllocation, efficiency: float):
        """Record allocation change for analysis."""
        change_record = {
            'timestamp': time.time(),
            'old_workers': old_allocation.max_workers,
            'new_workers': new_allocation.max_workers,
            'old_memory_mb': old_allocation.memory_limit_mb,
            'new_memory_mb': new_allocation.memory_limit_mb,
            'efficiency_trigger': efficiency,
            'change_reason': 'efficiency_optimization'
        }
        
        self._allocation_history.append(change_record)
        
        # Keep only recent history
        if len(self._allocation_history) > 50:
            self._allocation_history = self._allocation_history[-50:]
    
    def get_resource_recommendations(self) -> Dict[str, Any]:
        """
        Get resource optimization recommendations.
        """
        current_usage = self.monitor_resource_usage()
        current_allocation = self._current_allocation
        
        recommendations = []
        
        # CPU recommendations
        if current_usage['cpu_percent'] > 90:
            recommendations.append("Consider reducing parallel workers to decrease CPU load")
        elif current_usage['cpu_percent'] < 30:
            recommendations.append("CPU underutilized - consider increasing parallel workers")
        
        # Memory recommendations
        if current_usage['memory_percent'] > 85:
            recommendations.append("Consider reducing memory allocation or enabling aggressive memory management")
        elif current_usage['memory_percent'] < 40:
            recommendations.append("Memory underutilized - consider increasing cache size")
        
        # Optimization level recommendations
        if current_usage['overall_pressure'] > 80:
            recommendations.append("Consider reducing optimization level to decrease resource pressure")
        elif current_usage['overall_pressure'] < 30:
            recommendations.append("System resources available - consider increasing optimization level")
        
        return {
            'current_allocation': current_allocation.__dict__,
            'current_usage': current_usage,
            'recommendations': recommendations,
            'optimization_level': self.optimization_level.value,
            'system_capacity': self._system_resources.__dict__
        }
    
    def get_current_allocation(self) -> ResourceAllocation:
        """Get current resource allocation."""
        return self._current_allocation 
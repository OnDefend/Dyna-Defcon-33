#!/usr/bin/env python3
"""
Performance Optimizer - Memory Manager

memory management system with intelligent allocation,
monitoring, and automatic cleanup for enterprise-scale performance.
"""

import logging
import time
import gc
import psutil
import threading
from typing import Dict, List, Any, Optional, Callable
import weakref

from .data_structures import MemoryMetrics, MemoryMetrics, ResourceAllocation

class MemoryManager:
    """
    memory management system for AODS performance optimization
    
    Features:
    - Intelligent memory allocation and monitoring
    - Automatic garbage collection optimization
    - Memory pressure detection and mitigation
    - Resource allocation tracking and optimization
    - Thread-safe memory operations
    - Comprehensive memory usage analytics
    """
    
    def __init__(self, max_memory_mb: int = 1024):
        self.max_memory_mb = max_memory_mb
        self.logger = logging.getLogger(__name__)
        self.lock = threading.RLock()
        
        # Memory tracking
        self.metrics = MemoryMetrics()
        self.allocation_tracking = {}
        self.weak_references = weakref.WeakSet()
        
        # Memory management configuration
        self.memory_threshold_percent = 80.0
        self.cleanup_threshold_percent = 90.0
        self.monitoring_enabled = True
        
        # Initialize memory monitoring
        self._initialize_monitoring()
        
        self.logger.info(f"Memory manager initialized with {max_memory_mb}MB limit")
    
    def _initialize_monitoring(self):
        """Initialize memory monitoring and baseline metrics."""
        try:
            # Get system memory information
            system_memory = psutil.virtual_memory()
            self.metrics.available_mb = system_memory.available / (1024 * 1024)
            
            # Get current process memory
            process = psutil.Process()
            process_memory = process.memory_info()
            self.metrics.current_usage_mb = process_memory.rss / (1024 * 1024)
            
            # Calculate utilization
            self.metrics.utilization_percentage = (
                self.metrics.current_usage_mb / self.max_memory_mb * 100
                if self.max_memory_mb > 0 else 0
            )
            
            self.logger.info(f"Memory monitoring initialized - Current usage: {self.metrics.current_usage_mb:.1f}MB")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize memory monitoring: {e}")
    
    def check_memory_pressure(self) -> bool:
        """
        Check if system is under memory pressure and requires intervention.
        """
        with self.lock:
            try:
                # Update current memory metrics
                self._update_memory_metrics()
                
                # Check memory pressure conditions
                pressure_indicators = []
                
                # Check utilization threshold
                if self.metrics.utilization_percentage > self.memory_threshold_percent:
                    pressure_indicators.append("utilization_threshold_exceeded")
                
                # Check system memory availability
                if self.metrics.available_mb < (self.max_memory_mb * 0.2):
                    pressure_indicators.append("low_system_memory")
                
                # Check for excessive peak usage
                if self.metrics.peak_usage_mb > (self.max_memory_mb * 0.95):
                    pressure_indicators.append("peak_usage_exceeded")
                
                memory_pressure = len(pressure_indicators) > 0
                self.metrics.memory_pressure = memory_pressure
                
                if memory_pressure:
                    self.logger.warning(f"Memory pressure detected: {', '.join(pressure_indicators)}")
                    self.metrics.cleanup_required = True
                
                return memory_pressure
                
            except Exception as e:
                self.logger.error(f"Error checking memory pressure: {e}")
                return False
    
    def _update_memory_metrics(self):
        """Update comprehensive memory usage metrics."""
        try:
            # Get current process memory
            process = psutil.Process()
            memory_info = process.memory_info()
            
            current_usage = memory_info.rss / (1024 * 1024)
            self.metrics.current_usage_mb = current_usage
            
            # Update peak usage
            if current_usage > self.metrics.peak_usage_mb:
                self.metrics.peak_usage_mb = current_usage
            
            # Get system memory
            system_memory = psutil.virtual_memory()
            self.metrics.available_mb = system_memory.available / (1024 * 1024)
            
            # Calculate utilization percentage
            self.metrics.utilization_percentage = (
                current_usage / self.max_memory_mb * 100
                if self.max_memory_mb > 0 else 0
            )
            
            # Calculate efficiency metrics
            self._calculate_memory_efficiency()
            
        except Exception as e:
            self.logger.error(f"Error updating memory metrics: {e}")
    
    def _calculate_memory_efficiency(self):
        """Calculate memory allocation and usage efficiency."""
        try:
            # Allocation efficiency (how well we're using allocated memory)
            if self.max_memory_mb > 0:
                self.metrics.allocation_efficiency = min(100.0, 
                    (self.metrics.current_usage_mb / self.max_memory_mb) * 100
                )
            
            # Memory fragmentation estimation (simplified)
            # In a real implementation, this would use more sophisticated methods
            if self.metrics.peak_usage_mb > 0:
                fragmentation_estimate = (
                    (self.metrics.peak_usage_mb - self.metrics.current_usage_mb) / 
                    self.metrics.peak_usage_mb * 100
                )
                self.metrics.fragmentation_level = max(0.0, fragmentation_estimate)
            
            # Set optimization recommendations
            self.metrics.optimization_recommended = (
                self.metrics.utilization_percentage > 70.0 or
                self.metrics.fragmentation_level > 30.0
            )
            
        except Exception as e:
            self.logger.error(f"Error calculating memory efficiency: {e}")
    
    def optimize_memory_usage(self) -> bool:
        """
        Perform comprehensive memory optimization and cleanup.
        """
        with self.lock:
            try:
                self.logger.info("Starting memory optimization")
                
                initial_usage = self.metrics.current_usage_mb
                
                # Step 1: Trigger garbage collection
                collected_objects = self._perform_garbage_collection()
                
                # Step 2: Clear weak references
                self._cleanup_weak_references()
                
                # Step 3: Optimize allocation tracking
                self._optimize_allocation_tracking()
                
                # Step 4: Update metrics after optimization
                self._update_memory_metrics()
                
                final_usage = self.metrics.current_usage_mb
                memory_freed = initial_usage - final_usage
                
                if memory_freed > 0:
                    self.logger.info(f"Memory optimization complete - Freed {memory_freed:.1f}MB")
                    self.metrics.deallocation_efficiency = (memory_freed / initial_usage * 100) if initial_usage > 0 else 0
                else:
                    self.logger.info("Memory optimization complete - No significant memory freed")
                
                # Reset cleanup required flag
                self.metrics.cleanup_required = False
                
                return memory_freed > 0
                
            except Exception as e:
                self.logger.error(f"Memory optimization failed: {e}")
                return False
    
    def _perform_garbage_collection(self) -> int:
        """Perform intelligent garbage collection with metrics tracking."""
        try:
            # Get initial object counts
            initial_objects = len(gc.get_objects())
            
            # Perform full garbage collection
            collected_count = 0
            for generation in range(3):  # Python has 3 generations
                collected_count += gc.collect(generation)
            
            # Get final object counts
            final_objects = len(gc.get_objects())
            objects_collected = initial_objects - final_objects
            
            self.logger.debug(f"Garbage collection: {objects_collected} objects collected")
            return objects_collected
            
        except Exception as e:
            self.logger.error(f"Garbage collection error: {e}")
            return 0
    
    def _cleanup_weak_references(self):
        """Clean up dead weak references."""
        try:
            initial_count = len(self.weak_references)
            # Weak references clean themselves up automatically
            # This is mainly for metrics tracking
            current_count = len(self.weak_references)
            
            cleaned_count = initial_count - current_count
            if cleaned_count > 0:
                self.logger.debug(f"Cleaned {cleaned_count} dead weak references")
                
        except Exception as e:
            self.logger.error(f"Weak reference cleanup error: {e}")
    
    def _optimize_allocation_tracking(self):
        """Optimize allocation tracking structures."""
        try:
            # Remove stale allocation tracking entries
            current_time = time.time()
            stale_keys = []
            
            for key, allocation_info in self.allocation_tracking.items():
                if current_time - allocation_info.get('timestamp', 0) > 3600:  # 1 hour
                    stale_keys.append(key)
            
            for key in stale_keys:
                del self.allocation_tracking[key]
            
            if stale_keys:
                self.logger.debug(f"Cleaned {len(stale_keys)} stale allocation tracking entries")
                
        except Exception as e:
            self.logger.error(f"Allocation tracking optimization error: {e}")
    
    def allocate_resource(self, resource_id: str, size_mb: float, 
                         allocation_type: str = "general") -> ResourceAllocation:
        """
        Allocate memory resource with tracking and optimization.
        """
        with self.lock:
            try:
                # Check if allocation is possible
                if not self._can_allocate(size_mb):
                    raise MemoryError(f"Cannot allocate {size_mb}MB - insufficient memory")
                
                # Create allocation record
                allocation = ResourceAllocation(
                    memory_allocated_mb=size_mb,
                    memory_reservation_mb=size_mb * 1.1,  # 10% buffer
                    memory_limit_mb=min(size_mb * 2, self.max_memory_mb * 0.5),  # Conservative limit
                    allocation_strategy=allocation_type
                )
                
                # Track allocation
                self.allocation_tracking[resource_id] = {
                    'allocation': allocation,
                    'timestamp': time.time(),
                    'type': allocation_type
                }
                
                self.logger.debug(f"Allocated {size_mb}MB for resource: {resource_id}")
                return allocation
                
            except Exception as e:
                self.logger.error(f"Resource allocation failed for {resource_id}: {e}")
                raise
    
    def _can_allocate(self, size_mb: float) -> bool:
        """Check if memory allocation is possible without exceeding limits."""
        try:
            # Update current metrics
            self._update_memory_metrics()
            
            # Check against maximum memory limit
            projected_usage = self.metrics.current_usage_mb + size_mb
            if projected_usage > self.max_memory_mb:
                return False
            
            # Check system memory availability
            if size_mb > self.metrics.available_mb * 0.5:  # Don't use more than 50% of available
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking allocation feasibility: {e}")
            return False
    
    def deallocate_resource(self, resource_id: str):
        """Deallocate resource and update tracking."""
        with self.lock:
            try:
                if resource_id in self.allocation_tracking:
                    allocation_info = self.allocation_tracking[resource_id]
                    allocated_mb = allocation_info['allocation'].memory_allocated_mb
                    
                    del self.allocation_tracking[resource_id]
                    
                    self.logger.debug(f"Deallocated {allocated_mb}MB for resource: {resource_id}")
                else:
                    self.logger.warning(f"Attempted to deallocate unknown resource: {resource_id}")
                    
            except Exception as e:
                self.logger.error(f"Resource deallocation failed for {resource_id}: {e}")
    
    def get_memory_report(self) -> Dict[str, Any]:
        """Generate comprehensive memory usage report."""
        with self.lock:
            try:
                # Update metrics
                self._update_memory_metrics()
                
                # Calculate allocation statistics
                total_tracked_allocations = sum(
                    info['allocation'].memory_allocated_mb 
                    for info in self.allocation_tracking.values()
                )
                
                return {
                    'memory_usage': {
                        'current_mb': self.metrics.current_usage_mb,
                        'peak_mb': self.metrics.peak_usage_mb,
                        'available_mb': self.metrics.available_mb,
                        'utilization_percentage': self.metrics.utilization_percentage,
                        'limit_mb': self.max_memory_mb
                    },
                    'efficiency_metrics': {
                        'allocation_efficiency': self.metrics.allocation_efficiency,
                        'deallocation_efficiency': self.metrics.deallocation_efficiency,
                        'fragmentation_level': self.metrics.fragmentation_level
                    },
                    'allocation_tracking': {
                        'tracked_allocations': len(self.allocation_tracking),
                        'total_tracked_mb': total_tracked_allocations,
                        'tracking_overhead_mb': total_tracked_allocations - self.metrics.current_usage_mb
                    },
                    'status_indicators': {
                        'memory_pressure': self.metrics.memory_pressure,
                        'cleanup_required': self.metrics.cleanup_required,
                        'optimization_recommended': self.metrics.optimization_recommended
                    },
                    'recommendations': self._generate_memory_recommendations()
                }
                
            except Exception as e:
                self.logger.error(f"Error generating memory report: {e}")
                return {}
    
    def _generate_memory_recommendations(self) -> List[str]:
        """Generate memory optimization recommendations."""
        recommendations = []
        
        try:
            if self.metrics.utilization_percentage > 80:
                recommendations.append("Consider increasing memory limit or optimizing memory usage")
            
            if self.metrics.fragmentation_level > 30:
                recommendations.append("High memory fragmentation detected - consider garbage collection")
            
            if self.metrics.memory_pressure:
                recommendations.append("Memory pressure detected - immediate cleanup recommended")
            
            if len(self.allocation_tracking) > 100:
                recommendations.append("Large number of tracked allocations - consider cleanup")
            
            if not recommendations:
                recommendations.append("Memory usage is within optimal parameters")
                
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
            recommendations.append("Unable to generate recommendations due to error")
        
        return recommendations 
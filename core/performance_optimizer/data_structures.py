#!/usr/bin/env python3
"""
Performance Optimizer - Data Structures

Core data classes and type definitions for professional performance
optimization with comprehensive metrics and configuration management.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum

class OptimizationLevel(Enum):
    """Performance optimization levels"""
    MINIMAL = "minimal"           # Basic optimizations only
    BALANCED = "balanced"         # Standard optimization level
    AGGRESSIVE = "aggressive"     # Maximum performance optimization
    ENTERPRISE = "enterprise"     # High-quality optimization

class CacheStrategy(Enum):
    """Caching strategy options"""
    LRU = "lru"                  # Least Recently Used
    LFU = "lfu"                  # Least Frequently Used
    FIFO = "fifo"                # First In, First Out
    ADAPTIVE = "adaptive"        # Adaptive strategy based on usage patterns

class ParallelMode(Enum):
    """Parallel processing modes"""
    THREAD_BASED = "thread_based"       # Thread-based parallelism
    PROCESS_BASED = "process_based"     # Process-based parallelism
    HYBRID = "hybrid"                   # Hybrid approach
    ADAPTIVE = "adaptive"               # Adaptive based on workload

@dataclass
class PerformanceMetrics:
    """performance metrics for optimization tracking"""
    operation_name: str
    start_time: float
    end_time: float
    duration_ms: float
    memory_usage_mb: float
    cpu_usage_percent: float
    cache_hit_rate: float = 0.0
    parallel_workers: int = 1
    optimization_applied: List[str] = field(default_factory=list)
    
    # Extended metrics
    memory_peak_mb: float = 0.0
    memory_efficiency: float = 0.0
    throughput_items_per_second: float = 0.0
    resource_utilization: float = 0.0
    
    # Quality indicators
    optimization_effectiveness: float = 0.0
    performance_gain_percentage: float = 0.0
    meets_performance_targets: bool = False

@dataclass
class OptimizationConfig:
    """Configuration for performance optimization framework"""
    # Cache configuration
    cache_enabled: bool = True
    cache_strategy: CacheStrategy = CacheStrategy.ADAPTIVE
    cache_size_mb: int = 512
    cache_ttl_hours: int = 24
    cache_directory: str = "performance_cache"
    
    # Memory management
    max_memory_mb: int = 1024
    memory_threshold_percent: float = 80.0
    enable_memory_monitoring: bool = True
    memory_cleanup_enabled: bool = True
    
    # Parallel processing
    parallel_mode: ParallelMode = ParallelMode.ADAPTIVE
    max_workers: Optional[int] = None
    enable_parallel_processing: bool = True
    parallel_threshold_items: int = 100
    
    # Performance targets
    target_analysis_time_seconds: float = 60.0
    target_memory_usage_mb: float = 512.0
    target_speedup_factor: float = 2.0
    optimization_level: OptimizationLevel = OptimizationLevel.BALANCED
    
    # Monitoring and reporting
    enable_performance_monitoring: bool = True
    enable_metrics_collection: bool = True
    metrics_export_enabled: bool = False
    performance_reporting: bool = True

@dataclass
class CacheMetrics:
    """Comprehensive cache performance metrics"""
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    hit_rate_percentage: float = 0.0
    miss_rate_percentage: float = 0.0
    
    # Performance metrics
    average_lookup_time_ms: float = 0.0
    cache_size_mb: float = 0.0
    utilization_percentage: float = 0.0
    
    # Efficiency metrics
    eviction_count: int = 0
    memory_efficiency: float = 0.0
    storage_efficiency: float = 0.0

@dataclass
class MemoryMetrics:
    """memory management metrics"""
    current_usage_mb: float = 0.0
    peak_usage_mb: float = 0.0
    available_mb: float = 0.0
    utilization_percentage: float = 0.0
    
    # Memory efficiency
    allocation_efficiency: float = 0.0
    deallocation_efficiency: float = 0.0
    fragmentation_level: float = 0.0
    
    # Memory pressure indicators
    memory_pressure: bool = False
    cleanup_required: bool = False
    optimization_recommended: bool = False

@dataclass
class ParallelMetrics:
    """Parallel processing performance metrics"""
    workers_active: int = 0
    workers_total: int = 0
    utilization_percentage: float = 0.0
    
    # Performance indicators
    speedup_factor: float = 1.0
    efficiency_percentage: float = 0.0
    overhead_percentage: float = 0.0
    
    # Workload distribution
    tasks_completed: int = 0
    tasks_pending: int = 0
    average_task_duration_ms: float = 0.0
    
    # Quality metrics
    load_balance_efficiency: float = 0.0
    resource_contention: float = 0.0
    parallel_effectiveness: float = 0.0

@dataclass
class OptimizationResult:
    """Comprehensive optimization result with detailed metrics"""
    success: bool
    optimization_applied: bool
    performance_gain_percentage: float
    
    # Processing results
    original_items: int
    processed_items: int
    processing_time_ms: float
    
    # Resource utilization
    memory_used_mb: float
    cpu_utilization_percentage: float
    parallel_workers_used: int
    
    # Optimization metrics
    cache_metrics: CacheMetrics
    memory_metrics: MemoryMetrics
    parallel_metrics: ParallelMetrics
    performance_metrics: PerformanceMetrics
    
    # Quality indicators
    meets_performance_targets: bool = False
    optimization_effectiveness: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    
    # Error handling
    errors_encountered: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

@dataclass
class ResourceAllocation:
    """Resource allocation configuration and tracking"""
    # CPU allocation
    cpu_cores_allocated: int = 0
    cpu_utilization_target: float = 70.0
    cpu_priority_level: int = 0
    
    # Memory allocation
    memory_allocated_mb: float = 0.0
    memory_reservation_mb: float = 0.0
    memory_limit_mb: float = 0.0
    
    # I/O allocation
    io_bandwidth_limit: Optional[float] = None
    disk_space_allocated_mb: float = 0.0
    network_bandwidth_limit: Optional[float] = None
    
    # Scheduling
    scheduling_priority: int = 0
    resource_pool: str = "default"
    allocation_strategy: str = "balanced"

@dataclass
class PerformanceTarget:
    """Performance targets and thresholds for optimization"""
    # Time targets
    max_processing_time_seconds: float = 120.0
    target_response_time_ms: float = 1000.0
    timeout_threshold_seconds: float = 300.0
    
    # Resource targets
    max_memory_usage_mb: float = 1024.0
    target_cpu_utilization: float = 70.0
    max_disk_usage_mb: float = 2048.0
    
    # Quality targets
    min_cache_hit_rate: float = 80.0
    min_parallel_efficiency: float = 60.0
    min_memory_efficiency: float = 70.0
    
    # Throughput targets
    min_throughput_items_per_second: float = 10.0
    target_speedup_factor: float = 2.0
    max_acceptable_overhead: float = 20.0 
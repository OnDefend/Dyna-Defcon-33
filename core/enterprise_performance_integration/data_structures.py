#!/usr/bin/env python3
"""
Enterprise Performance Integration - Data Structures

Core data classes and type definitions for enterprise performance integration.
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from enum import Enum

class OptimizationStrategy(Enum):
    """Available optimization strategies for different APK characteristics"""
    SMALL_APK = "small_apk"
    MEDIUM_APK = "medium_apk"
    LARGE_APK = "large_apk"
    ENTERPRISE_BATCH = "enterprise_batch"
    MEMORY_CONSTRAINED = "memory_constrained"
    CPU_INTENSIVE = "cpu_intensive"
    BALANCED = "balanced"

class FrameworkAvailability(Enum):
    """Framework availability status"""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    PARTIALLY_AVAILABLE = "partially_available"
    ERROR = "error"

@dataclass
class IntegratedPerformanceMetrics:
    """Comprehensive performance metrics combining all optimization frameworks"""
    analysis_start_time: float
    analysis_end_time: float
    total_duration_seconds: float
    
    # Memory metrics
    initial_memory_mb: float
    peak_memory_mb: float
    final_memory_mb: float
    memory_efficiency_percent: float
    
    # Processing metrics
    findings_processed: int
    findings_filtered: int
    reduction_percentage: float
    
    # Cache metrics
    cache_hits: int
    cache_misses: int
    cache_hit_rate_percent: float
    
    # Parallel processing metrics
    parallel_workers_used: int
    parallel_efficiency_percent: float
    sequential_time_estimate: float
    parallel_speedup_factor: float
    
    # Enterprise metrics
    apk_size_mb: float
    complexity_score: int
    optimization_strategy: str
    batch_processing_enabled: bool

@dataclass
class FrameworkStatus:
    """Status information for optimization frameworks"""
    name: str
    availability: FrameworkAvailability
    initialization_success: bool
    error_message: Optional[str] = None
    capabilities: List[str] = None
    
    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []

@dataclass
class OptimizationResult:
    """Result of optimization processing"""
    status: str
    optimization_applied: bool
    enterprise_mode: bool
    original_findings: int
    final_findings: int
    reduction_percentage: float
    analysis_time_seconds: float
    optimization_strategy: str
    detailed_results: Dict[str, Any]
    error_message: Optional[str] = None

@dataclass
class SystemCapabilities:
    """System capability detection results"""
    cpu_count: int
    memory_gb: float
    recommended_max_workers: int
    recommended_cache_size_mb: int
    recommended_max_memory_mb: int
    supports_parallel_processing: bool
    supports_large_apk_analysis: bool 
"""
Enterprise Performance Integration - Data Structures

Core data classes and type definitions for enterprise performance integration.
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from enum import Enum

class OptimizationStrategy(Enum):
    """Available optimization strategies for different APK characteristics"""
    SMALL_APK = "small_apk"
    MEDIUM_APK = "medium_apk"
    LARGE_APK = "large_apk"
    ENTERPRISE_BATCH = "enterprise_batch"
    MEMORY_CONSTRAINED = "memory_constrained"
    CPU_INTENSIVE = "cpu_intensive"
    BALANCED = "balanced"

class FrameworkAvailability(Enum):
    """Framework availability status"""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    PARTIALLY_AVAILABLE = "partially_available"
    ERROR = "error"

@dataclass
class IntegratedPerformanceMetrics:
    """Comprehensive performance metrics combining all optimization frameworks"""
    analysis_start_time: float
    analysis_end_time: float
    total_duration_seconds: float
    
    # Memory metrics
    initial_memory_mb: float
    peak_memory_mb: float
    final_memory_mb: float
    memory_efficiency_percent: float
    
    # Processing metrics
    findings_processed: int
    findings_filtered: int
    reduction_percentage: float
    
    # Cache metrics
    cache_hits: int
    cache_misses: int
    cache_hit_rate_percent: float
    
    # Parallel processing metrics
    parallel_workers_used: int
    parallel_efficiency_percent: float
    sequential_time_estimate: float
    parallel_speedup_factor: float
    
    # Enterprise metrics
    apk_size_mb: float
    complexity_score: int
    optimization_strategy: str
    batch_processing_enabled: bool

@dataclass
class FrameworkStatus:
    """Status information for optimization frameworks"""
    name: str
    availability: FrameworkAvailability
    initialization_success: bool
    error_message: Optional[str] = None
    capabilities: List[str] = None
    
    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []

@dataclass
class OptimizationResult:
    """Result of optimization processing"""
    status: str
    optimization_applied: bool
    enterprise_mode: bool
    original_findings: int
    final_findings: int
    reduction_percentage: float
    analysis_time_seconds: float
    optimization_strategy: str
    detailed_results: Dict[str, Any]
    error_message: Optional[str] = None

@dataclass
class SystemCapabilities:
    """System capability detection results"""
    cpu_count: int
    memory_gb: float
    recommended_max_workers: int
    recommended_cache_size_mb: int
    recommended_max_memory_mb: int
    supports_parallel_processing: bool
    supports_large_apk_analysis: bool 
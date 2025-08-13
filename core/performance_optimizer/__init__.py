#!/usr/bin/env python3
"""
AODS Performance Optimizer - Professional Modular Architecture

Enterprise-scale performance optimization framework with intelligent caching,
memory management, and parallel processing capabilities. Transforms 1,388-line
monolithic implementation into focused, testable components.

PERFORMANCE OPTIMIZATION PRINCIPLES:
- Maximum analysis speed with intelligent caching systems
- Memory efficiency through professional resource management
- Parallel processing optimization for enterprise workloads
- monitoring and metrics collection
- Zero emoji, enterprise-appropriate logging and status reporting

Modular Components:
- performance_metrics.py: Comprehensive performance tracking and analysis
- intelligent_cache.py: Advanced caching system with persistence
- memory_manager.py: memory management and optimization
- parallel_processor.py: Intelligent parallel processing framework
- resource_manager.py: Optimized resource allocation and management
- timeout_manager.py: Enterprise timeout and error handling
- optimized_pipeline.py: Main performance optimization orchestrator
- data_structures.py: Core performance data types and metrics
- configuration_manager.py: Performance-aware configuration management

Original monolithic implementation has been successfully replaced by this modular architecture.
"""

from .data_structures import (
    PerformanceMetrics, 
    OptimizationConfig,
    ParallelMode,
    CacheStrategy,
    OptimizationLevel,
    ResourceAllocation
)
from .intelligent_cache import IntelligentCache
from .memory_manager import MemoryManager
from .parallel_processor import ParallelProcessor
from .resource_manager import OptimizedResourceManager
from .timeout_manager import EnterpriseTimeoutManager
from .optimized_pipeline import OptimizedAccuracyPipeline
from .configuration_manager import PerformanceConfigurationManager

# Legacy compatibility - maintain all original APIs
__all__ = [
    'PerformanceMetrics',
    'OptimizationConfig',
    'ParallelMode',
    'CacheStrategy', 
    'OptimizationLevel',
    'ResourceAllocation',
    'IntelligentCache',
    'MemoryManager',
    'ParallelProcessor',
    'OptimizedResourceManager',
    'EnterpriseTimeoutManager',
    'OptimizedAccuracyPipeline',
    'PerformanceConfigurationManager'
] 
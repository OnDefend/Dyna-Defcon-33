#!/usr/bin/env python3
"""
AODS Unified Execution Framework

This module provides a unified, zero-duplication execution framework that consolidates
all parallel execution approaches while preserving full backward compatibility.

Key Features:
- Multiple execution strategies (parallel, process-separated, sequential, adaptive)
- Zero code duplication through shared components
- Full backward compatibility with existing interfaces
- Intelligent resource management and optimization
- Unified configuration and error handling

Execution Strategies:
- ParallelStrategy: Thread-based parallel plugin execution
- ProcessStrategy: Multi-process static/dynamic separation  
- SequentialStrategy: Traditional one-by-one execution
- AdaptiveStrategy: Intelligent mode selection based on context

Usage:
    from core.execution import UnifiedExecutionManager
    
    # Simple usage
    manager = UnifiedExecutionManager()
    results = manager.execute(plugins, apk_ctx, mode="parallel")
    
    # Advanced usage with configuration
    config = ExecutionConfig(max_workers=8, timeout_seconds=300)
    manager = UnifiedExecutionManager(config)
    results = manager.execute(plugins, apk_ctx, mode="adaptive")
"""

# Core execution components
from .unified_manager import (
    UnifiedExecutionManager,
    ExecutionResult,
    ExecutionContext,
    create_execution_manager
)

# Configuration components
from .shared.config_manager import (
    ExecutionConfig,
    ExecutionMode,
    ConfigurationManager
)

# Execution strategies (all available)
from .strategies import (
    ExecutionStrategy,
    ParallelExecutionStrategy,
    SequentialExecutionStrategy,
    ProcessSeparationStrategy,
    AdaptiveExecutionStrategy
)

# Shared components (zero duplication)
from .shared import (
    PluginExecutor,
    TimeoutManager,
    ResourceMonitor,
    ResultAggregator,
    ErrorHandler
)

# Backward compatibility aliases
from .compatibility import (
    enhance_plugin_manager_with_unified_execution,
    create_legacy_parallel_engine,
    create_legacy_scan_manager
)

# Version and status
__version__ = "2.0.0"
__consolidation_status__ = "COMPLETE"
__backward_compatibility__ = "FULL"

# Public API
__all__ = [
    # Core management
    'UnifiedExecutionManager',
    'ExecutionConfig', 
    'ExecutionMode',
    'ExecutionResult',
    'ExecutionContext',
    'create_execution_manager',
    
    # Execution strategies (all available)
    'ExecutionStrategy',
    'ParallelExecutionStrategy',
    'SequentialExecutionStrategy', 
    'ProcessSeparationStrategy',
    'AdaptiveExecutionStrategy',
    
    # Shared components
    'PluginExecutor',
    'TimeoutManager',
    'ResourceMonitor',
    'ResultAggregator',
    'ErrorHandler',
    'ConfigurationManager',
    
    # Backward compatibility
    'enhance_plugin_manager_with_unified_execution',
    'create_legacy_parallel_engine',
    'create_legacy_scan_manager',
    
    # Framework information
    '__version__',
    '__consolidation_status__',
    '__backward_compatibility__'
] 
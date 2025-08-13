#!/usr/bin/env python3
"""
Unified Parallel Framework - Public API

modular parallel execution framework consolidating all parallel
execution approaches from AODS into a single, intelligent system.

CONSOLIDATED IMPLEMENTATIONS:
✅ parallel_analysis_engine.py (1,020 lines) → PluginExecutionStrategy
✅ parallel_execution_manager.py (711 lines) → ProcessSeparationStrategy  
✅ enhanced_parallel_execution.py (481 lines) → RobustExecutionStrategy
✅ Adaptive strategy selection with performance monitoring

KEY FEATURES:
- Intelligent strategy selection based on task characteristics
- Plugin-level execution with dependency management
- Process-level execution with isolation and IPC
- Robust execution with comprehensive error handling
- Adaptive resource management and optimization
- monitoring and performance tracking
- 100% backward compatibility with existing systems

EXECUTION STRATEGIES:
- PluginExecutionStrategy: Optimized for plugin coordination with dependencies
- ProcessSeparationStrategy: Static/dynamic analysis process isolation
- RobustExecutionStrategy: Enhanced error handling and timeout management
- AdaptiveExecutionStrategy: Dynamic strategy selection optimization

Usage:
    from core.unified_parallel_framework import (
        UnifiedParallelManager, execute_plugin_tasks, execute_analysis_tasks
    )
    
    # Intelligent parallel execution
    manager = UnifiedParallelManager()
    summary = manager.execute_parallel(tasks)
    
    # Convenience functions
    summary = execute_plugin_tasks(plugin_functions, apk_context)
    summary = execute_analysis_tasks(static_func, dynamic_func, apk_context)
"""

# Core execution components
from .execution_engine import (
    ExecutionEngine,
    ExecutionTask,
    ExecutionContext,
    ExecutionMetrics,
    ExecutionMode,
    ExecutionLevel,
    ResourceLevel,
    DependencyGraph,
    ThreadBasedEngine,
    ProcessBasedEngine,
    HybridEngine,
    create_execution_engine,
    create_plugin_task,
    create_analysis_task
)

# Execution strategies
from .execution_strategies import (
    ExecutionStrategy,
    ExecutionResult,
    StrategyConfig,
    PluginExecutionStrategy,
    ProcessSeparationStrategy,
    RobustExecutionStrategy,
    AdaptiveExecutionStrategy
)

# Unified management
from .unified_manager import (
    UnifiedParallelManager,
    UnifiedConfig,
    ExecutionSummary,
    get_unified_parallel_manager,
    execute_plugin_tasks,
    execute_analysis_tasks,
    execute_custom_parallel
)

# Version and framework information
__version__ = "1.0.0"
__framework_name__ = "Unified Parallel Framework"
__consolidation_status__ = "COMPLETE"

# Public API exports
__all__ = [
    # Core execution components
    'ExecutionEngine',
    'ExecutionTask', 
    'ExecutionContext',
    'ExecutionMetrics',
    'ExecutionMode',
    'ExecutionLevel',
    'ResourceLevel',
    'DependencyGraph',
    'ThreadBasedEngine',
    'ProcessBasedEngine', 
    'HybridEngine',
    'create_execution_engine',
    'create_plugin_task',
    'create_analysis_task',
    
    # Execution strategies
    'ExecutionStrategy',
    'ExecutionResult',
    'StrategyConfig',
    'PluginExecutionStrategy',
    'ProcessSeparationStrategy',
    'RobustExecutionStrategy',
    'AdaptiveExecutionStrategy',
    
    # Unified management
    'UnifiedParallelManager',
    'UnifiedConfig',
    'ExecutionSummary',
    'get_unified_parallel_manager',
    'execute_plugin_tasks',
    'execute_analysis_tasks',
    'execute_custom_parallel',
    
    # Framework information
    '__version__',
    '__framework_name__',
    '__consolidation_status__'
]

# Backward compatibility aliases
ParallelAnalysisEngine = UnifiedParallelManager  # For parallel_analysis_engine.py compatibility
ParallelExecutionManager = UnifiedParallelManager  # For parallel_execution_manager.py compatibility
EnhancedParallelExecution = UnifiedParallelManager  # For enhanced_parallel_execution.py compatibility

def create_parallel_engine(max_workers: int = 4, memory_limit_gb: float = 8.0, 
                          execution_mode: str = "adaptive") -> UnifiedParallelManager:
    """
    Factory function for backward compatibility with parallel_analysis_engine.py
    
    Args:
        max_workers: Maximum number of worker threads/processes
        memory_limit_gb: Memory limit for parallel execution
        execution_mode: Execution mode preference
        
    Returns:
        Configured UnifiedParallelManager instance
    """
    config = UnifiedConfig(
        max_workers=max_workers,
        memory_limit_gb=memory_limit_gb,
        preferred_strategy=execution_mode if execution_mode != "adaptive" else None,
        enable_adaptive_selection=execution_mode == "adaptive"
    )
    
    return UnifiedParallelManager(config)

def run_parallel_analysis(apk_path: str, package_name: str, 
                         static_analysis_func: callable = None,
                         dynamic_analysis_func: callable = None,
                         open_windows: bool = False) -> ExecutionSummary:
    """
    Backward compatibility function for parallel_execution_manager.py
    
    Args:
        apk_path: Path to APK file
        package_name: Package name for analysis
        static_analysis_func: Static analysis function
        dynamic_analysis_func: Dynamic analysis function  
        open_windows: Whether to open separate windows (legacy parameter)
        
    Returns:
        ExecutionSummary with analysis results
    """
    # Create analysis context
    context = ExecutionContext(
        execution_id=f"parallel_analysis_{package_name}",
        config={
            'apk_path': apk_path,
            'package_name': package_name,
            'open_windows': open_windows
        }
    )
    
    # Set shared data
    context.set_shared_data('apk_path', apk_path)
    context.set_shared_data('package_name', package_name)
    
    # Execute analysis tasks
    return execute_analysis_tasks(
        static_function=static_analysis_func,
        dynamic_function=dynamic_analysis_func,
        apk_context=context
    )

def enhance_plugin_manager_with_parallel_execution(plugin_manager, 
                                                  parallel_engine: UnifiedParallelManager = None):
    """
    Backward compatibility function for enhancing PluginManager with parallel execution.
    
    Args:
        plugin_manager: Existing PluginManager instance
        parallel_engine: Optional unified parallel manager
        
    Returns:
        Enhanced PluginManager with parallel execution capabilities
    """
    if parallel_engine is None:
        parallel_engine = get_unified_parallel_manager()
    
    # Store original execute method
    original_execute = getattr(plugin_manager, 'execute_all_plugins', None)
    
    def execute_all_plugins_parallel(apk_ctx):
        """Enhanced execute_all_plugins with unified parallel execution."""
        # Get plugins from manager - SCAN PROFILE OPTIMIZATION APPLIED
        if hasattr(plugin_manager, 'get_plugin_metadata_optimized'):
            # Use scan profile optimized plugins (respects Lightning/Fast/Standard modes)
            plugins = plugin_manager.get_plugin_metadata_optimized()
        elif hasattr(plugin_manager, 'get_available_plugins'):
            plugins = plugin_manager.get_available_plugins()
        elif hasattr(plugin_manager, 'plugins'):
            plugins = list(plugin_manager.plugins.values())
        else:
            # Fallback to original execution if we can't get plugins
            if original_execute:
                return original_execute(apk_ctx)
            else:
                return {}
        
        # Create plugin tasks
        plugin_functions = []
        for plugin in plugins:
            if hasattr(plugin, 'run_function'):
                plugin_functions.append(plugin.run_function)
        
        # Execute with unified framework
        summary = execute_plugin_tasks(plugin_functions, apk_ctx)
        
        # Convert summary back to expected format
        return summary.results if hasattr(summary, 'results') else {}
    
    # Replace the method
    plugin_manager.execute_all_plugins = execute_all_plugins_parallel
    plugin_manager._unified_parallel_engine = parallel_engine
    
    # Add cleanup method
    original_cleanup = getattr(plugin_manager, 'cleanup', lambda: None)
    
    def cleanup_with_parallel():
        """Enhanced cleanup including parallel engine."""
        parallel_engine.cleanup()
        original_cleanup()
    
    plugin_manager.cleanup = cleanup_with_parallel
    
    return plugin_manager

# Framework status and information functions
def get_framework_info() -> dict:
    """Get comprehensive framework information."""
    return {
        'name': __framework_name__,
        'version': __version__,
        'consolidation_status': __consolidation_status__,
        'consolidated_files': [
            'parallel_analysis_engine.py (1,020 lines)',
            'parallel_execution_manager.py (711 lines)', 
            'enhanced_parallel_execution.py (481 lines)'
        ],
        'total_lines_consolidated': 2212,
        'strategies_available': [
            'PluginExecutionStrategy',
            'ProcessSeparationStrategy', 
            'RobustExecutionStrategy',
            'AdaptiveExecutionStrategy'
        ],
        'features': [
            'Intelligent strategy selection',
            'Resource-aware optimization',
            'Dependency management',
            'Process isolation',
            'Comprehensive error handling',
            'Performance monitoring',
            'Adaptive worker management',
            'Backward compatibility'
        ]
    }

def get_consolidation_report() -> dict:
    """Get detailed consolidation report."""
    return {
        'consolidation_type': 'Parallel Execution Unification',
        'recommendation_implemented': '#4 - Execution Management',
        'original_implementations': {
            'parallel_analysis_engine.py': {
                'lines': 1020,
                'focus': 'Plugin-level parallel execution with dependencies',
                'key_features': [
                    'Advanced plugin scheduler',
                    'Resource monitoring',
                    'Dependency analysis',
                    'Adaptive worker management'
                ]
            },
            'parallel_execution_manager.py': {
                'lines': 711,
                'focus': 'Process-level execution with IPC',
                'key_features': [
                    'Inter-process communication',
                    'Window management',
                    'Progress synchronization',
                    'Results aggregation'
                ]
            },
            'enhanced_parallel_execution.py': {
                'lines': 481,
                'focus': 'Robust execution with error handling',
                'key_features': [
                    'Timeout management',
                    'Enhanced error recovery',
                    'Deadlock prevention',
                    'Clean termination'
                ]
            }
        },
        'unified_framework': {
            'total_lines': 'Distributed across modular components',
            'strategies': 4,
            'components': 5,
            'benefits': [
                'Single unified interface',
                'Intelligent strategy selection',
                'Comprehensive error handling',
                'Resource optimization',
                'Performance monitoring',
                '100% backward compatibility'
            ]
        },
        'consolidation_achievements': [
            'Eliminated code duplication',
            'Unified execution interface',
            'Enhanced error handling',
            'Improved resource management',
            'monitoring',
            'Strategy pattern implementation'
        ]
    }

# Framework validation
def validate_framework() -> bool:
    """Validate that the unified framework is properly configured."""
    try:
        # Test framework initialization
        manager = get_unified_parallel_manager()
        
        # Test strategy availability
        strategies = manager.strategies
        expected_strategies = ['plugin_execution', 'process_separation', 'robust_execution']
        
        for strategy_name in expected_strategies:
            if strategy_name not in strategies:
                return False
        
        # Test basic execution capability
        test_task = ExecutionTask(
            task_id="validation_test",
            task_type="test",
            priority=100,
            payload={'function': lambda: "test_success", 'args': (), 'kwargs': {}}
        )
        
        # Quick validation execution
        context = ExecutionContext("validation")
        summary = manager.execute_parallel([test_task], context)
        
        return summary.success_rate > 0
        
    except Exception:
        return False

# Initialize framework on import
_framework_initialized = False

def _initialize_framework():
    """Initialize the unified framework on import."""
    global _framework_initialized
    
    if not _framework_initialized:
        try:
            # Pre-initialize the global manager
            get_unified_parallel_manager()
            _framework_initialized = True
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Framework initialization warning: {e}")

# Auto-initialize
_initialize_framework() 
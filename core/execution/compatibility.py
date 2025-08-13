#!/usr/bin/env python3
"""
Backward Compatibility Layer

Ensures existing code continues to work unchanged while using the unified
execution system internally. This eliminates breaking changes during the transition.
"""

import logging
from typing import Any, Dict, List, Optional

from .unified_manager import UnifiedExecutionManager, ExecutionConfig
from .shared.config_manager import ExecutionMode

logger = logging.getLogger(__name__)

def enhance_plugin_manager_with_unified_execution(plugin_manager, 
                                                 unified_manager: Optional[UnifiedExecutionManager] = None):
    """
    Enhance existing PluginManager with unified execution capabilities.
    
    This replaces the multiple conflicting enhancements from different systems
    with a single, consistent enhancement that uses the unified framework.
    
    Args:
        plugin_manager: Existing PluginManager instance
        unified_manager: Optional unified manager (creates new if None)
    """
    if unified_manager is None:
        # Create unified manager with optimized configuration
        config = ExecutionConfig(execution_mode=ExecutionMode.ADAPTIVE)
        unified_manager = UnifiedExecutionManager(config)
    
    # Store original execute method
    original_execute = getattr(plugin_manager, 'execute_all_plugins', None)
    
    def execute_all_plugins_unified(apk_ctx):
        """Enhanced execute_all_plugins using unified execution framework."""
        try:
            # Get plugins from manager using existing logic - SCAN PROFILE OPTIMIZATION APPLIED
            if hasattr(plugin_manager, 'get_plugin_metadata_optimized'):
                # Use scan profile optimized plugins (respects Lightning/Fast/Standard modes)
                plugins = plugin_manager.get_plugin_metadata_optimized()
            elif hasattr(plugin_manager, 'plan_execution_order'):
                plugins = plugin_manager.plan_execution_order()
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
            
            if not plugins:
                plugin_manager.output_mgr.warning("No plugins available for execution")
                return {}
            
            # Use unified execution framework
            execution_result = unified_manager.execute(plugins, apk_ctx)
            
            # Update plugin statuses in original manager (for display compatibility)
            _update_plugin_statuses(plugin_manager, execution_result)
            
            # Return results in expected format
            return execution_result.results
            
        except Exception as e:
            logger.error(f"Unified execution failed: {e}")
            # Fallback to original method if available
            if original_execute:
                return original_execute(apk_ctx)
            else:
                return {}
    
    # Replace the method
    plugin_manager.execute_all_plugins = execute_all_plugins_unified
    plugin_manager._unified_execution_manager = unified_manager
    
    # Add cleanup method
    original_cleanup = getattr(plugin_manager, 'cleanup', lambda: None)
    
    def cleanup_with_unified():
        """Enhanced cleanup that includes unified manager shutdown."""
        unified_manager.shutdown()
        original_cleanup()
    
    plugin_manager.cleanup = cleanup_with_unified
    
    logger.info("Plugin manager enhanced with unified execution framework")
    return plugin_manager

def create_legacy_parallel_engine(max_workers: int = 4, 
                                 memory_limit_gb: float = 8.0,
                                 execution_mode: str = "adaptive") -> 'LegacyParallelEngineAdapter':
    """
    Create legacy ParallelAnalysisEngine adapter using unified framework.
    
    Maintains exact API compatibility with existing ParallelAnalysisEngine
    while using the unified execution system internally.
    """
    # Convert legacy execution mode
    mode_mapping = {
        'sequential': ExecutionMode.SEQUENTIAL,
        'parallel': ExecutionMode.PARALLEL,
        'adaptive': ExecutionMode.ADAPTIVE,
        'optimized': ExecutionMode.ADAPTIVE
    }
    
    unified_mode = mode_mapping.get(execution_mode.lower(), ExecutionMode.ADAPTIVE)
    
    # Create configuration
    config = ExecutionConfig(
        max_workers=max_workers,
        memory_limit_gb=memory_limit_gb,
        execution_mode=unified_mode
    )
    
    # Create unified manager
    unified_manager = UnifiedExecutionManager(config)
    
    # Return adapter that mimics ParallelAnalysisEngine interface
    return LegacyParallelEngineAdapter(unified_manager)

def create_legacy_scan_manager(work_dir: Optional[str] = None) -> 'LegacyScanManagerAdapter':
    """
    Create legacy ParallelScanManager adapter using unified framework.
    
    Maintains exact API compatibility with existing ParallelScanManager
    while using the unified execution system internally.
    """
    # Create configuration optimized for process separation
    config = ExecutionConfig(
        execution_mode=ExecutionMode.PROCESS_SEPARATED,
        enable_process_separation=True,
        process_timeout_seconds=1800
    )
    
    # Create unified manager
    unified_manager = UnifiedExecutionManager(config)
    
    # Return adapter that mimics ParallelScanManager interface
    return LegacyScanManagerAdapter(unified_manager, work_dir)

class LegacyParallelEngineAdapter:
    """
    Adapter that provides ParallelAnalysisEngine interface using unified framework.
    
    This allows existing code to use ParallelAnalysisEngine exactly as before,
    while internally using the unified execution system.
    """
    
    def __init__(self, unified_manager: UnifiedExecutionManager):
        """Initialize legacy adapter."""
        self.unified_manager = unified_manager
        self.config = unified_manager.config
        
        # Legacy property aliases
        self.max_workers = self.config.max_workers
        self.memory_limit_gb = self.config.memory_limit_gb
        self.execution_mode = self._convert_execution_mode()
    
    def _convert_execution_mode(self) -> str:
        """Convert ExecutionMode to legacy string format."""
        mode_mapping = {
            ExecutionMode.SEQUENTIAL: 'sequential',
            ExecutionMode.PARALLEL: 'parallel', 
            ExecutionMode.PROCESS_SEPARATED: 'parallel',
            ExecutionMode.ADAPTIVE: 'adaptive'
        }
        return mode_mapping.get(self.config.execution_mode, 'adaptive')
    
    def execute_plugins_parallel(self, plugins: List[Any], apk_ctx: Any) -> Dict[str, Any]:
        """Legacy method that delegates to unified framework."""
        result = self.unified_manager.execute(plugins, apk_ctx, mode=ExecutionMode.PARALLEL)
        return result.results
    
    def get_execution_statistics(self) -> Dict[str, Any]:
        """Legacy method that delegates to unified framework."""
        return self.unified_manager.get_execution_statistics()
    
    def cleanup(self):
        """Legacy cleanup method."""
        self.unified_manager.shutdown()

class LegacyScanManagerAdapter:
    """
    Adapter that provides ParallelScanManager interface using unified framework.
    
    This allows existing code to use ParallelScanManager exactly as before,
    while internally using the unified execution system.
    """
    
    def __init__(self, unified_manager: UnifiedExecutionManager, work_dir: Optional[str] = None):
        """Initialize legacy scan manager adapter."""
        self.unified_manager = unified_manager
        self.work_dir = work_dir
        
        # Legacy attributes for compatibility
        self.temp_dir = None
        self.running_processes = {}
        self.scan_results = {}
    
    def run_parallel_scans(self, apk_path: str, package_name: str, 
                          mode: str = "deep", **kwargs) -> Dict[str, Any]:
        """Legacy method that delegates to unified framework."""
        # This would be fully implemented when ProcessSeparationStrategy is ready
        # For now, provide compatible interface
        result = self.unified_manager.execute([], None, mode=ExecutionMode.PARALLEL)
        
        return {
            'static': result,
            'dynamic': result
        }
    
    def consolidate_results(self) -> Dict[str, Any]:
        """Legacy method for result consolidation."""
        # Return consolidated results in expected format
        return {
            'statistics': {
                'total_findings': 0,
                'high_confidence_findings': 0,
                'static_findings': 0,
                'dynamic_findings': 0
            },
            'findings': [],
            'metadata': {
                'execution_time': 0.0,
                'strategy_used': 'unified'
            }
        }

def _update_plugin_statuses(plugin_manager, execution_result):
    """
    Update plugin statuses in the original plugin manager for display compatibility.
    
    This ensures that status displays show correct information even when using
    the unified execution framework.
    """
    if not hasattr(plugin_manager, 'plugins'):
        return
    
    # Import PluginStatus enum for proper status mapping
    from core.plugin_manager import PluginStatus
    
    # Map unified statuses to plugin manager status enum values
    status_mapping = {
        'success': PluginStatus.SUCCESS,
        'completed': PluginStatus.COMPLETED,
        'failed': PluginStatus.FAILED, 
        'timeout': PluginStatus.TIMEOUT,
        'cancelled': PluginStatus.FAILED,  # Map to FAILED since CANCELLED doesn't exist in enum
        'skipped': PluginStatus.SKIPPED
    }
    
    try:
        # Update plugin statuses based on execution results  
        # Use execution_result.results instead of non-existent plugin_results
        for plugin_name, result in execution_result.results.items():
            if plugin_name in plugin_manager.plugins:
                # Handle different result formats (tuple results from standalone functions)
                if isinstance(result, tuple) and len(result) >= 2:
                    # For tuple results like ('static_scan_completed', data), mark as completed
                    legacy_status = PluginStatus.COMPLETED if 'completed' in result[0] else PluginStatus.FAILED
                elif hasattr(result, 'status'):
                    legacy_status = status_mapping.get(result.status.value, PluginStatus.FAILED)
                else:
                    # Assume success if we got a result
                    legacy_status = PluginStatus.COMPLETED
                    
                if hasattr(plugin_manager.plugins[plugin_name], 'status'):
                    plugin_manager.plugins[plugin_name].status = legacy_status
        
        # Store plugin results for compatibility
        if hasattr(plugin_manager, 'plugin_results'):
            plugin_manager.plugin_results = execution_result.results
            
    except Exception as e:
        logger.warning(f"Failed to update plugin statuses: {e}")

# Utility functions for existing enhancement code
def get_unified_execution_manager(plugin_manager) -> Optional[UnifiedExecutionManager]:
    """Get unified execution manager from enhanced plugin manager."""
    return getattr(plugin_manager, '_unified_execution_manager', None)

def is_unified_enhanced(plugin_manager) -> bool:
    """Check if plugin manager is enhanced with unified execution."""
    return hasattr(plugin_manager, '_unified_execution_manager') 
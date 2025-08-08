#!/usr/bin/env python3
"""
Process Separation Execution Strategy

Multi-process execution strategy providing:
- Static and dynamic analysis isolation
- Enhanced fault tolerance through process boundaries
- Independent resource management per process
- Inter-process communication for coordination
"""

import logging
import multiprocessing as mp
import os
import signal
import time
from concurrent.futures import ProcessPoolExecutor, Future, as_completed
from typing import Any, Dict, List, Optional, Tuple

from .base_strategy import ExecutionStrategy, StrategyResult
from ..shared.plugin_executor import PluginExecutor, PluginExecutionResult, PluginStatus
from ..shared.config_manager import ExecutionConfig

logger = logging.getLogger(__name__)

class ProcessSeparationStrategy(ExecutionStrategy):
    """
    Process-based execution strategy for isolated plugin execution.
    
    This strategy provides maximum isolation by executing plugins in
    separate processes, with particular emphasis on static/dynamic
    analysis separation.
    """
    
    def __init__(self, config: ExecutionConfig, plugin_executor: PluginExecutor):
        """Initialize process separation strategy."""
        super().__init__(config, plugin_executor)
        self.strategy_name = "ProcessSeparation"
        
        # Process management
        self.max_processes = min(config.max_workers, mp.cpu_count())
        self.process_executor = None
        self._active_processes: Dict[Future, Any] = {}
        
        logger.info(f"Process separation strategy initialized with {self.max_processes} max processes")
    
    def can_execute(self, plugins: List[Any], context: Dict[str, Any]) -> bool:
        """Check if process separation is suitable for the given plugins."""
        # Process separation is suitable for:
        # 1. Mixed static/dynamic analysis
        # 2. Large plugin sets that benefit from isolation
        # 3. Potentially unstable plugins
        
        if len(plugins) < 2:
            return False  # Not worth the overhead for single plugin
        
        # Check if we have mixed analysis types
        static_plugins = self._count_static_plugins(plugins)
        dynamic_plugins = len(plugins) - static_plugins
        
        # Process separation is most beneficial for mixed workloads
        return static_plugins > 0 and dynamic_plugins > 0
    
    def execute(self, plugins: List[Any], apk_ctx: Any, 
               context: Optional[Dict[str, Any]] = None) -> StrategyResult:
        """
        Execute plugins using process separation.
        
        Args:
            plugins: List of plugins to execute
            apk_ctx: APK context for analysis
            context: Additional execution context
            
        Returns:
            StrategyResult with execution details
        """
        start_time = time.time()
        context = context or {}
        
        self.logger.info(f"Starting process separation execution of {len(plugins)} plugins")
        
        # Create strategy result
        result = StrategyResult(
            strategy_name=self.strategy_name,
            total_plugins=len(plugins),
            start_time=start_time
        )
        
        try:
            # Categorize plugins by analysis type
            static_plugins, dynamic_plugins = self._categorize_plugins(plugins)
            
            self.logger.info(f"Plugin categorization: {len(static_plugins)} static, {len(dynamic_plugins)} dynamic")
            
            # Execute with process separation
            if len(static_plugins) > 0 and len(dynamic_plugins) > 0:
                # True separation: static and dynamic in different processes
                results = self._execute_separated_analysis(static_plugins, dynamic_plugins, apk_ctx)
            else:
                # Single category: use process pool for parallelization
                results = self._execute_process_parallel(plugins, apk_ctx)
            
            result.plugin_results.update(results)
            
            # Calculate final statistics
            result.execution_time = time.time() - start_time
            result.successful_plugins = sum(1 for r in result.plugin_results.values() if r.success)
            result.failed_plugins = sum(1 for r in result.plugin_results.values() if r.failed)
            result.success = result.failed_plugins == 0
            
            self.logger.info(f"Process separation execution completed in {result.execution_time:.2f}s "
                           f"({result.successful_plugins}/{result.total_plugins} successful)")
            
        except Exception as e:
            result.execution_time = time.time() - start_time
            result.error = str(e)
            result.success = False
            self.logger.error(f"Process separation execution failed: {e}")
        finally:
            self._cleanup_processes()
        
        return result
    
    def _execute_separated_analysis(self, static_plugins: List[Any], dynamic_plugins: List[Any], 
                                   apk_ctx: Any) -> Dict[str, PluginExecutionResult]:
        """Execute static and dynamic plugins in separate processes."""
        results = {}
        
        # Use process pool for execution
        with ProcessPoolExecutor(max_workers=self.max_processes) as executor:
            # Submit static analysis process
            static_future = executor.submit(
                self._execute_plugins_in_process, 
                static_plugins, 
                apk_ctx, 
                "static"
            )
            
            # Submit dynamic analysis process  
            dynamic_future = executor.submit(
                self._execute_plugins_in_process, 
                dynamic_plugins, 
                apk_ctx, 
                "dynamic"
            )
            
            # Collect results
            futures = {
                static_future: "static",
                dynamic_future: "dynamic"
            }
            
            for future in as_completed(futures):
                process_type = futures[future]
                try:
                    process_results = future.result()
                    results.update(process_results)
                    self.logger.info(f"Process {process_type} completed with {len(process_results)} results")
                except Exception as e:
                    self.logger.error(f"Process {process_type} failed: {e}")
                    # Create error results for failed process
                    plugin_list = static_plugins if process_type == "static" else dynamic_plugins
                    for plugin in plugin_list:
                        plugin_name = self._get_plugin_name(plugin)
                        results[plugin_name] = PluginExecutionResult(
                            plugin_name=plugin_name,
                            status=PluginStatus.FAILED,
                            error=f"Process execution failed: {e}",
                            result=("❌ Process Error", f"Process {process_type} failed: {e}")
                        )
        
        return results
    
    def _execute_process_parallel(self, plugins: List[Any], apk_ctx: Any) -> Dict[str, PluginExecutionResult]:
        """Execute plugins in parallel using process pool."""
        results = {}
        
        with ProcessPoolExecutor(max_workers=self.max_processes) as executor:
            # Submit individual plugins to process pool
            future_to_plugin = {}
            for plugin in plugins:
                future = executor.submit(self._execute_single_plugin_in_process, plugin, apk_ctx)
                future_to_plugin[future] = plugin
            
            # Collect results as they complete
            for future in as_completed(future_to_plugin):
                plugin = future_to_plugin[future]
                plugin_name = self._get_plugin_name(plugin)
                
                try:
                    plugin_result = future.result()
                    results[plugin_name] = plugin_result
                    self.logger.debug(f"Plugin '{plugin_name}' completed in process")
                except Exception as e:
                    error_result = PluginExecutionResult(
                        plugin_name=plugin_name,
                        status=PluginStatus.FAILED,
                        error=str(e),
                        result=("❌ Process Error", f"Plugin execution failed: {e}")
                    )
                    results[plugin_name] = error_result
                    self.logger.error(f"Plugin '{plugin_name}' failed in process: {e}")
        
        return results
    
    @staticmethod
    def _execute_plugins_in_process(plugins: List[Any], apk_ctx: Any, process_type: str) -> Dict[str, PluginExecutionResult]:
        """Execute a group of plugins in a single process."""
        # This method runs in a separate process
        import logging
        process_logger = logging.getLogger(f"ProcessStrategy.{process_type}")
        
        results = {}
        
        for plugin in plugins:
            plugin_name = ProcessSeparationStrategy._get_plugin_name_static(plugin)
            try:
                # Handle ExecutionTask objects with function_name payloads
                if hasattr(plugin, 'payload') and isinstance(plugin.payload, dict):
                    payload = plugin.payload
                    if 'function_name' in payload:
                        function_name = payload['function_name']
                        args = payload.get('args', ())
                        kwargs = payload.get('kwargs', {})
                        
                        process_logger.debug(f"Executing ExecutionTask function by name: {function_name}")
                        
                        # Import and call the function by name
                        if function_name == 'execute_static_scan':
                            from core.execution.shared.plugin_executor import execute_static_scan
                            result = execute_static_scan(*args, **kwargs)
                        elif function_name == 'execute_dynamic_scan':
                            from core.execution.shared.plugin_executor import execute_dynamic_scan
                            result = execute_dynamic_scan(*args, **kwargs)
                        else:
                            raise ValueError(f"Unknown function name: {function_name}")
                    else:
                        raise AttributeError(f"ExecutionTask {plugin_name} has no function_name in payload")
                
                # Traditional plugin execution
                elif hasattr(plugin, 'run'):
                    result = plugin.run(apk_ctx)
                elif hasattr(plugin, 'module') and hasattr(plugin.module, 'run'):
                    result = plugin.module.run(apk_ctx)
                else:
                    raise AttributeError(f"Plugin {plugin_name} has no run method")
                
                plugin_result = PluginExecutionResult(
                    plugin_name=plugin_name,
                    status=PluginStatus.SUCCESS,
                    result=(f"✅ {plugin_name}", result)
                )
                results[plugin_name] = plugin_result
                
            except Exception as e:
                error_result = PluginExecutionResult(
                    plugin_name=plugin_name,
                    status=PluginStatus.FAILED,
                    error=str(e),
                    result=(f"❌ {plugin_name}", f"Error: {e}")
                )
                results[plugin_name] = error_result
                process_logger.error(f"Plugin {plugin_name} failed: {e}")
        
        return results
    
    @staticmethod
    def _execute_single_plugin_in_process(plugin: Any, apk_ctx: Any) -> PluginExecutionResult:
        """Execute a single plugin in a process."""
        plugin_name = ProcessSeparationStrategy._get_plugin_name_static(plugin)
        
        try:
            # Handle ExecutionTask objects with function_name payloads
            if hasattr(plugin, 'payload') and isinstance(plugin.payload, dict):
                payload = plugin.payload
                if 'function_name' in payload:
                    function_name = payload['function_name']
                    args = payload.get('args', ())
                    kwargs = payload.get('kwargs', {})
                    
                    # Import and call the function by name
                    if function_name == 'execute_static_scan':
                        from core.execution.shared.plugin_executor import execute_static_scan
                        result = execute_static_scan(*args, **kwargs)
                    elif function_name == 'execute_dynamic_scan':
                        from core.execution.shared.plugin_executor import execute_dynamic_scan
                        result = execute_dynamic_scan(*args, **kwargs)
                    else:
                        raise ValueError(f"Unknown function name: {function_name}")
                else:
                    raise AttributeError(f"ExecutionTask {plugin_name} has no function_name in payload")
            
            # Traditional plugin execution
            elif hasattr(plugin, 'run'):
                result = plugin.run(apk_ctx)
            elif hasattr(plugin, 'module') and hasattr(plugin.module, 'run'):
                result = plugin.module.run(apk_ctx)
            else:
                raise AttributeError(f"Plugin {plugin_name} has no run method")

            return PluginExecutionResult(
                plugin_name=plugin_name,
                status=PluginStatus.SUCCESS,
                result=(f"✅ {plugin_name}", result)
            )
            
        except Exception as e:
            return PluginExecutionResult(
                plugin_name=plugin_name,
                status=PluginStatus.FAILED,
                error=str(e),
                result=(f"❌ {plugin_name}", f"Error: {e}")
            )
    
    def _categorize_plugins(self, plugins: List[Any]) -> Tuple[List[Any], List[Any]]:
        """Categorize plugins into static and dynamic analysis."""
        static_plugins = []
        dynamic_plugins = []
        
        for plugin in plugins:
            if self._is_static_plugin(plugin):
                static_plugins.append(plugin)
            else:
                dynamic_plugins.append(plugin)
        
        return static_plugins, dynamic_plugins
    
    def _is_static_plugin(self, plugin: Any) -> bool:
        """Determine if plugin performs static analysis."""
        plugin_name = self._get_plugin_name(plugin).lower()
        
        # Static analysis patterns
        static_patterns = [
            'static', 'manifest', 'apk_structure', 'certificate', 
            'permission', 'decompiled', 'code_analysis', 'secret',
            'hardcoded', 'resource', 'asset'
        ]
        
        # Dynamic analysis patterns
        dynamic_patterns = [
            'dynamic', 'runtime', 'frida', 'network', 'traffic',
            'behavioral', 'monitoring', 'instrumentation'
        ]
        
        # Check for dynamic patterns first (more specific)
        for pattern in dynamic_patterns:
            if pattern in plugin_name:
                return False
        
        # Check for static patterns
        for pattern in static_patterns:
            if pattern in plugin_name:
                return True
        
        # Default to static for unknown plugins
        return True
    
    def _count_static_plugins(self, plugins: List[Any]) -> int:
        """Count static analysis plugins."""
        return sum(1 for plugin in plugins if self._is_static_plugin(plugin))
    
    def _get_plugin_name(self, plugin: Any) -> str:
        """Get plugin name from plugin object."""
        return self.plugin_executor._get_plugin_name(plugin)
    
    @staticmethod
    def _get_plugin_name_static(plugin: Any) -> str:
        """Static method to get plugin name (for use in processes)."""
        if hasattr(plugin, 'name'):
            return plugin.name
        elif hasattr(plugin, '__name__'):
            return plugin.__name__
        elif hasattr(plugin, '__class__'):
            return plugin.__class__.__name__
        else:
            return str(plugin)
    
    def _cleanup_processes(self):
        """Cleanup any remaining process resources."""
        if self.process_executor:
            self.process_executor.shutdown(wait=True)
            self.process_executor = None
        
        # Clear active processes
        self._active_processes.clear()
    
    def get_execution_characteristics(self) -> Dict[str, Any]:
        """Get characteristics specific to process separation."""
        return {
            'concurrency_level': self.max_processes,
            'isolation_level': 'maximum',
            'fault_tolerance': 'high',
            'resource_overhead': 'medium',
            'suitable_for': [
                'mixed_static_dynamic_analysis',
                'fault_isolation',
                'resource_isolation',
                'large_plugin_sets'
            ],
            'communication_overhead': 'medium'
        } 
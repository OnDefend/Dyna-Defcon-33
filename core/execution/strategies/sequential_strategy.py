#!/usr/bin/env python3
"""
Sequential Execution Strategy

Traditional one-by-one plugin execution strategy for:
- Resource-constrained environments
- Plugins requiring exclusive system access
- Debugging and troubleshooting scenarios
- Legacy compatibility mode
"""

import logging
import time
from typing import Any, Dict, List, Optional

from .base_strategy import ExecutionStrategy, StrategyResult
from ..shared.plugin_executor import PluginExecutor, PluginExecutionResult, PluginStatus
from ..shared.config_manager import ExecutionConfig

logger = logging.getLogger(__name__)

class SequentialExecutionStrategy(ExecutionStrategy):
    """
    Sequential execution strategy for one-by-one plugin execution.
    
    This strategy executes plugins sequentially without parallelization,
    providing maximum stability and resource predictability.
    """
    
    def __init__(self, config: ExecutionConfig, plugin_executor: PluginExecutor):
        """Initialize sequential execution strategy."""
        super().__init__(config, plugin_executor)
        self.strategy_name = "Sequential"
        
        logger.info("Sequential execution strategy initialized")
    
    def can_execute(self, plugins: List[Any], context: Dict[str, Any]) -> bool:
        """Check if sequential execution is suitable for the given plugins."""
        # Sequential execution can handle any set of plugins
        return True
    
    def execute(self, plugins: List[Any], apk_ctx: Any, 
               context: Optional[Dict[str, Any]] = None) -> StrategyResult:
        """
        Execute plugins sequentially one by one.
        
        Args:
            plugins: List of plugins to execute
            apk_ctx: APK context for analysis
            context: Additional execution context
            
        Returns:
            StrategyResult with execution details
        """
        start_time = time.time()
        context = context or {}
        
        self.logger.info(f"Starting sequential execution of {len(plugins)} plugins")
        
        # Create strategy result
        result = StrategyResult(
            strategy_name=self.strategy_name,
            total_plugins=len(plugins),
            start_time=start_time
        )
        
        try:
            # Execute plugins one by one
            for i, plugin in enumerate(plugins, 1):
                plugin_name = self.plugin_executor._get_plugin_name(plugin)
                
                self.logger.info(f"Executing plugin {i}/{len(plugins)}: {plugin_name}")
                
                try:
                    # Execute single plugin
                    plugin_result = self._execute_single_plugin(plugin, apk_ctx)
                    result.plugin_results[plugin_name] = plugin_result
                    
                    self.logger.debug(f"Plugin '{plugin_name}' completed: {plugin_result.status.value}")
                    
                except Exception as e:
                    # Create error result for failed plugin
                    error_result = PluginExecutionResult(
                        plugin_name=plugin_name,
                        status=PluginStatus.FAILED,
                        error=str(e),
                        result=self.plugin_executor._create_error_result(plugin_name, str(e))
                    )
                    result.plugin_results[plugin_name] = error_result
                    self.logger.error(f"Plugin '{plugin_name}' failed in sequential execution: {e}")
                
                # Brief pause between plugins for system stability
                if i < len(plugins):
                    time.sleep(0.1)
            
            # Calculate final statistics
            result.execution_time = time.time() - start_time
            result.successful_plugins = sum(1 for r in result.plugin_results.values() if r.success)
            result.failed_plugins = sum(1 for r in result.plugin_results.values() if r.failed)
            result.success = result.failed_plugins == 0
            
            self.logger.info(f"Sequential execution completed in {result.execution_time:.2f}s "
                           f"({result.successful_plugins}/{result.total_plugins} successful)")
            
        except Exception as e:
            result.execution_time = time.time() - start_time
            result.error = str(e)
            result.success = False
            self.logger.error(f"Sequential execution failed: {e}")
        
        return result
    
    def _execute_single_plugin(self, plugin: Any, apk_ctx: Any) -> PluginExecutionResult:
        """Execute a single plugin using the unified plugin executor."""
        return self.plugin_executor.execute_plugin(plugin, apk_ctx)
    
    def get_execution_characteristics(self) -> Dict[str, Any]:
        """Get characteristics specific to sequential execution."""
        return {
            'concurrency_level': 1,
            'resource_usage': 'minimal',
            'memory_overhead': 'low',
            'stability': 'maximum',
            'debugging_friendly': True,
            'suitable_for': [
                'resource_constrained_systems',
                'debugging_scenarios',
                'legacy_compatibility',
                'exclusive_access_plugins'
            ]
        }
    
    def supports_plugin_type(self, plugin: Any) -> bool:
        """Check if this strategy supports the given plugin type."""
        # Sequential strategy supports all plugin types
        return True 
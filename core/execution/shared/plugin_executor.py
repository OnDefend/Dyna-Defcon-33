#!/usr/bin/env python3
"""
Unified Plugin Executor

Consolidates all plugin execution logic from different execution systems.
Eliminates duplication while providing consistent plugin execution behavior.
"""

import inspect
import logging
import time
import traceback
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from rich.text import Text

from .timeout_manager import TimeoutManager, TimeoutType, TimeoutContext

logger = logging.getLogger(__name__)

def execute_static_scan(apk_path: str, package_name: str, mode: str, vulnerable_app_mode: bool, timeout: int = 1800):
    """Standalone static analysis execution function for process separation."""
    try:
        logger.info(f"🔍 Executing static analysis for {package_name}")
        
        # Import APK context and create minimal setup for plugin execution
        from core.apk_ctx import APKContext
        from core.plugin_manager import create_plugin_manager
        
        # Create APK context for analysis
        apk_ctx = APKContext(apk_path_str=apk_path, package_name=package_name)
        apk_ctx.set_scan_mode(mode)
        apk_ctx.vulnerable_app_mode = vulnerable_app_mode
        
        # Create plugin manager with scan optimization
        plugin_manager = create_plugin_manager(
            scan_mode=mode,
            vulnerable_app_mode=vulnerable_app_mode
        )
        
        logger.info(f"🔧 Running {len(plugin_manager.plugins)} static analysis plugins")
        
        # Execute all plugins
        plugin_results = plugin_manager.execute_all_plugins(apk_ctx)
        
        # Convert plugin results to structured format
        static_results = {
            'scan_type': 'static',
            'package_name': package_name,
            'apk_path': apk_path,
            'plugin_results': plugin_results,
            'external_vulnerabilities': [],
            'vulnerabilities': [],
            'metadata': {
                'scan_duration': timeout,
                'analysis_type': 'static',
                'plugins_executed': len(plugin_results),
                'findings_count': len(plugin_results)
            }
        }
        
        # Extract vulnerabilities from plugin results
        for plugin_name, (title, content) in plugin_results.items():
            # Create vulnerability entry for each plugin result
            vuln_entry = {
                'title': title,
                'description': str(content),
                'severity': 'MEDIUM',  # Default severity
                'category': 'STATIC_ANALYSIS',
                'plugin': plugin_name,
                'source': 'static_scan'
            }
            static_results['external_vulnerabilities'].append(vuln_entry)
        
        logger.info(f"✅ Static analysis completed: {len(plugin_results)} plugins executed")
        return ('static_scan_completed', static_results)
        
    except Exception as e:
        logger.error(f"❌ Static analysis failed: {e}")
        return ('static_scan_failed', {'error': str(e)})

def execute_dynamic_scan(apk_path: str, package_name: str, mode: str, vulnerable_app_mode: bool, timeout: int = 1800):
    """Standalone dynamic analysis execution function for process separation."""
    try:
        logger.info(f"🔧 Executing dynamic analysis for {package_name}")
        
        # Import APK context and create minimal setup for plugin execution
        from core.apk_ctx import APKContext
        from core.plugin_manager import create_plugin_manager
        
        # Create APK context for analysis
        apk_ctx = APKContext(apk_path_str=apk_path, package_name=package_name)
        apk_ctx.set_scan_mode(mode)
        apk_ctx.vulnerable_app_mode = vulnerable_app_mode
        
        # Create plugin manager with scan optimization
        plugin_manager = create_plugin_manager(
            scan_mode=mode,
            vulnerable_app_mode=vulnerable_app_mode
        )
        
        logger.info(f"🔧 Running {len(plugin_manager.plugins)} dynamic analysis plugins")
        
        # Execute all plugins  
        plugin_results = plugin_manager.execute_all_plugins(apk_ctx)
        
        # Convert plugin results to structured format
        dynamic_results = {
            'scan_type': 'dynamic',
            'package_name': package_name,
            'apk_path': apk_path,
            'plugin_results': plugin_results,
            'external_vulnerabilities': [],
            'vulnerabilities': [],
            'metadata': {
                'scan_duration': timeout,
                'analysis_type': 'dynamic',
                'plugins_executed': len(plugin_results),
                'findings_count': len(plugin_results)
            }
        }
        
        # ENHANCED: Extract structured vulnerabilities using new extractor
        try:
            from core.dynamic_vulnerability_extractor import DynamicVulnerabilityExtractor
            
            vulnerability_extractor = DynamicVulnerabilityExtractor()
            
            # Create structured scan results for the extractor
            structured_results = {
                'results': {
                    plugin_name: {'title': title, 'result': content} 
                    for plugin_name, (title, content) in plugin_results.items()
                }
            }
            
            # Extract structured vulnerabilities
            structured_vulnerabilities = vulnerability_extractor.extract_vulnerabilities_from_scan_results(
                structured_results, apk_ctx
            )
            
            logger.info(f"🔍 Extracted {len(structured_vulnerabilities)} structured vulnerabilities from dynamic analysis")
            
            # Convert BaseVulnerability objects to dictionaries for JSON serialization
            for vuln in structured_vulnerabilities:
                vuln_dict = vuln.to_dict()
                dynamic_results['vulnerabilities'].append(vuln_dict)
            
            # Update metadata with structured vulnerability count
            dynamic_results['metadata']['structured_vulnerabilities'] = len(structured_vulnerabilities)
            dynamic_results['metadata']['findings_count'] = len(structured_vulnerabilities)
            
        except Exception as e:
            logger.warning(f"⚠️ Structured vulnerability extraction failed: {e}")
            logger.info("📄 Falling back to basic vulnerability extraction")
            
            # Fallback: Basic vulnerability extraction (original method)
            for plugin_name, (title, content) in plugin_results.items():
                # Create vulnerability entry for each plugin result
                vuln_entry = {
                    'title': title,
                    'description': str(content),
                    'severity': 'HIGH',  # Dynamic analysis typically higher severity
                    'category': 'DYNAMIC_ANALYSIS',
                    'plugin': plugin_name,
                    'source': 'dynamic_scan'
                }
                dynamic_results['external_vulnerabilities'].append(vuln_entry)
        
        logger.info(f"✅ Dynamic analysis completed: {len(plugin_results)} plugins executed")
        return ('dynamic_scan_completed', dynamic_results)
        
    except Exception as e:
        logger.error(f"❌ Dynamic analysis failed: {e}")
        return ('dynamic_scan_failed', {'error': str(e)})

class PluginStatus(Enum):
    """Unified plugin status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"

@dataclass
class PluginExecutionResult:
    """
    Unified plugin execution result structure.
    
    Consolidates result formats from different execution systems.
    """
    plugin_name: str
    status: PluginStatus
    result: Optional[Tuple[str, Union[str, Text]]] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    timeout_used: int = 0
    memory_used_mb: float = 0.0
    
    @property
    def success(self) -> bool:
        """Check if plugin execution was successful."""
        return self.status == PluginStatus.SUCCESS
    
    @property
    def failed(self) -> bool:
        """Check if plugin execution failed."""
        return self.status in [PluginStatus.FAILED, PluginStatus.TIMEOUT, PluginStatus.CANCELLED]

class PluginExecutor:
    """
    Unified plugin executor eliminating execution logic duplication.
    
    Consolidates plugin execution from:
    - ParallelAnalysisEngine._execute_plugin_safe()
    - RobustPluginExecutionManager._execute_plugin_robust()
    - UnifiedPluginExecutionManager._execute_plugin()
    - Individual plugin ThreadPoolExecutor implementations
    """
    
    def __init__(self, timeout_manager: Optional[TimeoutManager] = None):
        """Initialize unified plugin executor."""
        self.timeout_manager = timeout_manager or TimeoutManager()
        self.logger = logging.getLogger(__name__)
        
        # Execution statistics
        self._execution_stats = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'timeout_executions': 0,
            'total_execution_time': 0.0
        }
        
        self.logger.info("Unified plugin executor initialized")
    
    def execute_plugin(self, plugin: Any, apk_ctx: Any, 
                      timeout_seconds: Optional[int] = None,
                      deep_mode: bool = True) -> PluginExecutionResult:
        """
        Execute a single plugin with unified timeout and error handling.
        
        Args:
            plugin: Plugin object or function to execute
            apk_ctx: APK context for analysis
            timeout_seconds: Custom timeout override
            deep_mode: Whether to run in deep analysis mode
            
        Returns:
            PluginExecutionResult with execution details
        """
        plugin_name = self._get_plugin_name(plugin)
        
        # Determine timeout
        if timeout_seconds is None:
            timeout_seconds = self._get_plugin_timeout(plugin)
        
        # Create execution result
        result = PluginExecutionResult(
            plugin_name=plugin_name,
            status=PluginStatus.PENDING,
            timeout_used=timeout_seconds
        )
        
        # Track execution statistics
        self._execution_stats['total_executions'] += 1
        
        try:
            # Execute with timeout protection
            with self.timeout_manager.timeout_context(
                operation_name=f"plugin_{plugin_name}",
                timeout_seconds=timeout_seconds,
                operation_type=TimeoutType.PLUGIN
            ) as timeout_ctx:
                
                result.status = PluginStatus.RUNNING
                start_time = time.time()
                
                # Execute the plugin function
                plugin_result = self._execute_plugin_function(plugin, apk_ctx, deep_mode)
                
                # Calculate execution time
                result.execution_time = time.time() - start_time
                
                # Process and validate result
                result.result = self._process_plugin_result(plugin_name, plugin_result)
                result.status = PluginStatus.SUCCESS
                
                self._execution_stats['successful_executions'] += 1
                self._execution_stats['total_execution_time'] += result.execution_time
                
                self.logger.debug(f"Plugin '{plugin_name}' executed successfully in {result.execution_time:.2f}s")
        
        except Exception as e:
            result.execution_time = time.time() - start_time if 'start_time' in locals() else 0.0
            
            # Determine failure type
            if "timeout" in str(e).lower() or "TimeoutError" in str(type(e).__name__):
                result.status = PluginStatus.TIMEOUT
                result.error = f"Plugin execution timed out after {timeout_seconds}s"
                self._execution_stats['timeout_executions'] += 1
                self.logger.warning(f"Plugin '{plugin_name}' timed out after {timeout_seconds}s")
            else:
                result.status = PluginStatus.FAILED
                result.error = str(e)
                self._execution_stats['failed_executions'] += 1
                self.logger.error(f"Plugin '{plugin_name}' failed: {e}")
            
            # Create error result
            result.result = self._create_error_result(plugin_name, result.error)
        
        return result
    
    def _execute_plugin_function(self, plugin: Any, apk_ctx: Any, deep_mode: bool = False) -> Any:
        """
        Execute plugin function with unified handling.
        
        Supports both traditional plugin objects and ExecutionTask objects.
        """
        # Check if this is an ExecutionTask with a function payload
        if hasattr(plugin, 'payload') and isinstance(plugin.payload, dict):
            payload = plugin.payload
            
            # Handle function_name for process separation (picklable)
            if 'function_name' in payload:
                function_name = payload['function_name']
                args = payload.get('args', ())
                kwargs = payload.get('kwargs', {})
                
                self.logger.debug(f"Executing ExecutionTask function by name: {function_name}")
                
                # Call the function by name from the global scan functions
                if function_name == 'execute_static_scan':
                    return execute_static_scan(*args, **kwargs)
                elif function_name == 'execute_dynamic_scan':
                    return execute_dynamic_scan(*args, **kwargs)
                else:
                    raise ValueError(f"Unknown function name: {function_name}")
            
            # Handle direct function references (for thread-based execution)
            elif 'function' in payload:
                func = payload['function']
                args = payload.get('args', ())
                kwargs = payload.get('kwargs', {})
                
                self.logger.debug(f"Executing ExecutionTask function: {func.__name__}")
                
                # Call the function with extracted arguments
                return func(*args, **kwargs)
        
        # NEW: Check if this is a PluginMetadata object - extract the module
        if hasattr(plugin, 'module') and plugin.module is not None:
            self.logger.debug(f"Extracting module from PluginMetadata for {self._get_plugin_name(plugin)}")
            plugin = plugin.module
        
        # Traditional plugin execution logic
        # Try different common plugin execution patterns
        
        # First check for object methods (traditional plugin objects)
        if hasattr(plugin, 'execute') and callable(getattr(plugin, 'execute')):
            return plugin.execute(apk_ctx, deep_mode)
        elif hasattr(plugin, 'run') and callable(getattr(plugin, 'run')):
            return plugin.run(apk_ctx)
        elif hasattr(plugin, '__call__'):
            return plugin(apk_ctx)
        elif hasattr(plugin, 'run_function') and callable(getattr(plugin, 'run_function')):
            return plugin.run_function(apk_ctx)
        
        # Check for module-level functions (when plugin is a module object)
        elif hasattr(plugin, 'run_plugin') and callable(getattr(plugin, 'run_plugin')):
            self.logger.debug(f"Executing module-level run_plugin function for {self._get_plugin_name(plugin)}")
            return plugin.run_plugin(apk_ctx)
        elif hasattr(plugin, 'run') and callable(getattr(plugin, 'run')):
            self.logger.debug(f"Executing module-level run function for {self._get_plugin_name(plugin)}")
            return plugin.run(apk_ctx)
        
        # If no standard execution method found, try to call it directly
        elif callable(plugin):
            return plugin(apk_ctx)
        else:
            # Enhanced error message with available attributes for debugging
            available_attrs = [attr for attr in dir(plugin) if not attr.startswith('_') and callable(getattr(plugin, attr, None))]
            self.logger.debug(f"Plugin {self._get_plugin_name(plugin)} available callable attributes: {available_attrs}")
            raise AttributeError(f"Plugin {self._get_plugin_name(plugin)} has no callable execution method. Available: {available_attrs[:5]}")
    
    def _get_plugin_name(self, plugin: Any) -> str:
        """Extract plugin name from plugin object."""
        # Check if this is an ExecutionTask
        if hasattr(plugin, 'task_id'):
            return plugin.task_id
        elif hasattr(plugin, 'task_type'):
            return f"ExecutionTask_{plugin.task_type}"
        
        # Try various attributes to get the name
        name_attrs = ['name', 'plugin_name', 'module_name', '__name__', '__class__.__name__']
        
        for attr in name_attrs:
            if '.' in attr:
                # Handle nested attributes like __class__.__name__
                obj = plugin
                for part in attr.split('.'):
                    if hasattr(obj, part):
                        obj = getattr(obj, part)
                    else:
                        obj = None
                        break
                if obj and isinstance(obj, str):
                    return obj
            else:
                if hasattr(plugin, attr):
                    value = getattr(plugin, attr)
                    if isinstance(value, str):
                        return value
        
        # Fallback to string representation
        return str(plugin)
    
    def _get_plugin_timeout(self, plugin: Any) -> int:
        """Determine appropriate timeout for plugin."""
        # Check if plugin specifies its own timeout
        timeout_attrs = ['timeout', 'timeout_seconds', 'execution_timeout']
        
        for attr in timeout_attrs:
            if hasattr(plugin, attr):
                timeout = getattr(plugin, attr)
                if isinstance(timeout, (int, float)) and timeout > 0:
                    return int(timeout)
        
        # Check for heavy plugins that need longer timeouts
        plugin_name = self._get_plugin_name(plugin).lower()
        heavy_plugin_patterns = [
            ('jadx', 900),      # JADX needs 15 minutes
            ('frida', 300),     # Frida needs 5 minutes
            ('dynamic', 240),   # Dynamic analysis needs 4 minutes
            ('apk2url', 180),   # APK2URL needs 3 minutes
            ('decompil', 600),  # Decompilation needs 10 minutes
        ]
        
        for pattern, timeout in heavy_plugin_patterns:
            if pattern in plugin_name:
                return timeout
        
        # Default timeout from configuration
        return self.timeout_manager.config.plugin_timeout
    
    def _process_plugin_result(self, plugin_name: str, raw_result: Any) -> Tuple[str, Union[str, Text]]:
        """
        Process and validate plugin result into consistent format.
        
        Consolidates result processing from different execution systems.
        """
        # Handle None results
        if raw_result is None:
            return (plugin_name, "No results found")
        
        # Handle tuple results (most common format)
        if isinstance(raw_result, tuple):
            if len(raw_result) == 2:
                title, content = raw_result
                return (str(title), content)
            elif len(raw_result) == 1:
                return (plugin_name, raw_result[0])
            else:
                # Handle unexpected tuple length
                return (plugin_name, str(raw_result))
        
        # Handle string results
        if isinstance(raw_result, str):
            return (plugin_name, raw_result)
        
        # Handle Rich Text results
        if hasattr(raw_result, 'markup') or isinstance(raw_result, Text):
            return (plugin_name, raw_result)
        
        # Handle dict results (convert to readable format)
        if isinstance(raw_result, dict):
            if 'title' in raw_result and 'content' in raw_result:
                return (raw_result['title'], raw_result['content'])
            else:
                # Convert dict to readable string
                content = self._format_dict_result(raw_result)
                return (plugin_name, content)
        
        # Handle list results
        if isinstance(raw_result, list):
            if len(raw_result) == 0:
                return (plugin_name, "No findings detected")
            else:
                content = self._format_list_result(raw_result)
                return (plugin_name, content)
        
        # Fallback to string conversion
        return (plugin_name, str(raw_result))
    
    def _format_dict_result(self, result_dict: Dict[str, Any]) -> str:
        """Format dictionary result into readable string."""
        if not result_dict:
            return "No findings detected"
        
        lines = []
        for key, value in result_dict.items():
            if isinstance(value, (list, dict)):
                lines.append(f"{key}: {len(value) if isinstance(value, list) else 'complex object'}")
            else:
                lines.append(f"{key}: {value}")
        
        return "\n".join(lines)
    
    def _format_list_result(self, result_list: List[Any]) -> str:
        """Format list result into readable string."""
        if not result_list:
            return "No findings detected"
        
        # If list contains simple strings, join them
        if all(isinstance(item, str) for item in result_list):
            return "\n".join(result_list)
        
        # Otherwise, summarize the list
        return f"Found {len(result_list)} items: {', '.join(str(item)[:50] for item in result_list[:3])}{'...' if len(result_list) > 3 else ''}"
    
    def _create_error_result(self, plugin_name: str, error_message: str) -> Tuple[str, Text]:
        """Create formatted error result."""
        error_title = f"❌ {plugin_name}"
        error_content = Text(f"Error: {error_message}", style="red")
        return (error_title, error_content)
    
    def get_execution_statistics(self) -> Dict[str, Any]:
        """Get plugin execution statistics."""
        stats = self._execution_stats.copy()
        
        # Calculate derived statistics
        total = stats['total_executions']
        if total > 0:
            stats['success_rate'] = stats['successful_executions'] / total
            stats['failure_rate'] = stats['failed_executions'] / total
            stats['timeout_rate'] = stats['timeout_executions'] / total
            stats['average_execution_time'] = stats['total_execution_time'] / stats['successful_executions'] if stats['successful_executions'] > 0 else 0.0
        else:
            stats['success_rate'] = 0.0
            stats['failure_rate'] = 0.0
            stats['timeout_rate'] = 0.0
            stats['average_execution_time'] = 0.0
        
        return stats
    
    def reset_statistics(self):
        """Reset execution statistics."""
        self._execution_stats = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'timeout_executions': 0,
            'total_execution_time': 0.0
        }

def create_plugin_executor(timeout_manager: Optional[TimeoutManager] = None) -> PluginExecutor:
    """Factory function to create plugin executor."""
    return PluginExecutor(timeout_manager) 
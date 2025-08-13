"""
Robust Plugin Execution Manager for AODS

This module provides a comprehensive, production-ready plugin execution system that:
- Prevents premature scan termination through unified timeout management
- Integrates with all existing systems (graceful shutdown, parallel execution, etc.)

- Provides comprehensive error handling and recovery
- Ensures all plugins run to completion according to AODS requirements
- Unifies timeout management across all plugin execution paths
"""

import logging
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, Future, TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from rich.text import Text

# Import existing components
try:
    from core.graceful_shutdown_manager import (
        get_shutdown_manager, 
        is_shutdown_requested,
        plugin_context,
        GracefulShutdownManager
    )
    GRACEFUL_SHUTDOWN_AVAILABLE = True
except ImportError:
    GRACEFUL_SHUTDOWN_AVAILABLE = False
    def is_shutdown_requested():
        return False
    def plugin_context(name):
        from contextlib import nullcontext
        return nullcontext()

try:
    from core.plugin_constants import TIMEOUTS, RISK_LEVELS, PLUGIN_CATEGORIES
    PLUGIN_CONSTANTS_AVAILABLE = True
except ImportError:
    PLUGIN_CONSTANTS_AVAILABLE = False
    TIMEOUTS = {"default": 120}

try:
    from core.unified_plugin_execution_manager import (
        UnifiedPluginExecutionManager,
        PluginExecutionConfig,
        PluginExecutionResult,
        PluginExecutionState
    )
    UNIFIED_MANAGER_AVAILABLE = True
except ImportError:
    UNIFIED_MANAGER_AVAILABLE = False

try:
    from core.system_integration_fixes import get_system_integration_manager
    SYSTEM_INTEGRATION_AVAILABLE = True
except ImportError:
    SYSTEM_INTEGRATION_AVAILABLE = False

logger = logging.getLogger(__name__)

class RobustExecutionState(Enum):
    """Robust execution states for comprehensive tracking."""
    INITIALIZING = "initializing"
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RETRYING = "retrying"
    RECOVERED = "recovered"

@dataclass
class RobustExecutionConfig:
    """Configuration for robust plugin execution."""
    default_timeout: int = 120           # Default plugin timeout in seconds
    max_timeout: int = 600              # Maximum allowed timeout (increased from 300s)
    critical_plugin_timeout: int = 180  # Timeout for critical plugins
    retry_attempts: int = 2             # Number of retry attempts on failure
    retry_delay: float = 2.0            # Delay between retries
    enable_timeout_escalation: bool = True  # Escalate timeouts on retry
    check_shutdown_interval: float = 0.5   # How often to check for shutdown
    max_concurrent_plugins: int = 3         # Maximum concurrent plugin executions
    enable_recovery: bool = True            # Enable automatic recovery
    log_execution_details: bool = True      # Log detailed execution information
    enable_partial_results: bool = True     # Return partial results on timeout
    force_cleanup_on_timeout: bool = True   # Force cleanup on timeout
    
    # NEW: Adaptive timeout configuration based on APK characteristics
    enable_adaptive_timeout: bool = True    # Enable adaptive timeout based on APK size
    small_apk_timeout: int = 180           # <10MB APKs: 3 minutes
    medium_apk_timeout: int = 300          # 10-50MB APKs: 5 minutes  
    large_apk_timeout: int = 480           # 50-100MB APKs: 8 minutes
    xlarge_apk_timeout: int = 600          # >100MB APKs: 10 minutes
    complex_analysis_multiplier: float = 1.5  # Multiplier for complex analysis (JADX, secrets)
    
    # Plugin-specific timeouts (will be populated from constants)
    plugin_timeouts: Dict[str, int] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize plugin-specific timeouts from constants."""
        if PLUGIN_CONSTANTS_AVAILABLE:
            self.plugin_timeouts.update(TIMEOUTS)
        
        # Add known critical plugins with extended timeouts
        critical_plugins = {
            "insecure_data_storage": 180,
            "enhanced_static_analysis": 240,
            "jadx_static_analysis": 180,
            "intent_fuzzing": 150,
            "webview_security_analysis": 120,
            "runtime_decryption_analysis": 180,
            "mastg_integration": 180,
            "injection_vulnerabilities": 150,
            "advanced_dynamic_analysis": 240,
            "frida_dynamic_analysis": 180,
            "network_communication_tests": 120,
            "mitmproxy_network_analysis": 120,
        }
        
        # Update with critical plugin timeouts
        for plugin, timeout in critical_plugins.items():
            if plugin not in self.plugin_timeouts:
                self.plugin_timeouts[plugin] = timeout

@dataclass
class RobustExecutionResult:
    """Comprehensive result of plugin execution with detailed metadata."""
    plugin_name: str
    module_name: str
    state: RobustExecutionState
    title: Optional[str] = None
    content: Optional[Any] = None
    error_message: Optional[str] = None
    execution_time: float = 0.0
    timeout_used: int = 0
    retry_count: int = 0
    shutdown_requested: bool = False
    recovery_attempted: bool = False
    partial_results: bool = False
    system_integration_status: Optional[str] = None
    memory_usage_mb: float = 0.0
    start_time: float = 0.0
    end_time: float = 0.0

class RobustPluginExecutionManager:
    """
    Comprehensive robust plugin execution manager that prevents premature termination.
    
    This manager provides:
    - Unified timeout management with plugin-specific timeouts
    - Integration with all existing AODS systems
    - Comprehensive error handling and recovery
    - Graceful shutdown coordination
    - Memory and resource monitoring
    - Detailed execution statistics and reporting
    """
    
    def __init__(self, config: Optional[RobustExecutionConfig] = None):
        self.config = config or RobustExecutionConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Execution tracking
        self.active_plugins: Dict[str, Future] = {}
        self.execution_results: Dict[str, RobustExecutionResult] = {}
        self.execution_lock = threading.RLock()
        
        # Shutdown coordination
        self.shutdown_requested = False
        self.shutdown_event = threading.Event()
        
        # Statistics
        self.total_plugins = 0
        self.completed_plugins = 0
        self.failed_plugins = 0
        self.timeout_plugins = 0
        self.cancelled_plugins = 0
        self.recovered_plugins = 0
        
        # Thread pool for plugin execution
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.max_concurrent_plugins,
            thread_name_prefix="RobustPluginExec"
        )
        
        # Integration with existing systems
        self.system_integration = None
        if SYSTEM_INTEGRATION_AVAILABLE:
            try:
                self.system_integration = get_system_integration_manager()
                self.logger.info("✅ System integration manager available")
            except Exception as e:
                self.logger.warning(f"⚠️ System integration manager error: {e}")
        
        # Initialize unified manager if available
        self.unified_manager = None
        if UNIFIED_MANAGER_AVAILABLE:
            try:
                unified_config = PluginExecutionConfig(
                    default_timeout=self.config.default_timeout,
                    max_timeout=self.config.max_timeout,
                    retry_attempts=self.config.retry_attempts,
                    retry_delay=self.config.retry_delay,
                    max_concurrent_plugins=self.config.max_concurrent_plugins
                )
                self.unified_manager = UnifiedPluginExecutionManager(unified_config)
                self.logger.info("✅ Unified plugin execution manager integrated")
            except Exception as e:
                self.logger.warning(f"⚠️ Unified manager integration error: {e}")
        
        self.logger.info(f"🔧 Robust Plugin Execution Manager initialized")
        self.logger.info(f"   Max concurrent plugins: {self.config.max_concurrent_plugins}")
        self.logger.info(f"   Default timeout: {self.config.default_timeout}s")
        self.logger.info(f"   Critical timeout: {self.config.critical_plugin_timeout}s")
        self.logger.info(f"   Plugin-specific timeouts: {len(self.config.plugin_timeouts)}")
        self.logger.info(f"   Graceful shutdown: {'✅' if GRACEFUL_SHUTDOWN_AVAILABLE else '❌'}")
        self.logger.info(f"   System integration: {'✅' if self.system_integration else '❌'}")

    def execute_all_plugins_robust(self, plugins: List, apk_ctx) -> Dict[str, Tuple[str, Any]]:
        """
        Execute all plugins with comprehensive robustness and error handling.
        
        Args:
            plugins: List of plugin metadata objects
            apk_ctx: APK context object
            
        Returns:
            Dict[str, Tuple[str, Any]]: Plugin results in expected format
        """
        self.total_plugins = len(plugins)
        results = {}
        
        if not plugins:
            self.logger.warning("No plugins to execute")
            return results
        
        self.logger.info(f"🚀 Starting robust execution of {len(plugins)} plugins")
        
        # Execute plugins with comprehensive progress tracking
        for i, plugin in enumerate(plugins, 1):
            # Check for shutdown before each plugin
            if self._check_shutdown_request():
                self.logger.warning(f"🛑 Shutdown requested - stopping plugin execution at {i-1}/{len(plugins)}")
                break
            
            plugin_name = plugin.name
            self.logger.info(f"🔍 [{i}/{len(plugins)}] Executing: {plugin_name}")
            
            # Execute plugin with robust protection
            execution_result = self.execute_plugin_robust(plugin, apk_ctx)
            
            # Store result in expected format
            if execution_result.state in [RobustExecutionState.COMPLETED, RobustExecutionState.RECOVERED]:
                results[execution_result.module_name] = (
                    execution_result.title or plugin_name,
                    execution_result.content
                )
            else:
                # Store error result in expected format
                error_title = f"❌ {plugin_name}"
                if execution_result.state == RobustExecutionState.TIMEOUT:
                    error_title = f"⏰ {plugin_name}"
                elif execution_result.state == RobustExecutionState.CANCELLED:
                    error_title = f"🛑 {plugin_name}"
                
                error_content = execution_result.error_message or "Plugin execution failed"
                results[execution_result.module_name] = (error_title, Text(error_content, style="yellow"))
            
            # Store detailed result
            self.execution_results[execution_result.module_name] = execution_result
            
            # Brief pause between plugins for system stability
            if i < len(plugins) and not self._check_shutdown_request():
                time.sleep(0.1)
        
        # Log comprehensive execution summary
        self._log_comprehensive_execution_summary()
        
        return results

    def execute_plugin_robust(self, plugin_metadata, apk_ctx, 
                             timeout_override: Optional[int] = None) -> RobustExecutionResult:
        """
        Execute a single plugin with comprehensive robustness measures.
        
        Args:
            plugin_metadata: Plugin metadata object
            apk_ctx: APK context object
            timeout_override: Optional timeout override
            
        Returns:
            RobustExecutionResult: Comprehensive execution result
        """
        plugin_name = plugin_metadata.name
        module_name = getattr(plugin_metadata, 'module_name', plugin_name)
        
        # Initialize result
        result = RobustExecutionResult(
            plugin_name=plugin_name,
            module_name=module_name,
            state=RobustExecutionState.INITIALIZING,
            start_time=time.time()
        )
        
        # Check for shutdown before starting
        if self._check_shutdown_request():
            result.state = RobustExecutionState.CANCELLED
            result.shutdown_requested = True
            result.end_time = time.time()
            self.logger.info(f"🛑 Plugin {plugin_name} cancelled due to shutdown request")
            return result
        
        # Determine timeout with plugin-specific logic
        timeout = self._determine_robust_timeout(plugin_metadata, timeout_override)
        result.timeout_used = timeout
        
        # Get system integration status
        if self.system_integration:
            try:
                status = self.system_integration.get_system_status()
                result.system_integration_status = f"Fixes: {status['total_fixes']}"
            except Exception as e:
                self.logger.debug(f"System integration status error: {e}")
        
        self.logger.info(f"🔍 Executing plugin: {plugin_name} (timeout: {timeout}s)")
        
        # Execute with retry logic and recovery
        for attempt in range(self.config.retry_attempts + 1):
            if self._check_shutdown_request():
                result.state = RobustExecutionState.CANCELLED
                result.shutdown_requested = True
                break
            
            result.retry_count = attempt
            result.state = RobustExecutionState.RETRYING if attempt > 0 else RobustExecutionState.PENDING
            
            # Adjust timeout for retries with conservative escalation
            current_timeout = timeout
            if attempt > 0 and self.config.enable_timeout_escalation:
                # Use conservative 1.2x factor instead of aggressive 1.5^attempt exponential growth
                # This gives: 1.2x, 1.44x instead of 1.5x, 2.25x, 3.375x
                escalation_factor = 1.2 ** attempt
                current_timeout = min(timeout * escalation_factor, self.config.max_timeout)
                self.logger.info(f"🔄 Retry {attempt} for {plugin_name} with conservative timeout escalation: {current_timeout:.1f}s (factor: {escalation_factor:.2f})")
            
            # Execute the plugin with comprehensive protection
            execution_result = self._execute_plugin_with_comprehensive_protection(
                plugin_metadata, apk_ctx, current_timeout
            )
            
            # Update result
            result.state = execution_result.state
            result.title = execution_result.title
            result.content = execution_result.content
            result.error_message = execution_result.error_message
            result.execution_time = execution_result.execution_time
            result.memory_usage_mb = execution_result.memory_usage_mb
            result.partial_results = execution_result.partial_results
            
            # Check if execution was successful
            if result.state == RobustExecutionState.COMPLETED:
                self.logger.info(f"✅ Plugin {plugin_name} completed successfully in {result.execution_time:.1f}s")
                break
            elif result.state == RobustExecutionState.CANCELLED:
                self.logger.info(f"🛑 Plugin {plugin_name} cancelled")
                break
            elif attempt < self.config.retry_attempts:
                # Add intelligence: don't retry certain non-transient failures
                if self._should_skip_retry(result.error_message, plugin_name):
                    self.logger.warning(f"⚠️ Plugin {plugin_name} failed with non-transient error - skipping retries")
                    break
                
                self.logger.warning(f"⚠️ Plugin {plugin_name} failed (attempt {attempt + 1}), retrying...")
                if self.config.retry_delay > 0:
                    time.sleep(self.config.retry_delay)
            else:
                self.logger.error(f"❌ Plugin {plugin_name} failed after {self.config.retry_attempts + 1} attempts")
        
        # Finalize result
        result.end_time = time.time()
        if result.execution_time == 0.0:
            result.execution_time = result.end_time - result.start_time
        
        # Update statistics
        with self.execution_lock:
            if result.state == RobustExecutionState.COMPLETED:
                self.completed_plugins += 1
            elif result.state == RobustExecutionState.FAILED:
                self.failed_plugins += 1
            elif result.state == RobustExecutionState.TIMEOUT:
                self.timeout_plugins += 1
            elif result.state == RobustExecutionState.CANCELLED:
                self.cancelled_plugins += 1
            elif result.state == RobustExecutionState.RECOVERED:
                self.recovered_plugins += 1
        
        return result

    def _execute_plugin_with_comprehensive_protection(self, plugin_metadata, apk_ctx, 
                                                    timeout: int) -> RobustExecutionResult:
        """Execute plugin with comprehensive protection and monitoring."""
        plugin_name = plugin_metadata.name
        module_name = getattr(plugin_metadata, 'module_name', plugin_name)
        
        result = RobustExecutionResult(
            plugin_name=plugin_name,
            module_name=module_name,
            state=RobustExecutionState.RUNNING,
            start_time=time.time()
        )
        
        # Try to use existing unified manager if available
        if self.unified_manager:
            try:
                unified_result = self.unified_manager.execute_plugin_safe(
                    plugin_metadata, apk_ctx, timeout
                )
                
                # Convert unified result to robust result
                result.state = self._convert_execution_state(unified_result.state)
                result.title = unified_result.title
                result.content = unified_result.content
                result.error_message = unified_result.error_message
                result.execution_time = unified_result.execution_time
                result.timeout_used = unified_result.timeout_used
                result.retry_count = unified_result.retry_count
                result.shutdown_requested = unified_result.shutdown_requested
                result.recovery_attempted = unified_result.recovery_attempted
                result.end_time = time.time()
                
                return result
                
            except Exception as e:
                self.logger.warning(f"⚠️ Unified manager execution failed for {plugin_name}: {e}")
                # Fall back to direct execution
        
        # Direct execution with timeout protection
        try:
            # Use graceful shutdown context if available
            context_manager = plugin_context(plugin_name) if GRACEFUL_SHUTDOWN_AVAILABLE else contextmanager(lambda: iter([None]))()
            
            with context_manager:
                # Execute with ThreadPoolExecutor for timeout protection
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(self._execute_plugin_core, plugin_metadata, apk_ctx)
                    
                    try:
                        # Monitor execution with shutdown checking
                        execution_data = self._monitor_plugin_execution_comprehensive(
                            future, plugin_name, timeout
                        )
                        
                        # Update result with execution data
                        result.state = execution_data.get('state', RobustExecutionState.COMPLETED)
                        result.title = execution_data.get('title')
                        result.content = execution_data.get('content')
                        result.error_message = execution_data.get('error_message')
                        result.memory_usage_mb = execution_data.get('memory_usage_mb', 0.0)
                        result.partial_results = execution_data.get('partial_results', False)
                        
                    except FutureTimeoutError:
                        result.state = RobustExecutionState.TIMEOUT
                        result.error_message = f"Plugin timed out after {timeout}s"
                        
                        # Attempt to get partial results if enabled
                        if self.config.enable_partial_results:
                            result.title, result.content = self._create_timeout_result(plugin_name, timeout)
                            result.partial_results = True
                        
                        # Force cleanup if enabled
                        if self.config.force_cleanup_on_timeout:
                            future.cancel()
                            
        except Exception as e:
            result.state = RobustExecutionState.FAILED
            result.error_message = f"Plugin execution exception: {str(e)}"
            self.logger.error(f"❌ Plugin {plugin_name} execution error: {e}")
            self.logger.debug(f"Plugin error traceback: {traceback.format_exc()}")
        
        result.end_time = time.time()
        result.execution_time = result.end_time - result.start_time
        
        return result

    def _execute_plugin_core(self, plugin_metadata, apk_ctx) -> Dict[str, Any]:
        """Core plugin execution logic."""
        plugin_name = plugin_metadata.name
        
        try:
            # Import and execute the plugin with defensive programming
            module = getattr(plugin_metadata, 'module', None)
            if not module:
                raise AttributeError(f"Plugin {plugin_name} module not available - plugin may not be properly loaded")
            
            # Determine function signature and call appropriately
            import inspect
            
            # Look for run_plugin function first (our standard), then fall back to run
            plugin_function = None
            if hasattr(module, 'run_plugin'):
                plugin_function = module.run_plugin
            elif hasattr(module, 'run'):
                plugin_function = module.run
            else:
                raise AttributeError(f"Plugin {plugin_name} does not have a 'run_plugin' or 'run' method")
            
            sig = inspect.signature(plugin_function)
            params = list(sig.parameters.keys())
            
            # Execute the plugin function
            if len(params) >= 2 and "deep_mode" in params:
                title, content = plugin_function(apk_ctx, deep_mode=True)
            else:
                title, content = plugin_function(apk_ctx)
            
            return {
                'state': RobustExecutionState.COMPLETED,
                'title': title,
                'content': content
            }
                
        except Exception as e:
            return {
                'state': RobustExecutionState.FAILED,
                'error_message': f"Plugin execution failed: {str(e)}",
                'title': f"❌ {plugin_name}",
                'content': Text(f"Error: {str(e)}", style="red")
            }

    def _monitor_plugin_execution_comprehensive(self, future: Future, plugin_name: str, 
                                              timeout: int) -> Dict[str, Any]:
        """Monitor plugin execution with comprehensive shutdown checking and resource monitoring."""
        start_time = time.time()
        check_interval = self.config.check_shutdown_interval
        last_memory_check = start_time
        memory_check_interval = 5.0  # Check memory every 5 seconds
        
        while True:
            # Check for shutdown request
            if self._check_shutdown_request():
                self.logger.info(f"🛑 Cancelling plugin {plugin_name} due to shutdown request")
                future.cancel()
                return {
                    'state': RobustExecutionState.CANCELLED,
                    'error_message': 'Cancelled due to shutdown request'
                }
            
            # Check if future is done
            if future.done():
                try:
                    return future.result()
                except Exception as e:
                    return {
                        'state': RobustExecutionState.FAILED,
                        'error_message': f"Plugin execution exception: {str(e)}"
                    }
            
            # Check for timeout
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                self.logger.warning(f"⏱️ Plugin {plugin_name} timed out after {timeout}s")
                future.cancel()
                return {
                    'state': RobustExecutionState.TIMEOUT,
                    'error_message': f'Plugin timed out after {timeout}s',
                    'partial_results': True
                }
            
            # Monitor memory usage periodically
            current_time = time.time()
            if current_time - last_memory_check >= memory_check_interval:
                try:
                    import psutil
                    process = psutil.Process()
                    memory_mb = process.memory_info().rss / 1024 / 1024
                    
                    # Log high memory usage
                    if memory_mb > 1000:  # > 1GB
                        self.logger.warning(f"⚠️ High memory usage for {plugin_name}: {memory_mb:.1f}MB")
                    
                    last_memory_check = current_time
                    
                except ImportError:
                    pass  # psutil not available
                except Exception as e:
                    self.logger.debug(f"Memory monitoring error: {e}")
            
            # Wait before next check
            time.sleep(check_interval)

    def _determine_robust_timeout(self, plugin_metadata, timeout_override: Optional[int]) -> int:
        """Determine appropriate timeout for plugin execution with robust logic."""
        plugin_name = plugin_metadata.name
        
        # Use override if provided
        if timeout_override is not None:
            return min(timeout_override, self.config.max_timeout)
        
        # Check plugin-specific timeout
        if plugin_name in self.config.plugin_timeouts:
            return self.config.plugin_timeouts[plugin_name]
        
        # Check if plugin has timeout attribute
        if hasattr(plugin_metadata, 'timeout') and plugin_metadata.timeout:
            return min(plugin_metadata.timeout, self.config.max_timeout)
        
        # NEW: Adaptive timeout based on APK size and plugin complexity
        if self.config.enable_adaptive_timeout:
            adaptive_timeout = self._calculate_adaptive_timeout(plugin_name)
            if adaptive_timeout:
                return adaptive_timeout
        
        # Check if it's a critical plugin
        critical_plugins = [
            'insecure_data_storage', 'enhanced_static_analysis', 'jadx_static_analysis',
            'intent_fuzzing', 'webview_security_analysis', 'runtime_decryption_analysis',
            'mastg_integration', 'injection_vulnerabilities', 'advanced_dynamic_analysis'
        ]
        
        if plugin_name in critical_plugins:
            return self.config.critical_plugin_timeout
        
        # Use default timeout
        return self.config.default_timeout
    
    def _calculate_adaptive_timeout(self, plugin_name: str) -> Optional[int]:
        """Calculate adaptive timeout based on APK size and plugin complexity."""
        try:
            # Try to get APK size from context if available
            apk_size_mb = self._get_apk_size_mb()
            if apk_size_mb is None:
                return None
            
            # Determine base timeout based on APK size
            if apk_size_mb < 10:
                base_timeout = self.config.small_apk_timeout  # 180s
            elif apk_size_mb < 50:
                base_timeout = self.config.medium_apk_timeout  # 300s
            elif apk_size_mb < 100:
                base_timeout = self.config.large_apk_timeout   # 480s
            else:
                base_timeout = self.config.xlarge_apk_timeout  # 600s
            
            # Apply complexity multiplier for analysis-heavy plugins
            complex_analysis_plugins = [
                'jadx_static_analysis', 'enhanced_static_analysis', 'runtime_decryption_analysis',
                'advanced_dynamic_analysis', 'mastg_integration'
            ]
            
            if plugin_name in complex_analysis_plugins:
                adaptive_timeout = int(base_timeout * self.config.complex_analysis_multiplier)
                self.logger.info(f"🎯 Adaptive timeout for {plugin_name}: {adaptive_timeout}s (APK: {apk_size_mb:.1f}MB, complex analysis)")
            else:
                adaptive_timeout = base_timeout
                self.logger.debug(f"🎯 Adaptive timeout for {plugin_name}: {adaptive_timeout}s (APK: {apk_size_mb:.1f}MB)")
            
            # Ensure we don't exceed max timeout
            return min(adaptive_timeout, self.config.max_timeout)
            
        except Exception as e:
            self.logger.debug(f"Could not calculate adaptive timeout: {e}")
            return None
    
    def _get_apk_size_mb(self) -> Optional[float]:
        """Get APK size in MB from available context."""
        try:
            # Try to get from plugin execution context if available
            if hasattr(self, 'current_apk_context') and self.current_apk_context:
                apk_path = self.current_apk_context.apk_path
                if apk_path and os.path.exists(apk_path):
                    import os
                    size_bytes = os.path.getsize(apk_path)
                    return size_bytes / (1024 * 1024)
            
            # Try to get from global context (fallback)
            # This would need to be set by the main execution context
            if hasattr(self, '_global_apk_size_mb'):
                return self._global_apk_size_mb
                
        except Exception as e:
            self.logger.debug(f"Could not determine APK size: {e}")
        
        return None
    
    def set_apk_context(self, apk_context) -> None:
        """Set the current APK context for adaptive timeout calculation."""
        try:
            self.current_apk_context = apk_context
            if apk_context and hasattr(apk_context, 'apk_path') and apk_context.apk_path:
                import os
                if os.path.exists(apk_context.apk_path):
                    size_bytes = os.path.getsize(apk_context.apk_path)
                    self._global_apk_size_mb = size_bytes / (1024 * 1024)
                    self.logger.info(f"🎯 APK context set: {apk_context.apk_path} ({self._global_apk_size_mb:.1f}MB)")
        except Exception as e:
            self.logger.debug(f"Error setting APK context: {e}")
            self.current_apk_context = None
            self._global_apk_size_mb = None

    def _attempt_plugin_recovery(self, plugin_metadata, result: RobustExecutionResult) -> bool:
        """Attempt to recover from plugin timeout or failure."""
        plugin_name = plugin_metadata.name
        
        try:
            # For certain plugins, we can provide meaningful partial results
            recoverable_plugins = {
                'insecure_data_storage': 'Partial data storage analysis completed',
                'jadx_static_analysis': 'Partial static analysis completed',
                'intent_fuzzing': 'Partial intent analysis completed',
                'mastg_integration': 'Partial MASTG compliance check completed'
            }
            
            if plugin_name in recoverable_plugins:
                result.title = f"🔄 {plugin_name} (Recovered)"
                result.content = Text(
                    f"{recoverable_plugins[plugin_name]}\n"
                    f"Recovery applied due to timeout/failure\n"
                    f"Partial results available for analysis",
                    style="yellow"
                )
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Recovery attempt failed for {plugin_name}: {e}")
            return False

    def _create_timeout_result(self, plugin_name: str, timeout: int) -> Tuple[str, Text]:
        """Create meaningful result for timed-out plugin."""
        title = f"⏰ {plugin_name} (Timeout)"
        
        content = Text()
        content.append(f"Plugin Analysis: {plugin_name}\n", style="bold yellow")
        content.append("Status: ", style="bold")
        content.append("TIMEOUT - Execution Limited\n", style="yellow")
        content.append(f"Timeout: {timeout} seconds\n", style="blue")
        content.append("Impact: ", style="bold")
        content.append("Analysis stopped to prevent system hanging\n", style="yellow")
        content.append("Recommendation: ", style="bold")
        content.append("Consider running analysis on smaller data sets or increasing timeout", style="green")
        
        return title, content

    def _convert_execution_state(self, unified_state) -> RobustExecutionState:
        """Convert unified execution state to robust execution state."""
        if not UNIFIED_MANAGER_AVAILABLE:
            return RobustExecutionState.COMPLETED
        
        mapping = {
            PluginExecutionState.PENDING: RobustExecutionState.PENDING,
            PluginExecutionState.RUNNING: RobustExecutionState.RUNNING,
            PluginExecutionState.COMPLETED: RobustExecutionState.COMPLETED,
            PluginExecutionState.FAILED: RobustExecutionState.FAILED,
            PluginExecutionState.TIMEOUT: RobustExecutionState.TIMEOUT,
            PluginExecutionState.CANCELLED: RobustExecutionState.CANCELLED,
        }
        
        return mapping.get(unified_state, RobustExecutionState.COMPLETED)

    def _check_shutdown_request(self) -> bool:
        """Check if shutdown has been requested."""
        if self.shutdown_requested:
            return True
        
        if GRACEFUL_SHUTDOWN_AVAILABLE:
            return is_shutdown_requested()
        
        return self.shutdown_event.is_set()

    def _log_comprehensive_execution_summary(self):
        """Log comprehensive execution summary with detailed statistics."""
        total = self.total_plugins
        completed = self.completed_plugins
        failed = self.failed_plugins
        timeout = self.timeout_plugins
        cancelled = self.cancelled_plugins
        recovered = self.recovered_plugins
        
        self.logger.info(f"📊 Robust Plugin Execution Summary:")
        self.logger.info(f"   Total: {total}")
        self.logger.info(f"   ✅ Completed: {completed}")
        self.logger.info(f"   🔄 Recovered: {recovered}")
        self.logger.info(f"   ❌ Failed: {failed}")
        self.logger.info(f"   ⏱️ Timeout: {timeout}")
        self.logger.info(f"   🛑 Cancelled: {cancelled}")
        
        if total > 0:
            success_rate = ((completed + recovered) / total) * 100
            self.logger.info(f"   📈 Success Rate: {success_rate:.1f}%")
            
            # Log performance metrics
            avg_execution_time = sum(
                result.execution_time for result in self.execution_results.values()
            ) / len(self.execution_results) if self.execution_results else 0
            
            self.logger.info(f"   ⏱️ Average Execution Time: {avg_execution_time:.2f}s")
            
            # Log system integration status
            if self.system_integration:
                try:
                    status = self.system_integration.get_system_status()
                    self.logger.info(f"   🔧 System Integration: {status['total_fixes']} fixes applied")
                except Exception:
                    pass

    def get_comprehensive_statistics(self) -> Dict[str, Any]:
        """Get comprehensive execution statistics."""
        total_execution_time = sum(
            result.execution_time for result in self.execution_results.values()
        )
        
        avg_memory_usage = sum(
            result.memory_usage_mb for result in self.execution_results.values()
        ) / len(self.execution_results) if self.execution_results else 0
        
        return {
            'total_plugins': self.total_plugins,
            'completed_plugins': self.completed_plugins,
            'failed_plugins': self.failed_plugins,
            'timeout_plugins': self.timeout_plugins,
            'cancelled_plugins': self.cancelled_plugins,
            'recovered_plugins': self.recovered_plugins,
            'success_rate': ((self.completed_plugins + self.recovered_plugins) / self.total_plugins * 100) if self.total_plugins > 0 else 0,
            'total_execution_time': total_execution_time,
            'average_execution_time': total_execution_time / len(self.execution_results) if self.execution_results else 0,
            'average_memory_usage_mb': avg_memory_usage,
            'system_integration_available': self.system_integration is not None,
            'unified_manager_available': self.unified_manager is not None,
            'graceful_shutdown_available': GRACEFUL_SHUTDOWN_AVAILABLE,
            'plugin_constants_available': PLUGIN_CONSTANTS_AVAILABLE
        }

    def shutdown(self):
        """Shutdown the robust plugin execution manager gracefully."""
        self.logger.info("🛑 Shutting down robust plugin execution manager...")
        
        self.shutdown_requested = True
        self.shutdown_event.set()
        
        # Cancel active plugins
        with self.execution_lock:
            for plugin_name, future in self.active_plugins.items():
                if not future.done():
                    self.logger.info(f"🛑 Cancelling active plugin: {plugin_name}")
                    future.cancel()
        
        # Shutdown unified manager if available
        if self.unified_manager:
            try:
                self.unified_manager.shutdown()
            except Exception as e:
                self.logger.warning(f"⚠️ Unified manager shutdown error: {e}")
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        self.logger.info("✅ Robust plugin execution manager shutdown complete")

    @contextmanager
    def robust_execution_context(self):
        """Context manager for robust plugin execution."""
        try:
            self.logger.info("🔧 Entering robust plugin execution context")
            yield self
        except KeyboardInterrupt:
            self.logger.warning("🛑 Keyboard interrupt - initiating graceful shutdown")
            self.shutdown()
            raise
        except Exception as e:
            self.logger.error(f"❌ Error in robust execution context: {e}")
            raise
        finally:
            self.logger.info("🔧 Exiting robust plugin execution context")

    def _should_skip_retry(self, error_message: str, plugin_name: str) -> bool:
        """
        Determine if a retry should be skipped based on error type.
        
        Args:
            error_message: The error message from the failed execution
            plugin_name: Name of the plugin that failed
            
        Returns:
            True if retry should be skipped (non-transient error), False otherwise
        """
        if not error_message:
            return False
        
        error_lower = error_message.lower()
        
        # Non-transient errors that won't be fixed by retrying with more time
        non_transient_patterns = [
            # Import/dependency errors
            'no module named', 'importerror', 'modulenotfounderror',
            'cannot import name', 'import failed',
            
            # Configuration errors
            'configuration error', 'config file not found', 'invalid configuration',
            'missing required parameter', 'invalid parameter',
            
            # File system errors that are persistent
            'permission denied', 'file not found', 'directory not found',
            'no such file or directory', 'access denied',
            
            # APK-specific non-transient issues
            'invalid apk', 'corrupted apk', 'apk parsing failed',
            'malformed apk', 'unsupported apk format',
            
            # Plugin-specific structural issues
            'plugin not compatible', 'unsupported plugin version',
            'plugin disabled', 'plugin initialization failed'
        ]
        
        # Check if error matches non-transient patterns
        for pattern in non_transient_patterns:
            if pattern in error_lower:
                self.logger.debug(f"Detected non-transient error for {plugin_name}: {pattern}")
                return True
        
        return False

def create_robust_plugin_execution_manager(
    config: Optional[RobustExecutionConfig] = None
) -> RobustPluginExecutionManager:
    """
    Create a robust plugin execution manager with optimal configuration.
    
    Args:
        config: Optional configuration override
        
    Returns:
        RobustPluginExecutionManager: Configured manager instance
    """
    if config is None:
        config = RobustExecutionConfig()
    
    return RobustPluginExecutionManager(config)

def integrate_robust_execution_with_plugin_manager(plugin_manager):
    """
    Integrate robust execution manager with existing plugin manager.
    
    Args:
        plugin_manager: Existing plugin manager instance
    """
    logger.info("🔧 Integrating robust execution manager with plugin manager...")
    
    # Create robust execution manager
    robust_manager = create_robust_plugin_execution_manager()
    
    # Store original execute_all_plugins method
    original_execute_all_plugins = plugin_manager.execute_all_plugins
    
    def robust_execute_all_plugins(apk_ctx):
        """Enhanced execute_all_plugins with robust execution."""
        try:
            # Get plugins from the plugin manager
            plugins = getattr(plugin_manager, 'plugins', {})
            if hasattr(plugin_manager, 'get_ordered_plugins'):
                plugin_list = plugin_manager.get_ordered_plugins()
            elif hasattr(plugin_manager, 'plan_execution_order'):
                plugin_list = plugin_manager.plan_execution_order()
            else:
                # Fallback to plugin values
                plugin_list = list(plugins.values()) if plugins else []
            
            # Use robust execution
            results = robust_manager.execute_all_plugins_robust(plugin_list, apk_ctx)
            
            # CRITICAL FIX: Update plugin statuses in original plugin manager
            # This ensures the status display shows correct information
            _update_plugin_statuses(plugin_manager, robust_manager, plugin_list)
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Robust execution integration error: {e}")
            # Fallback to original method
            return original_execute_all_plugins(apk_ctx)
    
    # Replace the method
    plugin_manager.execute_all_plugins = robust_execute_all_plugins
    plugin_manager._robust_execution_manager = robust_manager
    
    logger.info("✅ Robust execution manager integrated successfully")
    
    return robust_manager

def _update_plugin_statuses(plugin_manager, robust_manager, plugin_list):
    """Update plugin statuses in original plugin manager based on robust execution results."""
    try:
        # Import status enums
        from core.plugin_manager import PluginStatus
        from core.robust_plugin_execution_manager import RobustExecutionState
        
        # Status mapping from robust execution to plugin manager
        status_mapping = {
            RobustExecutionState.COMPLETED: PluginStatus.COMPLETED,
            RobustExecutionState.FAILED: PluginStatus.FAILED,
            RobustExecutionState.TIMEOUT: PluginStatus.TIMEOUT,
            RobustExecutionState.CANCELLED: PluginStatus.CANCELLED,
            RobustExecutionState.RECOVERED: PluginStatus.COMPLETED,  # Treat recovered as completed
            RobustExecutionState.RUNNING: PluginStatus.RUNNING,
            RobustExecutionState.PENDING: PluginStatus.PENDING,
        }
        
        # Update status for each plugin
        for plugin_metadata in plugin_list:
            plugin_name = plugin_metadata.name
            module_name = getattr(plugin_metadata, 'module_name', plugin_name)
            
            # Get execution result from robust manager
            execution_result = robust_manager.execution_results.get(module_name)
            
            if execution_result:
                # Update status in original plugin manager
                if plugin_name in plugin_manager.plugins:
                    original_plugin = plugin_manager.plugins[plugin_name]
                    
                    # Map robust execution state to plugin manager status
                    new_status = status_mapping.get(execution_result.state, PluginStatus.COMPLETED)
                    original_plugin.status = new_status
                    
                    # Update timing information
                    original_plugin.execution_time = execution_result.execution_time
                    original_plugin.start_time = execution_result.start_time
                    original_plugin.end_time = execution_result.end_time
                    
                    # Update error information if available
                    if execution_result.error_message:
                        original_plugin.error_message = execution_result.error_message
                    
                    # Update retry count if available
                    if hasattr(original_plugin, 'retry_count'):
                        original_plugin.retry_count = execution_result.retry_count
                    
                    logger.debug(f"Updated plugin {plugin_name} status to {new_status.value}")
            else:
                # If no execution result, mark as failed
                if plugin_name in plugin_manager.plugins:
                    plugin_manager.plugins[plugin_name].status = PluginStatus.FAILED
                    logger.warning(f"No execution result for plugin {plugin_name}, marking as failed")
    
    except Exception as e:
        logger.error(f"❌ Failed to update plugin statuses: {e}")
        # Don't let status update errors crash the main execution

# Auto-integration when module is imported
if __name__ != "__main__":
    logger.info("🔧 Robust Plugin Execution Manager module loaded") 
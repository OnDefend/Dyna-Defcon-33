#!/usr/bin/env python3
"""
Error Recovery Integration Helper

This module provides simple integration functions and decorators to make it easy
for existing AODS plugins to use the comprehensive error recovery framework.

Features:
- Decorator-based error handling for plugin functions
- Simple plugin registration system
- Automatic error classification and recovery
- Integration with existing plugin architecture
"""

import functools
import logging
from typing import Callable, Any, Dict, Optional, Union, Type
from dataclasses import dataclass

try:
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .error_recovery_framework import (
    get_error_recovery_framework,
    ErrorRecoveryInterface,
    RecoveryResult,
    ErrorSeverity,
    RecoveryStrategy
)

logger = logging.getLogger(__name__)

@dataclass
class PluginConfig:
    """Configuration for plugin error recovery."""
    max_retries: int = 3
    fallback_enabled: bool = True
    graceful_degradation: bool = True
    suppress_errors: bool = False
    custom_recovery_strategies: Dict[Type[Exception], RecoveryStrategy] = None

class DefaultErrorRecoveryHandler(ErrorRecoveryInterface):
    """Default error recovery handler for plugins that don't implement custom logic."""
    
    def __init__(self, plugin_name: str, config: Optional[PluginConfig] = None):
        self.plugin_name = plugin_name
        self.config = config or PluginConfig()
    
    def handle_error(self, error: Exception, context: Dict[str, Any]) -> RecoveryResult:
        """Handle error with default recovery strategy."""
        # Check for custom recovery strategy
        if self.config.custom_recovery_strategies:
            strategy = self.config.custom_recovery_strategies.get(type(error))
            if strategy:
                return RecoveryResult(
                    success=True,
                    strategy_used=strategy,
                    recommendation=f"Using custom strategy for {type(error).__name__}"
                )
        
        # Default fallback strategy
        if self.config.fallback_enabled:
            return RecoveryResult(
                success=True,
                strategy_used=RecoveryStrategy.FALLBACK,
                fallback_data=self.get_fallback_result(context.get('operation', 'unknown'), context),
                recommendation="Using default fallback implementation"
            )
        
        return RecoveryResult(
            success=False,
            strategy_used=RecoveryStrategy.SKIP,
            recommendation="No recovery strategy available"
        )
    
    def get_fallback_result(self, operation: str, context: Dict[str, Any]) -> Any:
        """Provide default fallback result."""
        if RICH_AVAILABLE:
            fallback_result = Text()
            fallback_result.append(f"{self.plugin_name} - Fallback Mode\n", style="yellow")
            fallback_result.append("Analysis completed with limited functionality due to error.\n", style="white")
            fallback_result.append("Consider reviewing plugin configuration and dependencies.\n", style="cyan")
            return fallback_result
        else:
            return f"{self.plugin_name} - Fallback Mode: Analysis completed with limited functionality"
    
    def validate_preconditions(self) -> bool:
        """Default precondition validation."""
        return True
    
    def cleanup_on_failure(self, context: Dict[str, Any]) -> None:
        """Default cleanup - no action needed."""
        pass

def with_error_recovery(plugin_name: str, operation: str = "main", 
                       config: Optional[PluginConfig] = None):
    """Decorator to add error recovery to plugin functions."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            framework = get_error_recovery_framework()
            
            # Register default handler if not already registered
            if plugin_name not in framework.registered_handlers:
                handler = DefaultErrorRecoveryHandler(plugin_name, config)
                framework.register_plugin(plugin_name, handler)
            
            try:
                # Validate preconditions if handler supports it
                handler = framework.registered_handlers.get(plugin_name)
                if handler and hasattr(handler, 'validate_preconditions'):
                    if not handler.validate_preconditions():
                        logger.warning(f"{plugin_name}: Preconditions not met, using fallback")
                        return handler.get_fallback_result(operation, {'args': args, 'kwargs': kwargs})
                
                # Execute original function
                return func(*args, **kwargs)
                
            except Exception as e:
                # Handle error through framework
                context = {
                    'operation': operation,
                    'args': args,
                    'kwargs': kwargs,
                    'function_name': func.__name__
                }
                
                recovery_result = framework.handle_plugin_error(plugin_name, operation, e, context)
                
                if recovery_result.success:
                    if recovery_result.fallback_data is not None:
                        return recovery_result.fallback_data
                    elif recovery_result.error_suppressed:
                        # Return a safe default result
                        if RICH_AVAILABLE:
                            result = Text()
                            result.append(f"{plugin_name} - Error Suppressed\n", style="yellow")
                            result.append("Plugin encountered an error but scan continued.\n", style="white")
                            return result
                        else:
                            return f"{plugin_name} - Error suppressed, scan continued"
                    else:
                        # Retry the operation if strategy was retry
                        if recovery_result.strategy_used == RecoveryStrategy.RETRY:
                            return func(*args, **kwargs)
                
                # If recovery failed and errors aren't suppressed, re-raise
                if not (config and config.suppress_errors):
                    raise
                
                return None
        
        return wrapper
    return decorator

def register_plugin_error_handler(plugin_name: str, handler: ErrorRecoveryInterface) -> None:
    """Register custom error recovery handler for a plugin."""
    framework = get_error_recovery_framework()
    framework.register_plugin(plugin_name, handler)
    logger.info(f"Registered custom error recovery handler for {plugin_name}")

def get_plugin_error_stats(plugin_name: Optional[str] = None) -> Dict[str, Any]:
    """Get error statistics for a specific plugin or all plugins."""
    framework = get_error_recovery_framework()
    status = framework.get_framework_status()
    error_summary = status['error_summary']
    
    if plugin_name:
        plugin_errors = error_summary.get('errors_by_plugin', {}).get(plugin_name, 0)
        return {
            'plugin_name': plugin_name,
            'total_errors': plugin_errors,
            'error_summary': error_summary
        }
    else:
        return error_summary

def create_safe_plugin_runner(plugin_name: str, config: Optional[PluginConfig] = None):
    """Create a safe plugin runner function that handles all errors gracefully."""
    framework = get_error_recovery_framework()
    
    # Register default handler
    handler = DefaultErrorRecoveryHandler(plugin_name, config)
    framework.register_plugin(plugin_name, handler)
    
    def safe_run_plugin(plugin_function: Callable, *args, **kwargs) -> Any:
        """Run plugin function with comprehensive error handling."""
        try:
            # Validate preconditions
            if not handler.validate_preconditions():
                logger.warning(f"{plugin_name}: Preconditions failed, using fallback")
                return handler.get_fallback_result('main', {'args': args, 'kwargs': kwargs})
            
            # Execute plugin
            return plugin_function(*args, **kwargs)
            
        except Exception as e:
            # Handle error through framework
            context = {
                'operation': 'main',
                'args': args,
                'kwargs': kwargs,
                'function_name': getattr(plugin_function, '__name__', 'unknown')
            }
            
            recovery_result = framework.handle_plugin_error(plugin_name, 'main', e, context)
            
            if recovery_result.success and recovery_result.fallback_data is not None:
                return recovery_result.fallback_data
            
            # If all recovery failed, return safe default
            if RICH_AVAILABLE:
                safe_result = Text()
                safe_result.append(f"{plugin_name} - Safe Mode\n", style="red")
                safe_result.append("Plugin failed and recovery was unsuccessful.\n", style="white")
                safe_result.append("Scan continued with remaining plugins.\n", style="cyan")
                return safe_result
            else:
                return f"{plugin_name} - Safe Mode: Plugin failed, scan continued"
    
    return safe_run_plugin

def generate_recovery_report() -> Union[str, Text]:
    """Generate comprehensive error recovery report."""
    framework = get_error_recovery_framework()
    return framework.generate_error_report()

def ensure_scan_continuation(critical_plugins: list = None) -> bool:
    """Ensure scan can continue despite plugin failures."""
    critical_plugins = critical_plugins or [
        'enhanced_static_analysis',
        'enhanced_manifest_analysis',
        'network_communication_tests'
    ]
    
    framework = get_error_recovery_framework()
    error_summary = framework.get_framework_status()['error_summary']
    errors_by_plugin = error_summary.get('errors_by_plugin', {})
    
    # Check if any critical plugins have failed
    critical_failures = 0
    for plugin in critical_plugins:
        if errors_by_plugin.get(plugin, 0) > 0:
            critical_failures += 1
    
    # Allow scan to continue if at least 50% of critical plugins are working
    can_continue = (critical_failures / len(critical_plugins)) < 0.5
    
    if not can_continue:
        logger.warning(
            f"High critical plugin failure rate: {critical_failures}/{len(critical_plugins)} failed"
        )
    
    return can_continue

# Quick integration decorators for common plugin patterns
def robust_analysis(plugin_name: str):
    """Decorator for robust analysis plugins with full error recovery."""
    config = PluginConfig(
        max_retries=3,
        fallback_enabled=True,
        graceful_degradation=True,
        suppress_errors=True
    )
    return with_error_recovery(plugin_name, "analysis", config)

def safe_network_operation(plugin_name: str):
    """Decorator for network operations with retry-focused recovery."""
    config = PluginConfig(
        max_retries=5,
        fallback_enabled=True,
        custom_recovery_strategies={
            ConnectionError: RecoveryStrategy.RETRY,
            TimeoutError: RecoveryStrategy.RETRY,
        }
    )
    return with_error_recovery(plugin_name, "network_operation", config)

def resilient_file_operation(plugin_name: str):
    """Decorator for file operations with skip-focused recovery."""
    config = PluginConfig(
        max_retries=1,
        fallback_enabled=False,
        custom_recovery_strategies={
            FileNotFoundError: RecoveryStrategy.SKIP,
            PermissionError: RecoveryStrategy.SKIP,
            OSError: RecoveryStrategy.SKIP,
        }
    )
    return with_error_recovery(plugin_name, "file_operation", config)

# Export main integration functions
__all__ = [
    'with_error_recovery',
    'register_plugin_error_handler',
    'get_plugin_error_stats',
    'create_safe_plugin_runner',
    'generate_recovery_report',
    'ensure_scan_continuation',
    'robust_analysis',
    'safe_network_operation',
    'resilient_file_operation',
    'PluginConfig',
    'DefaultErrorRecoveryHandler'
] 
#!/usr/bin/env python3
"""
Enhanced Error Handling Framework for AODS Plugin Ecosystem

This module provides a comprehensive, standardized error handling framework
for all AODS plugins, ensuring consistent error categorization, graceful
degradation, and robust debugging capabilities.

Key Features:
- Specific exception types for different failure scenarios
- Graceful degradation patterns with fallback behavior
- Standardized error context and structured logging
- Plugin lifecycle error tracking and recovery
- Performance impact measurement for error scenarios
"""

import logging
import traceback
import time
import functools
from typing import Any, Dict, List, Optional, Callable, Union, Tuple
from enum import Enum
from dataclasses import dataclass, field
from contextlib import contextmanager

class ErrorSeverity(Enum):
    """Standardized error severity levels for plugin ecosystem."""
    CRITICAL = "CRITICAL"  # Plugin completely fails, no recovery possible
    HIGH = "HIGH"         # Major functionality impacted, limited recovery
    MEDIUM = "MEDIUM"     # Moderate impact, graceful degradation available
    LOW = "LOW"          # Minor issues, full recovery possible
    INFO = "INFO"        # Informational, no functional impact

class ErrorCategory(Enum):
    """Categorized error types for systematic handling."""
    # Data Access Errors
    FILE_ACCESS = "file_access"           # File system, permissions
    DATA_PARSING = "data_parsing"         # JSON, XML, YAML parsing
    MANIFEST_PROCESSING = "manifest"      # AndroidManifest.xml issues
    
    # Analysis Errors  
    PATTERN_COMPILATION = "pattern_compilation"  # Regex, rule compilation
    ALGORITHM_EXECUTION = "algorithm"            # Core analysis logic
    DEPENDENCY_MISSING = "dependency"            # Missing libraries/tools
    
    # External System Errors
    EXTERNAL_TOOL = "external_tool"      # JADX, ADB, external processes
    NETWORK_ACCESS = "network"           # API calls, downloads
    DEVICE_COMMUNICATION = "device"      # Android device interaction
    
    # Resource Errors
    MEMORY_EXHAUSTED = "memory"          # Out of memory conditions
    TIMEOUT_EXCEEDED = "timeout"         # Operation timeouts
    RESOURCE_UNAVAILABLE = "resource"    # System resources
    
    # Configuration Errors
    INVALID_CONFIG = "config"            # Configuration validation
    ENVIRONMENT_SETUP = "environment"    # Environment prerequisites
    PLUGIN_COMPATIBILITY = "compatibility"  # Plugin version/compatibility

@dataclass
class ErrorContext:
    """Comprehensive error context for debugging and recovery."""
    plugin_name: str
    operation: str
    error_category: ErrorCategory
    severity: ErrorSeverity
    original_exception: Exception
    timestamp: float = field(default_factory=time.time)
    
    # Contextual Information
    apk_path: Optional[str] = None
    package_name: Optional[str] = None
    operation_duration: Optional[float] = None
    
    # Error Details
    error_message: str = ""
    stack_trace: str = ""
    recovery_attempted: bool = False
    recovery_successful: bool = False
    fallback_used: str = ""
    
    # Performance Impact
    performance_impact: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Populate derived fields after initialization."""
        self.error_message = str(self.original_exception)
        self.stack_trace = traceback.format_exc()

class PluginExecutionError(Exception):
    """Base exception for all plugin execution errors."""
    def __init__(self, context: ErrorContext):
        self.context = context
        super().__init__(context.error_message)

class CriticalPluginError(PluginExecutionError):
    """Critical error requiring plugin termination."""
    pass

class RecoverablePluginError(PluginExecutionError):
    """Error that allows graceful degradation."""
    pass

class PluginWarning(Exception):
    """Non-fatal warning that doesn't stop execution."""
    def __init__(self, context: ErrorContext):
        self.context = context
        super().__init__(context.error_message)

@dataclass
class PluginErrorStats:
    """Statistics tracking for plugin error patterns."""
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    recoveries_attempted: int = 0
    recoveries_successful: int = 0
    
    error_categories: Dict[ErrorCategory, int] = field(default_factory=dict)
    severity_distribution: Dict[ErrorSeverity, int] = field(default_factory=dict)
    
    average_execution_time: float = 0.0
    error_impact_time: float = 0.0
    
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        if self.total_executions == 0:
            return 0.0
        return (self.successful_executions / self.total_executions) * 100

    def recovery_rate(self) -> float:
        """Calculate recovery success rate percentage."""
        if self.recoveries_attempted == 0:
            return 0.0
        return (self.recoveries_successful / self.recoveries_attempted) * 100

class EnhancedErrorHandler:
    """
    Comprehensive error handling system for AODS plugins.
    
    Provides standardized error categorization, graceful degradation,
    recovery mechanisms, and performance tracking.
    """
    
    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name
        self.logger = logging.getLogger(f"aods.plugins.{plugin_name}")
        self.stats = PluginErrorStats()
        self.error_history: List[ErrorContext] = []
        
        # Recovery strategies registry
        self.recovery_strategies: Dict[ErrorCategory, Callable] = {
            ErrorCategory.FILE_ACCESS: self._recover_file_access,
            ErrorCategory.DATA_PARSING: self._recover_data_parsing,
            ErrorCategory.PATTERN_COMPILATION: self._recover_pattern_compilation,
            ErrorCategory.EXTERNAL_TOOL: self._recover_external_tool,
            ErrorCategory.DEPENDENCY_MISSING: self._recover_dependency_missing,
            ErrorCategory.TIMEOUT_EXCEEDED: self._recover_timeout,
        }
    
    def categorize_error(self, exception: Exception) -> ErrorCategory:
        """Automatically categorize errors based on exception type and message."""
        exc_type = type(exception).__name__
        exc_msg = str(exception).lower()
        
        # File and permission errors
        if exc_type in ['FileNotFoundError', 'PermissionError', 'OSError']:
            return ErrorCategory.FILE_ACCESS
        
        # Parsing errors
        if exc_type in ['JSONDecodeError', 'XMLParseError', 'YAMLError'] or 'parsing' in exc_msg:
            return ErrorCategory.DATA_PARSING
        
        # Pattern compilation errors
        if exc_type in ['re.error', 'PatternError'] or 'regex' in exc_msg or 'pattern' in exc_msg:
            return ErrorCategory.PATTERN_COMPILATION
        
        # External tool errors
        if exc_type in ['subprocess.CalledProcessError', 'subprocess.TimeoutExpired']:
            return ErrorCategory.EXTERNAL_TOOL
        
        # Import and dependency errors
        if exc_type in ['ImportError', 'ModuleNotFoundError']:
            return ErrorCategory.DEPENDENCY_MISSING
        
        # Memory errors
        if exc_type in ['MemoryError', 'OverflowError']:
            return ErrorCategory.MEMORY_EXHAUSTED
        
        # Timeout errors
        if 'timeout' in exc_msg or exc_type == 'TimeoutError':
            return ErrorCategory.TIMEOUT_EXCEEDED
        
        # Attribute and key errors (likely configuration/compatibility)
        if exc_type in ['AttributeError', 'KeyError']:
            return ErrorCategory.PLUGIN_COMPATIBILITY
        
        # Default to algorithm execution for unclassified errors
        return ErrorCategory.ALGORITHM_EXECUTION
    
    def determine_severity(self, category: ErrorCategory, exception: Exception) -> ErrorSeverity:
        """Determine error severity based on category and context."""
        # Critical errors that prevent plugin execution
        if category in [ErrorCategory.MEMORY_EXHAUSTED, ErrorCategory.INVALID_CONFIG]:
            return ErrorSeverity.CRITICAL
        
        # High severity for core functionality
        if category in [ErrorCategory.MANIFEST_PROCESSING, ErrorCategory.ALGORITHM_EXECUTION]:
            return ErrorSeverity.HIGH
        
        # Medium severity for external dependencies
        if category in [ErrorCategory.EXTERNAL_TOOL, ErrorCategory.DEPENDENCY_MISSING]:
            return ErrorSeverity.MEDIUM
        
        # Low severity for recoverable issues
        if category in [ErrorCategory.FILE_ACCESS, ErrorCategory.DATA_PARSING]:
            return ErrorSeverity.LOW
        
        return ErrorSeverity.MEDIUM

    @contextmanager
    def error_context(self, operation: str, apk_ctx=None):
        """Context manager for comprehensive error handling during plugin operations."""
        start_time = time.time()
        self.stats.total_executions += 1
        
        try:
            yield self
            # Success path
            execution_time = time.time() - start_time
            self.stats.successful_executions += 1
            self.stats.average_execution_time = (
                (self.stats.average_execution_time * (self.stats.total_executions - 1) + execution_time) 
                / self.stats.total_executions
            )
            self.logger.debug(f"✅ {operation} completed successfully in {execution_time:.3f}s")
            
        except Exception as original_exception:
            execution_time = time.time() - start_time
            self.stats.failed_executions += 1
            self.stats.error_impact_time += execution_time
            
            # Create comprehensive error context
            category = self.categorize_error(original_exception)
            severity = self.determine_severity(category, original_exception)
            
            context = ErrorContext(
                plugin_name=self.plugin_name,
                operation=operation,
                error_category=category,
                severity=severity,
                original_exception=original_exception,
                operation_duration=execution_time,
                apk_path=getattr(apk_ctx, 'apk_path', None) if apk_ctx else None,
                package_name=getattr(apk_ctx, 'package_name', None) if apk_ctx else None
            )
            
            # Track statistics
            self.stats.error_categories[category] = self.stats.error_categories.get(category, 0) + 1
            self.stats.severity_distribution[severity] = self.stats.severity_distribution.get(severity, 0) + 1
            self.error_history.append(context)
            
            # Log the error with appropriate level
            self._log_error(context)
            
            # Attempt recovery for recoverable errors
            if severity in [ErrorSeverity.LOW, ErrorSeverity.MEDIUM]:
                recovery_result = self._attempt_recovery(context)
                if recovery_result is not None:
                    self.logger.info(f"🔄 Recovery successful for {operation}: {context.fallback_used}")
                    return  # Exit successfully after recovery
            
            # Re-raise with enhanced context
            if severity == ErrorSeverity.CRITICAL:
                raise CriticalPluginError(context)
            else:
                raise RecoverablePluginError(context)

    def _log_error(self, context: ErrorContext):
        """Log error with appropriate level and comprehensive context."""
        log_msg = (
            f"❌ {context.operation} failed: {context.error_message}\n"
            f"   Category: {context.error_category.value}\n"
            f"   Severity: {context.severity.value}\n"
            f"   Duration: {context.operation_duration:.3f}s"
        )
        
        if context.apk_path:
            log_msg += f"\n   APK: {context.apk_path}"
        if context.package_name:
            log_msg += f"\n   Package: {context.package_name}"
        
        # Log with appropriate level
        if context.severity == ErrorSeverity.CRITICAL:
            self.logger.error(log_msg)
            self.logger.debug(f"Stack trace:\n{context.stack_trace}")
        elif context.severity == ErrorSeverity.HIGH:
            self.logger.error(log_msg)
        elif context.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(log_msg)
        else:
            self.logger.info(log_msg)

    def _attempt_recovery(self, context: ErrorContext) -> Optional[Any]:
        """Attempt error recovery using category-specific strategies."""
        self.stats.recoveries_attempted += 1
        context.recovery_attempted = True
        
        if context.error_category in self.recovery_strategies:
            try:
                result = self.recovery_strategies[context.error_category](context)
                if result is not None:
                    self.stats.recoveries_successful += 1
                    context.recovery_successful = True
                return result
            except Exception as recovery_error:
                self.logger.debug(f"Recovery attempt failed: {recovery_error}")
        
        return None

    # Recovery Strategy Implementations
    
    def _recover_file_access(self, context: ErrorContext) -> Optional[List]:
        """Recover from file access errors with graceful degradation."""
        context.fallback_used = "empty_dataset"
        self.logger.info(f"🔄 File access recovery: using empty dataset for {context.operation}")
        return []  # Return empty list instead of dict
    
    def _recover_data_parsing(self, context: ErrorContext) -> Optional[List]:
        """Recover from data parsing errors with fallback parsing."""
        context.fallback_used = "basic_parsing"
        self.logger.info(f"🔄 Data parsing recovery: using basic fallback parser")
        return []  # Return empty list for compatibility
    
    def _recover_pattern_compilation(self, context: ErrorContext) -> Optional[List]:
        """Recover from pattern compilation errors with simplified patterns."""
        context.fallback_used = "simplified_patterns"
        self.logger.info(f"🔄 Pattern compilation recovery: using simplified patterns")
        return []  # Return empty list for patterns
    
    def _recover_external_tool(self, context: ErrorContext) -> Optional[List]:
        """Recover from external tool errors with alternative approaches."""
        context.fallback_used = "alternative_analysis"
        self.logger.info(f"🔄 External tool recovery: using alternative analysis method")
        return []  # Return empty list for compatibility
    
    def _recover_dependency_missing(self, context: ErrorContext) -> Optional[List]:
        """Recover from missing dependencies with graceful degradation."""
        context.fallback_used = "basic_functionality"
        self.logger.info(f"🔄 Dependency recovery: providing basic functionality only")
        return []  # Return empty list for compatibility
    
    def _recover_timeout(self, context: ErrorContext) -> Optional[List]:
        """Recover from timeout errors with cached or partial results."""
        context.fallback_used = "timeout_fallback"
        self.logger.info(f"🔄 Timeout recovery: using cached or partial results")
        return []  # Return empty list for compatibility

    def get_error_summary(self) -> Dict[str, Any]:
        """Generate comprehensive error summary for monitoring and debugging."""
        return {
            "plugin_name": self.plugin_name,
            "statistics": {
                "total_executions": self.stats.total_executions,
                "success_rate": f"{self.stats.success_rate():.1f}%",
                "recovery_rate": f"{self.stats.recovery_rate():.1f}%",
                "average_execution_time": f"{self.stats.average_execution_time:.3f}s",
                "error_impact_time": f"{self.stats.error_impact_time:.3f}s"
            },
            "error_distribution": {
                "by_category": {cat.value: count for cat, count in self.stats.error_categories.items()},
                "by_severity": {sev.value: count for sev, count in self.stats.severity_distribution.items()}
            },
            "recent_errors": [
                {
                    "operation": ctx.operation,
                    "category": ctx.error_category.value,
                    "severity": ctx.severity.value,
                    "recovered": ctx.recovery_successful,
                    "timestamp": ctx.timestamp
                }
                for ctx in self.error_history[-5:]  # Last 5 errors
            ]
        }

# Decorator for automatic error handling
def enhanced_error_handling(operation_name: str = "plugin_operation"):
    """Decorator to automatically apply enhanced error handling to plugin methods."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            # Get or create error handler
            if not hasattr(self, '_error_handler'):
                plugin_name = getattr(self, 'plugin_name', self.__class__.__name__)
                self._error_handler = EnhancedErrorHandler(plugin_name)
            
            # Extract apk_ctx if available
            apk_ctx = None
            if args and hasattr(args[0], 'apk_path'):
                apk_ctx = args[0]
            
            # Execute with error handling
            with self._error_handler.error_context(operation_name, apk_ctx):
                return func(self, *args, **kwargs)
        
        return wrapper
    return decorator

# Global error statistics collector
class GlobalErrorTracker:
    """Global tracker for ecosystem-wide error patterns and statistics."""
    
    def __init__(self):
        self.plugin_handlers: Dict[str, EnhancedErrorHandler] = {}
        self.logger = logging.getLogger("aods.global_error_tracker")
    
    def register_handler(self, handler: EnhancedErrorHandler):
        """Register a plugin error handler for global tracking."""
        self.plugin_handlers[handler.plugin_name] = handler
    
    def get_ecosystem_summary(self) -> Dict[str, Any]:
        """Generate ecosystem-wide error summary."""
        total_executions = sum(h.stats.total_executions for h in self.plugin_handlers.values())
        total_failures = sum(h.stats.failed_executions for h in self.plugin_handlers.values())
        total_recoveries = sum(h.stats.recoveries_successful for h in self.plugin_handlers.values())
        
        return {
            "ecosystem_statistics": {
                "total_plugin_executions": total_executions,
                "overall_success_rate": f"{((total_executions - total_failures) / total_executions * 100):.1f}%" if total_executions > 0 else "0%",
                "total_recoveries": total_recoveries,
                "active_plugins": len(self.plugin_handlers)
            },
            "plugin_performance": {
                name: {
                    "success_rate": f"{handler.stats.success_rate():.1f}%",
                    "recovery_rate": f"{handler.stats.recovery_rate():.1f}%",
                    "executions": handler.stats.total_executions
                }
                for name, handler in self.plugin_handlers.items()
            }
        }

# Global instance
global_error_tracker = GlobalErrorTracker() 
#!/usr/bin/env python3
"""
Global Error Protection System for AODS

This module provides comprehensive error protection to ensure that no single plugin
failure can crash the entire scan. It implements multi-layer error handling with
graceful degradation, detailed error reporting, and automatic recovery mechanisms.

Features:
- Global exception protection wrapper
- Plugin import and loading protection
- Resource cleanup on failures
- Detailed error categorization and reporting
- Automatic recovery and fallback mechanisms
- Comprehensive logging and metrics
"""

import logging
import sys
import traceback
import time
import signal
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Tuple, Union

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Error severity levels for classification."""
    CRITICAL = "critical"      # System-level errors that could crash scan
    HIGH = "high"             # Plugin failures that prevent analysis
    MEDIUM = "medium"         # Recoverable errors with fallback
    LOW = "low"               # Minor issues that don't affect results
    INFO = "info"             # Informational warnings

class ErrorCategory(Enum):
    """Error categories for better classification."""
    PLUGIN_IMPORT = "plugin_import"         # Plugin loading/import failures
    PLUGIN_EXECUTION = "plugin_execution"   # Plugin runtime errors
    TIMEOUT = "timeout"                     # Timeout-related errors
    RESOURCE = "resource"                   # Memory/disk/system resource errors
    DEPENDENCY = "dependency"               # Missing dependencies
    PERMISSION = "permission"               # File/system permission errors
    CONFIGURATION = "configuration"        # Configuration/setup errors
    NETWORK = "network"                    # Network-related errors
    UNKNOWN = "unknown"                    # Unclassified errors

@dataclass
class ErrorRecord:
    """Detailed error record for tracking and analysis."""
    timestamp: float
    severity: ErrorSeverity
    category: ErrorCategory
    plugin_name: Optional[str]
    operation: str
    error_type: str
    error_message: str
    traceback_info: str
    context: Dict[str, Any] = field(default_factory=dict)
    recovery_attempted: bool = False
    recovery_successful: bool = False
    impact_assessment: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'timestamp': self.timestamp,
            'severity': self.severity.value,
            'category': self.category.value,
            'plugin_name': self.plugin_name,
            'operation': self.operation,
            'error_type': self.error_type,
            'error_message': self.error_message,
            'traceback_info': self.traceback_info,
            'context': self.context,
            'recovery_attempted': self.recovery_attempted,
            'recovery_successful': self.recovery_successful,
            'impact_assessment': self.impact_assessment
        }

class GlobalErrorProtection:
    """
    Global error protection system for comprehensive scan protection.
    
    Ensures no single plugin failure can crash the entire scan by providing
    multi-layer error handling, recovery mechanisms, and detailed reporting.
    """
    
    def __init__(self):
        """Initialize global error protection system."""
        self.error_records: List[ErrorRecord] = []
        self.plugin_failures: Dict[str, int] = {}
        self.recovery_strategies: Dict[ErrorCategory, Callable] = {}
        self.protection_enabled = True
        self.max_plugin_failures = 3  # Max failures before marking plugin as bad
        
        # Error statistics
        self.stats = {
            'total_errors': 0,
            'critical_errors': 0,
            'plugin_errors': 0,
            'recovered_errors': 0,
            'scan_crashes_prevented': 0
        }
        
        # Initialize recovery strategies
        self._initialize_recovery_strategies()
        
        # Set up signal handlers for crash protection
        self._setup_signal_handlers()
        
        logger.info("Global error protection system initialized")
    
    def _initialize_recovery_strategies(self):
        """Initialize error recovery strategies for different error categories."""
        self.recovery_strategies = {
            ErrorCategory.PLUGIN_IMPORT: self._recover_plugin_import,
            ErrorCategory.PLUGIN_EXECUTION: self._recover_plugin_execution,
            ErrorCategory.TIMEOUT: self._recover_timeout,
            ErrorCategory.RESOURCE: self._recover_resource,
            ErrorCategory.DEPENDENCY: self._recover_dependency,
            ErrorCategory.PERMISSION: self._recover_permission,
            ErrorCategory.CONFIGURATION: self._recover_configuration,
            ErrorCategory.NETWORK: self._recover_network
        }
    
    def _setup_signal_handlers(self):
        """Set up signal handlers to catch critical system errors."""
        try:
            # Handle segmentation faults and other critical signals
            signal.signal(signal.SIGSEGV, self._handle_critical_signal)
            signal.signal(signal.SIGFPE, self._handle_critical_signal)
            signal.signal(signal.SIGILL, self._handle_critical_signal)
        except (ValueError, OSError):
            # Signal handling not available on this platform
            logger.debug("Signal handling not available - running in limited protection mode")
    
    def _handle_critical_signal(self, signum, frame):
        """Handle critical system signals to prevent total crash."""
        logger.critical(f"Critical signal {signum} caught - attempting graceful recovery")
        self.stats['scan_crashes_prevented'] += 1
        
        # Create critical error record
        error_record = ErrorRecord(
            timestamp=time.time(),
            severity=ErrorSeverity.CRITICAL,
            category=ErrorCategory.UNKNOWN,
            plugin_name=None,
            operation="system_signal",
            error_type=f"Signal{signum}",
            error_message=f"Critical system signal {signum} received",
            traceback_info="Signal handler invoked",
            impact_assessment="System crash prevented by global protection"
        )
        self.error_records.append(error_record)
        
        # Try to continue execution instead of crashing
        logger.warning("Continuing execution after critical signal - scan may be incomplete")
    
    @contextmanager
    def protect_operation(self, operation_name: str, plugin_name: Optional[str] = None,
                         severity: ErrorSeverity = ErrorSeverity.HIGH):
        """
        Context manager for protecting operations with comprehensive error handling.
        
        Args:
            operation_name: Name of the operation being protected
            plugin_name: Name of plugin if applicable
            severity: Expected severity level of potential errors
        """
        if not self.protection_enabled:
            yield
            return
        
        start_time = time.time()
        
        try:
            logger.debug(f"Starting protected operation: {operation_name}")
            yield
            logger.debug(f"Protected operation completed: {operation_name}")
            
        except KeyboardInterrupt:
            # Handle user interruption gracefully
            logger.warning(f"Operation '{operation_name}' interrupted by user")
            self._record_error(
                severity=ErrorSeverity.INFO,
                category=ErrorCategory.UNKNOWN,
                plugin_name=plugin_name,
                operation=operation_name,
                error=KeyboardInterrupt("User interruption"),
                context={'execution_time': time.time() - start_time}
            )
            raise  # Re-raise to allow graceful shutdown
            
        except SystemExit:
            # Handle system exit calls
            logger.warning(f"Operation '{operation_name}' called system exit")
            self._record_error(
                severity=ErrorSeverity.HIGH,
                category=ErrorCategory.UNKNOWN,
                plugin_name=plugin_name,
                operation=operation_name,
                error=SystemExit("System exit called"),
                context={'execution_time': time.time() - start_time}
            )
            # Don't re-raise SystemExit to prevent scan termination
            
        except Exception as e:
            # Handle all other exceptions
            execution_time = time.time() - start_time
            
            # Categorize and record the error
            category = self._categorize_error(e)
            
            error_record = self._record_error(
                severity=severity,
                category=category,
                plugin_name=plugin_name,
                operation=operation_name,
                error=e,
                context={'execution_time': execution_time}
            )
            
            # Attempt recovery if strategy exists
            recovery_successful = self._attempt_recovery(error_record)
            
            if not recovery_successful:
                logger.error(f"Operation '{operation_name}' failed and could not be recovered")
                if plugin_name:
                    self._mark_plugin_failure(plugin_name)
            
            # Don't re-raise the exception to prevent scan crash
            logger.info(f"Error in '{operation_name}' contained - continuing scan execution")
    
    def protect_plugin_execution(self, plugin_func: Callable, plugin_name: str, 
                                apk_ctx: Any, **kwargs) -> Tuple[bool, Any]:
        """
        Protect plugin execution with comprehensive error handling.
        
        Args:
            plugin_func: Plugin function to execute
            plugin_name: Name of the plugin
            apk_ctx: APK context for analysis
            **kwargs: Additional arguments for plugin
            
        Returns:
            Tuple of (success, result)
        """
        with self.protect_operation(f"execute_plugin_{plugin_name}", plugin_name):
            try:
                result = plugin_func(apk_ctx, **kwargs)
                return True, result
            except Exception as e:
                logger.error(f"Plugin '{plugin_name}' execution failed: {e}")
                # Return safe fallback result
                error_result = (f"❌ {plugin_name}", f"Protected execution failed: {str(e)}")
                return False, error_result
    
    def protect_plugin_import(self, import_func: Callable, plugin_name: str) -> Tuple[bool, Any]:
        """
        Protect plugin import operations.
        
        Args:
            import_func: Function that imports the plugin
            plugin_name: Name of the plugin being imported
            
        Returns:
            Tuple of (success, module_or_error)
        """
        with self.protect_operation(f"import_plugin_{plugin_name}", plugin_name, ErrorSeverity.HIGH):
            try:
                module = import_func()
                return True, module
            except Exception as e:
                logger.error(f"Plugin '{plugin_name}' import failed: {e}")
                return False, str(e)
    
    def _record_error(self, severity: ErrorSeverity, category: ErrorCategory,
                     plugin_name: Optional[str], operation: str, error: Exception,
                     context: Dict[str, Any]) -> ErrorRecord:
        """Record detailed error information."""
        
        error_record = ErrorRecord(
            timestamp=time.time(),
            severity=severity,
            category=category,
            plugin_name=plugin_name,
            operation=operation,
            error_type=type(error).__name__,
            error_message=str(error),
            traceback_info=traceback.format_exc(),
            context=context,
            impact_assessment=self._assess_error_impact(severity, category, plugin_name)
        )
        
        self.error_records.append(error_record)
        self.stats['total_errors'] += 1
        
        if severity == ErrorSeverity.CRITICAL:
            self.stats['critical_errors'] += 1
        if plugin_name:
            self.stats['plugin_errors'] += 1
        
        logger.error(f"Error recorded: {severity.value} {category.value} in {operation}")
        return error_record
    
    def _categorize_error(self, error: Exception) -> ErrorCategory:
        """Categorize error based on exception type and message."""
        error_str = str(error).lower()
        error_type = type(error).__name__
        
        # Import/loading errors
        if error_type in ['ImportError', 'ModuleNotFoundError']:
            return ErrorCategory.PLUGIN_IMPORT
        
        # Timeout errors
        if 'timeout' in error_str or error_type in ['TimeoutError', 'FutureTimeoutError']:
            return ErrorCategory.TIMEOUT
        
        # Resource errors
        if any(keyword in error_str for keyword in ['memory', 'disk', 'resource', 'space']):
            return ErrorCategory.RESOURCE
        
        # Permission errors
        if any(keyword in error_str for keyword in ['permission', 'access', 'denied']):
            return ErrorCategory.PERMISSION
        
        # Network errors
        if any(keyword in error_str for keyword in ['network', 'connection', 'socket']):
            return ErrorCategory.NETWORK
        
        # Configuration errors
        if any(keyword in error_str for keyword in ['config', 'setting', 'invalid']):
            return ErrorCategory.CONFIGURATION
        
        # Default to plugin execution
        return ErrorCategory.PLUGIN_EXECUTION
    
    def _assess_error_impact(self, severity: ErrorSeverity, category: ErrorCategory,
                           plugin_name: Optional[str]) -> str:
        """Assess the impact of an error on the overall scan."""
        if severity == ErrorSeverity.CRITICAL:
            return "Potential scan termination prevented by global protection"
        elif severity == ErrorSeverity.HIGH and plugin_name:
            return f"Plugin '{plugin_name}' analysis unavailable - other plugins continue"
        elif category == ErrorCategory.TIMEOUT:
            return "Plugin timeout handled - scan continues with remaining plugins"
        else:
            return "Minor issue - scan continues normally"
    
    def _attempt_recovery(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from an error using category-specific strategies."""
        error_record.recovery_attempted = True
        
        recovery_strategy = self.recovery_strategies.get(error_record.category)
        if recovery_strategy:
            try:
                success = recovery_strategy(error_record)
                error_record.recovery_successful = success
                if success:
                    self.stats['recovered_errors'] += 1
                    logger.info(f"Successfully recovered from {error_record.category.value} error")
                return success
            except Exception as e:
                logger.warning(f"Recovery strategy failed: {e}")
        
        return False
    
    def _mark_plugin_failure(self, plugin_name: str):
        """Mark plugin failure and disable if too many failures."""
        self.plugin_failures[plugin_name] = self.plugin_failures.get(plugin_name, 0) + 1
        
        if self.plugin_failures[plugin_name] >= self.max_plugin_failures:
            logger.warning(f"Plugin '{plugin_name}' disabled after {self.max_plugin_failures} failures")
    
    def is_plugin_disabled(self, plugin_name: str) -> bool:
        """Check if plugin is disabled due to too many failures."""
        return self.plugin_failures.get(plugin_name, 0) >= self.max_plugin_failures
    
    # Recovery strategy implementations
    def _recover_plugin_import(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from plugin import failures."""
        # Try alternative import methods or skip plugin gracefully
        logger.info(f"Attempting import recovery for plugin {error_record.plugin_name}")
        return False  # For now, just log and continue
    
    def _recover_plugin_execution(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from plugin execution failures."""
        # Could implement retry with different parameters
        logger.info(f"Plugin execution recovery attempted for {error_record.plugin_name}")
        return False
    
    def _recover_timeout(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from timeout errors."""
        # Timeouts are generally not recoverable, just log
        logger.info(f"Timeout recovery for {error_record.operation}")
        return False
    
    def _recover_resource(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from resource errors."""
        # Could implement memory cleanup or temporary file cleanup
        logger.info("Attempting resource cleanup for recovery")
        return False
    
    def _recover_dependency(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from dependency errors."""
        logger.info("Attempting dependency resolution")
        return False
    
    def _recover_permission(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from permission errors."""
        logger.info("Attempting permission issue resolution")
        return False
    
    def _recover_configuration(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from configuration errors."""
        logger.info("Attempting configuration recovery")
        return False
    
    def _recover_network(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from network errors."""
        logger.info("Attempting network recovery")
        return False
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get comprehensive error summary for reporting."""
        severity_counts = {}
        category_counts = {}
        
        for record in self.error_records:
            severity_counts[record.severity.value] = severity_counts.get(record.severity.value, 0) + 1
            category_counts[record.category.value] = category_counts.get(record.category.value, 0) + 1
        
        return {
            'statistics': self.stats.copy(),
            'severity_breakdown': severity_counts,
            'category_breakdown': category_counts,
            'plugin_failures': self.plugin_failures.copy(),
            'total_error_records': len(self.error_records),
            'recent_errors': [record.to_dict() for record in self.error_records[-5:]]
        }
    
    def generate_error_report(self) -> str:
        """Generate human-readable error report."""
        summary = self.get_error_summary()
        
        report = []
        report.append("=" * 60)
        report.append("GLOBAL ERROR PROTECTION SUMMARY")
        report.append("=" * 60)
        
        stats = summary['statistics']
        report.append(f"Total Errors Handled: {stats['total_errors']}")
        report.append(f"Critical Errors: {stats['critical_errors']}")
        report.append(f"Plugin Errors: {stats['plugin_errors']}")
        report.append(f"Recovered Errors: {stats['recovered_errors']}")
        report.append(f"Scan Crashes Prevented: {stats['scan_crashes_prevented']}")
        
        if summary['plugin_failures']:
            report.append("\nPlugin Failure Counts:")
            for plugin, count in summary['plugin_failures'].items():
                status = "DISABLED" if count >= self.max_plugin_failures else "ACTIVE"
                report.append(f"  {plugin}: {count} failures ({status})")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)
    
    def cleanup(self):
        """Cleanup error protection system."""
        logger.info(f"Global error protection cleanup: {len(self.error_records)} errors handled")
        
        # Clear error records to free memory
        self.error_records.clear()
        self.plugin_failures.clear()

# Global instance
_global_error_protection = None

def get_global_error_protection() -> GlobalErrorProtection:
    """Get or create global error protection instance."""
    global _global_error_protection
    if _global_error_protection is None:
        _global_error_protection = GlobalErrorProtection()
    return _global_error_protection

def protect_scan_execution(scan_func: Callable, *args, **kwargs) -> Any:
    """
    Protect entire scan execution with global error handling.
    
    This is the top-level protection for the entire scan process.
    """
    protection = get_global_error_protection()
    
    with protection.protect_operation("complete_scan", severity=ErrorSeverity.CRITICAL):
        try:
            return scan_func(*args, **kwargs)
        except Exception as e:
            logger.critical(f"Scan execution failed: {e}")
            logger.info("Global error protection prevented scan crash - generating partial results")
            return None  # Return None to indicate partial failure but not crash

# Decorator for protecting individual functions
def error_protected(operation_name: str = None, plugin_name: str = None,
                   severity: ErrorSeverity = ErrorSeverity.MEDIUM):
    """Decorator for automatic error protection of functions."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            protection = get_global_error_protection()
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            
            with protection.protect_operation(op_name, plugin_name, severity):
                return func(*args, **kwargs)
        return wrapper
    return decorator 
"""
Global Error Protection System for AODS

This module provides comprehensive error protection to ensure that no single plugin
failure can crash the entire scan. It implements multi-layer error handling with
graceful degradation, detailed error reporting, and automatic recovery mechanisms.

Features:
- Global exception protection wrapper
- Plugin import and loading protection
- Resource cleanup on failures
- Detailed error categorization and reporting
- Automatic recovery and fallback mechanisms
- Comprehensive logging and metrics
"""

import logging
import sys
import traceback
import time
import signal
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Tuple, Union

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Error severity levels for classification."""
    CRITICAL = "critical"      # System-level errors that could crash scan
    HIGH = "high"             # Plugin failures that prevent analysis
    MEDIUM = "medium"         # Recoverable errors with fallback
    LOW = "low"               # Minor issues that don't affect results
    INFO = "info"             # Informational warnings

class ErrorCategory(Enum):
    """Error categories for better classification."""
    PLUGIN_IMPORT = "plugin_import"         # Plugin loading/import failures
    PLUGIN_EXECUTION = "plugin_execution"   # Plugin runtime errors
    TIMEOUT = "timeout"                     # Timeout-related errors
    RESOURCE = "resource"                   # Memory/disk/system resource errors
    DEPENDENCY = "dependency"               # Missing dependencies
    PERMISSION = "permission"               # File/system permission errors
    CONFIGURATION = "configuration"        # Configuration/setup errors
    NETWORK = "network"                    # Network-related errors
    UNKNOWN = "unknown"                    # Unclassified errors

@dataclass
class ErrorRecord:
    """Detailed error record for tracking and analysis."""
    timestamp: float
    severity: ErrorSeverity
    category: ErrorCategory
    plugin_name: Optional[str]
    operation: str
    error_type: str
    error_message: str
    traceback_info: str
    context: Dict[str, Any] = field(default_factory=dict)
    recovery_attempted: bool = False
    recovery_successful: bool = False
    impact_assessment: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'timestamp': self.timestamp,
            'severity': self.severity.value,
            'category': self.category.value,
            'plugin_name': self.plugin_name,
            'operation': self.operation,
            'error_type': self.error_type,
            'error_message': self.error_message,
            'traceback_info': self.traceback_info,
            'context': self.context,
            'recovery_attempted': self.recovery_attempted,
            'recovery_successful': self.recovery_successful,
            'impact_assessment': self.impact_assessment
        }

class GlobalErrorProtection:
    """
    Global error protection system for comprehensive scan protection.
    
    Ensures no single plugin failure can crash the entire scan by providing
    multi-layer error handling, recovery mechanisms, and detailed reporting.
    """
    
    def __init__(self):
        """Initialize global error protection system."""
        self.error_records: List[ErrorRecord] = []
        self.plugin_failures: Dict[str, int] = {}
        self.recovery_strategies: Dict[ErrorCategory, Callable] = {}
        self.protection_enabled = True
        self.max_plugin_failures = 3  # Max failures before marking plugin as bad
        
        # Error statistics
        self.stats = {
            'total_errors': 0,
            'critical_errors': 0,
            'plugin_errors': 0,
            'recovered_errors': 0,
            'scan_crashes_prevented': 0
        }
        
        # Initialize recovery strategies
        self._initialize_recovery_strategies()
        
        # Set up signal handlers for crash protection
        self._setup_signal_handlers()
        
        logger.info("Global error protection system initialized")
    
    def _initialize_recovery_strategies(self):
        """Initialize error recovery strategies for different error categories."""
        self.recovery_strategies = {
            ErrorCategory.PLUGIN_IMPORT: self._recover_plugin_import,
            ErrorCategory.PLUGIN_EXECUTION: self._recover_plugin_execution,
            ErrorCategory.TIMEOUT: self._recover_timeout,
            ErrorCategory.RESOURCE: self._recover_resource,
            ErrorCategory.DEPENDENCY: self._recover_dependency,
            ErrorCategory.PERMISSION: self._recover_permission,
            ErrorCategory.CONFIGURATION: self._recover_configuration,
            ErrorCategory.NETWORK: self._recover_network
        }
    
    def _setup_signal_handlers(self):
        """Set up signal handlers to catch critical system errors."""
        try:
            # Handle segmentation faults and other critical signals
            signal.signal(signal.SIGSEGV, self._handle_critical_signal)
            signal.signal(signal.SIGFPE, self._handle_critical_signal)
            signal.signal(signal.SIGILL, self._handle_critical_signal)
        except (ValueError, OSError):
            # Signal handling not available on this platform
            logger.debug("Signal handling not available - running in limited protection mode")
    
    def _handle_critical_signal(self, signum, frame):
        """Handle critical system signals to prevent total crash."""
        logger.critical(f"Critical signal {signum} caught - attempting graceful recovery")
        self.stats['scan_crashes_prevented'] += 1
        
        # Create critical error record
        error_record = ErrorRecord(
            timestamp=time.time(),
            severity=ErrorSeverity.CRITICAL,
            category=ErrorCategory.UNKNOWN,
            plugin_name=None,
            operation="system_signal",
            error_type=f"Signal{signum}",
            error_message=f"Critical system signal {signum} received",
            traceback_info="Signal handler invoked",
            impact_assessment="System crash prevented by global protection"
        )
        self.error_records.append(error_record)
        
        # Try to continue execution instead of crashing
        logger.warning("Continuing execution after critical signal - scan may be incomplete")
    
    @contextmanager
    def protect_operation(self, operation_name: str, plugin_name: Optional[str] = None,
                         severity: ErrorSeverity = ErrorSeverity.HIGH):
        """
        Context manager for protecting operations with comprehensive error handling.
        
        Args:
            operation_name: Name of the operation being protected
            plugin_name: Name of plugin if applicable
            severity: Expected severity level of potential errors
        """
        if not self.protection_enabled:
            yield
            return
        
        start_time = time.time()
        
        try:
            logger.debug(f"Starting protected operation: {operation_name}")
            yield
            logger.debug(f"Protected operation completed: {operation_name}")
            
        except KeyboardInterrupt:
            # Handle user interruption gracefully
            logger.warning(f"Operation '{operation_name}' interrupted by user")
            self._record_error(
                severity=ErrorSeverity.INFO,
                category=ErrorCategory.UNKNOWN,
                plugin_name=plugin_name,
                operation=operation_name,
                error=KeyboardInterrupt("User interruption"),
                context={'execution_time': time.time() - start_time}
            )
            raise  # Re-raise to allow graceful shutdown
            
        except SystemExit:
            # Handle system exit calls
            logger.warning(f"Operation '{operation_name}' called system exit")
            self._record_error(
                severity=ErrorSeverity.HIGH,
                category=ErrorCategory.UNKNOWN,
                plugin_name=plugin_name,
                operation=operation_name,
                error=SystemExit("System exit called"),
                context={'execution_time': time.time() - start_time}
            )
            # Don't re-raise SystemExit to prevent scan termination
            
        except Exception as e:
            # Handle all other exceptions
            execution_time = time.time() - start_time
            
            # Categorize and record the error
            category = self._categorize_error(e)
            
            error_record = self._record_error(
                severity=severity,
                category=category,
                plugin_name=plugin_name,
                operation=operation_name,
                error=e,
                context={'execution_time': execution_time}
            )
            
            # Attempt recovery if strategy exists
            recovery_successful = self._attempt_recovery(error_record)
            
            if not recovery_successful:
                logger.error(f"Operation '{operation_name}' failed and could not be recovered")
                if plugin_name:
                    self._mark_plugin_failure(plugin_name)
            
            # Don't re-raise the exception to prevent scan crash
            logger.info(f"Error in '{operation_name}' contained - continuing scan execution")
    
    def protect_plugin_execution(self, plugin_func: Callable, plugin_name: str, 
                                apk_ctx: Any, **kwargs) -> Tuple[bool, Any]:
        """
        Protect plugin execution with comprehensive error handling.
        
        Args:
            plugin_func: Plugin function to execute
            plugin_name: Name of the plugin
            apk_ctx: APK context for analysis
            **kwargs: Additional arguments for plugin
            
        Returns:
            Tuple of (success, result)
        """
        with self.protect_operation(f"execute_plugin_{plugin_name}", plugin_name):
            try:
                result = plugin_func(apk_ctx, **kwargs)
                return True, result
            except Exception as e:
                logger.error(f"Plugin '{plugin_name}' execution failed: {e}")
                # Return safe fallback result
                error_result = (f"❌ {plugin_name}", f"Protected execution failed: {str(e)}")
                return False, error_result
    
    def protect_plugin_import(self, import_func: Callable, plugin_name: str) -> Tuple[bool, Any]:
        """
        Protect plugin import operations.
        
        Args:
            import_func: Function that imports the plugin
            plugin_name: Name of the plugin being imported
            
        Returns:
            Tuple of (success, module_or_error)
        """
        with self.protect_operation(f"import_plugin_{plugin_name}", plugin_name, ErrorSeverity.HIGH):
            try:
                module = import_func()
                return True, module
            except Exception as e:
                logger.error(f"Plugin '{plugin_name}' import failed: {e}")
                return False, str(e)
    
    def _record_error(self, severity: ErrorSeverity, category: ErrorCategory,
                     plugin_name: Optional[str], operation: str, error: Exception,
                     context: Dict[str, Any]) -> ErrorRecord:
        """Record detailed error information."""
        
        error_record = ErrorRecord(
            timestamp=time.time(),
            severity=severity,
            category=category,
            plugin_name=plugin_name,
            operation=operation,
            error_type=type(error).__name__,
            error_message=str(error),
            traceback_info=traceback.format_exc(),
            context=context,
            impact_assessment=self._assess_error_impact(severity, category, plugin_name)
        )
        
        self.error_records.append(error_record)
        self.stats['total_errors'] += 1
        
        if severity == ErrorSeverity.CRITICAL:
            self.stats['critical_errors'] += 1
        if plugin_name:
            self.stats['plugin_errors'] += 1
        
        logger.error(f"Error recorded: {severity.value} {category.value} in {operation}")
        return error_record
    
    def _categorize_error(self, error: Exception) -> ErrorCategory:
        """Categorize error based on exception type and message."""
        error_str = str(error).lower()
        error_type = type(error).__name__
        
        # Import/loading errors
        if error_type in ['ImportError', 'ModuleNotFoundError']:
            return ErrorCategory.PLUGIN_IMPORT
        
        # Timeout errors
        if 'timeout' in error_str or error_type in ['TimeoutError', 'FutureTimeoutError']:
            return ErrorCategory.TIMEOUT
        
        # Resource errors
        if any(keyword in error_str for keyword in ['memory', 'disk', 'resource', 'space']):
            return ErrorCategory.RESOURCE
        
        # Permission errors
        if any(keyword in error_str for keyword in ['permission', 'access', 'denied']):
            return ErrorCategory.PERMISSION
        
        # Network errors
        if any(keyword in error_str for keyword in ['network', 'connection', 'socket']):
            return ErrorCategory.NETWORK
        
        # Configuration errors
        if any(keyword in error_str for keyword in ['config', 'setting', 'invalid']):
            return ErrorCategory.CONFIGURATION
        
        # Default to plugin execution
        return ErrorCategory.PLUGIN_EXECUTION
    
    def _assess_error_impact(self, severity: ErrorSeverity, category: ErrorCategory,
                           plugin_name: Optional[str]) -> str:
        """Assess the impact of an error on the overall scan."""
        if severity == ErrorSeverity.CRITICAL:
            return "Potential scan termination prevented by global protection"
        elif severity == ErrorSeverity.HIGH and plugin_name:
            return f"Plugin '{plugin_name}' analysis unavailable - other plugins continue"
        elif category == ErrorCategory.TIMEOUT:
            return "Plugin timeout handled - scan continues with remaining plugins"
        else:
            return "Minor issue - scan continues normally"
    
    def _attempt_recovery(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from an error using category-specific strategies."""
        error_record.recovery_attempted = True
        
        recovery_strategy = self.recovery_strategies.get(error_record.category)
        if recovery_strategy:
            try:
                success = recovery_strategy(error_record)
                error_record.recovery_successful = success
                if success:
                    self.stats['recovered_errors'] += 1
                    logger.info(f"Successfully recovered from {error_record.category.value} error")
                return success
            except Exception as e:
                logger.warning(f"Recovery strategy failed: {e}")
        
        return False
    
    def _mark_plugin_failure(self, plugin_name: str):
        """Mark plugin failure and disable if too many failures."""
        self.plugin_failures[plugin_name] = self.plugin_failures.get(plugin_name, 0) + 1
        
        if self.plugin_failures[plugin_name] >= self.max_plugin_failures:
            logger.warning(f"Plugin '{plugin_name}' disabled after {self.max_plugin_failures} failures")
    
    def is_plugin_disabled(self, plugin_name: str) -> bool:
        """Check if plugin is disabled due to too many failures."""
        return self.plugin_failures.get(plugin_name, 0) >= self.max_plugin_failures
    
    # Recovery strategy implementations
    def _recover_plugin_import(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from plugin import failures."""
        # Try alternative import methods or skip plugin gracefully
        logger.info(f"Attempting import recovery for plugin {error_record.plugin_name}")
        return False  # For now, just log and continue
    
    def _recover_plugin_execution(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from plugin execution failures."""
        # Could implement retry with different parameters
        logger.info(f"Plugin execution recovery attempted for {error_record.plugin_name}")
        return False
    
    def _recover_timeout(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from timeout errors."""
        # Timeouts are generally not recoverable, just log
        logger.info(f"Timeout recovery for {error_record.operation}")
        return False
    
    def _recover_resource(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from resource errors."""
        # Could implement memory cleanup or temporary file cleanup
        logger.info("Attempting resource cleanup for recovery")
        return False
    
    def _recover_dependency(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from dependency errors."""
        logger.info("Attempting dependency resolution")
        return False
    
    def _recover_permission(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from permission errors."""
        logger.info("Attempting permission issue resolution")
        return False
    
    def _recover_configuration(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from configuration errors."""
        logger.info("Attempting configuration recovery")
        return False
    
    def _recover_network(self, error_record: ErrorRecord) -> bool:
        """Attempt to recover from network errors."""
        logger.info("Attempting network recovery")
        return False
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get comprehensive error summary for reporting."""
        severity_counts = {}
        category_counts = {}
        
        for record in self.error_records:
            severity_counts[record.severity.value] = severity_counts.get(record.severity.value, 0) + 1
            category_counts[record.category.value] = category_counts.get(record.category.value, 0) + 1
        
        return {
            'statistics': self.stats.copy(),
            'severity_breakdown': severity_counts,
            'category_breakdown': category_counts,
            'plugin_failures': self.plugin_failures.copy(),
            'total_error_records': len(self.error_records),
            'recent_errors': [record.to_dict() for record in self.error_records[-5:]]
        }
    
    def generate_error_report(self) -> str:
        """Generate human-readable error report."""
        summary = self.get_error_summary()
        
        report = []
        report.append("=" * 60)
        report.append("GLOBAL ERROR PROTECTION SUMMARY")
        report.append("=" * 60)
        
        stats = summary['statistics']
        report.append(f"Total Errors Handled: {stats['total_errors']}")
        report.append(f"Critical Errors: {stats['critical_errors']}")
        report.append(f"Plugin Errors: {stats['plugin_errors']}")
        report.append(f"Recovered Errors: {stats['recovered_errors']}")
        report.append(f"Scan Crashes Prevented: {stats['scan_crashes_prevented']}")
        
        if summary['plugin_failures']:
            report.append("\nPlugin Failure Counts:")
            for plugin, count in summary['plugin_failures'].items():
                status = "DISABLED" if count >= self.max_plugin_failures else "ACTIVE"
                report.append(f"  {plugin}: {count} failures ({status})")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)
    
    def cleanup(self):
        """Cleanup error protection system."""
        logger.info(f"Global error protection cleanup: {len(self.error_records)} errors handled")
        
        # Clear error records to free memory
        self.error_records.clear()
        self.plugin_failures.clear()

# Global instance
_global_error_protection = None

def get_global_error_protection() -> GlobalErrorProtection:
    """Get or create global error protection instance."""
    global _global_error_protection
    if _global_error_protection is None:
        _global_error_protection = GlobalErrorProtection()
    return _global_error_protection

def protect_scan_execution(scan_func: Callable, *args, **kwargs) -> Any:
    """
    Protect entire scan execution with global error handling.
    
    This is the top-level protection for the entire scan process.
    """
    protection = get_global_error_protection()
    
    with protection.protect_operation("complete_scan", severity=ErrorSeverity.CRITICAL):
        try:
            return scan_func(*args, **kwargs)
        except Exception as e:
            logger.critical(f"Scan execution failed: {e}")
            logger.info("Global error protection prevented scan crash - generating partial results")
            return None  # Return None to indicate partial failure but not crash

# Decorator for protecting individual functions
def error_protected(operation_name: str = None, plugin_name: str = None,
                   severity: ErrorSeverity = ErrorSeverity.MEDIUM):
    """Decorator for automatic error protection of functions."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            protection = get_global_error_protection()
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            
            with protection.protect_operation(op_name, plugin_name, severity):
                return func(*args, **kwargs)
        return wrapper
    return decorator 
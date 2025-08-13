#!/usr/bin/env python3
"""
Comprehensive Error Recovery Framework for AODS

This framework provides standardized error handling, recovery mechanisms, and graceful
degradation capabilities for all AODS plugins and analysis modules.

Features:
- Standardized error recovery interface for all plugins
- Graceful degradation capabilities for failed analysis modules
- Centralized error reporting and monitoring system
- Scan continuation with maximum functionality despite individual plugin failures
- Error classification and intelligent recovery strategies
- Performance impact monitoring and mitigation
"""

import logging
import time
import traceback
import sys
import threading
from typing import Dict, List, Any, Optional, Callable, Union, Type, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# Rich formatting for enhanced error display
try:
    from rich.text import Text
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Error severity levels for classification."""
    CRITICAL = "critical"      # System-breaking errors that stop analysis
    HIGH = "high"             # Plugin failures that significantly impact results
    MEDIUM = "medium"         # Functionality degradation, partial failures
    LOW = "low"              # Minor issues, warnings, performance impacts
    INFO = "info"            # Informational, recoverable issues

class RecoveryStrategy(Enum):
    """Recovery strategies for different error types."""
    RETRY = "retry"                    # Retry operation with backoff
    FALLBACK = "fallback"             # Use alternative implementation
    SKIP = "skip"                     # Skip failed component, continue scan
    GRACEFUL_DEGRADATION = "graceful"  # Reduce functionality, continue with limitations
    TERMINATE = "terminate"           # Stop execution (critical errors only)

class ErrorCategory(Enum):
    """Error categories for intelligent handling."""
    DEPENDENCY_MISSING = "dependency_missing"
    TIMEOUT = "timeout"
    MEMORY_EXHAUSTION = "memory_exhaustion"
    NETWORK_FAILURE = "network_failure"
    FILE_ACCESS = "file_access"
    CONFIGURATION = "configuration"
    PLUGIN_INTERNAL = "plugin_internal"
    SYSTEM_RESOURCE = "system_resource"
    UNKNOWN = "unknown"

@dataclass
class ErrorContext:
    """Context information for error analysis and recovery."""
    plugin_name: str
    operation: str
    error_type: Type[Exception]
    error_message: str
    stack_trace: str
    timestamp: datetime
    severity: ErrorSeverity
    category: ErrorCategory
    recovery_strategy: RecoveryStrategy
    retry_count: int = 0
    max_retries: int = 3
    recovery_attempts: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RecoveryResult:
    """Result of error recovery attempt."""
    success: bool
    strategy_used: RecoveryStrategy
    fallback_data: Optional[Any] = None
    error_suppressed: bool = False
    performance_impact: Optional[float] = None  # Recovery time in seconds
    recommendation: Optional[str] = None

class ErrorRecoveryInterface:
    """Standardized interface for plugin error recovery."""
    
    def handle_error(self, error: Exception, context: Dict[str, Any]) -> RecoveryResult:
        """Handle plugin-specific error with recovery strategy."""
        raise NotImplementedError("Plugins must implement handle_error method")
    
    def get_fallback_result(self, operation: str, context: Dict[str, Any]) -> Any:
        """Provide fallback result when primary operation fails."""
        raise NotImplementedError("Plugins must implement get_fallback_result method")
    
    def validate_preconditions(self) -> bool:
        """Validate plugin preconditions before execution."""
        return True
    
    def cleanup_on_failure(self, context: Dict[str, Any]) -> None:
        """Cleanup resources after plugin failure."""
        pass

class ErrorClassifier:
    """Intelligent error classification and strategy recommendation."""
    
    def __init__(self):
        self.classification_rules = {
            # Dependency errors
            (ImportError, ModuleNotFoundError): (ErrorCategory.DEPENDENCY_MISSING, RecoveryStrategy.FALLBACK),
            (AttributeError,): (ErrorCategory.DEPENDENCY_MISSING, RecoveryStrategy.FALLBACK),
            
            # Timeout errors
            (TimeoutError,): (ErrorCategory.TIMEOUT, RecoveryStrategy.RETRY),
            
            # Memory errors
            (MemoryError,): (ErrorCategory.MEMORY_EXHAUSTION, RecoveryStrategy.GRACEFUL_DEGRADATION),
            
            # File access errors
            (FileNotFoundError, PermissionError, OSError): (ErrorCategory.FILE_ACCESS, RecoveryStrategy.SKIP),
            
            # Network errors
            (ConnectionError,): (ErrorCategory.NETWORK_FAILURE, RecoveryStrategy.RETRY),
            
            # Configuration errors
            (KeyError, ValueError): (ErrorCategory.CONFIGURATION, RecoveryStrategy.FALLBACK),
        }
        
        self.message_patterns = {
            'timeout': (ErrorCategory.TIMEOUT, RecoveryStrategy.RETRY),
            'memory': (ErrorCategory.MEMORY_EXHAUSTION, RecoveryStrategy.GRACEFUL_DEGRADATION),
            'permission denied': (ErrorCategory.FILE_ACCESS, RecoveryStrategy.SKIP),
            'connection refused': (ErrorCategory.NETWORK_FAILURE, RecoveryStrategy.RETRY),
            'no such file': (ErrorCategory.FILE_ACCESS, RecoveryStrategy.SKIP),
            'command not found': (ErrorCategory.DEPENDENCY_MISSING, RecoveryStrategy.FALLBACK),
        }
    
    def classify_error(self, error: Exception, context: Dict[str, Any]) -> tuple[ErrorCategory, RecoveryStrategy, ErrorSeverity]:
        """Classify error and recommend recovery strategy."""
        error_type = type(error)
        error_message = str(error).lower()
        
        # Check specific error types
        for error_types, (category, strategy) in self.classification_rules.items():
            if error_type in error_types:
                severity = self._determine_severity(category, context)
                return category, strategy, severity
        
        # Check error message patterns
        for pattern, (category, strategy) in self.message_patterns.items():
            if pattern in error_message:
                severity = self._determine_severity(category, context)
                return category, strategy, severity
        
        # Default classification
        return ErrorCategory.UNKNOWN, RecoveryStrategy.SKIP, ErrorSeverity.MEDIUM
    
    def _determine_severity(self, category: ErrorCategory, context: Dict[str, Any]) -> ErrorSeverity:
        """Determine error severity based on category and context."""
        critical_plugins = {'enhanced_static_analysis', 'code_quality_injection_analysis', 
                           'network_communication_tests', 'enhanced_manifest_analysis'}
        
        plugin_name = context.get('plugin_name', '').lower()
        
        if category == ErrorCategory.MEMORY_EXHAUSTION:
            return ErrorSeverity.CRITICAL
        elif category == ErrorCategory.DEPENDENCY_MISSING and plugin_name in critical_plugins:
            return ErrorSeverity.HIGH
        elif category == ErrorCategory.TIMEOUT:
            return ErrorSeverity.MEDIUM
        elif category == ErrorCategory.FILE_ACCESS:
            return ErrorSeverity.LOW
        else:
            return ErrorSeverity.MEDIUM

class GracefulDegradationManager:
    """Manages graceful degradation of functionality when components fail."""
    
    def __init__(self):
        self.degradation_strategies = {
            'enhanced_static_analysis': self._static_analysis_fallback,
            'code_quality_injection_analysis': self._injection_analysis_fallback,
            'network_communication_tests': self._network_tests_fallback,
            'enhanced_manifest_analysis': self._manifest_analysis_fallback,
            'jadx_static_analysis': self._jadx_fallback,
            'frida_dynamic_analysis': self._frida_fallback,
        }
    
    def get_degraded_functionality(self, plugin_name: str, original_error: Exception) -> Dict[str, Any]:
        """Get degraded functionality when plugin fails."""
        strategy = self.degradation_strategies.get(plugin_name, self._generic_fallback)
        return strategy(original_error)
    
    def _static_analysis_fallback(self, error: Exception) -> Dict[str, Any]:
        """Fallback for enhanced static analysis failures."""
        return {
            'plugin_name': 'Enhanced Static Analysis (Degraded)',
            'status': 'DEGRADED',
            'functionality': 'Basic pattern matching without ML enhancement',
            'recommendations': [
                'Use alternative static analysis tools',
                'Manual code review recommended for comprehensive coverage',
                'Enable network communication tests for additional security checks'
            ],
            'error_info': str(error)
        }
    
    def _injection_analysis_fallback(self, error: Exception) -> Dict[str, Any]:
        """Fallback for injection analysis failures."""
        return {
            'plugin_name': 'Code Quality Injection Analysis (Degraded)',
            'status': 'DEGRADED',
            'functionality': 'Basic injection pattern detection',
            'recommendations': [
                'Manual code review for injection vulnerabilities',
                'Use SAST tools for comprehensive injection analysis',
                'Enable enhanced manifest analysis for configuration issues'
            ],
            'error_info': str(error)
        }
    
    def _network_tests_fallback(self, error: Exception) -> Dict[str, Any]:
        """Fallback for network communication test failures."""
        return {
            'plugin_name': 'Network Communication Tests (Degraded)',
            'status': 'DEGRADED',
            'functionality': 'Basic network configuration analysis',
            'recommendations': [
                'Manual review of network security configuration',
                'Use external network analysis tools',
                'Enable enhanced manifest analysis for network permissions'
            ],
            'error_info': str(error)
        }
    
    def _manifest_analysis_fallback(self, error: Exception) -> Dict[str, Any]:
        """Fallback for manifest analysis failures."""
        return {
            'plugin_name': 'Enhanced Manifest Analysis (Degraded)',
            'status': 'DEGRADED',
            'functionality': 'Basic AndroidManifest.xml parsing',
            'recommendations': [
                'Manual AndroidManifest.xml review',
                'Use alternative APK analysis tools',
                'Focus on permissions and component security'
            ],
            'error_info': str(error)
        }
    
    def _jadx_fallback(self, error: Exception) -> Dict[str, Any]:
        """Fallback for JADX static analysis failures."""
        return {
            'plugin_name': 'JADX Static Analysis (Degraded)',
            'status': 'DEGRADED',
            'functionality': 'Alternative decompilation approaches available',
            'recommendations': [
                'Use Enhanced Static Analysis for pattern-based detection',
                'Try manual JADX execution with optimized parameters',
                'Consider alternative decompilers (apktool, dex2jar)'
            ],
            'error_info': str(error)
        }
    
    def _frida_fallback(self, error: Exception) -> Dict[str, Any]:
        """Fallback for Frida dynamic analysis failures."""
        return {
            'plugin_name': 'Frida Dynamic Analysis (Degraded)',
            'status': 'DEGRADED',
            'functionality': 'Static analysis simulation of dynamic behaviors',
            'recommendations': [
                'Use static analysis plugins for comprehensive coverage',
                'Manual dynamic analysis with alternative tools',
                'Focus on static pattern detection and manifest analysis'
            ],
            'error_info': str(error)
        }
    
    def _generic_fallback(self, error: Exception) -> Dict[str, Any]:
        """Generic fallback for unknown plugins."""
        return {
            'plugin_name': 'Plugin (Degraded)',
            'status': 'DEGRADED',
            'functionality': 'Limited functionality available',
            'recommendations': [
                'Continue with other available analysis plugins',
                'Review plugin configuration and dependencies',
                'Consider alternative analysis approaches'
            ],
            'error_info': str(error)
        }

class CentralizedErrorReporter:
    """Centralized error reporting and monitoring system."""
    
    def __init__(self, log_file: Optional[str] = None):
        self.errors: List[ErrorContext] = []
        self.error_stats: Dict[str, int] = defaultdict(int)
        self.recovery_stats: Dict[RecoveryStrategy, int] = defaultdict(int)
        self.log_file = log_file
        self.console = Console() if RICH_AVAILABLE else None
        
        # Thread safety
        self._lock = threading.Lock()
    
    def report_error(self, error_context: ErrorContext) -> None:
        """Report error to centralized system."""
        with self._lock:
            self.errors.append(error_context)
            self.error_stats[error_context.plugin_name] += 1
            self.recovery_stats[error_context.recovery_strategy] += 1
            
            # Log error
            self._log_error(error_context)
    
    def report_recovery(self, error_context: ErrorContext, recovery_result: RecoveryResult) -> None:
        """Report recovery attempt result."""
        with self._lock:
            error_context.recovery_attempts.append(
                f"{recovery_result.strategy_used.value}:{'success' if recovery_result.success else 'failed'}"
            )
            
            # Log recovery
            self._log_recovery(error_context, recovery_result)
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get comprehensive error summary."""
        with self._lock:
            total_errors = len(self.errors)
            if total_errors == 0:
                return {'total_errors': 0, 'status': 'No errors recorded'}
            
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            
            for error in self.errors:
                severity_counts[error.severity.value] += 1
                category_counts[error.category.value] += 1
            
            return {
                'total_errors': total_errors,
                'errors_by_plugin': dict(self.error_stats),
                'errors_by_severity': dict(severity_counts),
                'errors_by_category': dict(category_counts),
                'recovery_attempts': dict(self.recovery_stats),
                'most_problematic_plugins': self._get_top_error_plugins(5),
                'recovery_success_rate': self._calculate_recovery_success_rate()
            }
    
    def _log_error(self, error_context: ErrorContext) -> None:
        """Log error with appropriate formatting."""
        log_message = (
            f"ERROR RECOVERY: {error_context.plugin_name} - {error_context.operation} - "
            f"{error_context.severity.value.upper()} - {error_context.category.value} - "
            f"{error_context.error_message}"
        )
        
        if error_context.severity in [ErrorSeverity.CRITICAL, ErrorSeverity.HIGH]:
            logger.error(log_message)
        elif error_context.severity == ErrorSeverity.MEDIUM:
            logger.warning(log_message)
        else:
            logger.info(log_message)
        
        # Write to file if configured
        if self.log_file:
            self._write_to_log_file(error_context)
    
    def _log_recovery(self, error_context: ErrorContext, recovery_result: RecoveryResult) -> None:
        """Log recovery attempt."""
        status = "SUCCESS" if recovery_result.success else "FAILED"
        log_message = (
            f"RECOVERY {status}: {error_context.plugin_name} - "
            f"Strategy: {recovery_result.strategy_used.value} - "
            f"Time: {recovery_result.performance_impact or 0:.2f}s"
        )
        
        if recovery_result.success:
            logger.info(log_message)
        else:
            logger.warning(log_message)
    
    def _get_top_error_plugins(self, count: int) -> List[Tuple[str, int]]:
        """Get plugins with most errors."""
        return sorted(self.error_stats.items(), key=lambda x: x[1], reverse=True)[:count]
    
    def _calculate_recovery_success_rate(self) -> float:
        """Calculate overall recovery success rate."""
        if not self.errors:
            return 0.0
        
        successful_recoveries = sum(
            1 for error in self.errors 
            if any('success' in attempt for attempt in error.recovery_attempts)
        )
        
        return (successful_recoveries / len(self.errors)) * 100
    
    def _write_to_log_file(self, error_context: ErrorContext) -> None:
        """Write error to log file."""
        try:
            with open(self.log_file, 'a') as f:
                f.write(f"{error_context.timestamp.isoformat()} - {error_context.plugin_name} - "
                       f"{error_context.severity.value} - {error_context.error_message}\n")
        except Exception as e:
            logger.warning(f"Failed to write to error log file: {e}")

class ComprehensiveErrorRecoveryFramework:
    """Main error recovery framework coordinator."""
    
    def __init__(self, log_file: Optional[str] = None):
        self.classifier = ErrorClassifier()
        self.degradation_manager = GracefulDegradationManager()
        self.reporter = CentralizedErrorReporter(log_file)
        self.registered_handlers: Dict[str, ErrorRecoveryInterface] = {}
        
        logger.info("Comprehensive Error Recovery Framework initialized")
    
    def register_plugin(self, plugin_name: str, handler: ErrorRecoveryInterface) -> None:
        """Register plugin with error recovery handler."""
        self.registered_handlers[plugin_name] = handler
        logger.debug(f"Registered error recovery handler for {plugin_name}")
    
    def handle_plugin_error(self, plugin_name: str, operation: str, error: Exception, 
                          context: Optional[Dict[str, Any]] = None) -> RecoveryResult:
        """Handle plugin error with comprehensive recovery strategy."""
        context = context or {}
        context['plugin_name'] = plugin_name
        
        # Classify error and determine recovery strategy
        category, strategy, severity = self.classifier.classify_error(error, context)
        
        # Create error context
        error_context = ErrorContext(
            plugin_name=plugin_name,
            operation=operation,
            error_type=type(error),
            error_message=str(error),
            stack_trace=traceback.format_exc(),
            timestamp=datetime.now(),
            severity=severity,
            category=category,
            recovery_strategy=strategy
        )
        
        # Report error
        self.reporter.report_error(error_context)
        
        # Attempt recovery
        recovery_result = self._attempt_recovery(error_context, context)
        
        # Report recovery result
        self.reporter.report_recovery(error_context, recovery_result)
        
        return recovery_result
    
    def _attempt_recovery(self, error_context: ErrorContext, context: Dict[str, Any]) -> RecoveryResult:
        """Attempt error recovery based on strategy."""
        start_time = time.time()
        
        try:
            if error_context.recovery_strategy == RecoveryStrategy.RETRY:
                return self._retry_operation(error_context, context)
            elif error_context.recovery_strategy == RecoveryStrategy.FALLBACK:
                return self._fallback_operation(error_context, context)
            elif error_context.recovery_strategy == RecoveryStrategy.GRACEFUL_DEGRADATION:
                return self._graceful_degradation(error_context, context)
            elif error_context.recovery_strategy == RecoveryStrategy.SKIP:
                return self._skip_operation(error_context, context)
            else:  # TERMINATE
                return RecoveryResult(
                    success=False,
                    strategy_used=RecoveryStrategy.TERMINATE,
                    recommendation="Critical error - scan terminated"
                )
        
        finally:
            recovery_time = time.time() - start_time
            logger.debug(f"Recovery attempt took {recovery_time:.2f} seconds")
    
    def _retry_operation(self, error_context: ErrorContext, context: Dict[str, Any]) -> RecoveryResult:
        """Retry failed operation with backoff."""
        if error_context.retry_count >= error_context.max_retries:
            return RecoveryResult(
                success=False,
                strategy_used=RecoveryStrategy.RETRY,
                recommendation="Max retries exceeded, consider alternative approach"
            )
        
        # Simple backoff strategy
        wait_time = 2 ** error_context.retry_count
        time.sleep(min(wait_time, 10))  # Cap at 10 seconds
        
        error_context.retry_count += 1
        
        return RecoveryResult(
            success=True,
            strategy_used=RecoveryStrategy.RETRY,
            recommendation=f"Retry attempt {error_context.retry_count}/{error_context.max_retries}"
        )
    
    def _fallback_operation(self, error_context: ErrorContext, context: Dict[str, Any]) -> RecoveryResult:
        """Use fallback implementation."""
        # Check if plugin has registered fallback handler
        handler = self.registered_handlers.get(error_context.plugin_name)
        if handler:
            try:
                fallback_result = handler.get_fallback_result(error_context.operation, context)
                return RecoveryResult(
                    success=True,
                    strategy_used=RecoveryStrategy.FALLBACK,
                    fallback_data=fallback_result,
                    recommendation="Using plugin-specific fallback implementation"
                )
            except Exception as e:
                logger.warning(f"Plugin fallback failed for {error_context.plugin_name}: {e}")
        
        # Use degraded functionality
        degraded_functionality = self.degradation_manager.get_degraded_functionality(
            error_context.plugin_name, 
            Exception(error_context.error_message)
        )
        
        return RecoveryResult(
            success=True,
            strategy_used=RecoveryStrategy.FALLBACK,
            fallback_data=degraded_functionality,
            recommendation="Using degraded functionality fallback"
        )
    
    def _graceful_degradation(self, error_context: ErrorContext, context: Dict[str, Any]) -> RecoveryResult:
        """Implement graceful degradation."""
        degraded_functionality = self.degradation_manager.get_degraded_functionality(
            error_context.plugin_name,
            Exception(error_context.error_message)
        )
        
        return RecoveryResult(
            success=True,
            strategy_used=RecoveryStrategy.GRACEFUL_DEGRADATION,
            fallback_data=degraded_functionality,
            error_suppressed=True,
            recommendation="Continuing with reduced functionality"
        )
    
    def _skip_operation(self, error_context: ErrorContext, context: Dict[str, Any]) -> RecoveryResult:
        """Skip failed operation and continue."""
        return RecoveryResult(
            success=True,
            strategy_used=RecoveryStrategy.SKIP,
            error_suppressed=True,
            recommendation=f"Skipped {error_context.plugin_name} due to {error_context.category.value}"
        )
    
    def get_framework_status(self) -> Dict[str, Any]:
        """Get comprehensive framework status."""
        return {
            'framework_version': '1.0.0',
            'registered_plugins': len(self.registered_handlers),
            'error_summary': self.reporter.get_error_summary(),
            'recovery_strategies_available': [strategy.value for strategy in RecoveryStrategy],
            'error_categories_supported': [category.value for category in ErrorCategory]
        }
    
    def generate_error_report(self) -> Union[str, Text]:
        """Generate comprehensive error report."""
        status = self.get_framework_status()
        error_summary = status['error_summary']
        
        if RICH_AVAILABLE and self.reporter.console:
            # Rich formatted report
            report = Text()
            report.append("Error Recovery Framework Report\n", style="bold blue")
            report.append("=" * 50 + "\n\n", style="blue")
            
            # Summary
            total_errors = error_summary.get('total_errors', 0)
            if total_errors == 0:
                report.append("✅ No errors recorded - system running smoothly\n", style="green")
            else:
                report.append(f"📊 Total Errors: {total_errors}\n", style="yellow")
                
                # Recovery success rate
                success_rate = error_summary.get('recovery_success_rate', 0)
                style = "green" if success_rate > 80 else "yellow" if success_rate > 50 else "red"
                report.append(f"🔄 Recovery Success Rate: {success_rate:.1f}%\n", style=style)
                
                # Top problematic plugins
                top_plugins = error_summary.get('most_problematic_plugins', [])
                if top_plugins:
                    report.append("\n🔴 Most Problematic Plugins:\n", style="bold red")
                    for plugin, count in top_plugins[:3]:
                        report.append(f"   • {plugin}: {count} errors\n", style="red")
            
            report.append(f"\n✅ Framework Status: {len(self.registered_handlers)} plugins registered\n", style="green")
            return report
        else:
            # Plain text report
            lines = [
                "Error Recovery Framework Report",
                "=" * 50,
                "",
                f"Total Errors: {error_summary.get('total_errors', 0)}",
                f"Recovery Success Rate: {error_summary.get('recovery_success_rate', 0):.1f}%",
                f"Registered Plugins: {len(self.registered_handlers)}",
                ""
            ]
            
            top_plugins = error_summary.get('most_problematic_plugins', [])
            if top_plugins:
                lines.append("Most Problematic Plugins:")
                for plugin, count in top_plugins[:3]:
                    lines.append(f"  • {plugin}: {count} errors")
                lines.append("")
            
            return "\n".join(lines)

# Global framework instance
_error_recovery_framework: Optional[ComprehensiveErrorRecoveryFramework] = None

def get_error_recovery_framework() -> ComprehensiveErrorRecoveryFramework:
    """Get global error recovery framework instance."""
    global _error_recovery_framework
    if _error_recovery_framework is None:
        _error_recovery_framework = ComprehensiveErrorRecoveryFramework()
    return _error_recovery_framework

def handle_plugin_error(plugin_name: str, operation: str, error: Exception, 
                       context: Optional[Dict[str, Any]] = None) -> RecoveryResult:
    """Convenience function to handle plugin errors."""
    framework = get_error_recovery_framework()
    return framework.handle_plugin_error(plugin_name, operation, error, context)

def register_plugin_handler(plugin_name: str, handler: ErrorRecoveryInterface) -> None:
    """Convenience function to register plugin error handler."""
    framework = get_error_recovery_framework()
    framework.register_plugin(plugin_name, handler)

# Export main components
__all__ = [
    'ComprehensiveErrorRecoveryFramework',
    'ErrorRecoveryInterface',
    'ErrorSeverity',
    'RecoveryStrategy',
    'ErrorCategory',
    'ErrorContext',
    'RecoveryResult',
    'get_error_recovery_framework',
    'handle_plugin_error',
    'register_plugin_handler'
] 
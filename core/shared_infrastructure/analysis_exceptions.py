"""
AODS Structured Error Handling Framework

Provides hierarchical exception classes with contextual logging for comprehensive
error handling across all AODS analysis components.

Features:
- Hierarchical exception hierarchy for specific error types
- Contextual error information with analysis context
- Automatic error logging with detailed context
- Recovery mechanisms and fallback strategies
- Performance-aware error handling
"""

import logging
import traceback
from abc import ABC
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import sys

logger = logging.getLogger(__name__)

@dataclass
class ErrorContext:
    """Contextual information for error analysis and debugging."""
    component_name: str
    operation: str
    apk_path: Optional[Path] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    pattern_id: Optional[str] = None
    confidence_value: Optional[float] = None
    analysis_stage: Optional[str] = None
    additional_context: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error context to dictionary for logging."""
        return {
            'component_name': self.component_name,
            'operation': self.operation,
            'apk_path': str(self.apk_path) if self.apk_path else None,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'pattern_id': self.pattern_id,
            'confidence_value': self.confidence_value,
            'analysis_stage': self.analysis_stage,
            'additional_context': self.additional_context,
            'timestamp': self.timestamp.isoformat()
        }

class AnalysisError(Exception, ABC):
    """
    Base exception class for all analysis errors.
    
    Provides structured error handling with contextual information
    and automatic logging capabilities.
    
    This is the generic base class for analysis framework errors,
    designed for future-proof and maintainable API design.
    """
    
    def __init__(self, 
                 message: str, 
                 context: Optional[ErrorContext] = None,
                 cause: Optional[Exception] = None,
                 recoverable: bool = True):
        """
        Initialize analysis error.
        
        Args:
            message: Human-readable error message
            context: Error context with detailed information
            cause: Original exception that caused this error
            recoverable: Whether this error can be recovered from
        """
        super().__init__(message)
        self.message = message
        self.context = context or ErrorContext(component_name="unknown", operation="unknown")
        self.cause = cause
        self.recoverable = recoverable
        self.error_id = f"ANALYSIS_{self.__class__.__name__}_{id(self)}"
        
        # Automatic logging
        self._log_error()
    
    def _log_error(self):
        """Log the error with full context."""
        log_data = {
            'error_id': self.error_id,
            'error_type': self.__class__.__name__,
            'error_message': self.message,  # Renamed from 'message' to avoid logging conflict
            'recoverable': self.recoverable,
            'context': self.context.to_dict() if self.context else {},
            'cause': str(self.cause) if self.cause else None,
            'traceback': traceback.format_exc() if self.cause else None
        }
        
        # Choose log level based on error severity
        if self.recoverable:
            logger.warning(f"Recoverable analysis error: {self.message}", extra=log_data)
        else:
            logger.error(f"Critical analysis error: {self.message}", extra=log_data)
    
    def get_context_summary(self) -> str:
        """Get a human-readable context summary."""
        if not self.context:
            return "No context available"
        
        summary_parts = [f"Component: {self.context.component_name}"]
        if self.context.operation:
            summary_parts.append(f"Operation: {self.context.operation}")
        if self.context.apk_path:
            summary_parts.append(f"APK: {self.context.apk_path.name}")
        if self.context.analysis_stage:
            summary_parts.append(f"Stage: {self.context.analysis_stage}")
        
        return " | ".join(summary_parts)
    
    def __str__(self) -> str:
        """String representation with context."""
        base_msg = f"{self.__class__.__name__}: {self.message}"
        if self.context:
            base_msg += f" [{self.get_context_summary()}]"
        return base_msg

# Backward compatibility alias
AODSAnalysisError = AnalysisError

class ConfigurationError(AnalysisError):
    """Error in configuration loading or validation."""
    
    def __init__(self, message: str, config_path: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="configuration",
            operation="config_load",
            file_path=config_path,
            additional_context={'config_path': config_path}
        )
        super().__init__(message, context, recoverable=False, **kwargs)

class PatternAnalysisError(AnalysisError):
    """Error in pattern matching or analysis."""
    
    def __init__(self, message: str, pattern_id: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="pattern_analyzer",
            operation="pattern_match",
            pattern_id=pattern_id,
            additional_context={'pattern_id': pattern_id}
        )
        super().__init__(message, context, **kwargs)

class ConfidenceCalculationError(AnalysisError):
    """Error in confidence calculation."""
    
    def __init__(self, message: str, confidence_value: Optional[float] = None, **kwargs):
        context = ErrorContext(
            component_name="confidence_calculator",
            operation="calculate_confidence",
            confidence_value=confidence_value,
            additional_context={'confidence_value': confidence_value}
        )
        super().__init__(message, context, **kwargs)

class CryptoAnalysisError(AnalysisError):
    """Error in cryptographic analysis."""
    
    def __init__(self, message: str, algorithm: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="crypto_analyzer",
            operation="crypto_analysis",
            additional_context={'algorithm': algorithm}
        )
        super().__init__(message, context, **kwargs)

class BinaryAnalysisError(AnalysisError):
    """Error in binary analysis."""
    
    def __init__(self, message: str, binary_path: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="binary_analyzer",
            operation="binary_analysis",
            file_path=binary_path,
            additional_context={'binary_path': binary_path}
        )
        super().__init__(message, context, **kwargs)

class NetworkAnalysisError(AnalysisError):
    """Error in network analysis."""
    
    def __init__(self, message: str, endpoint: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="network_analyzer",
            operation="network_analysis",
            additional_context={'endpoint': endpoint}
        )
        super().__init__(message, context, **kwargs)

class NetworkSecurityConfigError(AnalysisError):
    """Error in network security configuration analysis."""
    
    def __init__(self, message: str, config_path: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="network_security_config_analyzer",
            operation="network_security_config_analysis",
            additional_context={'config_path': config_path}
        )
        super().__init__(message, context, **kwargs)

class SSLTLSAnalysisError(AnalysisError):
    """Error in SSL/TLS analysis."""
    
    def __init__(self, message: str, certificate_path: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="ssl_tls_analyzer",
            operation="ssl_tls_analysis",
            additional_context={'certificate_path': certificate_path}
        )
        super().__init__(message, context, **kwargs)

class CertificateAnalysisError(AnalysisError):
    """Error in certificate analysis."""
    
    def __init__(self, message: str, certificate_path: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="certificate_analyzer",
            operation="certificate_analysis",
            additional_context={'certificate_path': certificate_path}
        )
        super().__init__(message, context, **kwargs)

class TLSAnalysisError(AnalysisError):
    """Error in TLS analysis."""
    
    def __init__(self, message: str, tls_context: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="tls_analyzer",
            operation="tls_analysis",
            additional_context={'tls_context': tls_context}
        )
        super().__init__(message, context, **kwargs)

class DynamicSSLTestingError(AnalysisError):
    """Error in dynamic SSL testing."""
    
    def __init__(self, message: str, ssl_context: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="dynamic_ssl_tester",
            operation="dynamic_ssl_testing",
            additional_context={'ssl_context': ssl_context}
        )
        super().__init__(message, context, **kwargs)

class StorageAnalysisError(AnalysisError):
    """Error in storage analysis."""
    
    def __init__(self, message: str, storage_type: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="storage_analyzer",
            operation="storage_analysis",
            additional_context={'storage_type': storage_type}
        )
        super().__init__(message, context, **kwargs)

class PlatformAnalysisError(AnalysisError):
    """Error in platform usage analysis."""
    
    def __init__(self, message: str, platform_component: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="platform_analyzer",
            operation="platform_analysis",
            additional_context={'platform_component': platform_component}
        )
        super().__init__(message, context, **kwargs)

class DecompilationError(AnalysisError):
    """Error in APK decompilation process."""
    
    def __init__(self, message: str, decompiler: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="decompiler",
            operation="decompilation",
            additional_context={'decompiler': decompiler}
        )
        super().__init__(message, context, recoverable=False, **kwargs)

class FileSystemError(AnalysisError):
    """Error in file system operations."""
    
    def __init__(self, message: str, file_path: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="filesystem",
            operation="file_operation",
            file_path=file_path,
            additional_context={'file_path': file_path}
        )
        super().__init__(message, context, **kwargs)

class DependencyInjectionError(AnalysisError):
    """Error in dependency injection or component creation."""
    
    def __init__(self, message: str, component_name: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="dependency_injector",
            operation="component_creation",
            additional_context={'failed_component': component_name}
        )
        super().__init__(message, context, recoverable=False, **kwargs)

class ParallelProcessingError(AnalysisError):
    """Error in parallel processing or task scheduling."""
    
    def __init__(self, message: str, task_id: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="parallel_processor",
            operation="task_execution",
            additional_context={'task_id': task_id}
        )
        super().__init__(message, context, **kwargs)

class ValidationError(AnalysisError):
    """Error in input validation or data validation."""
    
    def __init__(self, message: str, validation_rule: Optional[str] = None, **kwargs):
        context = ErrorContext(
            component_name="validator",
            operation="validation",
            additional_context={'validation_rule': validation_rule}
        )
        super().__init__(message, context, **kwargs)

class ContextualLogger:
    """
    Context-aware logger that enriches log messages with analysis context.
    
    Provides structured logging with automatic context injection for
    easier debugging and error tracking.
    """
    
    def __init__(self, component_name: str, context: Optional[ErrorContext] = None):
        """
        Initialize contextual logger.
        
        Args:
            component_name: Name of the component using this logger
            context: Optional base context for all log messages
        """
        self.component_name = component_name
        self.base_context = context
        self.logger = logging.getLogger(f"aods.{component_name}")
    
    def _enrich_message(self, message: str, context: Optional[ErrorContext] = None) -> str:
        """Enrich log message with context information."""
        effective_context = context or self.base_context
        if effective_context:
            context_str = f"[{effective_context.component_name}:{effective_context.operation}]"
            if effective_context.pattern_id:
                context_str += f"[pattern:{effective_context.pattern_id}]"
            return f"{context_str} {message}"
        return f"[{self.component_name}] {message}"
    
    def _get_extra(self, context: Optional[ErrorContext] = None) -> Dict[str, Any]:
        """Get extra logging context."""
        effective_context = context or self.base_context
        if effective_context:
            return {'analysis_context': effective_context.to_dict()}
        return {}
    
    def debug(self, message: str, context: Optional[ErrorContext] = None):
        """Log debug message with context."""
        enriched_message = self._enrich_message(message, context)
        self.logger.debug(enriched_message, extra=self._get_extra(context))
    
    def info(self, message: str, context: Optional[ErrorContext] = None):
        """Log info message with context."""
        enriched_message = self._enrich_message(message, context)
        self.logger.info(enriched_message, extra=self._get_extra(context))
    
    def warning(self, message: str, context: Optional[ErrorContext] = None):
        """Log warning message with context."""
        enriched_message = self._enrich_message(message, context)
        self.logger.warning(enriched_message, extra=self._get_extra(context))
    
    def error(self, message: str, context: Optional[ErrorContext] = None, exc_info: bool = False):
        """Log error message with context."""
        enriched_message = self._enrich_message(message, context)
        self.logger.error(enriched_message, extra=self._get_extra(context), exc_info=exc_info)
    
    def critical(self, message: str, context: Optional[ErrorContext] = None, exc_info: bool = False):
        """Log critical message with context."""
        enriched_message = self._enrich_message(message, context)
        self.logger.critical(enriched_message, extra=self._get_extra(context), exc_info=exc_info)

class ErrorRecoveryManager:
    """
    Manages error recovery strategies and fallback mechanisms.
    
    Provides automatic error recovery for recoverable errors and
    graceful degradation for critical errors.
    """
    
    def __init__(self):
        self.recovery_strategies: Dict[type, List[callable]] = {}
        self.fallback_strategies: Dict[type, callable] = {}
        self.logger = ContextualLogger("error_recovery")
    
    def register_recovery_strategy(self, error_type: type, strategy: callable):
        """Register a recovery strategy for a specific error type."""
        if error_type not in self.recovery_strategies:
            self.recovery_strategies[error_type] = []
        self.recovery_strategies[error_type].append(strategy)
    
    def register_fallback_strategy(self, error_type: type, strategy: callable):
        """Register a fallback strategy for a specific error type."""
        self.fallback_strategies[error_type] = strategy
    
    def handle_error(self, error: AnalysisError, *args, **kwargs) -> Any:
        """
        Handle an error using registered recovery or fallback strategies.
        
        Args:
            error: The error to handle
            *args, **kwargs: Additional arguments for recovery strategies
            
        Returns:
            Result from recovery strategy or fallback
            
        Raises:
            AnalysisError: If no recovery strategy succeeds
        """
        error_type = type(error)
        
        # Try recovery strategies first
        if error.recoverable and error_type in self.recovery_strategies:
            for strategy in self.recovery_strategies[error_type]:
                try:
                    result = strategy(error, *args, **kwargs)
                    self.logger.info(f"Successfully recovered from {error_type.__name__}")
                    return result
                except Exception as e:
                    self.logger.warning(f"Recovery strategy failed: {e}")
                    continue
        
        # Try fallback strategy
        if error_type in self.fallback_strategies:
            try:
                result = self.fallback_strategies[error_type](error, *args, **kwargs)
                self.logger.info(f"Used fallback strategy for {error_type.__name__}")
                return result
            except Exception as e:
                self.logger.error(f"Fallback strategy failed: {e}")
        
        # No recovery possible
        self.logger.error(f"No recovery possible for {error_type.__name__}: {error.message}")
        raise error

# Global error recovery manager
_recovery_manager = ErrorRecoveryManager()

def get_recovery_manager() -> ErrorRecoveryManager:
    """Get the global error recovery manager."""
    return _recovery_manager

def safe_execute(operation: callable, 
                error_context: Optional[ErrorContext] = None,
                recovery_strategies: Optional[List[callable]] = None,
                fallback_result: Any = None) -> Any:
    """
    Safely execute an operation with automatic error handling.
    
    Args:
        operation: The operation to execute
        error_context: Context for error logging
        recovery_strategies: Custom recovery strategies
        fallback_result: Fallback result if all strategies fail
        
    Returns:
        Result from operation or fallback
    """
    try:
        return operation()
    except AnalysisError as e:
        if recovery_strategies:
            for strategy in recovery_strategies:
                try:
                    return strategy(e)
                except Exception:
                    continue
        
        # Use global recovery manager
        try:
            return _recovery_manager.handle_error(e)
        except AnalysisError:
            if fallback_result is not None:
                return fallback_result
            raise
    except Exception as e:
        # Wrap non-AODS exceptions
        wrapped_error = AnalysisError(
            message=f"Unexpected error: {str(e)}",
            context=error_context,
            cause=e
        )
        
        if fallback_result is not None:
            return fallback_result
        raise wrapped_error 

# Additional exception types for monitoring and other components
class MonitoringError(AnalysisError):
    """Error during monitoring operations."""
    pass

class FeedbackError(AnalysisError):
    """Error during feedback operations."""
    pass

class AnalyticsError(AnalysisError):
    """Error during analytics operations."""
    pass
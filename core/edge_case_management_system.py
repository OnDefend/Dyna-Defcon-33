#!/usr/bin/env python3
"""
Comprehensive Edge Case Management System for AODS

This system provides robust error handling, input validation, and graceful degradation
for all security analyzers in the AODS framework. It ensures production-ready reliability
and professional user experience even in edge cases and failure scenarios.

Key Features:
- Standardized error handling patterns
- Comprehensive input validation
- Graceful degradation mechanisms  
- Resource management and cleanup
- Timeout protection
- User-friendly error reporting
- Performance optimization for edge cases

"""

import asyncio
import functools
import logging
import os
import signal
import sys
import time
import traceback
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, Type
from threading import Lock, RLock
import weakref
import gc
import resource
import psutil
import re

# Import user notification system
try:
    from core.unified_plugin_execution_manager import UserNotificationSystem
    USER_NOTIFICATION_AVAILABLE = True
except ImportError:
    USER_NOTIFICATION_AVAILABLE = False

# Import enhanced logging
try:
    from core.enhanced_logging import EnhancedLogger
    ENHANCED_LOGGING_AVAILABLE = True
except ImportError:
    ENHANCED_LOGGING_AVAILABLE = False

class EdgeCaseType(Enum):
    """Types of edge cases and error conditions."""
    FILE_NOT_FOUND = "file_not_found"
    PERMISSION_DENIED = "permission_denied"
    INVALID_INPUT = "invalid_input"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    TIMEOUT_EXCEEDED = "timeout_exceeded"
    DEPENDENCY_MISSING = "dependency_missing"
    NETWORK_UNAVAILABLE = "network_unavailable"
    PARSING_ERROR = "parsing_error"
    BINARY_CORRUPTION = "binary_corruption"
    MEMORY_LIMIT = "memory_limit"
    CONCURRENT_ACCESS = "concurrent_access"
    CONFIGURATION_ERROR = "configuration_error"
    UNKNOWN_ERROR = "unknown_error"

class EdgeCaseSeverity(Enum):
    """Severity levels for edge case handling."""
    CRITICAL = "critical"  # Analysis cannot continue
    HIGH = "high"         # Major feature unavailable
    MEDIUM = "medium"     # Minor feature degraded
    LOW = "low"           # Cosmetic issue
    INFO = "info"         # Informational only

@dataclass
class EdgeCaseReport:
    """Comprehensive edge case report."""
    case_type: EdgeCaseType
    severity: EdgeCaseSeverity
    error_message: str
    technical_details: str
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    stack_trace: Optional[str] = None
    recovery_attempted: bool = False
    recovery_successful: bool = False
    user_impact: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    confidence_impact: float = 0.0  # Impact on analysis confidence (0.0-1.0)

@dataclass
class EdgeCaseMetrics:
    """Metrics for edge case monitoring."""
    total_cases: int = 0
    by_type: Dict[EdgeCaseType, int] = field(default_factory=dict)
    by_severity: Dict[EdgeCaseSeverity, int] = field(default_factory=dict)
    recovery_attempts: int = 0
    recovery_successes: int = 0
    user_notifications: int = 0
    performance_impact: float = 0.0  # milliseconds
    memory_impact: int = 0  # bytes

class EdgeCaseManager:
    """
    Central manager for edge case handling across all AODS components.
    
    Features:
    - Centralized error handling and logging
    - Automatic recovery mechanisms
    - User notification system integration
    - Performance monitoring
    - Resource cleanup
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.metrics = EdgeCaseMetrics()
        self.reports: List[EdgeCaseReport] = []
        self.recovery_strategies: Dict[EdgeCaseType, Callable] = {}
        self.user_notification_system = self._initialize_user_notification()
        self.resource_manager = ResourceManager()
        self._lock = RLock()
        
        # Performance optimization: use sets for O(1) lookups
        self.critical_errors = {
            EdgeCaseType.RESOURCE_EXHAUSTED,
            EdgeCaseType.MEMORY_LIMIT,
            EdgeCaseType.BINARY_CORRUPTION
        }
        
        self.recoverable_errors = {
            EdgeCaseType.FILE_NOT_FOUND,
            EdgeCaseType.PERMISSION_DENIED,
            EdgeCaseType.TIMEOUT_EXCEEDED,
            EdgeCaseType.NETWORK_UNAVAILABLE,
            EdgeCaseType.PARSING_ERROR
        }
        
        # Initialize recovery strategies
        self._register_recovery_strategies()
    
    def _initialize_user_notification(self) -> Optional[UserNotificationSystem]:
        """Initialize user notification system if available."""
        if USER_NOTIFICATION_AVAILABLE:
            return UserNotificationSystem()
        return None
    
    def _register_recovery_strategies(self) -> None:
        """Register recovery strategies for different edge cases."""
        self.recovery_strategies = {
            EdgeCaseType.FILE_NOT_FOUND: self._recover_file_not_found,
            EdgeCaseType.PERMISSION_DENIED: self._recover_permission_denied,
            EdgeCaseType.TIMEOUT_EXCEEDED: self._recover_timeout_exceeded,
            EdgeCaseType.PARSING_ERROR: self._recover_parsing_error,
            EdgeCaseType.NETWORK_UNAVAILABLE: self._recover_network_unavailable,
            EdgeCaseType.DEPENDENCY_MISSING: self._recover_dependency_missing,
            EdgeCaseType.RESOURCE_EXHAUSTED: self._recover_resource_exhausted,
            EdgeCaseType.MEMORY_LIMIT: self._recover_memory_limit,
            EdgeCaseType.CONCURRENT_ACCESS: self._recover_concurrent_access,
            EdgeCaseType.CONFIGURATION_ERROR: self._recover_configuration_error,
        }
    
    def handle_edge_case(self, case_type: EdgeCaseType, error: Exception = None, 
                        context: Dict[str, Any] = None) -> EdgeCaseReport:
        """
        Handle an edge case with comprehensive analysis and recovery.
        
        Args:
            case_type: Type of edge case
            error: Original exception (if any)
            context: Additional context information
            
        Returns:
            EdgeCaseReport with handling results
        """
        start_time = time.time()
        
        with self._lock:
            # Create comprehensive report
            report = EdgeCaseReport(
                case_type=case_type,
                severity=self._determine_severity(case_type),
                error_message=str(error) if error else f"Edge case: {case_type.value}",
                technical_details=self._extract_technical_details(error),
                context=context or {},
                stack_trace=traceback.format_exc() if error else None,
                user_impact=self._assess_user_impact(case_type),
                remediation_steps=self._generate_remediation_steps(case_type),
                confidence_impact=self._calculate_confidence_impact(case_type)
            )
            
            # Update metrics
            self.metrics.total_cases += 1
            self.metrics.by_type[case_type] = self.metrics.by_type.get(case_type, 0) + 1
            self.metrics.by_severity[report.severity] = self.metrics.by_severity.get(report.severity, 0) + 1
            
            # Attempt recovery if strategy exists
            if case_type in self.recovery_strategies:
                report.recovery_attempted = True
                self.metrics.recovery_attempts += 1
                
                try:
                    recovery_result = self.recovery_strategies[case_type](error, context)
                    report.recovery_successful = bool(recovery_result)
                    if report.recovery_successful:
                        self.metrics.recovery_successes += 1
                        self.logger.info(f"Successfully recovered from {case_type.value}")
                except Exception as recovery_error:
                    self.logger.error(f"Recovery failed for {case_type.value}: {recovery_error}")
            
            # Log the edge case
            self._log_edge_case(report)
            
            # Notify user if necessary
            if self._should_notify_user(report):
                self._notify_user(report)
                self.metrics.user_notifications += 1
            
            # Store report
            self.reports.append(report)
            
            # Update performance metrics
            processing_time = (time.time() - start_time) * 1000  # milliseconds
            self.metrics.performance_impact += processing_time
            
            return report
    
    def _determine_severity(self, case_type: EdgeCaseType) -> EdgeCaseSeverity:
        """Determine severity based on edge case type."""
        severity_mapping = {
            EdgeCaseType.BINARY_CORRUPTION: EdgeCaseSeverity.CRITICAL,
            EdgeCaseType.MEMORY_LIMIT: EdgeCaseSeverity.CRITICAL,
            EdgeCaseType.RESOURCE_EXHAUSTED: EdgeCaseSeverity.CRITICAL,
            EdgeCaseType.PERMISSION_DENIED: EdgeCaseSeverity.HIGH,
            EdgeCaseType.DEPENDENCY_MISSING: EdgeCaseSeverity.HIGH,
            EdgeCaseType.TIMEOUT_EXCEEDED: EdgeCaseSeverity.HIGH,
            EdgeCaseType.FILE_NOT_FOUND: EdgeCaseSeverity.MEDIUM,
            EdgeCaseType.PARSING_ERROR: EdgeCaseSeverity.MEDIUM,
            EdgeCaseType.NETWORK_UNAVAILABLE: EdgeCaseSeverity.MEDIUM,
            EdgeCaseType.CONCURRENT_ACCESS: EdgeCaseSeverity.MEDIUM,
            EdgeCaseType.CONFIGURATION_ERROR: EdgeCaseSeverity.MEDIUM,
            EdgeCaseType.INVALID_INPUT: EdgeCaseSeverity.LOW,
            EdgeCaseType.UNKNOWN_ERROR: EdgeCaseSeverity.LOW,
        }
        return severity_mapping.get(case_type, EdgeCaseSeverity.LOW)
    
    def _extract_technical_details(self, error: Exception) -> str:
        """Extract technical details from exception."""
        if not error:
            return "No exception details available"
        
        details = []
        details.append(f"Error Type: {type(error).__name__}")
        details.append(f"Error Message: {str(error)}")
        
        if hasattr(error, 'errno'):
            details.append(f"Error Code: {error.errno}")
        
        if hasattr(error, 'filename'):
            details.append(f"File: {error.filename}")
        
        if hasattr(error, 'lineno'):
            details.append(f"Line: {error.lineno}")
        
        return " | ".join(details)
    
    def _assess_user_impact(self, case_type: EdgeCaseType) -> str:
        """Assess user impact for different edge cases."""
        impact_descriptions = {
            EdgeCaseType.FILE_NOT_FOUND: "Analysis of specific file skipped, overall analysis continues",
            EdgeCaseType.PERMISSION_DENIED: "Cannot access protected files, analysis may be incomplete",
            EdgeCaseType.INVALID_INPUT: "Invalid input detected, using fallback processing",
            EdgeCaseType.RESOURCE_EXHAUSTED: "System resources exhausted, analysis may be limited",
            EdgeCaseType.TIMEOUT_EXCEEDED: "Operation timed out, analysis may be incomplete",
            EdgeCaseType.DEPENDENCY_MISSING: "Required dependency unavailable, feature disabled",
            EdgeCaseType.NETWORK_UNAVAILABLE: "Network features disabled, offline analysis only",
            EdgeCaseType.PARSING_ERROR: "File parsing failed, content analysis skipped",
            EdgeCaseType.BINARY_CORRUPTION: "Binary file corrupted, analysis cannot continue",
            EdgeCaseType.MEMORY_LIMIT: "Memory limit exceeded, analysis may be incomplete",
            EdgeCaseType.CONCURRENT_ACCESS: "File locked by another process, analysis delayed",
            EdgeCaseType.CONFIGURATION_ERROR: "Configuration issue detected, using defaults",
            EdgeCaseType.UNKNOWN_ERROR: "Unexpected error occurred, analysis may be affected",
        }
        return impact_descriptions.get(case_type, "Unknown impact")
    
    def _generate_remediation_steps(self, case_type: EdgeCaseType) -> List[str]:
        """Generate remediation steps for different edge cases."""
        remediation_steps = {
            EdgeCaseType.FILE_NOT_FOUND: [
                "Verify APK file exists and is readable",
                "Check file path correctness",
                "Ensure APK extraction completed successfully",
                "Verify file system permissions"
            ],
            EdgeCaseType.PERMISSION_DENIED: [
                "Run analysis with appropriate permissions",
                "Check file and directory access rights",
                "Verify user has read access to APK files",
                "Consider running as administrator if necessary"
            ],
            EdgeCaseType.INVALID_INPUT: [
                "Validate input parameters",
                "Check file format compatibility",
                "Verify APK file integrity",
                "Use supported APK versions"
            ],
            EdgeCaseType.RESOURCE_EXHAUSTED: [
                "Close other applications to free resources",
                "Increase available memory or disk space",
                "Process smaller APK files",
                "Restart analysis tool if necessary"
            ],
            EdgeCaseType.TIMEOUT_EXCEEDED: [
                "Increase timeout limits if possible",
                "Check system performance",
                "Verify network connectivity for online features",
                "Consider processing smaller files"
            ],
            EdgeCaseType.DEPENDENCY_MISSING: [
                "Install required dependencies",
                "Check tool installation completeness",
                "Verify system compatibility",
                "Update to latest tool versions"
            ],
            EdgeCaseType.NETWORK_UNAVAILABLE: [
                "Check network connectivity",
                "Verify firewall settings",
                "Use offline analysis mode",
                "Retry analysis when network is available"
            ],
            EdgeCaseType.PARSING_ERROR: [
                "Verify file format and integrity",
                "Check for file corruption",
                "Try alternative parsing methods",
                "Contact support if issue persists"
            ],
            EdgeCaseType.BINARY_CORRUPTION: [
                "Verify APK file integrity",
                "Re-download or re-acquire APK file",
                "Check for file system corruption",
                "Use backup copies if available"
            ],
            EdgeCaseType.MEMORY_LIMIT: [
                "Close unnecessary applications",
                "Increase system memory if possible",
                "Process files in smaller batches",
                "Optimize analysis settings"
            ],
            EdgeCaseType.CONCURRENT_ACCESS: [
                "Close other applications accessing the file",
                "Wait for file lock to be released",
                "Copy file to different location",
                "Retry analysis after brief delay"
            ],
            EdgeCaseType.CONFIGURATION_ERROR: [
                "Check configuration file syntax",
                "Verify all required settings are present",
                "Reset to default configuration",
                "Contact support for configuration help"
            ],
        }
        return remediation_steps.get(case_type, ["Contact support for assistance"])
    
    def _calculate_confidence_impact(self, case_type: EdgeCaseType) -> float:
        """Calculate impact on analysis confidence (0.0-1.0)."""
        confidence_impacts = {
            EdgeCaseType.BINARY_CORRUPTION: 0.8,  # High impact
            EdgeCaseType.RESOURCE_EXHAUSTED: 0.6,
            EdgeCaseType.MEMORY_LIMIT: 0.6,
            EdgeCaseType.DEPENDENCY_MISSING: 0.5,
            EdgeCaseType.TIMEOUT_EXCEEDED: 0.4,
            EdgeCaseType.PERMISSION_DENIED: 0.3,
            EdgeCaseType.PARSING_ERROR: 0.3,
            EdgeCaseType.NETWORK_UNAVAILABLE: 0.2,
            EdgeCaseType.FILE_NOT_FOUND: 0.2,
            EdgeCaseType.CONCURRENT_ACCESS: 0.1,
            EdgeCaseType.CONFIGURATION_ERROR: 0.1,
            EdgeCaseType.INVALID_INPUT: 0.1,
            EdgeCaseType.UNKNOWN_ERROR: 0.2,
        }
        return confidence_impacts.get(case_type, 0.1)
    
    def _log_edge_case(self, report: EdgeCaseReport) -> None:
        """Log edge case with appropriate severity."""
        log_message = f"Edge case handled: {report.case_type.value} | " \
                     f"Severity: {report.severity.value} | " \
                     f"Message: {report.error_message}"
        
        if report.severity == EdgeCaseSeverity.CRITICAL:
            self.logger.critical(log_message)
        elif report.severity == EdgeCaseSeverity.HIGH:
            self.logger.error(log_message)
        elif report.severity == EdgeCaseSeverity.MEDIUM:
            self.logger.warning(log_message)
        elif report.severity == EdgeCaseSeverity.LOW:
            self.logger.info(log_message)
        else:
            self.logger.debug(log_message)
        
        # Log technical details at debug level
        if report.technical_details:
            self.logger.debug(f"Technical details: {report.technical_details}")
    
    def _should_notify_user(self, report: EdgeCaseReport) -> bool:
        """Determine if user should be notified about this edge case."""
        # Always notify for critical and high severity cases
        if report.severity in [EdgeCaseSeverity.CRITICAL, EdgeCaseSeverity.HIGH]:
            return True
        
        # Notify for medium severity if it impacts user workflow
        if report.severity == EdgeCaseSeverity.MEDIUM:
            return report.case_type in {
                EdgeCaseType.PARSING_ERROR,
                EdgeCaseType.TIMEOUT_EXCEEDED,
                EdgeCaseType.CONCURRENT_ACCESS
            }
        
        return False
    
    def _notify_user(self, report: EdgeCaseReport) -> None:
        """Notify user about edge case through notification system."""
        if not self.user_notification_system:
            return
        
        try:
            self.user_notification_system.notify_analysis_failure(
                file_path=report.context.get("file_path", "Unknown"),
                operation_type=report.context.get("operation_type", "Analysis"),
                error_message=report.error_message,
                technical_details=report.technical_details,
                remediation_steps=report.remediation_steps
            )
        except Exception as e:
            self.logger.error(f"Failed to notify user about edge case: {e}")
    
    # Recovery strategy implementations
    def _recover_file_not_found(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Recovery strategy for file not found errors."""
        file_path = context.get("file_path") if context else None
        if not file_path:
            return False
        
        # Try alternative file locations
        alternative_paths = [
            file_path + ".bak",
            file_path + ".tmp",
            str(Path(file_path).parent / (Path(file_path).stem + "_alt" + Path(file_path).suffix))
        ]
        
        for alt_path in alternative_paths:
            if Path(alt_path).exists():
                context["recovered_file_path"] = alt_path
                return True
        
        return False
    
    def _recover_permission_denied(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Recovery strategy for permission denied errors."""
        file_path = context.get("file_path") if context else None
        if not file_path:
            return False
        
        try:
            # Try to copy to temp location with different permissions
            import shutil
            import tempfile
            
            temp_path = tempfile.mktemp(suffix=Path(file_path).suffix)
            shutil.copy2(file_path, temp_path)
            os.chmod(temp_path, 0o644)
            
            context["recovered_file_path"] = temp_path
            context["cleanup_required"] = True
            return True
        except Exception:
            return False
    
    def _recover_timeout_exceeded(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Recovery strategy for timeout exceeded errors."""
        # Suggest reduced scope analysis
        context["suggested_recovery"] = "reduce_analysis_scope"
        context["timeout_multiplier"] = 2.0  # Suggest doubling timeout
        return True
    
    def _recover_parsing_error(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Recovery strategy for parsing errors."""
        file_path = context.get("file_path") if context else None
        if not file_path:
            return False
        
        # Try alternative parsing methods
        context["suggested_recovery"] = "try_alternative_parser"
        context["skip_malformed_sections"] = True
        return True
    
    def _recover_network_unavailable(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Recovery strategy for network unavailable errors."""
        # Enable offline mode
        context["offline_mode"] = True
        context["skip_network_features"] = True
        return True
    
    def _recover_dependency_missing(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Recovery strategy for missing dependencies."""
        dependency = context.get("dependency") if context else None
        if not dependency:
            return False
        
        # Suggest alternative implementations
        context["use_fallback_implementation"] = True
        context["missing_dependency"] = dependency
        return True
    
    def _recover_resource_exhausted(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Recovery strategy for resource exhaustion."""
        # Suggest resource optimization
        context["reduce_memory_usage"] = True
        context["process_in_batches"] = True
        context["garbage_collect"] = True
        return True
    
    def _recover_memory_limit(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Recovery strategy for memory limit exceeded."""
        # Force garbage collection and suggest batch processing
        gc.collect()
        context["batch_processing"] = True
        context["reduce_cache_size"] = True
        return True
    
    def _recover_concurrent_access(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Recovery strategy for concurrent access errors."""
        # Suggest retry with backoff
        context["retry_with_backoff"] = True
        context["max_retries"] = 3
        context["backoff_multiplier"] = 2.0
        return True
    
    def _recover_configuration_error(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Recovery strategy for configuration errors."""
        # Suggest using default configuration
        context["use_default_config"] = True
        context["config_validation_required"] = True
        return True
    
    def get_metrics(self) -> EdgeCaseMetrics:
        """Get comprehensive edge case metrics."""
        return self.metrics
    
    def get_reports(self, case_type: EdgeCaseType = None, 
                   severity: EdgeCaseSeverity = None) -> List[EdgeCaseReport]:
        """Get edge case reports filtered by type and/or severity."""
        reports = self.reports
        
        if case_type:
            reports = [r for r in reports if r.case_type == case_type]
        
        if severity:
            reports = [r for r in reports if r.severity == severity]
        
        return reports
    
    def clear_reports(self) -> None:
        """Clear all stored reports."""
        with self._lock:
            self.reports.clear()
            self.metrics = EdgeCaseMetrics()

class ResourceManager:
    """
    Resource management for edge case scenarios.
    
    Monitors and manages system resources to prevent edge cases
    and provide early warning for resource exhaustion.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__ + ".ResourceManager")
        self.memory_threshold = 0.9  # 90% memory usage threshold
        self.disk_threshold = 0.95   # 95% disk usage threshold
        self.cpu_threshold = 0.95    # 95% CPU usage threshold
        self.monitoring_active = False
        self._cleanup_handlers: List[Callable] = []
    
    def register_cleanup_handler(self, handler: Callable) -> None:
        """Register a cleanup handler for resource management."""
        self._cleanup_handlers.append(handler)
    
    def check_resource_availability(self) -> Dict[str, Any]:
        """Check current resource availability."""
        try:
            # Memory usage
            memory = psutil.virtual_memory()
            memory_available = memory.available
            memory_percent = memory.percent / 100.0
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.total - disk.free) / disk.total
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1) / 100.0
            
            return {
                "memory": {
                    "available_gb": memory_available / (1024**3),
                    "usage_percent": memory_percent,
                    "critical": memory_percent > self.memory_threshold
                },
                "disk": {
                    "available_gb": disk.free / (1024**3),
                    "usage_percent": disk_percent,
                    "critical": disk_percent > self.disk_threshold
                },
                "cpu": {
                    "usage_percent": cpu_percent,
                    "critical": cpu_percent > self.cpu_threshold
                }
            }
        except Exception as e:
            self.logger.error(f"Error checking resource availability: {e}")
            return {"error": str(e)}
    
    def cleanup_resources(self) -> None:
        """Perform resource cleanup."""
        self.logger.info("Performing resource cleanup...")
        
        # Run registered cleanup handlers
        for handler in self._cleanup_handlers:
            try:
                handler()
            except Exception as e:
                self.logger.error(f"Cleanup handler failed: {e}")
        
        # Force garbage collection
        gc.collect()
        
        # Log resource status after cleanup
        resources = self.check_resource_availability()
        if "error" not in resources:
            self.logger.info(f"Resource cleanup completed. "
                           f"Memory: {resources['memory']['usage_percent']:.1%}, "
                           f"Disk: {resources['disk']['usage_percent']:.1%}")

class InputValidator:
    """
    Comprehensive input validation for edge case prevention.
    
    Validates input parameters to prevent edge cases before they occur.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__ + ".InputValidator")
        
        # Performance optimization: compiled regex patterns
        self.path_validation_pattern = re.compile(r'^[a-zA-Z0-9\-_./\\:]+$')
        self.package_name_pattern = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)*$')
        self.file_extension_pattern = re.compile(r'\.[a-zA-Z0-9]+$')
    
    def validate_file_path(self, file_path: Union[str, Path]) -> Tuple[bool, str]:
        """Validate file path for security and existence."""
        try:
            path_str = str(file_path)
            
            # Check for empty path
            if not path_str or path_str.isspace():
                return False, "Empty file path"
            
            # Check for suspicious characters
            if not self.path_validation_pattern.match(path_str):
                return False, "Invalid characters in file path"
            
            # Check for path traversal attempts
            if '..' in path_str or path_str.startswith('/'):
                return False, "Potential path traversal attack"
            
            # Check if file exists
            path_obj = Path(path_str)
            if not path_obj.exists():
                return False, f"File does not exist: {path_str}"
            
            # Check if it's actually a file
            if not path_obj.is_file():
                return False, f"Path is not a file: {path_str}"
            
            # Check file size
            file_size = path_obj.stat().st_size
            if file_size == 0:
                return False, "File is empty"
            
            # Check if file is too large (100MB default)
            if file_size > 100 * 1024 * 1024:
                return False, f"File too large: {file_size} bytes"
            
            return True, "Valid file path"
            
        except Exception as e:
            return False, f"File path validation error: {e}"
    
    def validate_package_name(self, package_name: str) -> Tuple[bool, str]:
        """Validate Android package name format."""
        try:
            if not package_name or not isinstance(package_name, str):
                return False, "Invalid package name format"
            
            # Check pattern match
            if not self.package_name_pattern.match(package_name):
                return False, "Package name does not match Android format"
            
            # Check length
            if len(package_name) > 255:
                return False, "Package name too long"
            
            # Check for reserved words
            reserved_words = {'com.android', 'android', 'java', 'javax'}
            if any(package_name.startswith(word) for word in reserved_words):
                return False, "Package name uses reserved prefix"
            
            return True, "Valid package name"
            
        except Exception as e:
            return False, f"Package name validation error: {e}"
    
    def validate_apk_file(self, apk_path: Union[str, Path]) -> Tuple[bool, str]:
        """Validate APK file for analysis."""
        try:
            # Basic file path validation
            valid_path, path_message = self.validate_file_path(apk_path)
            if not valid_path:
                return False, path_message
            
            path_obj = Path(apk_path)
            
            # Check file extension
            if not path_obj.suffix.lower() == '.apk':
                return False, "File is not an APK"
            
            # Check if it's a valid ZIP file (APK is a ZIP)
            import zipfile
            try:
                with zipfile.ZipFile(path_obj, 'r') as zip_file:
                    # Check for AndroidManifest.xml
                    if 'AndroidManifest.xml' not in zip_file.namelist():
                        return False, "APK missing AndroidManifest.xml"
                    
                    # Check for classes.dex
                    dex_files = [f for f in zip_file.namelist() if f.endswith('.dex')]
                    if not dex_files:
                        return False, "APK missing DEX files"
                    
            except zipfile.BadZipFile:
                return False, "APK file is corrupted or not a valid ZIP"
            
            return True, "Valid APK file"
            
        except Exception as e:
            return False, f"APK validation error: {e}"
    
    def validate_analysis_parameters(self, parameters: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate analysis parameters for edge case prevention."""
        try:
            # Check for required parameters
            required_params = ['apk_path']
            for param in required_params:
                if param not in parameters:
                    return False, f"Missing required parameter: {param}"
            
            # Validate APK path
            valid_apk, apk_message = self.validate_apk_file(parameters['apk_path'])
            if not valid_apk:
                return False, f"APK validation failed: {apk_message}"
            
            # Validate timeout if provided
            if 'timeout' in parameters:
                timeout = parameters['timeout']
                if not isinstance(timeout, (int, float)) or timeout <= 0:
                    return False, "Invalid timeout value"
                if timeout > 3600:  # 1 hour max
                    return False, "Timeout too large (max 1 hour)"
            
            # Validate memory limit if provided
            if 'memory_limit' in parameters:
                memory_limit = parameters['memory_limit']
                if not isinstance(memory_limit, (int, float)) or memory_limit <= 0:
                    return False, "Invalid memory limit value"
            
            return True, "Valid analysis parameters"
            
        except Exception as e:
            return False, f"Parameter validation error: {e}"

def edge_case_handler(case_type: EdgeCaseType, recovery_strategy: str = None):
    """
    Decorator for automatic edge case handling.
    
    Args:
        case_type: Type of edge case to handle
        recovery_strategy: Optional recovery strategy name
    
    Usage:
        @edge_case_handler(EdgeCaseType.FILE_NOT_FOUND)
        def analyze_file(file_path):
            # Function implementation
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            edge_case_manager = EdgeCaseManager()
            
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Extract context from function arguments
                context = {
                    "function": func.__name__,
                    "args": str(args)[:200],  # Truncate for logging
                    "kwargs": str(kwargs)[:200],
                }
                
                # Handle the edge case
                report = edge_case_manager.handle_edge_case(
                    case_type=case_type,
                    error=e,
                    context=context
                )
                
                # If recovery was successful, retry the function
                if report.recovery_successful:
                    try:
                        return func(*args, **kwargs)
                    except Exception as retry_error:
                        # If retry fails, log and re-raise
                        edge_case_manager.logger.error(f"Retry failed for {func.__name__}: {retry_error}")
                        raise retry_error
                else:
                    # No recovery possible, re-raise original exception
                    raise e
        
        return wrapper
    return decorator

def with_timeout(timeout_seconds: int):
    """
    Decorator for timeout protection.
    
    Args:
        timeout_seconds: Maximum execution time in seconds
    
    Usage:
        @with_timeout(300)  # 5 minutes
        def long_running_analysis():
            # Function implementation
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            def timeout_handler(signum, frame):
                raise TimeoutError(f"Function {func.__name__} timed out after {timeout_seconds} seconds")
            
            # Set timeout signal handler
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout_seconds)
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                # Restore original signal handler
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
        
        return wrapper
    return decorator

@contextmanager
def resource_monitoring():
    """
    Context manager for resource monitoring during analysis.
    
    Usage:
        with resource_monitoring():
            # Perform analysis
            pass
    """
    resource_manager = ResourceManager()
    
    # Check initial resource state
    initial_resources = resource_manager.check_resource_availability()
    
    try:
        yield resource_manager
    finally:
        # Check final resource state
        final_resources = resource_manager.check_resource_availability()
        
        # Log resource usage
        if "error" not in initial_resources and "error" not in final_resources:
            memory_change = (final_resources['memory']['usage_percent'] - 
                           initial_resources['memory']['usage_percent'])
            
            if memory_change > 0.1:  # 10% increase
                resource_manager.logger.warning(f"High memory usage increase: {memory_change:.1%}")
        
        # Perform cleanup if needed
        if (final_resources.get('memory', {}).get('critical', False) or
            final_resources.get('disk', {}).get('critical', False)):
            resource_manager.cleanup_resources()

# Global edge case manager instance
_global_edge_case_manager = None

def get_edge_case_manager() -> EdgeCaseManager:
    """Get the global edge case manager instance."""
    global _global_edge_case_manager
    if _global_edge_case_manager is None:
        _global_edge_case_manager = EdgeCaseManager()
    return _global_edge_case_manager

def initialize_edge_case_system():
    """Initialize the edge case management system."""
    manager = get_edge_case_manager()
    manager.logger.info("Edge case management system initialized")
    return manager

if __name__ == "__main__":
    # Example usage and testing
    manager = initialize_edge_case_system()
    
    # Test edge case handling
    try:
        raise FileNotFoundError("Test file not found")
    except FileNotFoundError as e:
        report = manager.handle_edge_case(
            EdgeCaseType.FILE_NOT_FOUND,
            error=e,
            context={"file_path": "/nonexistent/file.apk"}
        )
        print(f"Edge case handled: {report.case_type.value}")
        print(f"Recovery attempted: {report.recovery_attempted}")
        print(f"User impact: {report.user_impact}")
    
    # Display metrics
    metrics = manager.get_metrics()
    print(f"Total edge cases handled: {metrics.total_cases}")
    print(f"Recovery success rate: {metrics.recovery_successes}/{metrics.recovery_attempts}") 
 
 
 
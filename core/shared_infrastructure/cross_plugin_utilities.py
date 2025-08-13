#!/usr/bin/env python3
"""
Cross-Plugin Utilities

Common utility functions and helpers used across multiple AODS plugins.
Provides standardized, efficient, and reusable functionality.

Features:
- Universal pattern matching utilities
- Common formatting and display helpers  
- Performance monitoring and profiling utilities
- Error handling and logging standardization
- Configuration management helpers
- Result aggregation and merging utilities
"""

import time
import logging
import hashlib
import threading
from typing import Dict, List, Optional, Any, Union, Callable, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from pathlib import Path
import functools
import math

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Container for performance monitoring data."""
    operation_name: str
    start_time: float
    end_time: float
    duration: float
    memory_usage: Optional[int] = None
    cpu_usage: Optional[float] = None
    success: bool = True
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_ms(self) -> float:
        """Get duration in milliseconds."""
        return self.duration * 1000
    
    @property
    def duration_str(self) -> str:
        """Get formatted duration string."""
        if self.duration < 1:
            return f"{self.duration_ms:.1f}ms"
        elif self.duration < 60:
            return f"{self.duration:.2f}s"
        else:
            minutes = int(self.duration // 60)
            seconds = self.duration % 60
            return f"{minutes}m {seconds:.1f}s"

class PerformanceMonitor:
    """Performance monitoring and profiling utilities."""
    
    def __init__(self):
        self._metrics: List[PerformanceMetrics] = []
        self._active_operations: Dict[str, float] = {}
        self._lock = threading.RLock()
    
    def start_operation(self, operation_name: str) -> str:
        """
        Start monitoring an operation.
        
        Args:
            operation_name: Name of the operation to monitor
            
        Returns:
            str: Operation ID for tracking
        """
        operation_id = f"{operation_name}_{time.time()}_{threading.current_thread().ident}"
        
        with self._lock:
            self._active_operations[operation_id] = time.time()
        
        return operation_id
    
    def end_operation(self, operation_id: str, success: bool = True, 
                     error_message: Optional[str] = None, **metadata) -> PerformanceMetrics:
        """
        End monitoring an operation and record metrics.
        
        Args:
            operation_id: Operation ID from start_operation
            success: Whether operation completed successfully
            error_message: Error message if operation failed
            **metadata: Additional metadata to record
            
        Returns:
            PerformanceMetrics: Recorded performance metrics
        """
        end_time = time.time()
        
        with self._lock:
            start_time = self._active_operations.pop(operation_id, end_time)
        
        # Extract operation name from ID
        operation_name = operation_id.split('_')[0]
        
        metrics = PerformanceMetrics(
            operation_name=operation_name,
            start_time=start_time,
            end_time=end_time,
            duration=end_time - start_time,
            success=success,
            error_message=error_message,
            metadata=metadata
        )
        
        with self._lock:
            self._metrics.append(metrics)
        
        return metrics
    
    def get_operation_stats(self, operation_name: str) -> Dict[str, Any]:
        """
        Get statistics for a specific operation.
        
        Args:
            operation_name: Name of operation to analyze
            
        Returns:
            Dict[str, Any]: Operation statistics
        """
        with self._lock:
            relevant_metrics = [m for m in self._metrics if m.operation_name == operation_name]
        
        if not relevant_metrics:
            return {}
        
        durations = [m.duration for m in relevant_metrics]
        successes = [m.success for m in relevant_metrics]
        
        return {
            'total_executions': len(relevant_metrics),
            'success_rate': sum(successes) / len(successes),
            'avg_duration': sum(durations) / len(durations),
            'min_duration': min(durations),
            'max_duration': max(durations),
            'total_duration': sum(durations),
            'avg_duration_str': PerformanceMetrics(
                operation_name="", start_time=0, end_time=sum(durations) / len(durations), 
                duration=sum(durations) / len(durations)
            ).duration_str
        }
    
    def performance_timer(self, operation_name: str):
        """Decorator for timing function execution."""
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                op_id = self.start_operation(operation_name)
                try:
                    result = func(*args, **kwargs)
                    self.end_operation(op_id, success=True)
                    return result
                except Exception as e:
                    self.end_operation(op_id, success=False, error_message=str(e))
                    raise
            return wrapper
        return decorator

class TextFormatter:
    """Text formatting and display utilities."""
    
    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """
        Format file size in human-readable format.
        
        Args:
            size_bytes: Size in bytes
            
        Returns:
            str: Formatted size string
        """
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        
        return f"{s} {size_names[i]}"
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """
        Format duration in human-readable format.
        
        Args:
            seconds: Duration in seconds
            
        Returns:
            str: Formatted duration string
        """
        if seconds < 1:
            return f"{seconds * 1000:.1f}ms"
        elif seconds < 60:
            return f"{seconds:.2f}s"
        else:
            delta = timedelta(seconds=seconds)
            return str(delta)
    
    @staticmethod
    def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
        """
        Truncate text to specified length.
        
        Args:
            text: Text to truncate
            max_length: Maximum allowed length
            suffix: Suffix to add when truncating
            
        Returns:
            str: Truncated text
        """
        if not text or len(text) <= max_length:
            return text
        
        return text[:max_length - len(suffix)] + suffix
    
    @staticmethod
    def format_percentage(value: float, total: float, decimal_places: int = 1) -> str:
        """
        Format percentage with proper handling of edge cases.
        
        Args:
            value: Numerator value
            total: Denominator value
            decimal_places: Number of decimal places
            
        Returns:
            str: Formatted percentage string
        """
        if total == 0:
            return "0.0%"
        
        percentage = (value / total) * 100
        return f"{percentage:.{decimal_places}f}%"
    
    @staticmethod
    def format_confidence_score(confidence: float) -> str:
        """
        Format confidence score with color coding hints.
        
        Args:
            confidence: Confidence score (0.0 to 1.0)
            
        Returns:
            str: Formatted confidence string with color hint
        """
        percentage = confidence * 100
        
        if confidence >= 0.8:
            color = "green"
        elif confidence >= 0.6:
            color = "yellow"
        else:
            color = "red"
        
        return f"{percentage:.1f}% ({color})"

class HashingUtils:
    """Hashing and fingerprinting utilities."""
    
    @staticmethod
    def calculate_content_hash(content: str, algorithm: str = 'sha256') -> str:
        """
        Calculate hash of content.
        
        Args:
            content: Content to hash
            algorithm: Hash algorithm to use
            
        Returns:
            str: Hex digest of hash
        """
        if not content:
            return ""
        
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(content.encode('utf-8'))
        return hash_obj.hexdigest()
    
    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256', 
                          chunk_size: int = 8192) -> Optional[str]:
        """
        Calculate hash of file contents.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm to use
            chunk_size: Size of chunks to read
            
        Returns:
            Optional[str]: Hex digest of hash or None if error
        """
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            logger.debug(f"Failed to calculate hash for {file_path}: {e}")
            return None
    
    @staticmethod
    def create_finding_fingerprint(finding_data: Dict[str, Any]) -> str:
        """
        Create unique fingerprint for a security finding.
        
        Args:
            finding_data: Finding data to fingerprint
            
        Returns:
            str: Unique fingerprint string
        """
        # Extract key fields for fingerprinting
        key_fields = ['title', 'file_path', 'line_number', 'pattern', 'evidence']
        fingerprint_parts = []
        
        for field in key_fields:
            if field in finding_data and finding_data[field]:
                fingerprint_parts.append(str(finding_data[field]))
        
        fingerprint_content = '|'.join(fingerprint_parts)
        return HashingUtils.calculate_content_hash(fingerprint_content, 'md5')[:12]

class ConfigurationHelper:
    """Configuration management utilities."""
    
    @staticmethod
    def merge_configs(base_config: Dict[str, Any], 
                     override_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge configuration dictionaries with deep merging.
        
        Args:
            base_config: Base configuration
            override_config: Configuration to merge in
            
        Returns:
            Dict[str, Any]: Merged configuration
        """
        merged = base_config.copy()
        
        for key, value in override_config.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = ConfigurationHelper.merge_configs(merged[key], value)
            else:
                merged[key] = value
        
        return merged
    
    @staticmethod
    def validate_config_keys(config: Dict[str, Any], 
                            required_keys: Set[str],
                            optional_keys: Optional[Set[str]] = None) -> List[str]:
        """
        Validate configuration has required keys.
        
        Args:
            config: Configuration to validate
            required_keys: Set of required keys
            optional_keys: Set of optional keys (for validation)
            
        Returns:
            List[str]: List of validation errors
        """
        errors = []
        
        # Check required keys
        missing_keys = required_keys - set(config.keys())
        if missing_keys:
            errors.append(f"Missing required keys: {missing_keys}")
        
        # Check for unknown keys if optional_keys provided
        if optional_keys is not None:
            all_valid_keys = required_keys | optional_keys
            unknown_keys = set(config.keys()) - all_valid_keys
            if unknown_keys:
                errors.append(f"Unknown keys: {unknown_keys}")
        
        return errors
    
    @staticmethod
    def get_config_value(config: Dict[str, Any], key_path: str, 
                        default: Any = None) -> Any:
        """
        Get configuration value using dot notation path.
        
        Args:
            config: Configuration dictionary
            key_path: Dot-separated key path (e.g., 'section.subsection.key')
            default: Default value if key not found
            
        Returns:
            Any: Configuration value or default
        """
        try:
            current = config
            for key in key_path.split('.'):
                current = current[key]
            return current
        except (KeyError, TypeError):
            return default

class ResultAggregator:
    """Utilities for aggregating and merging analysis results."""
    
    @staticmethod
    def merge_vulnerability_lists(lists: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Merge multiple vulnerability lists with deduplication.
        
        Args:
            lists: List of vulnerability lists to merge
            
        Returns:
            List[Dict[str, Any]]: Merged and deduplicated vulnerabilities
        """
        seen_fingerprints = set()
        merged = []
        
        for vuln_list in lists:
            for vuln in vuln_list:
                fingerprint = HashingUtils.create_finding_fingerprint(vuln)
                if fingerprint not in seen_fingerprints:
                    seen_fingerprints.add(fingerprint)
                    merged.append(vuln)
        
        return merged
    
    @staticmethod
    def aggregate_severity_counts(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Aggregate vulnerability counts by severity.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Dict[str, int]: Counts by severity level
        """
        severity_counts = Counter()
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            severity_counts[severity] += 1
        
        return dict(severity_counts)
    
    @staticmethod
    def calculate_risk_score(vulnerabilities: List[Dict[str, Any]]) -> float:
        """
        Calculate overall risk score based on vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            float: Risk score (0.0 to 10.0)
        """
        if not vulnerabilities:
            return 0.0
        
        # Severity weights
        severity_weights = {
            'CRITICAL': 10.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5,
            'INFO': 1.0
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW').upper()
            confidence = vuln.get('confidence', 0.5)
            
            weight = severity_weights.get(severity, 1.0)
            score = weight * confidence
            
            total_score += score
            total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        # Normalize to 0-10 scale
        normalized_score = min(10.0, (total_score / len(vulnerabilities)) * 1.5)
        return round(normalized_score, 2)

class ErrorHandler:
    """Standardized error handling utilities."""
    
    @staticmethod
    def log_error_with_context(logger: logging.Logger, error: Exception, 
                              context: Dict[str, Any]) -> str:
        """
        Log error with contextual information.
        
        Args:
            logger: Logger instance to use
            error: Exception that occurred
            context: Contextual information
            
        Returns:
            str: Error message with context
        """
        context_str = ", ".join(f"{k}={v}" for k, v in context.items())
        error_msg = f"{type(error).__name__}: {error} (Context: {context_str})"
        
        logger.error(error_msg, exc_info=True)
        return error_msg
    
    @staticmethod
    def create_error_summary(errors: List[Exception]) -> Dict[str, Any]:
        """
        Create summary of multiple errors.
        
        Args:
            errors: List of exceptions
            
        Returns:
            Dict[str, Any]: Error summary statistics
        """
        if not errors:
            return {'total_errors': 0}
        
        error_types = Counter(type(error).__name__ for error in errors)
        
        return {
            'total_errors': len(errors),
            'error_types': dict(error_types),
            'most_common_error': error_types.most_common(1)[0][0] if error_types else None,
            'sample_messages': [str(error) for error in errors[:3]]
        }

class LoggingMixin:
    """Simple logging mixin for AODS components."""
    
    def __init__(self):
        """Initialize logging for the component."""
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def log_info(self, message: str, **kwargs):
        """Log info message with optional context."""
        self.logger.info(message, extra=kwargs)
    
    def log_warning(self, message: str, **kwargs):
        """Log warning message with optional context."""
        self.logger.warning(message, extra=kwargs)
    
    def log_error(self, message: str, **kwargs):
        """Log error message with optional context."""
        self.logger.error(message, extra=kwargs)
    
    def log_debug(self, message: str, **kwargs):
        """Log debug message with optional context."""
        self.logger.debug(message, extra=kwargs)


class InputValidator:
    """Input validation utilities for AODS components."""
    
    def __init__(self):
        """Initialize the input validator."""
        self.logger = logging.getLogger(__name__)
    
    def validate_non_empty_string(self, value: Any, field_name: str = "field") -> str:
        """Validate that a value is a non-empty string."""
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string, got {type(value)}")
        if not value.strip():
            raise ValueError(f"{field_name} cannot be empty")
        return value.strip()
    
    def validate_positive_number(self, value: Any, field_name: str = "field") -> Union[int, float]:
        """Validate that a value is a positive number."""
        if not isinstance(value, (int, float)):
            raise ValueError(f"{field_name} must be a number, got {type(value)}")
        if value <= 0:
            raise ValueError(f"{field_name} must be positive, got {value}")
        return value
    
    def validate_list(self, value: Any, field_name: str = "field") -> List:
        """Validate that a value is a list."""
        if not isinstance(value, list):
            raise ValueError(f"{field_name} must be a list, got {type(value)}")
        return value
    
    def validate_dict(self, value: Any, field_name: str = "field") -> Dict:
        """Validate that a value is a dictionary."""
        if not isinstance(value, dict):
            raise ValueError(f"{field_name} must be a dictionary, got {type(value)}")
        return value
    
    def validate_string(self, value: Any, field_name: str = "field", min_length: int = 0, max_length: Optional[int] = None) -> str:
        """Validate that a value is a string with optional length constraints."""
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string, got {type(value)}")
        
        if len(value) < min_length:
            raise ValueError(f"{field_name} must be at least {min_length} characters long, got {len(value)}")
        
        if max_length is not None and len(value) > max_length:
            raise ValueError(f"{field_name} must be at most {max_length} characters long, got {len(value)}")
        
        return value


# Global performance monitor instance
performance_monitor = PerformanceMonitor()

# Export main utilities
__all__ = [
    'PerformanceMetrics',
    'PerformanceMonitor', 
    'TextFormatter',
    'HashingUtils',
    'ConfigurationHelper',
    'ResultAggregator',
    'ErrorHandler',
    'LoggingMixin',
    'InputValidator',
    'performance_monitor'
] 
#!/usr/bin/env python3
"""
Result Validation and Sanitization Pipeline for AODS

This module provides comprehensive validation and sanitization of plugin results
to ensure data quality, consistency, and format standardization across all plugins.

Features:
- Schema validation for plugin results
- Data type validation and conversion
- Content sanitization and normalization
- Format standardization across plugins
- Error detection and correction
- Performance metrics and reporting
"""

import logging
import re
import json
import traceback
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Tuple, Set
from pathlib import Path

from rich.text import Text

logger = logging.getLogger(__name__)

class ValidationSeverity(Enum):
    """Severity levels for validation issues."""
    CRITICAL = "critical"      # Result cannot be used, major data corruption
    HIGH = "high"             # Significant issues, data quality compromised
    MEDIUM = "medium"         # Minor issues, data usable with corrections
    LOW = "low"               # Style/format issues, minimal impact
    INFO = "info"             # Informational warnings

class ValidationCategory(Enum):
    """Categories of validation issues."""
    SCHEMA_VIOLATION = "schema_violation"       # Result doesn't match expected schema
    TYPE_MISMATCH = "type_mismatch"            # Wrong data types
    CONTENT_INVALID = "content_invalid"        # Invalid content or malformed data
    FORMAT_INCONSISTENT = "format_inconsistent" # Inconsistent formatting
    SECURITY_CONCERN = "security_concern"      # Potential security issues in data
    ENCODING_ERROR = "encoding_error"          # Text encoding problems
    MISSING_REQUIRED = "missing_required"      # Missing required fields
    UNKNOWN = "unknown"                        # Unclassified validation issue

@dataclass
class ValidationIssue:
    """Detailed validation issue record."""
    severity: ValidationSeverity
    category: ValidationCategory
    plugin_name: str
    field_path: str
    issue_description: str
    original_value: Any
    suggested_correction: Any = None
    auto_corrected: bool = False
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'severity': self.severity.value,
            'category': self.category.value,
            'plugin_name': self.plugin_name,
            'field_path': self.field_path,
            'issue_description': self.issue_description,
            'original_value': str(self.original_value)[:500],  # Truncate for safety
            'suggested_correction': str(self.suggested_correction)[:500] if self.suggested_correction else None,
            'auto_corrected': self.auto_corrected,
            'context': self.context
        }

@dataclass
class ValidationResult:
    """Result of validation and sanitization process."""
    is_valid: bool
    sanitized_result: Tuple[str, Union[str, Text]]
    issues: List[ValidationIssue] = field(default_factory=list)
    corrections_applied: int = 0
    validation_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Get count of issues by severity."""
        counts = {severity.value: 0 for severity in ValidationSeverity}
        for issue in self.issues:
            counts[issue.severity.value] += 1
        return counts

class PluginResultSchema:
    """Expected schema for plugin results."""
    
    # Standard plugin result format: Tuple[str, Union[str, Text]]
    EXPECTED_FORMAT = {
        'type': 'tuple',
        'length': 2,
        'elements': [
            {'type': 'string', 'description': 'Plugin title/name'},
            {'type': ['string', 'Text', 'dict'], 'description': 'Plugin content/result'}
        ]
    }
    
    # Expected content patterns for different plugin types
    CONTENT_PATTERNS = {
        'vulnerability': {
            'required_fields': ['status', 'description'],
            'optional_fields': ['severity', 'risk_level', 'evidence', 'masvs_control'],
            'severity_values': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
            'status_values': ['PASS', 'FAIL', 'VULNERABLE', 'SECURE', 'INFO']
        },
        'analysis': {
            'required_fields': ['analysis_result'],
            'optional_fields': ['confidence', 'details', 'recommendations'],
            'confidence_range': (0.0, 1.0)
        },
        'info': {
            'required_fields': ['information'],
            'optional_fields': ['source', 'timestamp']
        }
    }

class ResultValidationPipeline:
    """
    Comprehensive validation and sanitization pipeline for plugin results.
    
    Ensures all plugin results meet quality standards and follow consistent formats.
    """
    
    def __init__(self):
        """Initialize the validation pipeline."""
        self.logger = logging.getLogger(__name__)
        self.schema = PluginResultSchema()
        
        # Validation statistics
        self.stats = {
            'total_validations': 0,
            'successful_validations': 0,
            'failed_validations': 0,
            'auto_corrections': 0,
            'total_issues': 0,
            'validation_time': 0.0
        }
        
        # Issue tracking
        self.all_issues: List[ValidationIssue] = []
        self.plugin_stats: Dict[str, Dict[str, int]] = {}
        
        # Sanitization rules
        self._initialize_sanitization_rules()
        
        self.logger.info("Result validation pipeline initialized")
    
    def _initialize_sanitization_rules(self):
        """Initialize data sanitization and correction rules."""
        self.sanitization_rules = {
            'html_tags': re.compile(r'<[^>]+>'),
            'control_chars': re.compile(r'[\x00-\x1f\x7f-\x9f]'),
            'excessive_whitespace': re.compile(r'\s{3,}'),
            'unicode_errors': re.compile(r'[\ufffd\ufffe\ufeff]'),
            'sql_injection_patterns': re.compile(r'(\b(SELECT|INSERT|UPDATE|DELETE|UNION|DROP)\b)', re.IGNORECASE),
            'script_patterns': re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL)
        }
        
        # Auto-correction mappings
        self.auto_corrections = {
            'severity_mapping': {
                'critical': 'CRITICAL',
                'high': 'HIGH', 
                'medium': 'MEDIUM',
                'low': 'LOW',
                'info': 'INFO',
                'information': 'INFO'
            },
            'status_mapping': {
                'passed': 'PASS',
                'failed': 'FAIL',
                'vulnerable': 'VULNERABLE',
                'secure': 'SECURE',
                'safe': 'SECURE',
                'insecure': 'VULNERABLE'
            },
            'boolean_mapping': {
                'true': True,
                'false': False,
                'yes': True,
                'no': False,
                '1': True,
                '0': False
            }
        }
    
    def validate_plugin_result(self, plugin_name: str, result: Any) -> ValidationResult:
        """
        Validate and sanitize a single plugin result.
        
        Args:
            plugin_name: Name of the plugin that generated the result
            result: Plugin result to validate
            
        Returns:
            ValidationResult with validation status and sanitized data
        """
        start_time = time.time()
        
        # Initialize validation result
        validation_result = ValidationResult(
            is_valid=True,
            sanitized_result=result,
            metadata={'plugin_name': plugin_name, 'original_type': type(result).__name__}
        )
        
        try:
            # Step 1: Basic format validation
            self._validate_basic_format(plugin_name, result, validation_result)
            
            # Step 2: Type validation and conversion
            self._validate_and_convert_types(plugin_name, result, validation_result)
            
            # Step 3: Content validation and sanitization
            self._validate_and_sanitize_content(plugin_name, validation_result)
            
            # Step 4: Security validation
            self._validate_security(plugin_name, validation_result)
            
            # Step 5: Format standardization
            self._standardize_format(plugin_name, validation_result)
            
            # Update statistics
            self.stats['total_validations'] += 1
            if validation_result.is_valid:
                self.stats['successful_validations'] += 1
            else:
                self.stats['failed_validations'] += 1
            
            validation_result.validation_time = time.time() - start_time
            self.stats['validation_time'] += validation_result.validation_time
            
            # Track plugin-specific statistics
            self._update_plugin_stats(plugin_name, validation_result)
            
            self.logger.debug(f"Validation completed for {plugin_name}: "
                            f"{'PASS' if validation_result.is_valid else 'FAIL'} "
                            f"({len(validation_result.issues)} issues)")
            
            return validation_result
            
        except Exception as e:
            # Handle validation pipeline failures
            self.logger.error(f"Validation pipeline failed for {plugin_name}: {e}")
            
            critical_issue = ValidationIssue(
                severity=ValidationSeverity.CRITICAL,
                category=ValidationCategory.UNKNOWN,
                plugin_name=plugin_name,
                field_path="validation_pipeline",
                issue_description=f"Validation pipeline failure: {str(e)}",
                original_value=result
            )
            
            validation_result.is_valid = False
            validation_result.issues.append(critical_issue)
            validation_result.validation_time = time.time() - start_time
            
            return validation_result
    
    def _validate_basic_format(self, plugin_name: str, result: Any, validation_result: ValidationResult):
        """Validate basic result format structure."""
        
        # Check if result is a tuple with 2 elements
        if not isinstance(result, tuple):
            issue = ValidationIssue(
                severity=ValidationSeverity.HIGH,
                category=ValidationCategory.SCHEMA_VIOLATION,
                plugin_name=plugin_name,
                field_path="result",
                issue_description="Result is not a tuple",
                original_value=result,
                suggested_correction=f"({str(result)[:100]}, 'Additional info needed')"
            )
            validation_result.issues.append(issue)
            
            # Auto-correct by converting to tuple
            if isinstance(result, (str, Text)):
                validation_result.sanitized_result = (f"✅ {plugin_name}", result)
                issue.auto_corrected = True
                validation_result.corrections_applied += 1
            else:
                validation_result.is_valid = False
                return
        
        if len(result) != 2:
            issue = ValidationIssue(
                severity=ValidationSeverity.HIGH,
                category=ValidationCategory.SCHEMA_VIOLATION,
                plugin_name=plugin_name,
                field_path="result.length",
                issue_description=f"Tuple has {len(result)} elements, expected 2",
                original_value=result
            )
            validation_result.issues.append(issue)
            
            # Auto-correct by truncating or padding
            if len(result) > 2:
                validation_result.sanitized_result = result[:2]
                issue.auto_corrected = True
                validation_result.corrections_applied += 1
            elif len(result) == 1:
                validation_result.sanitized_result = (result[0], "No additional information")
                issue.auto_corrected = True
                validation_result.corrections_applied += 1
            else:
                validation_result.is_valid = False
    
    def _validate_and_convert_types(self, plugin_name: str, result: Any, validation_result: ValidationResult):
        """Validate and convert data types."""
        if not isinstance(validation_result.sanitized_result, tuple) or len(validation_result.sanitized_result) != 2:
            # Handle malformed sanitized_result gracefully
            validation_result.sanitized_result = (f"✅ {plugin_name}", validation_result.sanitized_result)
        
        try:
            title, content = validation_result.sanitized_result
        except ValueError as e:
            # Handle unpacking errors gracefully
            title = f"✅ {plugin_name}"
            content = str(validation_result.sanitized_result)
        
        # Validate title type
        if not isinstance(title, str):
            issue = ValidationIssue(
                severity=ValidationSeverity.MEDIUM,
                category=ValidationCategory.TYPE_MISMATCH,
                plugin_name=plugin_name,
                field_path="result.title",
                issue_description=f"Title is {type(title).__name__}, expected string",
                original_value=title,
                suggested_correction=str(title)
            )
            validation_result.issues.append(issue)
            
            # Auto-correct by converting to string
            title = str(title)
            issue.auto_corrected = True
            validation_result.corrections_applied += 1
        
        # Validate content type (allow string, Text, or dict)
        if not isinstance(content, (str, Text, dict)):
            issue = ValidationIssue(
                severity=ValidationSeverity.MEDIUM,
                category=ValidationCategory.TYPE_MISMATCH,
                plugin_name=plugin_name,
                field_path="result.content",
                issue_description=f"Content is {type(content).__name__}, expected string, Text, or dict",
                original_value=content,
                suggested_correction=str(content)
            )
            validation_result.issues.append(issue)
            
            # Auto-correct by converting to string
            content = str(content)
            issue.auto_corrected = True
            validation_result.corrections_applied += 1
        
        # Update sanitized result
        validation_result.sanitized_result = (title, content)
    
    def _validate_and_sanitize_content(self, plugin_name: str, validation_result: ValidationResult):
        """Validate and sanitize content data."""
        try:
            title, content = validation_result.sanitized_result
        except ValueError as e:
            # Handle unpacking errors gracefully
            title = f"✅ {plugin_name}"
            content = str(validation_result.sanitized_result)
        
        # Sanitize title
        sanitized_title = self._sanitize_text(title)
        if sanitized_title != title:
            issue = ValidationIssue(
                severity=ValidationSeverity.LOW,
                category=ValidationCategory.CONTENT_INVALID,
                plugin_name=plugin_name,
                field_path="result.title",
                issue_description="Title contains invalid characters or formatting",
                original_value=title,
                suggested_correction=sanitized_title,
                auto_corrected=True
            )
            validation_result.issues.append(issue)
            validation_result.corrections_applied += 1
            title = sanitized_title
        
        # Sanitize content based on type
        if isinstance(content, str):
            sanitized_content = self._sanitize_text(content)
            if sanitized_content != content:
                issue = ValidationIssue(
                    severity=ValidationSeverity.LOW,
                    category=ValidationCategory.CONTENT_INVALID,
                    plugin_name=plugin_name,
                    field_path="result.content",
                    issue_description="Content contains invalid characters or formatting",
                    original_value=content[:200] + "..." if len(content) > 200 else content,
                    suggested_correction=sanitized_content[:200] + "..." if len(sanitized_content) > 200 else sanitized_content,
                    auto_corrected=True
                )
                validation_result.issues.append(issue)
                validation_result.corrections_applied += 1
                content = sanitized_content
                
        elif isinstance(content, dict):
            content = self._sanitize_dict_content(content, plugin_name, validation_result)
        
        # Update sanitized result
        validation_result.sanitized_result = (title, content)
    
    def _sanitize_text(self, text: str) -> str:
        """Sanitize text content by removing invalid characters and patterns."""
        if not isinstance(text, str):
            return str(text)
        
        # Remove HTML tags
        text = self.sanitization_rules['html_tags'].sub('', text)
        
        # Remove control characters
        text = self.sanitization_rules['control_chars'].sub('', text)
        
        # Normalize whitespace
        text = self.sanitization_rules['excessive_whitespace'].sub(' ', text)
        
        # Remove unicode error characters
        text = self.sanitization_rules['unicode_errors'].sub('', text)
        
        # Remove potential script injection
        text = self.sanitization_rules['script_patterns'].sub('', text)
        
        # Strip leading/trailing whitespace
        text = text.strip()
        
        return text
    
    def _sanitize_dict_content(self, content: Dict[str, Any], plugin_name: str, 
                              validation_result: ValidationResult) -> Dict[str, Any]:
        """Sanitize dictionary content."""
        sanitized = {}
        
        for key, value in content.items():
            # Sanitize key
            sanitized_key = self._sanitize_text(str(key))
            
            # Sanitize value based on type
            if isinstance(value, str):
                sanitized_value = self._sanitize_text(value)
            elif isinstance(value, (list, tuple)):
                sanitized_value = [self._sanitize_text(str(item)) if isinstance(item, str) else item for item in value]
            elif isinstance(value, dict):
                sanitized_value = self._sanitize_dict_content(value, plugin_name, validation_result)
            else:
                sanitized_value = value
            
            # Apply auto-corrections for known fields
            if sanitized_key.lower() in ['severity', 'risk_level']:
                corrected_value = self.auto_corrections['severity_mapping'].get(str(sanitized_value).lower())
                if corrected_value and corrected_value != sanitized_value:
                    issue = ValidationIssue(
                        severity=ValidationSeverity.LOW,
                        category=ValidationCategory.FORMAT_INCONSISTENT,
                        plugin_name=plugin_name,
                        field_path=f"result.content.{sanitized_key}",
                        issue_description=f"Severity value standardized",
                        original_value=sanitized_value,
                        suggested_correction=corrected_value,
                        auto_corrected=True
                    )
                    validation_result.issues.append(issue)
                    validation_result.corrections_applied += 1
                    sanitized_value = corrected_value
            
            elif sanitized_key.lower() in ['status']:
                corrected_value = self.auto_corrections['status_mapping'].get(str(sanitized_value).lower())
                if corrected_value and corrected_value != sanitized_value:
                    issue = ValidationIssue(
                        severity=ValidationSeverity.LOW,
                        category=ValidationCategory.FORMAT_INCONSISTENT,
                        plugin_name=plugin_name,
                        field_path=f"result.content.{sanitized_key}",
                        issue_description=f"Status value standardized",
                        original_value=sanitized_value,
                        suggested_correction=corrected_value,
                        auto_corrected=True
                    )
                    validation_result.issues.append(issue)
                    validation_result.corrections_applied += 1
                    sanitized_value = corrected_value
            
            sanitized[sanitized_key] = sanitized_value
        
        return sanitized
    
    def _validate_security(self, plugin_name: str, validation_result: ValidationResult):
        """Validate content for security concerns."""
        try:
            title, content = validation_result.sanitized_result
        except ValueError as e:
            # Handle unpacking errors gracefully
            title = f"✅ {plugin_name}"
            content = str(validation_result.sanitized_result)
        
        # Check for SQL injection patterns
        content_str = str(content)
        if self.sanitization_rules['sql_injection_patterns'].search(content_str):
            issue = ValidationIssue(
                severity=ValidationSeverity.HIGH,
                category=ValidationCategory.SECURITY_CONCERN,
                plugin_name=plugin_name,
                field_path="result.content",
                issue_description="Content contains potential SQL injection patterns",
                original_value=content_str[:100] + "..." if len(content_str) > 100 else content_str
            )
            validation_result.issues.append(issue)
        
        # Check for excessive data size (potential DoS)
        if len(content_str) > 1000000:  # 1MB limit
            issue = ValidationIssue(
                severity=ValidationSeverity.MEDIUM,
                category=ValidationCategory.SECURITY_CONCERN,
                plugin_name=plugin_name,
                field_path="result.content",
                issue_description=f"Content size ({len(content_str)} bytes) exceeds safe limit",
                original_value=f"Large content ({len(content_str)} bytes)",
                suggested_correction="Content should be truncated or summarized"
            )
            validation_result.issues.append(issue)
    
    def _standardize_format(self, plugin_name: str, validation_result: ValidationResult):
        """Standardize result format for consistency."""
        try:
            title, content = validation_result.sanitized_result
        except ValueError as e:
            # Handle unpacking errors gracefully
            title = f"✅ {plugin_name}"
            content = str(validation_result.sanitized_result)
        
        # Standardize title format
        if not title.startswith(('✅', '❌', '⚠️', '📋', '🔍')):
            # Add appropriate icon based on content analysis
            if isinstance(content, dict):
                status = content.get('status', '').upper()
                if status in ['FAIL', 'FAILED', 'VULNERABLE']:
                    title = f"❌ {title}"
                elif status in ['PASS', 'PASSED', 'SECURE']:
                    title = f"✅ {title}"
                else:
                    title = f"📋 {title}"
            else:
                content_str = str(content).lower()
                if any(word in content_str for word in ['fail', 'error', 'vulnerable', 'insecure']):
                    title = f"❌ {title}"
                elif any(word in content_str for word in ['pass', 'success', 'secure', 'safe']):
                    title = f"✅ {title}"
                else:
                    title = f"📋 {title}"
            
            issue = ValidationIssue(
                severity=ValidationSeverity.LOW,
                category=ValidationCategory.FORMAT_INCONSISTENT,
                plugin_name=plugin_name,
                field_path="result.title",
                issue_description="Title formatted with status icon for consistency",
                original_value=validation_result.sanitized_result[0],
                suggested_correction=title,
                auto_corrected=True
            )
            validation_result.issues.append(issue)
            validation_result.corrections_applied += 1
        
        # Update result
        validation_result.sanitized_result = (title, content)
    
    def _update_plugin_stats(self, plugin_name: str, validation_result: ValidationResult):
        """Update plugin-specific validation statistics."""
        if plugin_name not in self.plugin_stats:
            self.plugin_stats[plugin_name] = {
                'total_validations': 0,
                'successful_validations': 0,
                'total_issues': 0,
                'auto_corrections': 0
            }
        
        stats = self.plugin_stats[plugin_name]
        stats['total_validations'] += 1
        if validation_result.is_valid:
            stats['successful_validations'] += 1
        stats['total_issues'] += len(validation_result.issues)
        stats['auto_corrections'] += validation_result.corrections_applied
        
        # Add issues to global tracking
        self.all_issues.extend(validation_result.issues)
        self.stats['total_issues'] += len(validation_result.issues)
        self.stats['auto_corrections'] += validation_result.corrections_applied
    
    def validate_all_plugin_results(self, plugin_results: Dict[str, Tuple[str, Any]]) -> Dict[str, ValidationResult]:
        """
        Validate all plugin results in batch.
        
        Args:
            plugin_results: Dictionary of plugin_name -> result tuples
            
        Returns:
            Dictionary of plugin_name -> ValidationResult
        """
        validation_results = {}
        
        self.logger.info(f"Starting batch validation of {len(plugin_results)} plugin results")
        
        for plugin_name, result in plugin_results.items():
            validation_results[plugin_name] = self.validate_plugin_result(plugin_name, result)
        
        self.logger.info(f"Batch validation completed: "
                        f"{self.stats['successful_validations']}/{self.stats['total_validations']} successful")
        
        return validation_results
    
    def get_sanitized_results(self, validation_results: Dict[str, ValidationResult]) -> Dict[str, Tuple[str, Any]]:
        """Extract sanitized results from validation results."""
        return {
            plugin_name: vr.sanitized_result 
            for plugin_name, vr in validation_results.items()
        }
    
    def generate_validation_report(self) -> Dict[str, Any]:
        """Generate comprehensive validation report."""
        severity_counts = {severity.value: 0 for severity in ValidationSeverity}
        category_counts = {category.value: 0 for category in ValidationCategory}
        
        for issue in self.all_issues:
            severity_counts[issue.severity.value] += 1
            category_counts[issue.category.value] += 1
        
        return {
            'validation_statistics': self.stats.copy(),
            'severity_breakdown': severity_counts,
            'category_breakdown': category_counts,
            'plugin_statistics': self.plugin_stats.copy(),
            'total_issues': len(self.all_issues),
            'auto_correction_rate': (self.stats['auto_corrections'] / max(self.stats['total_issues'], 1)) * 100,
            'validation_success_rate': (self.stats['successful_validations'] / max(self.stats['total_validations'], 1)) * 100,
            'recent_issues': [issue.to_dict() for issue in self.all_issues[-10:]]
        }
    
    def cleanup(self):
        """Cleanup validation pipeline resources."""
        self.logger.info(f"Validation pipeline cleanup: {len(self.all_issues)} issues processed")
        self.all_issues.clear()
        self.plugin_stats.clear()

# Global validation pipeline instance
_validation_pipeline = None

def get_validation_pipeline() -> ResultValidationPipeline:
    """Get or create global validation pipeline instance."""
    global _validation_pipeline
    if _validation_pipeline is None:
        _validation_pipeline = ResultValidationPipeline()
    return _validation_pipeline

def validate_plugin_result(plugin_name: str, result: Any) -> ValidationResult:
    """
    Validate a single plugin result using the global pipeline.
    
    Args:
        plugin_name: Name of the plugin
        result: Plugin result to validate
        
    Returns:
        ValidationResult with validation status and sanitized data
    """
    pipeline = get_validation_pipeline()
    return pipeline.validate_plugin_result(plugin_name, result)

def validate_and_sanitize_all_results(plugin_results: Dict[str, Tuple[str, Any]]) -> Tuple[Dict[str, Tuple[str, Any]], Dict[str, Any]]:
    """
    Validate and sanitize all plugin results, returning sanitized results and validation report.
    
    Args:
        plugin_results: Dictionary of plugin results
        
    Returns:
        Tuple of (sanitized_results, validation_report)
    """
    pipeline = get_validation_pipeline()
    
    # Validate all results
    validation_results = pipeline.validate_all_plugin_results(plugin_results)
    
    # Extract sanitized results
    sanitized_results = pipeline.get_sanitized_results(validation_results)
    
    # Generate validation report
    validation_report = pipeline.generate_validation_report()
    
    return sanitized_results, validation_report 
"""
Result Validation and Sanitization Pipeline for AODS

This module provides comprehensive validation and sanitization of plugin results
to ensure data quality, consistency, and format standardization across all plugins.

Features:
- Schema validation for plugin results
- Data type validation and conversion
- Content sanitization and normalization
- Format standardization across plugins
- Error detection and correction
- Performance metrics and reporting
"""

import logging
import re
import json
import traceback
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Tuple, Set
from pathlib import Path

from rich.text import Text

logger = logging.getLogger(__name__)

class ValidationSeverity(Enum):
    """Severity levels for validation issues."""
    CRITICAL = "critical"      # Result cannot be used, major data corruption
    HIGH = "high"             # Significant issues, data quality compromised
    MEDIUM = "medium"         # Minor issues, data usable with corrections
    LOW = "low"               # Style/format issues, minimal impact
    INFO = "info"             # Informational warnings

class ValidationCategory(Enum):
    """Categories of validation issues."""
    SCHEMA_VIOLATION = "schema_violation"       # Result doesn't match expected schema
    TYPE_MISMATCH = "type_mismatch"            # Wrong data types
    CONTENT_INVALID = "content_invalid"        # Invalid content or malformed data
    FORMAT_INCONSISTENT = "format_inconsistent" # Inconsistent formatting
    SECURITY_CONCERN = "security_concern"      # Potential security issues in data
    ENCODING_ERROR = "encoding_error"          # Text encoding problems
    MISSING_REQUIRED = "missing_required"      # Missing required fields
    UNKNOWN = "unknown"                        # Unclassified validation issue

@dataclass
class ValidationIssue:
    """Detailed validation issue record."""
    severity: ValidationSeverity
    category: ValidationCategory
    plugin_name: str
    field_path: str
    issue_description: str
    original_value: Any
    suggested_correction: Any = None
    auto_corrected: bool = False
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'severity': self.severity.value,
            'category': self.category.value,
            'plugin_name': self.plugin_name,
            'field_path': self.field_path,
            'issue_description': self.issue_description,
            'original_value': str(self.original_value)[:500],  # Truncate for safety
            'suggested_correction': str(self.suggested_correction)[:500] if self.suggested_correction else None,
            'auto_corrected': self.auto_corrected,
            'context': self.context
        }

@dataclass
class ValidationResult:
    """Result of validation and sanitization process."""
    is_valid: bool
    sanitized_result: Tuple[str, Union[str, Text]]
    issues: List[ValidationIssue] = field(default_factory=list)
    corrections_applied: int = 0
    validation_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Get count of issues by severity."""
        counts = {severity.value: 0 for severity in ValidationSeverity}
        for issue in self.issues:
            counts[issue.severity.value] += 1
        return counts

class PluginResultSchema:
    """Expected schema for plugin results."""
    
    # Standard plugin result format: Tuple[str, Union[str, Text]]
    EXPECTED_FORMAT = {
        'type': 'tuple',
        'length': 2,
        'elements': [
            {'type': 'string', 'description': 'Plugin title/name'},
            {'type': ['string', 'Text', 'dict'], 'description': 'Plugin content/result'}
        ]
    }
    
    # Expected content patterns for different plugin types
    CONTENT_PATTERNS = {
        'vulnerability': {
            'required_fields': ['status', 'description'],
            'optional_fields': ['severity', 'risk_level', 'evidence', 'masvs_control'],
            'severity_values': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
            'status_values': ['PASS', 'FAIL', 'VULNERABLE', 'SECURE', 'INFO']
        },
        'analysis': {
            'required_fields': ['analysis_result'],
            'optional_fields': ['confidence', 'details', 'recommendations'],
            'confidence_range': (0.0, 1.0)
        },
        'info': {
            'required_fields': ['information'],
            'optional_fields': ['source', 'timestamp']
        }
    }

class ResultValidationPipeline:
    """
    Comprehensive validation and sanitization pipeline for plugin results.
    
    Ensures all plugin results meet quality standards and follow consistent formats.
    """
    
    def __init__(self):
        """Initialize the validation pipeline."""
        self.logger = logging.getLogger(__name__)
        self.schema = PluginResultSchema()
        
        # Validation statistics
        self.stats = {
            'total_validations': 0,
            'successful_validations': 0,
            'failed_validations': 0,
            'auto_corrections': 0,
            'total_issues': 0,
            'validation_time': 0.0
        }
        
        # Issue tracking
        self.all_issues: List[ValidationIssue] = []
        self.plugin_stats: Dict[str, Dict[str, int]] = {}
        
        # Sanitization rules
        self._initialize_sanitization_rules()
        
        self.logger.info("Result validation pipeline initialized")
    
    def _initialize_sanitization_rules(self):
        """Initialize data sanitization and correction rules."""
        self.sanitization_rules = {
            'html_tags': re.compile(r'<[^>]+>'),
            'control_chars': re.compile(r'[\x00-\x1f\x7f-\x9f]'),
            'excessive_whitespace': re.compile(r'\s{3,}'),
            'unicode_errors': re.compile(r'[\ufffd\ufffe\ufeff]'),
            'sql_injection_patterns': re.compile(r'(\b(SELECT|INSERT|UPDATE|DELETE|UNION|DROP)\b)', re.IGNORECASE),
            'script_patterns': re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL)
        }
        
        # Auto-correction mappings
        self.auto_corrections = {
            'severity_mapping': {
                'critical': 'CRITICAL',
                'high': 'HIGH', 
                'medium': 'MEDIUM',
                'low': 'LOW',
                'info': 'INFO',
                'information': 'INFO'
            },
            'status_mapping': {
                'passed': 'PASS',
                'failed': 'FAIL',
                'vulnerable': 'VULNERABLE',
                'secure': 'SECURE',
                'safe': 'SECURE',
                'insecure': 'VULNERABLE'
            },
            'boolean_mapping': {
                'true': True,
                'false': False,
                'yes': True,
                'no': False,
                '1': True,
                '0': False
            }
        }
    
    def validate_plugin_result(self, plugin_name: str, result: Any) -> ValidationResult:
        """
        Validate and sanitize a single plugin result.
        
        Args:
            plugin_name: Name of the plugin that generated the result
            result: Plugin result to validate
            
        Returns:
            ValidationResult with validation status and sanitized data
        """
        start_time = time.time()
        
        # Initialize validation result
        validation_result = ValidationResult(
            is_valid=True,
            sanitized_result=result,
            metadata={'plugin_name': plugin_name, 'original_type': type(result).__name__}
        )
        
        try:
            # Step 1: Basic format validation
            self._validate_basic_format(plugin_name, result, validation_result)
            
            # Step 2: Type validation and conversion
            self._validate_and_convert_types(plugin_name, result, validation_result)
            
            # Step 3: Content validation and sanitization
            self._validate_and_sanitize_content(plugin_name, validation_result)
            
            # Step 4: Security validation
            self._validate_security(plugin_name, validation_result)
            
            # Step 5: Format standardization
            self._standardize_format(plugin_name, validation_result)
            
            # Update statistics
            self.stats['total_validations'] += 1
            if validation_result.is_valid:
                self.stats['successful_validations'] += 1
            else:
                self.stats['failed_validations'] += 1
            
            validation_result.validation_time = time.time() - start_time
            self.stats['validation_time'] += validation_result.validation_time
            
            # Track plugin-specific statistics
            self._update_plugin_stats(plugin_name, validation_result)
            
            self.logger.debug(f"Validation completed for {plugin_name}: "
                            f"{'PASS' if validation_result.is_valid else 'FAIL'} "
                            f"({len(validation_result.issues)} issues)")
            
            return validation_result
            
        except Exception as e:
            # Handle validation pipeline failures
            self.logger.error(f"Validation pipeline failed for {plugin_name}: {e}")
            
            critical_issue = ValidationIssue(
                severity=ValidationSeverity.CRITICAL,
                category=ValidationCategory.UNKNOWN,
                plugin_name=plugin_name,
                field_path="validation_pipeline",
                issue_description=f"Validation pipeline failure: {str(e)}",
                original_value=result
            )
            
            validation_result.is_valid = False
            validation_result.issues.append(critical_issue)
            validation_result.validation_time = time.time() - start_time
            
            return validation_result
    
    def _validate_basic_format(self, plugin_name: str, result: Any, validation_result: ValidationResult):
        """Validate basic result format structure."""
        
        # Check if result is a tuple with 2 elements
        if not isinstance(result, tuple):
            issue = ValidationIssue(
                severity=ValidationSeverity.HIGH,
                category=ValidationCategory.SCHEMA_VIOLATION,
                plugin_name=plugin_name,
                field_path="result",
                issue_description="Result is not a tuple",
                original_value=result,
                suggested_correction=f"({str(result)[:100]}, 'Additional info needed')"
            )
            validation_result.issues.append(issue)
            
            # Auto-correct by converting to tuple
            if isinstance(result, (str, Text)):
                validation_result.sanitized_result = (f"✅ {plugin_name}", result)
                issue.auto_corrected = True
                validation_result.corrections_applied += 1
            else:
                validation_result.is_valid = False
                return
        
        if len(result) != 2:
            issue = ValidationIssue(
                severity=ValidationSeverity.HIGH,
                category=ValidationCategory.SCHEMA_VIOLATION,
                plugin_name=plugin_name,
                field_path="result.length",
                issue_description=f"Tuple has {len(result)} elements, expected 2",
                original_value=result
            )
            validation_result.issues.append(issue)
            
            # Auto-correct by truncating or padding
            if len(result) > 2:
                validation_result.sanitized_result = result[:2]
                issue.auto_corrected = True
                validation_result.corrections_applied += 1
            elif len(result) == 1:
                validation_result.sanitized_result = (result[0], "No additional information")
                issue.auto_corrected = True
                validation_result.corrections_applied += 1
            else:
                validation_result.is_valid = False
    
    def _validate_and_convert_types(self, plugin_name: str, result: Any, validation_result: ValidationResult):
        """Validate and convert data types."""
        if not isinstance(validation_result.sanitized_result, tuple) or len(validation_result.sanitized_result) != 2:
            # Handle malformed sanitized_result gracefully
            validation_result.sanitized_result = (f"✅ {plugin_name}", validation_result.sanitized_result)
        
        try:
            title, content = validation_result.sanitized_result
        except ValueError as e:
            # Handle unpacking errors gracefully
            title = f"✅ {plugin_name}"
            content = str(validation_result.sanitized_result)
        
        # Validate title type
        if not isinstance(title, str):
            issue = ValidationIssue(
                severity=ValidationSeverity.MEDIUM,
                category=ValidationCategory.TYPE_MISMATCH,
                plugin_name=plugin_name,
                field_path="result.title",
                issue_description=f"Title is {type(title).__name__}, expected string",
                original_value=title,
                suggested_correction=str(title)
            )
            validation_result.issues.append(issue)
            
            # Auto-correct by converting to string
            title = str(title)
            issue.auto_corrected = True
            validation_result.corrections_applied += 1
        
        # Validate content type (allow string, Text, or dict)
        if not isinstance(content, (str, Text, dict)):
            issue = ValidationIssue(
                severity=ValidationSeverity.MEDIUM,
                category=ValidationCategory.TYPE_MISMATCH,
                plugin_name=plugin_name,
                field_path="result.content",
                issue_description=f"Content is {type(content).__name__}, expected string, Text, or dict",
                original_value=content,
                suggested_correction=str(content)
            )
            validation_result.issues.append(issue)
            
            # Auto-correct by converting to string
            content = str(content)
            issue.auto_corrected = True
            validation_result.corrections_applied += 1
        
        # Update sanitized result
        validation_result.sanitized_result = (title, content)
    
    def _validate_and_sanitize_content(self, plugin_name: str, validation_result: ValidationResult):
        """Validate and sanitize content data."""
        try:
            title, content = validation_result.sanitized_result
        except ValueError as e:
            # Handle unpacking errors gracefully
            title = f"✅ {plugin_name}"
            content = str(validation_result.sanitized_result)
        
        # Sanitize title
        sanitized_title = self._sanitize_text(title)
        if sanitized_title != title:
            issue = ValidationIssue(
                severity=ValidationSeverity.LOW,
                category=ValidationCategory.CONTENT_INVALID,
                plugin_name=plugin_name,
                field_path="result.title",
                issue_description="Title contains invalid characters or formatting",
                original_value=title,
                suggested_correction=sanitized_title,
                auto_corrected=True
            )
            validation_result.issues.append(issue)
            validation_result.corrections_applied += 1
            title = sanitized_title
        
        # Sanitize content based on type
        if isinstance(content, str):
            sanitized_content = self._sanitize_text(content)
            if sanitized_content != content:
                issue = ValidationIssue(
                    severity=ValidationSeverity.LOW,
                    category=ValidationCategory.CONTENT_INVALID,
                    plugin_name=plugin_name,
                    field_path="result.content",
                    issue_description="Content contains invalid characters or formatting",
                    original_value=content[:200] + "..." if len(content) > 200 else content,
                    suggested_correction=sanitized_content[:200] + "..." if len(sanitized_content) > 200 else sanitized_content,
                    auto_corrected=True
                )
                validation_result.issues.append(issue)
                validation_result.corrections_applied += 1
                content = sanitized_content
                
        elif isinstance(content, dict):
            content = self._sanitize_dict_content(content, plugin_name, validation_result)
        
        # Update sanitized result
        validation_result.sanitized_result = (title, content)
    
    def _sanitize_text(self, text: str) -> str:
        """Sanitize text content by removing invalid characters and patterns."""
        if not isinstance(text, str):
            return str(text)
        
        # Remove HTML tags
        text = self.sanitization_rules['html_tags'].sub('', text)
        
        # Remove control characters
        text = self.sanitization_rules['control_chars'].sub('', text)
        
        # Normalize whitespace
        text = self.sanitization_rules['excessive_whitespace'].sub(' ', text)
        
        # Remove unicode error characters
        text = self.sanitization_rules['unicode_errors'].sub('', text)
        
        # Remove potential script injection
        text = self.sanitization_rules['script_patterns'].sub('', text)
        
        # Strip leading/trailing whitespace
        text = text.strip()
        
        return text
    
    def _sanitize_dict_content(self, content: Dict[str, Any], plugin_name: str, 
                              validation_result: ValidationResult) -> Dict[str, Any]:
        """Sanitize dictionary content."""
        sanitized = {}
        
        for key, value in content.items():
            # Sanitize key
            sanitized_key = self._sanitize_text(str(key))
            
            # Sanitize value based on type
            if isinstance(value, str):
                sanitized_value = self._sanitize_text(value)
            elif isinstance(value, (list, tuple)):
                sanitized_value = [self._sanitize_text(str(item)) if isinstance(item, str) else item for item in value]
            elif isinstance(value, dict):
                sanitized_value = self._sanitize_dict_content(value, plugin_name, validation_result)
            else:
                sanitized_value = value
            
            # Apply auto-corrections for known fields
            if sanitized_key.lower() in ['severity', 'risk_level']:
                corrected_value = self.auto_corrections['severity_mapping'].get(str(sanitized_value).lower())
                if corrected_value and corrected_value != sanitized_value:
                    issue = ValidationIssue(
                        severity=ValidationSeverity.LOW,
                        category=ValidationCategory.FORMAT_INCONSISTENT,
                        plugin_name=plugin_name,
                        field_path=f"result.content.{sanitized_key}",
                        issue_description=f"Severity value standardized",
                        original_value=sanitized_value,
                        suggested_correction=corrected_value,
                        auto_corrected=True
                    )
                    validation_result.issues.append(issue)
                    validation_result.corrections_applied += 1
                    sanitized_value = corrected_value
            
            elif sanitized_key.lower() in ['status']:
                corrected_value = self.auto_corrections['status_mapping'].get(str(sanitized_value).lower())
                if corrected_value and corrected_value != sanitized_value:
                    issue = ValidationIssue(
                        severity=ValidationSeverity.LOW,
                        category=ValidationCategory.FORMAT_INCONSISTENT,
                        plugin_name=plugin_name,
                        field_path=f"result.content.{sanitized_key}",
                        issue_description=f"Status value standardized",
                        original_value=sanitized_value,
                        suggested_correction=corrected_value,
                        auto_corrected=True
                    )
                    validation_result.issues.append(issue)
                    validation_result.corrections_applied += 1
                    sanitized_value = corrected_value
            
            sanitized[sanitized_key] = sanitized_value
        
        return sanitized
    
    def _validate_security(self, plugin_name: str, validation_result: ValidationResult):
        """Validate content for security concerns."""
        try:
            title, content = validation_result.sanitized_result
        except ValueError as e:
            # Handle unpacking errors gracefully
            title = f"✅ {plugin_name}"
            content = str(validation_result.sanitized_result)
        
        # Check for SQL injection patterns
        content_str = str(content)
        if self.sanitization_rules['sql_injection_patterns'].search(content_str):
            issue = ValidationIssue(
                severity=ValidationSeverity.HIGH,
                category=ValidationCategory.SECURITY_CONCERN,
                plugin_name=plugin_name,
                field_path="result.content",
                issue_description="Content contains potential SQL injection patterns",
                original_value=content_str[:100] + "..." if len(content_str) > 100 else content_str
            )
            validation_result.issues.append(issue)
        
        # Check for excessive data size (potential DoS)
        if len(content_str) > 1000000:  # 1MB limit
            issue = ValidationIssue(
                severity=ValidationSeverity.MEDIUM,
                category=ValidationCategory.SECURITY_CONCERN,
                plugin_name=plugin_name,
                field_path="result.content",
                issue_description=f"Content size ({len(content_str)} bytes) exceeds safe limit",
                original_value=f"Large content ({len(content_str)} bytes)",
                suggested_correction="Content should be truncated or summarized"
            )
            validation_result.issues.append(issue)
    
    def _standardize_format(self, plugin_name: str, validation_result: ValidationResult):
        """Standardize result format for consistency."""
        try:
            title, content = validation_result.sanitized_result
        except ValueError as e:
            # Handle unpacking errors gracefully
            title = f"✅ {plugin_name}"
            content = str(validation_result.sanitized_result)
        
        # Standardize title format
        if not title.startswith(('✅', '❌', '⚠️', '📋', '🔍')):
            # Add appropriate icon based on content analysis
            if isinstance(content, dict):
                status = content.get('status', '').upper()
                if status in ['FAIL', 'FAILED', 'VULNERABLE']:
                    title = f"❌ {title}"
                elif status in ['PASS', 'PASSED', 'SECURE']:
                    title = f"✅ {title}"
                else:
                    title = f"📋 {title}"
            else:
                content_str = str(content).lower()
                if any(word in content_str for word in ['fail', 'error', 'vulnerable', 'insecure']):
                    title = f"❌ {title}"
                elif any(word in content_str for word in ['pass', 'success', 'secure', 'safe']):
                    title = f"✅ {title}"
                else:
                    title = f"📋 {title}"
            
            issue = ValidationIssue(
                severity=ValidationSeverity.LOW,
                category=ValidationCategory.FORMAT_INCONSISTENT,
                plugin_name=plugin_name,
                field_path="result.title",
                issue_description="Title formatted with status icon for consistency",
                original_value=validation_result.sanitized_result[0],
                suggested_correction=title,
                auto_corrected=True
            )
            validation_result.issues.append(issue)
            validation_result.corrections_applied += 1
        
        # Update result
        validation_result.sanitized_result = (title, content)
    
    def _update_plugin_stats(self, plugin_name: str, validation_result: ValidationResult):
        """Update plugin-specific validation statistics."""
        if plugin_name not in self.plugin_stats:
            self.plugin_stats[plugin_name] = {
                'total_validations': 0,
                'successful_validations': 0,
                'total_issues': 0,
                'auto_corrections': 0
            }
        
        stats = self.plugin_stats[plugin_name]
        stats['total_validations'] += 1
        if validation_result.is_valid:
            stats['successful_validations'] += 1
        stats['total_issues'] += len(validation_result.issues)
        stats['auto_corrections'] += validation_result.corrections_applied
        
        # Add issues to global tracking
        self.all_issues.extend(validation_result.issues)
        self.stats['total_issues'] += len(validation_result.issues)
        self.stats['auto_corrections'] += validation_result.corrections_applied
    
    def validate_all_plugin_results(self, plugin_results: Dict[str, Tuple[str, Any]]) -> Dict[str, ValidationResult]:
        """
        Validate all plugin results in batch.
        
        Args:
            plugin_results: Dictionary of plugin_name -> result tuples
            
        Returns:
            Dictionary of plugin_name -> ValidationResult
        """
        validation_results = {}
        
        self.logger.info(f"Starting batch validation of {len(plugin_results)} plugin results")
        
        for plugin_name, result in plugin_results.items():
            validation_results[plugin_name] = self.validate_plugin_result(plugin_name, result)
        
        self.logger.info(f"Batch validation completed: "
                        f"{self.stats['successful_validations']}/{self.stats['total_validations']} successful")
        
        return validation_results
    
    def get_sanitized_results(self, validation_results: Dict[str, ValidationResult]) -> Dict[str, Tuple[str, Any]]:
        """Extract sanitized results from validation results."""
        return {
            plugin_name: vr.sanitized_result 
            for plugin_name, vr in validation_results.items()
        }
    
    def generate_validation_report(self) -> Dict[str, Any]:
        """Generate comprehensive validation report."""
        severity_counts = {severity.value: 0 for severity in ValidationSeverity}
        category_counts = {category.value: 0 for category in ValidationCategory}
        
        for issue in self.all_issues:
            severity_counts[issue.severity.value] += 1
            category_counts[issue.category.value] += 1
        
        return {
            'validation_statistics': self.stats.copy(),
            'severity_breakdown': severity_counts,
            'category_breakdown': category_counts,
            'plugin_statistics': self.plugin_stats.copy(),
            'total_issues': len(self.all_issues),
            'auto_correction_rate': (self.stats['auto_corrections'] / max(self.stats['total_issues'], 1)) * 100,
            'validation_success_rate': (self.stats['successful_validations'] / max(self.stats['total_validations'], 1)) * 100,
            'recent_issues': [issue.to_dict() for issue in self.all_issues[-10:]]
        }
    
    def cleanup(self):
        """Cleanup validation pipeline resources."""
        self.logger.info(f"Validation pipeline cleanup: {len(self.all_issues)} issues processed")
        self.all_issues.clear()
        self.plugin_stats.clear()

# Global validation pipeline instance
_validation_pipeline = None

def get_validation_pipeline() -> ResultValidationPipeline:
    """Get or create global validation pipeline instance."""
    global _validation_pipeline
    if _validation_pipeline is None:
        _validation_pipeline = ResultValidationPipeline()
    return _validation_pipeline

def validate_plugin_result(plugin_name: str, result: Any) -> ValidationResult:
    """
    Validate a single plugin result using the global pipeline.
    
    Args:
        plugin_name: Name of the plugin
        result: Plugin result to validate
        
    Returns:
        ValidationResult with validation status and sanitized data
    """
    pipeline = get_validation_pipeline()
    return pipeline.validate_plugin_result(plugin_name, result)

def validate_and_sanitize_all_results(plugin_results: Dict[str, Tuple[str, Any]]) -> Tuple[Dict[str, Tuple[str, Any]], Dict[str, Any]]:
    """
    Validate and sanitize all plugin results, returning sanitized results and validation report.
    
    Args:
        plugin_results: Dictionary of plugin results
        
    Returns:
        Tuple of (sanitized_results, validation_report)
    """
    pipeline = get_validation_pipeline()
    
    # Validate all results
    validation_results = pipeline.validate_all_plugin_results(plugin_results)
    
    # Extract sanitized results
    sanitized_results = pipeline.get_sanitized_results(validation_results)
    
    # Generate validation report
    validation_report = pipeline.generate_validation_report()
    
    return sanitized_results, validation_report 
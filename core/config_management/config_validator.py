#!/usr/bin/env python3
"""
Configuration Validator for AODS Plugin Modularization

This module provides comprehensive validation for configuration files,
patterns, and data structures used across all AODS plugins.

Features:
- YAML/JSON configuration validation
- Schema validation with custom rules
- Pattern validation for security patterns
- Plugin configuration validation
- Comprehensive error reporting
"""

import logging
import json
import yaml
from typing import Dict, List, Optional, Any, Union, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import re

# Optional jsonschema import
try:
    import jsonschema
    from jsonschema import validate, ValidationError as JSONValidationError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    jsonschema = None
    validate = None
    JSONValidationError = Exception

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Configuration validation error."""
    
    def __init__(self, message: str, field_path: str = "", errors: List[str] = None):
        super().__init__(message)
        self.field_path = field_path
        self.errors = errors or []
        self.message = message
    
    def __str__(self) -> str:
        if self.field_path:
            return f"Validation error in '{self.field_path}': {self.message}"
        return f"Validation error: {self.message}"

class ValidationSeverity(Enum):
    """Validation issue severity levels."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

@dataclass
class ValidationIssue:
    """Represents a validation issue."""
    severity: ValidationSeverity
    message: str
    field_path: str = ""
    suggestion: str = ""
    
    def __str__(self) -> str:
        severity_str = self.severity.value.upper()
        if self.field_path:
            return f"[{severity_str}] {self.field_path}: {self.message}"
        return f"[{severity_str}] {self.message}"

@dataclass
class ValidationResult:
    """Validation result containing issues and status."""
    is_valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    
    @property
    def errors(self) -> List[ValidationIssue]:
        """Get only error-level issues."""
        return [issue for issue in self.issues if issue.severity == ValidationSeverity.ERROR]
    
    @property
    def warnings(self) -> List[ValidationIssue]:
        """Get only warning-level issues."""
        return [issue for issue in self.issues if issue.severity == ValidationSeverity.WARNING]
    
    @property
    def has_errors(self) -> bool:
        """Check if there are any errors."""
        return len(self.errors) > 0
    
    @property
    def has_warnings(self) -> bool:
        """Check if there are any warnings."""
        return len(self.warnings) > 0
    
    def add_issue(self, issue: ValidationIssue):
        """Add a validation issue."""
        self.issues.append(issue)
        if issue.severity == ValidationSeverity.ERROR:
            self.is_valid = False
    
    def add_error(self, message: str, field_path: str = "", suggestion: str = ""):
        """Add an error issue."""
        self.add_issue(ValidationIssue(
            severity=ValidationSeverity.ERROR,
            message=message,
            field_path=field_path,
            suggestion=suggestion
        ))
    
    def add_warning(self, message: str, field_path: str = "", suggestion: str = ""):
        """Add a warning issue."""
        self.add_issue(ValidationIssue(
            severity=ValidationSeverity.WARNING,
            message=message,
            field_path=field_path,
            suggestion=suggestion
        ))

class ConfigValidator:
    """
    Comprehensive configuration validator for AODS configurations.
    
    Validates YAML/JSON configurations, patterns, and plugin settings
    with detailed error reporting and suggestions.
    """
    
    def __init__(self):
        """Initialize configuration validator."""
        self.logger = logging.getLogger(__name__)
        
        # Validation schemas (only if jsonschema is available)
        self.schemas = {}
        if JSONSCHEMA_AVAILABLE:
            self.schemas = {
                'plugin_config': self._get_plugin_config_schema(),
                'pattern_config': self._get_pattern_config_schema(),
                'analysis_config': self._get_analysis_config_schema()
            }
        
        # Validation rules
        self.validation_rules = {
            'pattern_id': self._validate_pattern_id,
            'regex_pattern': self._validate_regex_pattern,
            'confidence_score': self._validate_confidence_score,
            'severity': self._validate_severity,
            'file_path': self._validate_file_path,
            'plugin_name': self._validate_plugin_name
        }
        
        if not JSONSCHEMA_AVAILABLE:
            logger.warning("jsonschema not available - schema validation will be skipped")
        
        logger.info("Configuration validator initialized")
    
    def validate_config_file(self, file_path: Path, config_type: str = "auto") -> ValidationResult:
        """
        Validate a configuration file.
        
        Args:
            file_path: Path to configuration file
            config_type: Type of configuration (auto, plugin_config, pattern_config)
            
        Returns:
            ValidationResult with validation status and issues
        """
        result = ValidationResult(is_valid=True)
        
        try:
            # Check file existence
            if not file_path.exists():
                result.add_error(f"Configuration file not found: {file_path}")
                return result
            
            # Load configuration
            config_data = self._load_config_file(file_path)
            if config_data is None:
                result.add_error(f"Failed to load configuration file: {file_path}")
                return result
            
            # Detect configuration type if auto
            if config_type == "auto":
                config_type = self._detect_config_type(config_data)
            
            # Validate configuration
            self._validate_config_data(config_data, config_type, result)
            
        except Exception as e:
            result.add_error(f"Validation failed: {str(e)}")
        
        return result
    
    def validate_config_data(self, config_data: Dict[str, Any], config_type: str) -> ValidationResult:
        """
        Validate configuration data.
        
        Args:
            config_data: Configuration data to validate
            config_type: Type of configuration
            
        Returns:
            ValidationResult with validation status and issues
        """
        result = ValidationResult(is_valid=True)
        self._validate_config_data(config_data, config_type, result)
        return result
    
    def validate_pattern_config(self, pattern_config: Dict[str, Any]) -> ValidationResult:
        """Validate pattern configuration."""
        result = ValidationResult(is_valid=True)
        
        # Validate top-level structure
        if not isinstance(pattern_config, dict):
            result.add_error("Pattern configuration must be a dictionary")
            return result
        
        # Validate each pattern category
        for category, patterns in pattern_config.items():
            self._validate_pattern_category(category, patterns, result)
        
        return result
    
    def validate_plugin_config(self, plugin_config: Dict[str, Any]) -> ValidationResult:
        """Validate plugin configuration."""
        result = ValidationResult(is_valid=True)
        
        # Required fields
        required_fields = ['plugin_name', 'plugin_version', 'enabled']
        for field in required_fields:
            if field not in plugin_config:
                result.add_error(f"Missing required field: {field}")
        
        # Validate individual fields
        if 'plugin_name' in plugin_config:
            if not self._is_valid_plugin_name(plugin_config['plugin_name']):
                result.add_error("Invalid plugin name format", "plugin_name")
        
        if 'enabled' in plugin_config:
            if not isinstance(plugin_config['enabled'], bool):
                result.add_error("'enabled' must be a boolean", "enabled")
        
        if 'priority' in plugin_config:
            priority = plugin_config['priority']
            if not isinstance(priority, int) or not 0 <= priority <= 100:
                result.add_error("Priority must be an integer between 0 and 100", "priority")
        
        return result
    
    def validate_analysis_config(self, analysis_config: Dict[str, Any]) -> ValidationResult:
        """Validate analysis configuration."""
        result = ValidationResult(is_valid=True)
        
        # Validate scan configuration
        if 'scan_config' in analysis_config:
            self._validate_scan_config(analysis_config['scan_config'], result)
        
        # Validate performance configuration
        if 'performance_config' in analysis_config:
            self._validate_performance_config(analysis_config['performance_config'], result)
        
        return result
    
    def _load_config_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load configuration file (YAML or JSON)."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                if file_path.suffix.lower() in ['.yaml', '.yml']:
                    return yaml.safe_load(content)
                elif file_path.suffix.lower() == '.json':
                    return json.loads(content)
                else:
                    # Try to detect format
                    try:
                        return yaml.safe_load(content)
                    except yaml.YAMLError:
                        return json.loads(content)
        
        except Exception as e:
            self.logger.error(f"Failed to load config file {file_path}: {e}")
            return None
    
    def _detect_config_type(self, config_data: Dict[str, Any]) -> str:
        """Detect configuration type from data structure."""
        if 'plugin_name' in config_data:
            return 'plugin_config'
        elif any(key in config_data for key in ['root_detection', 'debugger_detection', 'crypto_patterns']):
            return 'pattern_config'
        elif 'scan_config' in config_data or 'performance_config' in config_data:
            return 'analysis_config'
        else:
            return 'unknown'
    
    def _validate_config_data(self, config_data: Dict[str, Any], config_type: str, result: ValidationResult):
        """Validate configuration data against schema."""
        # Schema validation (only if jsonschema is available)
        if JSONSCHEMA_AVAILABLE and config_type in self.schemas:
            try:
                validate(instance=config_data, schema=self.schemas[config_type])
            except JSONValidationError as e:
                result.add_error(f"Schema validation failed: {e.message}", str(e.absolute_path))
        
        # Custom validation rules
        if config_type == 'pattern_config':
            self._validate_pattern_config_custom(config_data, result)
        elif config_type == 'plugin_config':
            self._validate_plugin_config_custom(config_data, result)
        elif config_type == 'analysis_config':
            self._validate_analysis_config_custom(config_data, result)
    
    def _validate_pattern_category(self, category: str, patterns: Any, result: ValidationResult):
        """Validate a pattern category."""
        if not isinstance(patterns, (list, dict)):
            result.add_error(f"Pattern category '{category}' must be a list or dictionary")
            return
        
        if isinstance(patterns, list):
            for i, pattern in enumerate(patterns):
                self._validate_single_pattern(pattern, f"{category}[{i}]", result)
        else:
            for pattern_id, pattern in patterns.items():
                self._validate_single_pattern(pattern, f"{category}.{pattern_id}", result)
    
    def _validate_single_pattern(self, pattern: Any, path: str, result: ValidationResult):
        """Validate a single pattern."""
        if not isinstance(pattern, dict):
            result.add_error("Pattern must be a dictionary", path)
            return
        
        # Required fields
        required_fields = ['pattern', 'description']
        for field in required_fields:
            if field not in pattern:
                result.add_error(f"Missing required field: {field}", f"{path}.{field}")
        
        # Validate pattern regex
        if 'pattern' in pattern:
            if not self._is_valid_regex(pattern['pattern']):
                result.add_error("Invalid regex pattern", f"{path}.pattern")
        
        # Validate confidence score
        if 'confidence' in pattern:
            if not self._is_valid_confidence(pattern['confidence']):
                result.add_error("Confidence must be between 0.0 and 1.0", f"{path}.confidence")
        
        # Validate severity
        if 'severity' in pattern:
            if not self._is_valid_severity(pattern['severity']):
                result.add_error("Invalid severity level", f"{path}.severity")
    
    def _validate_scan_config(self, scan_config: Dict[str, Any], result: ValidationResult):
        """Validate scan configuration."""
        if 'min_confidence_threshold' in scan_config:
            threshold = scan_config['min_confidence_threshold']
            if not isinstance(threshold, (int, float)) or not 0.0 <= threshold <= 1.0:
                result.add_error("Min confidence threshold must be between 0.0 and 1.0", "scan_config.min_confidence_threshold")
        
        if 'max_vulnerabilities_per_type' in scan_config:
            max_vulns = scan_config['max_vulnerabilities_per_type']
            if not isinstance(max_vulns, int) or max_vulns <= 0:
                result.add_error("Max vulnerabilities per type must be a positive integer", "scan_config.max_vulnerabilities_per_type")
    
    def _validate_performance_config(self, perf_config: Dict[str, Any], result: ValidationResult):
        """Validate performance configuration."""
        if 'max_memory_usage_mb' in perf_config:
            memory = perf_config['max_memory_usage_mb']
            if not isinstance(memory, int) or memory <= 0:
                result.add_error("Max memory usage must be a positive integer", "performance_config.max_memory_usage_mb")
        
        if 'max_worker_threads' in perf_config:
            threads = perf_config['max_worker_threads']
            if not isinstance(threads, int) or threads <= 0:
                result.add_error("Max worker threads must be a positive integer", "performance_config.max_worker_threads")
    
    def _validate_pattern_config_custom(self, config_data: Dict[str, Any], result: ValidationResult):
        """Custom validation for pattern configuration."""
        # Check for duplicate pattern IDs
        pattern_ids = set()
        for category, patterns in config_data.items():
            if isinstance(patterns, dict):
                for pattern_id in patterns.keys():
                    if pattern_id in pattern_ids:
                        result.add_warning(f"Duplicate pattern ID: {pattern_id}")
                    pattern_ids.add(pattern_id)
    
    def _validate_plugin_config_custom(self, config_data: Dict[str, Any], result: ValidationResult):
        """Custom validation for plugin configuration."""
        # Check for reasonable timeout values
        if 'timeout_seconds' in config_data:
            timeout = config_data['timeout_seconds']
            if isinstance(timeout, int) and timeout > 3600:
                result.add_warning("Plugin timeout is very high (> 1 hour)", "timeout_seconds")
    
    def _validate_analysis_config_custom(self, config_data: Dict[str, Any], result: ValidationResult):
        """Custom validation for analysis configuration."""
        # Check for compatible settings
        if 'scan_config' in config_data:
            scan_config = config_data['scan_config']
            if scan_config.get('enable_deep_analysis') and scan_config.get('analysis_mode') == 'fast':
                result.add_warning("Deep analysis enabled with fast mode - may conflict")
    
    # Validation rule methods
    def _validate_pattern_id(self, pattern_id: str) -> bool:
        """Validate pattern ID format."""
        return bool(re.match(r'^[A-Z_][A-Z0-9_]*$', pattern_id))
    
    def _validate_regex_pattern(self, pattern: str) -> bool:
        """Validate regex pattern."""
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False
    
    def _validate_confidence_score(self, confidence: Union[int, float]) -> bool:
        """Validate confidence score."""
        return isinstance(confidence, (int, float)) and 0.0 <= confidence <= 1.0
    
    def _validate_severity(self, severity: str) -> bool:
        """Validate severity level."""
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        return severity.upper() in valid_severities
    
    def _validate_file_path(self, file_path: str) -> bool:
        """Validate file path."""
        try:
            Path(file_path)
            return True
        except Exception:
            return False
    
    def _validate_plugin_name(self, plugin_name: str) -> bool:
        """Validate plugin name."""
        return bool(re.match(r'^[a-z][a-z0-9_]*$', plugin_name))
    
    # Helper methods
    def _is_valid_regex(self, pattern: str) -> bool:
        """Check if regex pattern is valid."""
        return self._validate_regex_pattern(pattern)
    
    def _is_valid_confidence(self, confidence: Union[int, float]) -> bool:
        """Check if confidence score is valid."""
        return self._validate_confidence_score(confidence)
    
    def _is_valid_severity(self, severity: str) -> bool:
        """Check if severity level is valid."""
        return self._validate_severity(severity)
    
    def _is_valid_plugin_name(self, plugin_name: str) -> bool:
        """Check if plugin name is valid."""
        return self._validate_plugin_name(plugin_name)
    
    def _get_plugin_config_schema(self) -> Dict[str, Any]:
        """Get JSON schema for plugin configuration."""
        return {
            "type": "object",
            "properties": {
                "plugin_name": {"type": "string"},
                "plugin_version": {"type": "string"},
                "enabled": {"type": "boolean"},
                "priority": {"type": "integer", "minimum": 0, "maximum": 100},
                "timeout_seconds": {"type": "integer", "minimum": 1},
                "custom_settings": {"type": "object"},
                "required_plugins": {"type": "array", "items": {"type": "string"}},
                "optional_plugins": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["plugin_name", "plugin_version", "enabled"],
            "additionalProperties": True
        }
    
    def _get_pattern_config_schema(self) -> Dict[str, Any]:
        """Get JSON schema for pattern configuration."""
        return {
            "type": "object",
            "patternProperties": {
                ".*": {
                    "oneOf": [
                        {"type": "array"},
                        {"type": "object"}
                    ]
                }
            },
            "additionalProperties": True
        }
    
    def _get_analysis_config_schema(self) -> Dict[str, Any]:
        """Get JSON schema for analysis configuration."""
        return {
            "type": "object",
            "properties": {
                "scan_config": {
                    "type": "object",
                    "properties": {
                        "analysis_mode": {"type": "string"},
                        "enable_deep_analysis": {"type": "boolean"},
                        "min_confidence_threshold": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                        "max_vulnerabilities_per_type": {"type": "integer", "minimum": 1}
                    }
                },
                "performance_config": {
                    "type": "object",
                    "properties": {
                        "max_memory_usage_mb": {"type": "integer", "minimum": 1},
                        "max_worker_threads": {"type": "integer", "minimum": 1},
                        "max_execution_time_seconds": {"type": "integer", "minimum": 1}
                    }
                }
            },
            "additionalProperties": True
        }

# Convenience functions
def validate_config_file(file_path: Path, config_type: str = "auto") -> ValidationResult:
    """Validate a configuration file."""
    validator = ConfigValidator()
    return validator.validate_config_file(file_path, config_type)

def validate_pattern_config(pattern_config: Dict[str, Any]) -> ValidationResult:
    """Validate pattern configuration."""
    validator = ConfigValidator()
    return validator.validate_pattern_config(pattern_config)

def validate_plugin_config(plugin_config: Dict[str, Any]) -> ValidationResult:
    """Validate plugin configuration."""
    validator = ConfigValidator()
    return validator.validate_plugin_config(plugin_config) 
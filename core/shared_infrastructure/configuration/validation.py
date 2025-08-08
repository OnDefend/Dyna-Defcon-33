#!/usr/bin/env python3
"""
Configuration Validation Framework for AODS Shared Infrastructure

Provides comprehensive validation capabilities for all configuration types
including schema validation, business rule validation, and security checks.

Features:
- JSON Schema validation for structured validation
- Business rule validation with custom validators
- Security configuration validation
- Pattern validation for security patterns
- Plugin configuration validation
- Performance and resource validation
- Cross-reference validation between related configs
- Detailed error reporting with suggestions
- Validation caching for performance

This component ensures all AODS configurations are valid, secure,
and optimized for the target environment.
"""

import re
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import urllib.parse

# Optional JSON Schema validation
try:
    import jsonschema
    from jsonschema import validate, ValidationError as JSONSchemaError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    jsonschema = None
    validate = None
    JSONSchemaError = Exception

from .system_detection import get_system_detector, HardwareCapabilities
from ..analysis_exceptions import ValidationError

logger = logging.getLogger(__name__)

class ValidationSeverity(Enum):
    """Validation issue severity levels."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

class ValidationType(Enum):
    """Types of validation checks."""
    SCHEMA = "schema"
    BUSINESS_RULE = "business_rule"
    SECURITY = "security"
    PERFORMANCE = "performance"
    CROSS_REFERENCE = "cross_reference"

@dataclass
class ValidationIssue:
    """Represents a validation issue."""
    severity: ValidationSeverity
    validation_type: ValidationType
    field_path: str
    message: str
    suggestion: Optional[str] = None
    code: Optional[str] = None
    
    def __str__(self) -> str:
        """String representation of validation issue."""
        prefix = f"[{self.severity.value.upper()}]"
        if self.field_path:
            return f"{prefix} {self.field_path}: {self.message}"
        return f"{prefix} {self.message}"

@dataclass
class ValidationResult:
    """Results of configuration validation."""
    is_valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    validated_paths: Set[str] = field(default_factory=set)
    
    def add_error(self, field_path: str, message: str, suggestion: Optional[str] = None, 
                  validation_type: ValidationType = ValidationType.SCHEMA) -> None:
        """Add validation error."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.ERROR,
            validation_type=validation_type,
            field_path=field_path,
            message=message,
            suggestion=suggestion
        ))
        self.is_valid = False
    
    def add_warning(self, field_path: str, message: str, suggestion: Optional[str] = None,
                   validation_type: ValidationType = ValidationType.BUSINESS_RULE) -> None:
        """Add validation warning."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.WARNING,
            validation_type=validation_type,
            field_path=field_path,
            message=message,
            suggestion=suggestion
        ))
    
    def add_info(self, field_path: str, message: str, suggestion: Optional[str] = None) -> None:
        """Add validation info."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.INFO,
            validation_type=ValidationType.BUSINESS_RULE,
            field_path=field_path,
            message=message,
            suggestion=suggestion
        ))
    
    def get_errors(self) -> List[ValidationIssue]:
        """Get all error-level issues."""
        return [issue for issue in self.issues if issue.severity == ValidationSeverity.ERROR]
    
    def get_warnings(self) -> List[ValidationIssue]:
        """Get all warning-level issues."""
        return [issue for issue in self.issues if issue.severity == ValidationSeverity.WARNING]
    
    def has_errors(self) -> bool:
        """Check if there are any errors."""
        return len(self.get_errors()) > 0

class ConfigurationValidator:
    """
    Comprehensive configuration validator for AODS.
    
    Provides multi-layered validation including schema validation,
    business rules, security checks, and performance optimization.
    """
    
    def __init__(self):
        """Initialize configuration validator."""
        self.logger = logging.getLogger(__name__)
        
        # Schema definitions
        self.schemas = self._load_validation_schemas()
        
        # Custom validators
        self.custom_validators = {
            'regex_pattern': self._validate_regex_pattern,
            'file_path': self._validate_file_path,
            'directory_path': self._validate_directory_path,
            'ip_address': self._validate_ip_address,
            'url': self._validate_url,
            'port_number': self._validate_port_number,
            'confidence_score': self._validate_confidence_score,
            'severity_level': self._validate_severity_level,
            'plugin_name': self._validate_plugin_name,
            'version_string': self._validate_version_string,
            'memory_size': self._validate_memory_size,
            'timeout_value': self._validate_timeout_value
        }
        
        # Business rule validators
        self.rule_validators = {
            'performance_limits': self._validate_performance_limits,
            'security_settings': self._validate_security_settings,
            'plugin_compatibility': self._validate_plugin_compatibility,
            'resource_allocation': self._validate_resource_allocation,
            'pattern_consistency': self._validate_pattern_consistency
        }
        
        # Validation cache
        self._validation_cache: Dict[str, ValidationResult] = {}
        
        if not JSONSCHEMA_AVAILABLE:
            logger.warning("JSON Schema validation not available - install 'jsonschema' package for full validation")
        
        logger.info("Configuration validator initialized")
    
    def validate_configuration(self, 
                             config_data: Dict[str, Any],
                             config_type: str = "general",
                             strict_mode: bool = False,
                             environment_context: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """
        Validate configuration data comprehensively.
        
        Args:
            config_data: Configuration data to validate
            config_type: Type of configuration (plugin, pattern, analysis, etc.)
            strict_mode: Enable strict validation (warnings as errors)
            environment_context: Environment context for validation
            
        Returns:
            ValidationResult with all validation issues
        """
        result = ValidationResult(is_valid=True)
        
        try:
            # Generate cache key
            cache_key = self._generate_cache_key(config_data, config_type, strict_mode)
            
            # Check cache (for performance)
            if cache_key in self._validation_cache:
                return self._validation_cache[cache_key]
            
            # Schema validation
            if JSONSCHEMA_AVAILABLE and config_type in self.schemas:
                self._validate_schema(config_data, config_type, result)
            
            # Custom field validation
            self._validate_custom_fields(config_data, "", result)
            
            # Business rule validation
            self._validate_business_rules(config_data, config_type, result, environment_context)
            
            # Security validation
            self._validate_security_aspects(config_data, result)
            
            # Performance validation
            self._validate_performance_aspects(config_data, result, environment_context)
            
            # Type-specific validation
            if config_type == "plugin":
                self._validate_plugin_specific(config_data, result)
            elif config_type == "pattern":
                self._validate_pattern_specific(config_data, result)
            elif config_type == "analysis":
                self._validate_analysis_specific(config_data, result)
            
            # Cross-reference validation
            self._validate_cross_references(config_data, result)
            
            # Apply strict mode
            if strict_mode:
                for issue in result.issues:
                    if issue.severity == ValidationSeverity.WARNING:
                        issue.severity = ValidationSeverity.ERROR
                        result.is_valid = False
            
            # Cache result
            self._validation_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            self.logger.error(f"Validation failed: {e}")
            result.add_error("", f"Validation process failed: {e}")
            return result
    
    def validate_plugin_configuration(self, config_data: Dict[str, Any], 
                                    plugin_name: str) -> ValidationResult:
        """Validate plugin-specific configuration."""
        result = ValidationResult(is_valid=True)
        
        # Required plugin fields
        required_fields = {
            'plugin_name': str,
            'version': str,
            'enabled': bool
        }
        
        for field, expected_type in required_fields.items():
            if field not in config_data:
                result.add_error(field, f"Required field '{field}' is missing")
            elif not isinstance(config_data[field], expected_type):
                result.add_error(field, f"Field '{field}' must be of type {expected_type.__name__}")
        
        # Validate plugin name consistency
        if 'plugin_name' in config_data and config_data['plugin_name'] != plugin_name:
            result.add_warning('plugin_name', 
                             f"Plugin name mismatch: config says '{config_data['plugin_name']}', expected '{plugin_name}'")
        
        # Validate configuration sections
        if 'configuration' in config_data:
            self._validate_plugin_configuration_section(config_data['configuration'], result)
        
        return result
    
    def validate_security_patterns(self, patterns: Dict[str, Any]) -> ValidationResult:
        """Validate security pattern configuration."""
        result = ValidationResult(is_valid=True)
        
        for category, pattern_list in patterns.items():
            if not isinstance(pattern_list, (list, dict)):
                result.add_error(f"{category}", "Pattern category must be a list or dictionary")
                continue
            
            # Convert dict to list for uniform processing
            if isinstance(pattern_list, dict):
                pattern_list = list(pattern_list.values())
            
            for i, pattern in enumerate(pattern_list):
                if not isinstance(pattern, dict):
                    result.add_error(f"{category}[{i}]", "Pattern must be a dictionary")
                    continue
                
                self._validate_single_pattern(pattern, f"{category}[{i}]", result)
        
        return result
    
    def validate_analysis_configuration(self, config_data: Dict[str, Any],
                                      hardware_context: Optional[HardwareCapabilities] = None) -> ValidationResult:
        """Validate analysis configuration with hardware context."""
        result = ValidationResult(is_valid=True)
        
        # Get hardware context if not provided
        if hardware_context is None:
            try:
                hardware_context = get_system_detector().detect_hardware_capabilities()
            except Exception:
                hardware_context = None
        
        # Validate scan configuration
        if 'scan_config' in config_data:
            self._validate_scan_configuration(config_data['scan_config'], result, hardware_context)
        
        # Validate performance configuration
        if 'performance_config' in config_data:
            self._validate_performance_configuration(config_data['performance_config'], result, hardware_context)
        
        # Validate timeout settings
        if 'timeout_config' in config_data:
            self._validate_timeout_configuration(config_data['timeout_config'], result)
        
        return result
    
    def _validate_schema(self, config_data: Dict[str, Any], config_type: str, result: ValidationResult) -> None:
        """Validate configuration against JSON schema."""
        if not JSONSCHEMA_AVAILABLE:
            return
        
        try:
            schema = self.schemas.get(config_type)
            if schema:
                validate(config_data, schema)
                result.validated_paths.add(f"schema.{config_type}")
        except JSONSchemaError as e:
            # Convert JSON schema error to our format
            field_path = '.'.join(str(p) for p in e.absolute_path) if e.absolute_path else ""
            result.add_error(field_path, f"Schema validation failed: {e.message}", 
                           validation_type=ValidationType.SCHEMA)
    
    def _validate_custom_fields(self, data: Any, path: str, result: ValidationResult) -> None:
        """Recursively validate custom fields."""
        if isinstance(data, dict):
            for key, value in data.items():
                field_path = f"{path}.{key}" if path else key
                
                # Check if field has custom validator
                if key in self.custom_validators:
                    validator = self.custom_validators[key]
                    try:
                        validator(value, field_path, result)
                    except Exception as e:
                        result.add_error(field_path, f"Custom validation failed: {e}")
                
                # Recurse into nested structures
                self._validate_custom_fields(value, field_path, result)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                item_path = f"{path}[{i}]"
                self._validate_custom_fields(item, item_path, result)
    
    def _validate_business_rules(self, config_data: Dict[str, Any], config_type: str,
                               result: ValidationResult, environment_context: Optional[Dict[str, Any]]) -> None:
        """Validate business rules."""
        for rule_name, rule_validator in self.rule_validators.items():
            try:
                rule_validator(config_data, result, environment_context)
            except Exception as e:
                result.add_error("", f"Business rule validation failed for {rule_name}: {e}")
    
    def _validate_security_aspects(self, config_data: Dict[str, Any], result: ValidationResult) -> None:
        """Validate security aspects of configuration."""
        # Check for sensitive information in configuration
        sensitive_patterns = [
            (r'password\s*[:=]\s*["\']?([^"\'\s]+)', 'password'),
            (r'api_key\s*[:=]\s*["\']?([^"\'\s]+)', 'api_key'),
            (r'secret\s*[:=]\s*["\']?([^"\'\s]+)', 'secret'),
            (r'token\s*[:=]\s*["\']?([^"\'\s]+)', 'token')
        ]
        
        config_str = json.dumps(config_data, default=str).lower()
        
        for pattern, sensitive_type in sensitive_patterns:
            if re.search(pattern, config_str, re.IGNORECASE):
                result.add_warning("", 
                                 f"Possible {sensitive_type} found in configuration",
                                 "Consider using environment variables for sensitive data",
                                 ValidationType.SECURITY)
        
        # Check file permissions settings
        if 'file_permissions' in config_data:
            perms = config_data['file_permissions']
            if isinstance(perms, (int, str)):
                try:
                    perm_value = int(str(perms), 8) if isinstance(perms, str) else perms
                    if perm_value & 0o022:  # World or group writable
                        result.add_warning('file_permissions',
                                         "File permissions allow world or group write access",
                                         "Consider more restrictive permissions")
                except ValueError:
                    result.add_error('file_permissions', "Invalid file permission format")
    
    def _validate_performance_aspects(self, config_data: Dict[str, Any], result: ValidationResult,
                                    environment_context: Optional[Dict[str, Any]]) -> None:
        """Validate performance-related configuration."""
        # Get hardware context for performance validation
        try:
            hardware = get_system_detector().detect_hardware_capabilities()
        except Exception:
            return  # Skip validation if hardware detection fails
        
        # Validate memory settings
        if 'max_memory_mb' in config_data:
            max_memory = config_data['max_memory_mb']
            available_memory_mb = hardware.memory_available_gb * 1024
            
            if max_memory > available_memory_mb * 0.8:  # Using more than 80% of available memory
                result.add_warning('max_memory_mb',
                                 f"Memory setting ({max_memory}MB) may exceed available memory ({available_memory_mb:.0f}MB)",
                                 f"Consider reducing to {int(available_memory_mb * 0.8)}MB or less")
        
        # Validate thread count
        if 'max_threads' in config_data:
            max_threads = config_data['max_threads']
            if max_threads > hardware.cpu_count * 2:
                result.add_warning('max_threads',
                                 f"Thread count ({max_threads}) is high for {hardware.cpu_count} CPU cores",
                                 f"Consider reducing to {hardware.cpu_count * 2} or fewer")
    
    def _validate_plugin_specific(self, config_data: Dict[str, Any], result: ValidationResult) -> None:
        """Validate plugin-specific configuration."""
        # Validate plugin metadata
        if 'metadata' in config_data:
            metadata = config_data['metadata']
            
            # Check for required metadata fields
            recommended_fields = ['author', 'description', 'license', 'homepage']
            for field in recommended_fields:
                if field not in metadata:
                    result.add_info(f'metadata.{field}', f"Recommended field '{field}' is missing")
        
        # Validate dependencies
        if 'dependencies' in config_data:
            deps = config_data['dependencies']
            if isinstance(deps, list):
                for i, dep in enumerate(deps):
                    if isinstance(dep, str):
                        if not re.match(r'^[a-zA-Z0-9_-]+$', dep):
                            result.add_warning(f'dependencies[{i}]', 
                                             f"Dependency name '{dep}' contains unusual characters")
                    elif isinstance(dep, dict):
                        if 'name' not in dep:
                            result.add_error(f'dependencies[{i}]', "Dependency object missing 'name' field")
    
    def _validate_pattern_specific(self, config_data: Dict[str, Any], result: ValidationResult) -> None:
        """Validate pattern-specific configuration."""
        for key, value in config_data.items():
            if key.endswith('_patterns'):
                if isinstance(value, dict):
                    for pattern_name, pattern_data in value.items():
                        self._validate_single_pattern(pattern_data, f"{key}.{pattern_name}", result)
                elif isinstance(value, list):
                    for i, pattern_data in enumerate(value):
                        self._validate_single_pattern(pattern_data, f"{key}[{i}]", result)
    
    def _validate_analysis_specific(self, config_data: Dict[str, Any], result: ValidationResult) -> None:
        """Validate analysis-specific configuration."""
        # Validate analysis modes
        if 'analysis_mode' in config_data:
            valid_modes = ['static', 'dynamic', 'hybrid', 'comprehensive']
            if config_data['analysis_mode'] not in valid_modes:
                result.add_error('analysis_mode', 
                               f"Invalid analysis mode. Must be one of: {', '.join(valid_modes)}")
        
        # Validate threshold values
        threshold_fields = {
            'min_confidence_threshold': (0.0, 1.0),
            'max_false_positive_rate': (0.0, 1.0),
            'performance_threshold': (0.0, 100.0)
        }
        
        for field, (min_val, max_val) in threshold_fields.items():
            if field in config_data:
                value = config_data[field]
                if not isinstance(value, (int, float)):
                    result.add_error(field, f"Field '{field}' must be a number")
                elif not min_val <= value <= max_val:
                    result.add_error(field, f"Field '{field}' must be between {min_val} and {max_val}")
    
    def _validate_single_pattern(self, pattern: Dict[str, Any], path: str, result: ValidationResult) -> None:
        """Validate a single security pattern."""
        # Required pattern fields
        required_fields = ['name', 'pattern', 'severity']
        for field in required_fields:
            if field not in pattern:
                result.add_error(f"{path}.{field}", f"Required pattern field '{field}' is missing")
        
        # Validate pattern regex
        if 'pattern' in pattern:
            try:
                re.compile(pattern['pattern'])
            except re.error as e:
                result.add_error(f"{path}.pattern", f"Invalid regex pattern: {e}")
        
        # Validate severity
        if 'severity' in pattern:
            valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            if pattern['severity'] not in valid_severities:
                result.add_error(f"{path}.severity", 
                               f"Invalid severity. Must be one of: {', '.join(valid_severities)}")
        
        # Validate confidence if present
        if 'confidence' in pattern:
            confidence = pattern['confidence']
            if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
                result.add_error(f"{path}.confidence", "Confidence must be a number between 0.0 and 1.0")
        
        # Validate MASVS controls if present
        if 'masvs_controls' in pattern:
            controls = pattern['masvs_controls']
            if isinstance(controls, list):
                for i, control in enumerate(controls):
                    if not isinstance(control, str) or not re.match(r'^MASVS-[A-Z]+-\d+', control):
                        result.add_warning(f"{path}.masvs_controls[{i}]", 
                                         f"MASVS control '{control}' doesn't match expected format")
    
    def _validate_cross_references(self, config_data: Dict[str, Any], result: ValidationResult) -> None:
        """Validate cross-references between configuration sections."""
        # Validate plugin references
        if 'enabled_plugins' in config_data and 'plugins' in config_data:
            enabled = config_data['enabled_plugins']
            available = list(config_data['plugins'].keys())
            
            for plugin in enabled:
                if plugin not in available:
                    result.add_error('enabled_plugins', 
                                   f"Referenced plugin '{plugin}' is not defined in plugins section")
        
        # Validate pattern references
        if 'active_patterns' in config_data:
            # Validate that referenced patterns exist in pattern definitions
            active_patterns = config_data['active_patterns']
            pattern_definitions = config_data.get('pattern_definitions', {})
            
            if isinstance(active_patterns, list):
                for pattern_ref in active_patterns:
                    if isinstance(pattern_ref, str):
                        if pattern_ref not in pattern_definitions:
                            result.add_error('active_patterns', 
                                           f"Referenced pattern '{pattern_ref}' is not defined in pattern_definitions")
            elif isinstance(active_patterns, dict):
                for category, patterns in active_patterns.items():
                    if isinstance(patterns, list):
                        for pattern_ref in patterns:
                            if isinstance(pattern_ref, str):
                                # Check if pattern exists in global definitions or category-specific
                                category_patterns = pattern_definitions.get(category, {})
                                global_patterns = pattern_definitions.get('global', {})
                                
                                if (pattern_ref not in category_patterns and 
                                    pattern_ref not in global_patterns):
                                    result.add_error(f'active_patterns.{category}', 
                                                   f"Referenced pattern '{pattern_ref}' is not defined in pattern_definitions")
    
    # Custom field validators
    def _validate_regex_pattern(self, value: Any, path: str, result: ValidationResult) -> None:
        """Validate regex pattern field."""
        if not isinstance(value, str):
            result.add_error(path, "Regex pattern must be a string")
            return
        
        try:
            re.compile(value)
        except re.error as e:
            result.add_error(path, f"Invalid regex pattern: {e}")
    
    def _validate_file_path(self, value: Any, path: str, result: ValidationResult) -> None:
        """Validate file path field."""
        if not isinstance(value, str):
            result.add_error(path, "File path must be a string")
            return
        
        file_path = Path(value)
        if not file_path.exists():
            result.add_warning(path, f"File does not exist: {value}")
    
    def _validate_directory_path(self, value: Any, path: str, result: ValidationResult) -> None:
        """Validate directory path field."""
        if not isinstance(value, str):
            result.add_error(path, "Directory path must be a string")
            return
        
        dir_path = Path(value)
        if not dir_path.exists():
            result.add_warning(path, f"Directory does not exist: {value}")
        elif not dir_path.is_dir():
            result.add_error(path, f"Path is not a directory: {value}")
    
    def _validate_ip_address(self, value: Any, path: str, result: ValidationResult) -> None:
        """Validate IP address field."""
        if not isinstance(value, str):
            result.add_error(path, "IP address must be a string")
            return
        
        try:
            ipaddress.ip_address(value)
        except ValueError:
            result.add_error(path, f"Invalid IP address: {value}")
    
    def _validate_url(self, value: Any, path: str, result: ValidationResult) -> None:
        """Validate URL field."""
        if not isinstance(value, str):
            result.add_error(path, "URL must be a string")
            return
        
        try:
            parsed = urllib.parse.urlparse(value)
            if not parsed.scheme or not parsed.netloc:
                result.add_error(path, f"Invalid URL format: {value}")
        except Exception:
            result.add_error(path, f"Invalid URL: {value}")
    
    def _validate_port_number(self, value: Any, path: str, result: ValidationResult) -> None:
        """Validate port number field."""
        if not isinstance(value, int):
            result.add_error(path, "Port number must be an integer")
            return
        
        if not 1 <= value <= 65535:
            result.add_error(path, f"Port number must be between 1 and 65535, got {value}")
    
    def _validate_confidence_score(self, value: Any, path: str, result: ValidationResult) -> None:
        """Validate confidence score field."""
        if not isinstance(value, (int, float)):
            result.add_error(path, "Confidence score must be a number")
            return
        
        if not 0.0 <= value <= 1.0:
            result.add_error(path, f"Confidence score must be between 0.0 and 1.0, got {value}")
    
    def _validate_severity_level(self, value: Any, path: str, result: ValidationResult) -> None:
        """Validate severity level field."""
        if not isinstance(value, str):
            result.add_error(path, "Severity level must be a string")
            return
        
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        if value.upper() not in valid_severities:
            result.add_error(path, f"Invalid severity level. Must be one of: {', '.join(valid_severities)}")
    
    def _validate_plugin_name(self, value: Any, path: str, result: ValidationResult) -> None:
        """Validate plugin name field."""
        if not isinstance(value, str):
            result.add_error(path, "Plugin name must be a string")
            return
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', value):
            result.add_error(path, "Plugin name can only contain letters, numbers, underscores, and hyphens")
    
    def _validate_version_string(self, value: Any, path: str, result: ValidationResult) -> None:
        """Validate version string field."""
        if not isinstance(value, str):
            result.add_error(path, "Version must be a string")
            return
        
        # Basic semantic version pattern
        if not re.match(r'^\d+\.\d+\.\d+', value):
            result.add_warning(path, "Version should follow semantic versioning (x.y.z)")
    
    def _validate_memory_size(self, value: Any, path: str, result: ValidationResult) -> None:
        """Validate memory size field."""
        if isinstance(value, str):
            # Handle string formats like "1GB", "512MB"
            match = re.match(r'^(\d+)\s*(GB|MB|KB)$', value.upper())
            if not match:
                result.add_error(path, "Invalid memory size format. Use format like '1GB', '512MB'")
                return
            
            size, unit = match.groups()
            size = int(size)
            
            # Convert to MB for validation
            if unit == 'GB':
                size_mb = size * 1024
            elif unit == 'KB':
                size_mb = size / 1024
            else:  # MB
                size_mb = size
            
            if size_mb < 1:
                result.add_error(path, "Memory size must be at least 1MB")
        elif isinstance(value, int):
            if value < 1:
                result.add_error(path, "Memory size must be positive")
        else:
            result.add_error(path, "Memory size must be a string (e.g., '1GB') or integer (MB)")
    
    def _validate_timeout_value(self, value: Any, path: str, result: ValidationResult) -> None:
        """Validate timeout value field."""
        if not isinstance(value, (int, float)):
            result.add_error(path, "Timeout value must be a number")
            return
        
        if value <= 0:
            result.add_error(path, "Timeout value must be positive")
        elif value > 3600:  # 1 hour
            result.add_warning(path, "Timeout value is very high (>1 hour)")
    
    # Business rule validators
    def _validate_performance_limits(self, config_data: Dict[str, Any], result: ValidationResult,
                                   environment_context: Optional[Dict[str, Any]]) -> None:
        """Validate performance-related limits."""
        # Validate that performance settings are reasonable for the target environment
        performance_config = config_data.get('performance', {})
        
        # Check memory limits
        if 'max_memory_mb' in performance_config:
            max_memory = performance_config['max_memory_mb']
            if isinstance(max_memory, int):
                # Check against system memory if available
                if environment_context and 'available_memory_mb' in environment_context:
                    available_memory = environment_context['available_memory_mb']
                    if max_memory > available_memory * 0.9:  # Don't use more than 90% of available memory
                        result.add_warning('performance.max_memory_mb',
                                         f"Memory limit ({max_memory}MB) is very high compared to available memory ({available_memory}MB)")
                
                # Check reasonable bounds
                if max_memory < 512:  # Less than 512MB
                    result.add_warning('performance.max_memory_mb',
                                     "Memory limit is very low, may cause performance issues")
                elif max_memory > 16384:  # More than 16GB
                    result.add_warning('performance.max_memory_mb',
                                     "Memory limit is very high, ensure system has sufficient resources")
        
        # Check thread limits
        if 'max_threads' in performance_config:
            max_threads = performance_config['max_threads']
            if isinstance(max_threads, int):
                import os
                cpu_count = os.cpu_count() or 1
                
                if max_threads > cpu_count * 4:  # More than 4x CPU cores
                    result.add_warning('performance.max_threads',
                                     f"Thread count ({max_threads}) is very high compared to CPU cores ({cpu_count})")
                elif max_threads < 1:
                    result.add_error('performance.max_threads',
                                   "Thread count must be at least 1")
        
        # Check timeout settings
        if 'timeout_seconds' in performance_config:
            timeout = performance_config['timeout_seconds']
            if isinstance(timeout, (int, float)):
                if timeout < 10:  # Less than 10 seconds
                    result.add_warning('performance.timeout_seconds',
                                     "Timeout is very short, may cause premature failures")
                elif timeout > 3600:  # More than 1 hour
                    result.add_warning('performance.timeout_seconds',
                                     "Timeout is very long, may cause hanging processes")
    
    def _validate_security_settings(self, config_data: Dict[str, Any], result: ValidationResult,
                                  environment_context: Optional[Dict[str, Any]]) -> None:
        """Validate security-related settings."""
        # Check for insecure configurations
        if config_data.get('debug_mode') is True:
            result.add_warning('debug_mode', 
                             "Debug mode is enabled",
                             "Disable debug mode in production environments")
        
        if config_data.get('allow_insecure_connections') is True:
            result.add_warning('allow_insecure_connections',
                             "Insecure connections are allowed",
                             "Use secure connections in production")
    
    def _validate_plugin_compatibility(self, config_data: Dict[str, Any], result: ValidationResult,
                                     environment_context: Optional[Dict[str, Any]]) -> None:
        """Validate plugin compatibility."""
        # Check for known incompatible plugin combinations
        enabled_plugins = config_data.get('enabled_plugins', [])
        
        # Define known incompatible plugin combinations
        incompatible_combinations = [
            # Plugins that conflict due to overlapping functionality
            {'plugins': ['static_analysis_v1', 'static_analysis_v2'], 
             'reason': 'Cannot enable both static analysis versions simultaneously'},
            {'plugins': ['drozer_legacy', 'drozer_enhanced'], 
             'reason': 'Cannot enable both legacy and enhanced Drozer managers'},
            {'plugins': ['frida_basic', 'frida_advanced'], 
             'reason': 'Cannot enable both basic and advanced Frida analyzers'},
            {'plugins': ['certificate_pinning_basic', 'certificate_pinning_advanced'], 
             'reason': 'Cannot enable both basic and advanced certificate pinning analyzers'},
        ]
        
        # Check for incompatible combinations
        for combination in incompatible_combinations:
            conflicting_plugins = combination['plugins']
            enabled_conflicting = [p for p in conflicting_plugins if p in enabled_plugins]
            
            if len(enabled_conflicting) > 1:
                result.add_error('enabled_plugins',
                               f"Incompatible plugins enabled: {', '.join(enabled_conflicting)}. "
                               f"{combination['reason']}")
        
        # Check for plugins that require specific dependencies
        plugin_dependencies = {
            'advanced_ssl_analysis': ['network_analysis', 'certificate_analysis'],
            'dynamic_analysis': ['frida_manager'],
            'hybrid_analysis': ['static_analysis', 'dynamic_analysis'],
            'network_traffic_analysis': ['mitmproxy_manager'],
        }
        
        for plugin, dependencies in plugin_dependencies.items():
            if plugin in enabled_plugins:
                missing_deps = [dep for dep in dependencies if dep not in enabled_plugins]
                if missing_deps:
                    result.add_warning(f'enabled_plugins',
                                     f"Plugin '{plugin}' requires dependencies: {', '.join(missing_deps)}")
        
        # Check for resource-intensive plugin combinations
        resource_intensive_plugins = [
            'full_static_analysis', 'comprehensive_dynamic_analysis', 
            'ml_enhanced_analysis', 'network_traffic_capture'
        ]
        
        enabled_intensive = [p for p in resource_intensive_plugins if p in enabled_plugins]
        if len(enabled_intensive) > 2:
            result.add_warning('enabled_plugins',
                             f"Multiple resource-intensive plugins enabled: {', '.join(enabled_intensive)}. "
                             "This may cause performance issues on systems with limited resources.")
    
    def _validate_resource_allocation(self, config_data: Dict[str, Any], result: ValidationResult,
                                    environment_context: Optional[Dict[str, Any]]) -> None:
        """Validate resource allocation settings."""
        # Check total resource allocation doesn't exceed system capabilities
        resource_config = config_data.get('resources', {})
        
        # Calculate total memory allocation across all components
        total_memory_mb = 0
        memory_allocations = []
        
        for component, settings in resource_config.items():
            if isinstance(settings, dict) and 'memory_mb' in settings:
                memory_mb = settings['memory_mb']
                if isinstance(memory_mb, int) and memory_mb > 0:
                    total_memory_mb += memory_mb
                    memory_allocations.append((component, memory_mb))
        
        # Check against system memory if available
        if environment_context and 'available_memory_mb' in environment_context:
            available_memory = environment_context['available_memory_mb']
            
            if total_memory_mb > available_memory:
                result.add_error('resources',
                               f"Total memory allocation ({total_memory_mb}MB) exceeds available system memory ({available_memory}MB)")
            elif total_memory_mb > available_memory * 0.8:  # More than 80% of available memory
                result.add_warning('resources',
                                 f"Total memory allocation ({total_memory_mb}MB) uses more than 80% of available memory ({available_memory}MB)")
        
        # Check for unreasonable individual allocations
        for component, memory_mb in memory_allocations:
            if memory_mb > 8192:  # More than 8GB for a single component
                result.add_warning(f'resources.{component}.memory_mb',
                                 f"Very high memory allocation ({memory_mb}MB) for component '{component}'")
            elif memory_mb < 128:  # Less than 128MB
                result.add_warning(f'resources.{component}.memory_mb',
                                 f"Very low memory allocation ({memory_mb}MB) for component '{component}', may cause performance issues")
        
        # Check CPU allocation
        total_cpu_cores = 0
        for component, settings in resource_config.items():
            if isinstance(settings, dict) and 'cpu_cores' in settings:
                cpu_cores = settings['cpu_cores']
                if isinstance(cpu_cores, (int, float)) and cpu_cores > 0:
                    total_cpu_cores += cpu_cores
        
        if environment_context and 'cpu_cores' in environment_context:
            available_cores = environment_context['cpu_cores']
            if total_cpu_cores > available_cores:
                result.add_warning('resources',
                                 f"Total CPU allocation ({total_cpu_cores}) exceeds available CPU cores ({available_cores})")
        
        # Check for resource conflicts
        if len(memory_allocations) > 1:
            # Sort by memory allocation descending
            memory_allocations.sort(key=lambda x: x[1], reverse=True)
            largest_component, largest_memory = memory_allocations[0]
            
            if largest_memory > total_memory_mb * 0.7:  # One component uses more than 70% of total
                result.add_warning('resources',
                                 f"Component '{largest_component}' uses {largest_memory}MB, which is more than 70% of total allocation")
    
    def _validate_pattern_consistency(self, config_data: Dict[str, Any], result: ValidationResult,
                                    environment_context: Optional[Dict[str, Any]]) -> None:
        """Validate pattern consistency across configuration."""
        # Check for duplicate or conflicting patterns
        pattern_definitions = config_data.get('pattern_definitions', {})
        
        # Track all patterns across categories to detect duplicates
        all_patterns = {}
        duplicate_patterns = []
        
        # Collect patterns from all categories
        for category, patterns in pattern_definitions.items():
            if isinstance(patterns, dict):
                for pattern_name, pattern_data in patterns.items():
                    if pattern_name in all_patterns:
                        duplicate_patterns.append({
                            'pattern': pattern_name,
                            'categories': [all_patterns[pattern_name], category]
                        })
                    else:
                        all_patterns[pattern_name] = category
        
        # Report duplicate pattern names
        for duplicate in duplicate_patterns:
            result.add_warning('pattern_definitions',
                             f"Pattern '{duplicate['pattern']}' is defined in multiple categories: "
                             f"{', '.join(duplicate['categories'])}")
        
        # Check for conflicting regex patterns with same names
        regex_patterns = {}
        for category, patterns in pattern_definitions.items():
            if isinstance(patterns, dict):
                for pattern_name, pattern_data in patterns.items():
                    if isinstance(pattern_data, dict) and 'regex' in pattern_data:
                        regex = pattern_data['regex']
                        if pattern_name in regex_patterns:
                            if regex_patterns[pattern_name] != regex:
                                result.add_error('pattern_definitions',
                                               f"Pattern '{pattern_name}' has conflicting regex definitions: "
                                               f"'{regex_patterns[pattern_name]}' vs '{regex}'")
                        else:
                            regex_patterns[pattern_name] = regex
        
        # Check for overly broad patterns that might cause false positives
        broad_pattern_indicators = [
            r'.*', r'.+', r'[\s\S]*', r'[^]*', r'.*?.*'
        ]
        
        for category, patterns in pattern_definitions.items():
            if isinstance(patterns, dict):
                for pattern_name, pattern_data in patterns.items():
                    if isinstance(pattern_data, dict) and 'regex' in pattern_data:
                        regex = pattern_data['regex']
                        for broad_indicator in broad_pattern_indicators:
                            if broad_indicator in regex:
                                result.add_warning(f'pattern_definitions.{category}.{pattern_name}',
                                                 f"Pattern contains overly broad regex '{broad_indicator}' "
                                                 "which may cause false positives")
                                break
        
        # Check for patterns that might conflict with each other
        security_patterns = pattern_definitions.get('security', {})
        if isinstance(security_patterns, dict):
            encryption_patterns = [name for name in security_patterns.keys() if 'encrypt' in name.lower()]
            decryption_patterns = [name for name in security_patterns.keys() if 'decrypt' in name.lower()]
            
            # Warn if encryption patterns exist without corresponding decryption patterns
            if encryption_patterns and not decryption_patterns:
                result.add_warning('pattern_definitions.security',
                                 "Encryption patterns defined but no decryption patterns found. "
                                 "Consider adding decryption detection for comprehensive analysis.")
        
        # Check pattern priority conflicts
        priority_conflicts = {}
        for category, patterns in pattern_definitions.items():
            if isinstance(patterns, dict):
                for pattern_name, pattern_data in patterns.items():
                    if isinstance(pattern_data, dict) and 'priority' in pattern_data:
                        priority = pattern_data['priority']
                        if priority in priority_conflicts:
                            priority_conflicts[priority].append(f"{category}.{pattern_name}")
                        else:
                            priority_conflicts[priority] = [f"{category}.{pattern_name}"]
        
        # Report priority conflicts for high-priority patterns
        for priority, pattern_list in priority_conflicts.items():
            if len(pattern_list) > 1 and priority >= 8:  # High priority threshold
                result.add_warning('pattern_definitions',
                                 f"Multiple high-priority patterns ({priority}) may conflict: "
                                 f"{', '.join(pattern_list)}")
    
    def _load_validation_schemas(self) -> Dict[str, Dict[str, Any]]:
        """Load JSON schemas for validation."""
        schemas = {}
        
        # Plugin configuration schema
        schemas['plugin'] = {
            "type": "object",
            "required": ["plugin_name", "version", "enabled"],
            "properties": {
                "plugin_name": {"type": "string", "pattern": "^[a-zA-Z0-9_-]+$"},
                "version": {"type": "string"},
                "enabled": {"type": "boolean"},
                "description": {"type": "string"},
                "author": {"type": "string"},
                "license": {"type": "string"},
                "dependencies": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "configuration": {"type": "object"}
            }
        }
        
        # Pattern configuration schema
        schemas['pattern'] = {
            "type": "object",
            "patternProperties": {
                ".*_patterns": {
                    "type": ["array", "object"],
                    "items": {
                        "type": "object",
                        "required": ["name", "pattern", "severity"],
                        "properties": {
                            "name": {"type": "string"},
                            "pattern": {"type": "string"},
                            "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                            "description": {"type": "string"},
                            "masvs_controls": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
        
        # Analysis configuration schema
        schemas['analysis'] = {
            "type": "object",
            "properties": {
                "analysis_mode": {"enum": ["static", "dynamic", "hybrid", "comprehensive"]},
                "scan_config": {
                    "type": "object",
                    "properties": {
                        "enable_deep_analysis": {"type": "boolean"},
                        "min_confidence_threshold": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                        "max_vulnerabilities_per_type": {"type": "integer", "minimum": 1}
                    }
                },
                "performance_config": {
                    "type": "object",
                    "properties": {
                        "max_memory_mb": {"type": "integer", "minimum": 1},
                        "max_threads": {"type": "integer", "minimum": 1},
                        "timeout_seconds": {"type": "integer", "minimum": 1}
                    }
                }
            }
        }
        
        return schemas
    
    def _generate_cache_key(self, config_data: Dict[str, Any], config_type: str, strict_mode: bool) -> str:
        """Generate cache key for validation result."""
        import hashlib
        data_str = json.dumps(config_data, sort_keys=True, default=str)
        data_hash = hashlib.md5(data_str.encode()).hexdigest()
        return f"{config_type}:{strict_mode}:{data_hash}"

# Global validator instance
_config_validator = None

def get_config_validator() -> ConfigurationValidator:
    """Get global configuration validator instance."""
    global _config_validator
    if _config_validator is None:
        _config_validator = ConfigurationValidator()
    return _config_validator

def validate_configuration(config_data: Dict[str, Any], **kwargs) -> ValidationResult:
    """Validate configuration using global validator."""
    return get_config_validator().validate_configuration(config_data, **kwargs) 
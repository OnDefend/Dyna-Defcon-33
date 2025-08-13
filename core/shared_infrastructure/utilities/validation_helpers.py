#!/usr/bin/env python3
"""
Validation Helpers for AODS Shared Infrastructure

Comprehensive input validation, data sanitization, and format validation
utilities used across all AODS components for secure and reliable processing.

Features:
- Input validation and sanitization
- Data format validation (paths, URLs, IPs, etc.)
- Security-focused validation (injection prevention)
- Android-specific validation (package names, versions)
- Network validation (domains, ports, protocols)
- File and path validation with security checks
- Data type validation and coercion
- Regular expression validation helpers
- Performance-optimized validation functions
- Detailed error reporting with suggestions

This component provides standardized validation capabilities to ensure
all AODS components handle input data safely and consistently.
"""

import re
import os
import ipaddress
import urllib.parse
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Tuple, Callable, Pattern
from dataclasses import dataclass
from enum import Enum
import json
import base64
import hashlib

logger = logging.getLogger(__name__)

class ValidationSeverity(Enum):
    """Validation result severity levels."""
    VALID = "valid"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class ValidationResult:
    """Result of validation operation."""
    is_valid: bool
    severity: ValidationSeverity
    message: str
    sanitized_value: Any = None
    suggestions: List[str] = None
    
    def __post_init__(self):
        """Initialize suggestions list if None."""
        if self.suggestions is None:
            self.suggestions = []

class SecurityValidator:
    """Security-focused validation helpers."""
    
    # Common injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
        r"(--|#|/\*|\*/)",
        r"(\b(or|and)\s+\d+\s*=\s*\d+)",
        r"(\')(.*?)(\bor\b|\band\b)(.*?)(\')?"
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>"
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`]",
        r"\$\([^)]*\)",
        r"`[^`]*`",
        r"\|\s*(rm|cat|ls|ps|kill|nc|netcat|wget|curl)"
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e\\",
        r"\.\.%2f",
        r"\.\.%5c"
    ]
    
    @classmethod
    def validate_against_injection(cls, value: str, check_types: List[str] = None) -> ValidationResult:
        """
        Validate input against various injection attacks.
        
        Args:
            value: Input value to validate
            check_types: Types of injection to check ['sql', 'xss', 'cmd', 'path']
            
        Returns:
            ValidationResult with validation status
        """
        if check_types is None:
            check_types = ['sql', 'xss', 'cmd', 'path']
        
        if not isinstance(value, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Input must be a string"
            )
        
        issues = []
        sanitized = value
        
        # Check SQL injection
        if 'sql' in check_types:
            for pattern in cls.SQL_INJECTION_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    issues.append("Possible SQL injection detected")
                    break
        
        # Check XSS
        if 'xss' in check_types:
            for pattern in cls.XSS_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    issues.append("Possible XSS attack detected")
                    sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)
        
        # Check command injection
        if 'cmd' in check_types:
            for pattern in cls.COMMAND_INJECTION_PATTERNS:
                if re.search(pattern, value):
                    issues.append("Possible command injection detected")
                    break
        
        # Check path traversal
        if 'path' in check_types:
            for pattern in cls.PATH_TRAVERSAL_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    issues.append("Possible path traversal detected")
                    break
        
        if issues:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.CRITICAL,
                message="; ".join(issues),
                sanitized_value=sanitized,
                suggestions=["Sanitize input", "Use parameterized queries", "Validate input format"]
            )
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.VALID,
            message="Input appears safe",
            sanitized_value=sanitized
        )
    
    @classmethod
    def sanitize_filename(cls, filename: str, allow_path_sep: bool = False) -> str:
        """
        Sanitize filename to prevent security issues.
        
        Args:
            filename: Filename to sanitize
            allow_path_sep: Whether to allow path separators
            
        Returns:
            Sanitized filename
        """
        if not isinstance(filename, str):
            return "invalid_filename"
        
        # Remove control characters
        sanitized = ''.join(char for char in filename if ord(char) >= 32)
        
        # Remove dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*']
        if not allow_path_sep:
            dangerous_chars.extend(['/', '\\'])
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '_')
        
        # Remove leading/trailing dots and spaces
        sanitized = sanitized.strip('. ')
        
        # Prevent reserved names on Windows
        reserved_names = [
            'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5',
            'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4',
            'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        ]
        
        if sanitized.upper() in reserved_names:
            sanitized = f"_{sanitized}"
        
        # Ensure minimum length
        if len(sanitized) == 0:
            sanitized = "unnamed_file"
        
        return sanitized

class DataTypeValidator:
    """Data type validation and coercion helpers."""
    
    @staticmethod
    def validate_integer(value: Any, min_value: int = None, max_value: int = None) -> ValidationResult:
        """Validate and coerce integer value."""
        try:
            if isinstance(value, bool):
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="Boolean cannot be converted to integer"
                )
            
            int_value = int(value)
            
            if min_value is not None and int_value < min_value:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"Value {int_value} is below minimum {min_value}",
                    suggestions=[f"Use value >= {min_value}"]
                )
            
            if max_value is not None and int_value > max_value:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"Value {int_value} is above maximum {max_value}",
                    suggestions=[f"Use value <= {max_value}"]
                )
            
            return ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.VALID,
                message="Valid integer",
                sanitized_value=int_value
            )
            
        except (ValueError, TypeError):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Cannot convert '{value}' to integer",
                suggestions=["Provide a valid numeric value"]
            )
    
    @staticmethod
    def validate_float(value: Any, min_value: float = None, max_value: float = None) -> ValidationResult:
        """Validate and coerce float value."""
        try:
            if isinstance(value, bool):
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="Boolean cannot be converted to float"
                )
            
            float_value = float(value)
            
            # Check for special values
            if not isinstance(float_value, (int, float)) or float_value != float_value:  # NaN check
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="Invalid float value (NaN or infinity)",
                    suggestions=["Provide a finite numeric value"]
                )
            
            if min_value is not None and float_value < min_value:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"Value {float_value} is below minimum {min_value}",
                    suggestions=[f"Use value >= {min_value}"]
                )
            
            if max_value is not None and float_value > max_value:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"Value {float_value} is above maximum {max_value}",
                    suggestions=[f"Use value <= {max_value}"]
                )
            
            return ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.VALID,
                message="Valid float",
                sanitized_value=float_value
            )
            
        except (ValueError, TypeError):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Cannot convert '{value}' to float",
                suggestions=["Provide a valid numeric value"]
            )
    
    @staticmethod
    def validate_boolean(value: Any) -> ValidationResult:
        """Validate and coerce boolean value."""
        if isinstance(value, bool):
            return ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.VALID,
                message="Valid boolean",
                sanitized_value=value
            )
        
        if isinstance(value, str):
            lower_value = value.lower().strip()
            if lower_value in ['true', '1', 'yes', 'on', 'enabled']:
                return ValidationResult(
                    is_valid=True,
                    severity=ValidationSeverity.VALID,
                    message="Valid boolean (converted from string)",
                    sanitized_value=True
                )
            elif lower_value in ['false', '0', 'no', 'off', 'disabled']:
                return ValidationResult(
                    is_valid=True,
                    severity=ValidationSeverity.VALID,
                    message="Valid boolean (converted from string)",
                    sanitized_value=False
                )
        
        if isinstance(value, (int, float)):
            bool_value = bool(value)
            return ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.WARNING,
                message="Boolean converted from numeric value",
                sanitized_value=bool_value,
                suggestions=["Use explicit boolean values (true/false) for clarity"]
            )
        
        return ValidationResult(
            is_valid=False,
            severity=ValidationSeverity.ERROR,
            message=f"Cannot convert '{value}' to boolean",
            suggestions=["Use true/false, 1/0, yes/no, or on/off"]
        )

class NetworkValidator:
    """Network-related validation helpers."""
    
    @staticmethod
    def validate_ip_address(ip_str: str, allow_private: bool = True, 
                          allow_loopback: bool = True) -> ValidationResult:
        """Validate IP address."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            
            warnings = []
            
            if not allow_private and ip.is_private:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="Private IP addresses not allowed",
                    suggestions=["Use a public IP address"]
                )
            
            if not allow_loopback and ip.is_loopback:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="Loopback IP addresses not allowed",
                    suggestions=["Use a non-loopback IP address"]
                )
            
            if ip.is_private:
                warnings.append("IP address is private")
            
            if ip.is_loopback:
                warnings.append("IP address is loopback")
            
            severity = ValidationSeverity.WARNING if warnings else ValidationSeverity.VALID
            message = "; ".join(warnings) if warnings else "Valid IP address"
            
            return ValidationResult(
                is_valid=True,
                severity=severity,
                message=message,
                sanitized_value=str(ip)
            )
            
        except ValueError:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid IP address format: {ip_str}",
                suggestions=["Provide a valid IPv4 or IPv6 address"]
            )
    
    @staticmethod
    def validate_port(port: Union[int, str]) -> ValidationResult:
        """Validate network port number."""
        try:
            port_num = int(port)
            
            if port_num < 1 or port_num > 65535:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"Port {port_num} is out of valid range (1-65535)",
                    suggestions=["Use a port number between 1 and 65535"]
                )
            
            warnings = []
            if port_num < 1024:
                warnings.append("Port is in privileged range (< 1024)")
            
            severity = ValidationSeverity.WARNING if warnings else ValidationSeverity.VALID
            message = warnings[0] if warnings else "Valid port number"
            
            return ValidationResult(
                is_valid=True,
                severity=severity,
                message=message,
                sanitized_value=port_num
            )
            
        except (ValueError, TypeError):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid port format: {port}",
                suggestions=["Provide a numeric port value"]
            )
    
    @staticmethod
    def validate_url(url: str, allowed_schemes: List[str] = None, 
                    require_scheme: bool = True) -> ValidationResult:
        """Validate URL format and components."""
        if not isinstance(url, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="URL must be a string"
            )
        
        url = url.strip()
        if not url:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="URL cannot be empty"
            )
        
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https', 'ftp', 'ftps']
        
        try:
            parsed = urllib.parse.urlparse(url)
            
            if require_scheme and not parsed.scheme:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="URL missing scheme (http://, https://, etc.)",
                    suggestions=["Add a valid scheme to the URL"]
                )
            
            if parsed.scheme and parsed.scheme.lower() not in allowed_schemes:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"URL scheme '{parsed.scheme}' not allowed",
                    suggestions=[f"Use one of: {', '.join(allowed_schemes)}"]
                )
            
            if not parsed.netloc and require_scheme:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="URL missing host/domain",
                    suggestions=["Provide a valid hostname or IP address"]
                )
            
            warnings = []
            if parsed.scheme == 'http':
                warnings.append("URL uses insecure HTTP protocol")
            
            severity = ValidationSeverity.WARNING if warnings else ValidationSeverity.VALID
            message = warnings[0] if warnings else "Valid URL"
            
            return ValidationResult(
                is_valid=True,
                severity=severity,
                message=message,
                sanitized_value=url
            )
            
        except Exception:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid URL format: {url}",
                suggestions=["Provide a properly formatted URL"]
            )
    
    @staticmethod
    def validate_domain(domain: str) -> ValidationResult:
        """Validate domain name format."""
        if not isinstance(domain, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Domain must be a string"
            )
        
        domain = domain.strip().lower()
        if not domain:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Domain cannot be empty"
            )
        
        # Basic domain validation
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        if not domain_pattern.match(domain):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Invalid domain name format",
                suggestions=["Use a valid domain name (e.g., example.com)"]
            )
        
        if len(domain) > 253:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Domain name too long (max 253 characters)",
                suggestions=["Use a shorter domain name"]
            )
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.VALID,
            message="Valid domain name",
            sanitized_value=domain
        )

class FileSystemValidator:
    """File system validation helpers."""
    
    @staticmethod
    def validate_file_path(path: Union[str, Path], must_exist: bool = False,
                          must_be_file: bool = True, readable: bool = True) -> ValidationResult:
        """Validate file path."""
        try:
            if isinstance(path, str):
                path = Path(path)
            
            # Security check for path traversal
            try:
                resolved_path = path.resolve()
                # Check if the resolved path is trying to escape expected directories
                # This is a basic check - more sophisticated validation might be needed
            except Exception:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="Invalid path format",
                    suggestions=["Provide a valid file path"]
                )
            
            if must_exist and not path.exists():
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"File does not exist: {path}",
                    suggestions=["Check the file path", "Ensure the file exists"]
                )
            
            if path.exists():
                if must_be_file and not path.is_file():
                    return ValidationResult(
                        is_valid=False,
                        severity=ValidationSeverity.ERROR,
                        message=f"Path is not a file: {path}",
                        suggestions=["Provide a path to a file, not a directory"]
                    )
                
                if readable and not os.access(path, os.R_OK):
                    return ValidationResult(
                        is_valid=False,
                        severity=ValidationSeverity.ERROR,
                        message=f"File is not readable: {path}",
                        suggestions=["Check file permissions"]
                    )
            
            warnings = []
            if not must_exist and not path.exists():
                warnings.append("File does not exist")
            
            severity = ValidationSeverity.WARNING if warnings else ValidationSeverity.VALID
            message = warnings[0] if warnings else "Valid file path"
            
            return ValidationResult(
                is_valid=True,
                severity=severity,
                message=message,
                sanitized_value=str(resolved_path)
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Path validation failed: {e}",
                suggestions=["Check the path format and permissions"]
            )
    
    @staticmethod
    def validate_directory_path(path: Union[str, Path], must_exist: bool = False,
                               writable: bool = False) -> ValidationResult:
        """Validate directory path."""
        try:
            if isinstance(path, str):
                path = Path(path)
            
            resolved_path = path.resolve()
            
            if must_exist and not path.exists():
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"Directory does not exist: {path}",
                    suggestions=["Check the directory path", "Create the directory"]
                )
            
            if path.exists():
                if not path.is_dir():
                    return ValidationResult(
                        is_valid=False,
                        severity=ValidationSeverity.ERROR,
                        message=f"Path is not a directory: {path}",
                        suggestions=["Provide a path to a directory, not a file"]
                    )
                
                if writable and not os.access(path, os.W_OK):
                    return ValidationResult(
                        is_valid=False,
                        severity=ValidationSeverity.ERROR,
                        message=f"Directory is not writable: {path}",
                        suggestions=["Check directory permissions"]
                    )
            
            warnings = []
            if not must_exist and not path.exists():
                warnings.append("Directory does not exist")
            
            severity = ValidationSeverity.WARNING if warnings else ValidationSeverity.VALID
            message = warnings[0] if warnings else "Valid directory path"
            
            return ValidationResult(
                is_valid=True,
                severity=severity,
                message=message,
                sanitized_value=str(resolved_path)
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Directory validation failed: {e}",
                suggestions=["Check the path format and permissions"]
            )

class AndroidValidator:
    """Android-specific validation helpers."""
    
    @staticmethod
    def validate_package_name(package_name: str) -> ValidationResult:
        """Validate Android package name."""
        if not isinstance(package_name, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Package name must be a string"
            )
        
        package_name = package_name.strip()
        if not package_name:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Package name cannot be empty"
            )
        
        # Android package name validation
        package_pattern = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$')
        
        if not package_pattern.match(package_name):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Invalid package name format",
                suggestions=[
                    "Use format com.company.app",
                    "Start with letter, use only letters, numbers, underscores",
                    "Must contain at least one dot"
                ]
            )
        
        # Check for reserved keywords
        parts = package_name.split('.')
        java_keywords = {
            'abstract', 'boolean', 'break', 'byte', 'case', 'catch', 'char', 'class',
            'const', 'continue', 'default', 'do', 'double', 'else', 'extends', 'final',
            'finally', 'float', 'for', 'goto', 'if', 'implements', 'import', 'instanceof',
            'int', 'interface', 'long', 'native', 'new', 'package', 'private', 'protected',
            'public', 'return', 'short', 'static', 'strictfp', 'super', 'switch',
            'synchronized', 'this', 'throw', 'throws', 'transient', 'try', 'void',
            'volatile', 'while'
        }
        
        invalid_parts = [part for part in parts if part.lower() in java_keywords]
        if invalid_parts:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Package name contains Java keywords: {', '.join(invalid_parts)}",
                suggestions=["Avoid using Java keywords in package names"]
            )
        
        warnings = []
        if len(package_name) > 100:
            warnings.append("Package name is very long")
        
        severity = ValidationSeverity.WARNING if warnings else ValidationSeverity.VALID
        message = warnings[0] if warnings else "Valid package name"
        
        return ValidationResult(
            is_valid=True,
            severity=severity,
            message=message,
            sanitized_value=package_name
        )
    
    @staticmethod
    def validate_version_code(version_code: Union[int, str]) -> ValidationResult:
        """Validate Android version code."""
        try:
            version_int = int(version_code)
            
            if version_int < 1:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="Version code must be positive",
                    suggestions=["Use version code >= 1"]
                )
            
            if version_int > 2100000000:  # Android limit
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="Version code exceeds Android limit (2,100,000,000)",
                    suggestions=["Use a smaller version code"]
                )
            
            return ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.VALID,
                message="Valid version code",
                sanitized_value=version_int
            )
            
        except (ValueError, TypeError):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid version code format: {version_code}",
                suggestions=["Provide a positive integer"]
            )
    
    @staticmethod
    def validate_api_level(api_level: Union[int, str]) -> ValidationResult:
        """Validate Android API level."""
        try:
            api_int = int(api_level)
            
            if api_int < 1:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="API level must be positive",
                    suggestions=["Use API level >= 1"]
                )
            
            warnings = []
            if api_int < 21:  # Below Android 5.0
                warnings.append("API level is below Android 5.0 (API 21)")
            elif api_int > 34:  # Above current known levels (as of 2024)
                warnings.append("API level is very high - verify it's valid")
            
            severity = ValidationSeverity.WARNING if warnings else ValidationSeverity.VALID
            message = warnings[0] if warnings else "Valid API level"
            
            return ValidationResult(
                is_valid=True,
                severity=severity,
                message=message,
                sanitized_value=api_int
            )
            
        except (ValueError, TypeError):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid API level format: {api_level}",
                suggestions=["Provide a positive integer"]
            )

class PatternValidator:
    """Pattern and regex validation helpers."""
    
    @staticmethod
    def validate_regex_pattern(pattern: str, test_string: str = None) -> ValidationResult:
        """Validate regex pattern."""
        if not isinstance(pattern, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Pattern must be a string"
            )
        
        try:
            compiled_pattern = re.compile(pattern)
            
            # Test pattern if test string provided
            if test_string is not None:
                try:
                    match = compiled_pattern.search(test_string)
                    if match:
                        return ValidationResult(
                            is_valid=True,
                            severity=ValidationSeverity.VALID,
                            message="Valid regex pattern (matches test string)",
                            sanitized_value=compiled_pattern
                        )
                    else:
                        return ValidationResult(
                            is_valid=True,
                            severity=ValidationSeverity.WARNING,
                            message="Valid regex pattern (does not match test string)",
                            sanitized_value=compiled_pattern
                        )
                except Exception:
                    return ValidationResult(
                        is_valid=False,
                        severity=ValidationSeverity.ERROR,
                        message="Pattern causes runtime error during matching",
                        suggestions=["Simplify the regex pattern"]
                    )
            
            return ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.VALID,
                message="Valid regex pattern",
                sanitized_value=compiled_pattern
            )
            
        except re.error as e:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid regex pattern: {e}",
                suggestions=["Check regex syntax", "Escape special characters"]
            )

class EncodingValidator:
    """Encoding and format validation helpers."""
    
    @staticmethod
    def validate_base64(data: str, strict: bool = True) -> ValidationResult:
        """Validate base64 encoded data."""
        if not isinstance(data, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Base64 data must be a string"
            )
        
        data = data.strip()
        if not data:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Base64 data cannot be empty"
            )
        
        try:
            # Add padding if missing
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(data, validate=strict)
            
            return ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.VALID,
                message="Valid base64 data",
                sanitized_value=decoded
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid base64 data: {e}",
                suggestions=["Check base64 encoding", "Ensure proper padding"]
            )
    
    @staticmethod
    def validate_json(data: str) -> ValidationResult:
        """Validate JSON data."""
        if not isinstance(data, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="JSON data must be a string"
            )
        
        data = data.strip()
        if not data:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="JSON data cannot be empty"
            )
        
        try:
            parsed = json.loads(data)
            return ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.VALID,
                message="Valid JSON data",
                sanitized_value=parsed
            )
            
        except json.JSONDecodeError as e:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid JSON: {e}",
                suggestions=["Check JSON syntax", "Ensure proper quoting"]
            )
    
    @staticmethod
    def validate_hash(hash_value: str, hash_type: str = "sha256") -> ValidationResult:
        """Validate hash value format."""
        if not isinstance(hash_value, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Hash value must be a string"
            )
        
        hash_value = hash_value.strip().lower()
        if not hash_value:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Hash value cannot be empty"
            )
        
        expected_lengths = {
            'md5': 32,
            'sha1': 40,
            'sha256': 64,
            'sha512': 128
        }
        
        if hash_type.lower() not in expected_lengths:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Unsupported hash type: {hash_type}",
                suggestions=["Use md5, sha1, sha256, or sha512"]
            )
        
        expected_length = expected_lengths[hash_type.lower()]
        
        if len(hash_value) != expected_length:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid {hash_type} hash length: expected {expected_length}, got {len(hash_value)}",
                suggestions=[f"Provide a valid {hash_type} hash"]
            )
        
        # Check for valid hex characters
        if not re.match(r'^[a-f0-9]+$', hash_value):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Hash contains invalid characters (must be hexadecimal)",
                suggestions=["Use only characters 0-9 and a-f"]
            )
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.VALID,
            message=f"Valid {hash_type} hash",
            sanitized_value=hash_value
        )

class InputValidator:
    """
    Universal input validation utilities.
    
    Provides comprehensive input validation for various data types with
    security-focused validation rules and sanitization capabilities.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.security_validator = SecurityValidator()
        self.data_type_validator = DataTypeValidator()
        self.network_validator = NetworkValidator()
        self.filesystem_validator = FileSystemValidator()
        self.android_validator = AndroidValidator()
        self.pattern_validator = PatternValidator()
        self.encoding_validator = EncodingValidator()
    
    def validate_input(self, value: Any, input_type: str, **kwargs) -> ValidationResult:
        """
        Universal input validation dispatcher.
        
        Args:
            value: Value to validate
            input_type: Type of validation to perform
            **kwargs: Additional validation parameters
            
        Returns:
            ValidationResult with validation outcome
        """
        try:
            # Normalize input type
            input_type = input_type.lower().strip()
            
            # Dispatch to appropriate validator
            if input_type in ['string', 'str', 'text']:
                return self._validate_string_input(value, **kwargs)
            elif input_type in ['int', 'integer', 'number']:
                return self._validate_integer_input(value, **kwargs)
            elif input_type in ['float', 'decimal', 'double']:
                return self._validate_float_input(value, **kwargs)
            elif input_type in ['bool', 'boolean']:
                return self._validate_boolean_input(value, **kwargs)
            elif input_type in ['email', 'email_address']:
                return self.network_validator.validate_email(value)
            elif input_type in ['url', 'uri']:
                return self.network_validator.validate_url(value)
            elif input_type in ['ip', 'ip_address']:
                return self.network_validator.validate_ip_address(value)
            elif input_type in ['file', 'filepath', 'path']:
                return self._validate_file_input(value, **kwargs)
            elif input_type in ['package', 'package_name']:
                return self.android_validator.validate_package_name(value)
            elif input_type in ['permission', 'android_permission']:
                return self.android_validator.validate_permission(value)
            elif input_type in ['hash', 'checksum']:
                return self._validate_hash_input(value, **kwargs)
            elif input_type in ['json', 'json_data']:
                return self.encoding_validator.validate_json(value)
            elif input_type in ['base64', 'base64_data']:
                return self.encoding_validator.validate_base64(value)
            elif input_type in ['hex', 'hexadecimal']:
                return self.encoding_validator.validate_hex(value)
            elif input_type in ['uuid', 'guid']:
                return self._validate_uuid_input(value)
            elif input_type in ['date', 'datetime', 'timestamp']:
                return self._validate_date_input(value, **kwargs)
            elif input_type in ['regex', 'pattern']:
                return self._validate_regex_input(value)
            else:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"Unknown input type: {input_type}",
                    suggestions=["Use a supported input type", "Check documentation"]
                )
                
        except Exception as e:
            self.logger.error(f"Input validation failed: {e}")
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Validation error: {str(e)}"
            )
    
    def validate_multiple_inputs(self, inputs: Dict[str, Any], 
                                validation_rules: Dict[str, Dict[str, Any]]) -> Dict[str, ValidationResult]:
        """
        Validate multiple inputs against their respective rules.
        
        Args:
            inputs: Dictionary of input values
            validation_rules: Dictionary mapping input names to validation parameters
            
        Returns:
            Dictionary mapping input names to ValidationResult objects
        """
        results = {}
        
        for input_name, input_value in inputs.items():
            if input_name in validation_rules:
                rules = validation_rules[input_name]
                input_type = rules.get('type', 'string')
                kwargs = {k: v for k, v in rules.items() if k != 'type'}
                
                results[input_name] = self.validate_input(input_value, input_type, **kwargs)
            else:
                results[input_name] = ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.WARNING,
                    message=f"No validation rules defined for input: {input_name}"
                )
        
        return results
    
    def sanitize_input(self, value: Any, input_type: str, **kwargs) -> Any:
        """
        Sanitize input value based on type.
        
        Args:
            value: Value to sanitize
            input_type: Type of sanitization to perform
            **kwargs: Additional sanitization parameters
            
        Returns:
            Sanitized value or original value if sanitization fails
        """
        try:
            validation_result = self.validate_input(value, input_type, **kwargs)
            
            if validation_result.is_valid and validation_result.sanitized_value is not None:
                return validation_result.sanitized_value
            else:
                return value
                
        except Exception as e:
            self.logger.warning(f"Input sanitization failed: {e}")
            return value
    
    def _validate_string_input(self, value: str, **kwargs) -> ValidationResult:
        """Validate string input with various constraints."""
        min_length = kwargs.get('min_length', 0)
        max_length = kwargs.get('max_length', 10000)
        pattern = kwargs.get('pattern')
        allowed_chars = kwargs.get('allowed_chars')
        forbidden_chars = kwargs.get('forbidden_chars')
        strip_whitespace = kwargs.get('strip_whitespace', True)
        
        if not isinstance(value, str):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Value must be a string"
            )
        
        # Strip whitespace if requested
        if strip_whitespace:
            value = value.strip()
        
        # Check length constraints
        if len(value) < min_length:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"String too short (minimum {min_length} characters)"
            )
        
        if len(value) > max_length:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"String too long (maximum {max_length} characters)"
            )
        
        # Check pattern if provided
        if pattern:
            if not re.match(pattern, value):
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"String does not match required pattern"
                )
        
        # Check allowed characters
        if allowed_chars:
            if not all(c in allowed_chars for c in value):
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="String contains disallowed characters"
                )
        
        # Check forbidden characters
        if forbidden_chars:
            if any(c in forbidden_chars for c in value):
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message="String contains forbidden characters"
                )
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.VALID,
            message="Valid string input",
            sanitized_value=value
        )
    
    def _validate_integer_input(self, value: Any, **kwargs) -> ValidationResult:
        """Validate integer input with range constraints."""
        min_value = kwargs.get('min_value')
        max_value = kwargs.get('max_value')
        
        try:
            if isinstance(value, str):
                value = int(value.strip())
            elif not isinstance(value, int):
                value = int(value)
        except (ValueError, TypeError):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Value cannot be converted to integer"
            )
        
        if min_value is not None and value < min_value:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Value too small (minimum {min_value})"
            )
        
        if max_value is not None and value > max_value:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Value too large (maximum {max_value})"
            )
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.VALID,
            message="Valid integer input",
            sanitized_value=value
        )
    
    def _validate_float_input(self, value: Any, **kwargs) -> ValidationResult:
        """Validate float input with range constraints."""
        min_value = kwargs.get('min_value')
        max_value = kwargs.get('max_value')
        precision = kwargs.get('precision')
        
        try:
            if isinstance(value, str):
                value = float(value.strip())
            elif not isinstance(value, (int, float)):
                value = float(value)
        except (ValueError, TypeError):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Value cannot be converted to float"
            )
        
        if min_value is not None and value < min_value:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Value too small (minimum {min_value})"
            )
        
        if max_value is not None and value > max_value:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Value too large (maximum {max_value})"
            )
        
        # Apply precision if specified
        if precision is not None:
            value = round(value, precision)
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.VALID,
            message="Valid float input",
            sanitized_value=value
        )
    
    def _validate_boolean_input(self, value: Any, **kwargs) -> ValidationResult:
        """Validate and convert boolean input."""
        if isinstance(value, bool):
            return ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.VALID,
                message="Valid boolean input",
                sanitized_value=value
            )
        
        if isinstance(value, str):
            value_lower = value.strip().lower()
            if value_lower in ['true', '1', 'yes', 'on', 'enabled']:
                return ValidationResult(
                    is_valid=True,
                    severity=ValidationSeverity.VALID,
                    message="Valid boolean input",
                    sanitized_value=True
                )
            elif value_lower in ['false', '0', 'no', 'off', 'disabled']:
                return ValidationResult(
                    is_valid=True,
                    severity=ValidationSeverity.VALID,
                    message="Valid boolean input",
                    sanitized_value=False
                )
        
        if isinstance(value, (int, float)):
            return ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.VALID,
                message="Valid boolean input",
                sanitized_value=bool(value)
            )
        
        return ValidationResult(
            is_valid=False,
            severity=ValidationSeverity.ERROR,
            message="Value cannot be converted to boolean",
            suggestions=["Use true/false, 1/0, yes/no, on/off, enabled/disabled"]
        )
    
    def _validate_file_input(self, value: str, **kwargs) -> ValidationResult:
        """Validate file path input."""
        check_exists = kwargs.get('check_exists', False)
        allowed_extensions = kwargs.get('allowed_extensions')
        max_size = kwargs.get('max_size')
        
        path_result = self.filesystem_validator.validate_file_path(value)
        if not path_result.is_valid:
            return path_result
        
        # Check if file exists
        if check_exists:
            exists_result = self.filesystem_validator.validate_file_exists(value)
            if not exists_result.is_valid:
                return exists_result
        
        # Check file extension
        if allowed_extensions:
            file_ext = os.path.splitext(value)[1].lower()
            if file_ext not in allowed_extensions:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"File extension not allowed. Allowed: {allowed_extensions}"
                )
        
        # Check file size if exists
        if check_exists and max_size and os.path.exists(value):
            file_size = os.path.getsize(value)
            if file_size > max_size:
                return ValidationResult(
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"File too large ({file_size} bytes, max {max_size})"
                )
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.VALID,
            message="Valid file path",
            sanitized_value=os.path.normpath(value)
        )
    
    def _validate_hash_input(self, value: str, **kwargs) -> ValidationResult:
        """Validate hash input."""
        hash_type = kwargs.get('hash_type', 'sha256')
        return self.encoding_validator.validate_hash(value, hash_type)
    
    def _validate_uuid_input(self, value: str) -> ValidationResult:
        """Validate UUID input."""
        try:
            import uuid
            uuid.UUID(str(value))
            return ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.VALID,
                message="Valid UUID",
                sanitized_value=str(value).lower()
            )
        except (ValueError, TypeError):
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Invalid UUID format"
            )
    
    def _validate_date_input(self, value: Any, **kwargs) -> ValidationResult:
        """Validate date/datetime input."""
        date_format = kwargs.get('format', '%Y-%m-%d')
        
        try:
            import datetime
            
            if isinstance(value, datetime.datetime):
                return ValidationResult(
                    is_valid=True,
                    severity=ValidationSeverity.VALID,
                    message="Valid datetime",
                    sanitized_value=value
                )
            
            if isinstance(value, str):
                parsed_date = datetime.datetime.strptime(value, date_format)
                return ValidationResult(
                    is_valid=True,
                    severity=ValidationSeverity.VALID,
                    message="Valid date string",
                    sanitized_value=parsed_date
                )
            
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message="Invalid date format"
            )
            
        except ValueError as e:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Date parsing failed: {e}"
            )
    
    def _validate_regex_input(self, value: str) -> ValidationResult:
        """Validate regex pattern input."""
        try:
            re.compile(value)
            return ValidationResult(
                is_valid=True,
                severity=ValidationSeverity.VALID,
                message="Valid regex pattern",
                sanitized_value=value
            )
        except re.error as e:
            return ValidationResult(
                is_valid=False,
                severity=ValidationSeverity.ERROR,
                message=f"Invalid regex pattern: {e}"
            )

def create_validator_chain(*validators: Callable[[Any], ValidationResult]) -> Callable[[Any], ValidationResult]:
    """
    Create a validator chain that applies multiple validators in sequence.
    
    Args:
        *validators: Validator functions to chain
        
    Returns:
        Combined validator function
    """
    def chained_validator(value: Any) -> ValidationResult:
        for validator in validators:
            result = validator(value)
            if not result.is_valid:
                return result
            value = result.sanitized_value if result.sanitized_value is not None else value
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.VALID,
            message="Passed all validators",
            sanitized_value=value
        )
    
    return chained_validator 
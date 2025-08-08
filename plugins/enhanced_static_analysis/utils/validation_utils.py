"""
Validation utilities for enhanced static analysis results.

Provides comprehensive validation for all data structures used in
enhanced static analysis to ensure data integrity and consistency.
"""

import logging
from typing import Any, Dict, List, Tuple, Union

logger = logging.getLogger(__name__)

def validate_analysis_results(results: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate complete analysis results structure.
    
    Args:
        results: Analysis results to validate
        
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_errors)
    """
    errors = []
    
    if not isinstance(results, dict):
        errors.append("Results must be a dictionary")
        return False, errors
    
    # Check required sections
    required_sections = [
        "secret_analysis",
        "security_findings", 
        "manifest_analysis",
        "code_quality_metrics",
        "risk_assessment"
    ]
    
    for section in required_sections:
        if section not in results:
            errors.append(f"Missing required section: {section}")
    
    # Validate individual sections
    if "secret_analysis" in results:
        is_valid, section_errors = validate_secret_data(results["secret_analysis"])
        if not is_valid:
            errors.extend([f"Secret analysis: {err}" for err in section_errors])
    
    if "security_findings" in results:
        is_valid, section_errors = validate_security_findings(results["security_findings"])
        if not is_valid:
            errors.extend([f"Security findings: {err}" for err in section_errors])
    
    if "manifest_analysis" in results:
        is_valid, section_errors = validate_manifest_data(results["manifest_analysis"])
        if not is_valid:
            errors.extend([f"Manifest analysis: {err}" for err in section_errors])
    
    if "code_quality_metrics" in results:
        is_valid, section_errors = validate_quality_metrics(results["code_quality_metrics"])
        if not is_valid:
            errors.extend([f"Code quality: {err}" for err in section_errors])
    
    # Validate risk assessment
    if "risk_assessment" in results:
        is_valid, section_errors = validate_risk_assessment(results["risk_assessment"])
        if not is_valid:
            errors.extend([f"Risk assessment: {err}" for err in section_errors])
    
    return len(errors) == 0, errors

def validate_secret_data(secret_data: List[Any]) -> Tuple[bool, List[str]]:
    """
    Validate secret analysis data structure.
    
    Args:
        secret_data: Secret analysis data to validate
        
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_errors)
    """
    errors = []
    
    if not isinstance(secret_data, list):
        errors.append("Secret data must be a list")
        return False, errors
    
    for i, secret in enumerate(secret_data):
        # Check required attributes
        required_attrs = ["pattern_type", "value", "confidence", "entropy", "file_path"]
        
        for attr in required_attrs:
            if not hasattr(secret, attr):
                errors.append(f"Secret {i}: Missing required attribute '{attr}'")
        
        # Validate confidence range
        if hasattr(secret, "confidence"):
            confidence = getattr(secret, "confidence", 0.0)
            if not isinstance(confidence, (int, float)) or confidence < 0 or confidence > 1:
                errors.append(f"Secret {i}: Invalid confidence value: {confidence}")
        
        # Validate entropy
        if hasattr(secret, "entropy"):
            entropy = getattr(secret, "entropy", 0.0)
            if not isinstance(entropy, (int, float)) or entropy < 0:
                errors.append(f"Secret {i}: Invalid entropy value: {entropy}")
        
        # Validate pattern type
        if hasattr(secret, "pattern_type"):
            pattern_type = getattr(secret, "pattern_type", "")
            if not isinstance(pattern_type, str) or not pattern_type:
                errors.append(f"Secret {i}: Invalid pattern type: {pattern_type}")
        
        # Validate file path
        if hasattr(secret, "file_path"):
            file_path = getattr(secret, "file_path", "")
            if not isinstance(file_path, str):
                errors.append(f"Secret {i}: Invalid file path type: {type(file_path)}")
    
    return len(errors) == 0, errors

def validate_security_findings(findings_data: List[Any]) -> Tuple[bool, List[str]]:
    """
    Validate security findings data structure.
    
    Args:
        findings_data: Security findings data to validate
        
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_errors)
    """
    errors = []
    
    if not isinstance(findings_data, list):
        errors.append("Security findings must be a list")
        return False, errors
    
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    
    for i, finding in enumerate(findings_data):
        # Check required attributes
        required_attrs = ["title", "severity", "confidence", "category", "file_path"]
        
        for attr in required_attrs:
            if not hasattr(finding, attr):
                errors.append(f"Finding {i}: Missing required attribute '{attr}'")
        
        # Validate severity
        if hasattr(finding, "severity"):
            severity = getattr(finding, "severity", "")
            if severity not in valid_severities:
                errors.append(f"Finding {i}: Invalid severity: {severity}")
        
        # Validate confidence
        if hasattr(finding, "confidence"):
            confidence = getattr(finding, "confidence", 0.0)
            if not isinstance(confidence, (int, float)) or confidence < 0 or confidence > 1:
                errors.append(f"Finding {i}: Invalid confidence value: {confidence}")
        
        # Validate title
        if hasattr(finding, "title"):
            title = getattr(finding, "title", "")
            if not isinstance(title, str) or not title:
                errors.append(f"Finding {i}: Invalid title: {title}")
        
        # Validate category
        if hasattr(finding, "category"):
            category = getattr(finding, "category", "")
            if not isinstance(category, str) or not category:
                errors.append(f"Finding {i}: Invalid category: {category}")
    
    return len(errors) == 0, errors

def validate_manifest_data(manifest_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate manifest analysis data structure.
    
    Args:
        manifest_data: Manifest analysis data to validate
        
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_errors)
    """
    errors = []
    
    if not isinstance(manifest_data, dict):
        errors.append("Manifest data must be a dictionary")
        return False, errors
    
    # Check for error condition
    if "error" in manifest_data:
        return True, []  # Error condition is valid
    
    # Check expected sections
    expected_sections = ["security_features", "permissions", "activities", "services", "receivers", "providers"]
    
    # Validate security features
    if "security_features" in manifest_data:
        security_features = manifest_data["security_features"]
        if not isinstance(security_features, dict):
            errors.append("Security features must be a dictionary")
    
    # Validate permissions
    if "permissions" in manifest_data:
        permissions = manifest_data["permissions"]
        if not isinstance(permissions, list):
            errors.append("Permissions must be a list")
        else:
            for i, perm in enumerate(permissions):
                if not isinstance(perm, dict):
                    errors.append(f"Permission {i}: Must be a dictionary")
                elif "name" not in perm:
                    errors.append(f"Permission {i}: Missing 'name' field")
    
    # Validate components
    component_types = ["activities", "services", "receivers", "providers"]
    for comp_type in component_types:
        if comp_type in manifest_data:
            components = manifest_data[comp_type]
            if not isinstance(components, list):
                errors.append(f"{comp_type} must be a list")
            else:
                for i, comp in enumerate(components):
                    if not isinstance(comp, dict):
                        errors.append(f"{comp_type} {i}: Must be a dictionary")
                    elif "name" not in comp:
                        errors.append(f"{comp_type} {i}: Missing 'name' field")
    
    return len(errors) == 0, errors

def validate_quality_metrics(quality_data: Union[Dict[str, Any], Any]) -> Tuple[bool, List[str]]:
    """
    Validate code quality metrics data structure.
    
    Args:
        quality_data: Code quality metrics data to validate (dict or CodeQualityMetrics object)
        
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_errors)
    """
    errors = []
    
    # Handle both CodeQualityMetrics objects and dictionaries
    if hasattr(quality_data, '__dict__'):
        # Convert object to dictionary for validation
        if hasattr(quality_data, 'to_dict'):
            quality_dict = quality_data.to_dict()
        else:
            quality_dict = vars(quality_data)
    elif isinstance(quality_data, dict):
        quality_dict = quality_data
    else:
        errors.append("Quality metrics must be a dictionary or CodeQualityMetrics object")
        return False, errors
    
    # Check for error condition
    if "error" in quality_dict:
        return True, []  # Error condition is valid
    
    # Validate basic metrics
    numeric_fields = ["total_files", "code_files", "obfuscation_level"]
    
    for field in numeric_fields:
        if field in quality_dict:
            value = quality_dict[field]
            if not isinstance(value, (int, float)):
                errors.append(f"Field '{field}' must be numeric, got {type(value)}")
            elif field == "obfuscation_level" and (value < 0 or value > 1):
                errors.append(f"Obfuscation level must be between 0 and 1, got {value}")
            elif field in ["total_files", "code_files"] and value < 0:
                errors.append(f"Field '{field}' must be non-negative, got {value}")
    
    return len(errors) == 0, errors

def validate_risk_assessment(risk_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate risk assessment data structure.
    
    Args:
        risk_data: Risk assessment data to validate
        
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_errors)
    """
    errors = []
    
    if not isinstance(risk_data, dict):
        errors.append("Risk assessment must be a dictionary")
        return False, errors
    
    # Validate risk level
    if "overall_risk" in risk_data:
        risk_level = risk_data["overall_risk"]
        valid_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"}
        if risk_level not in valid_levels:
            errors.append(f"Invalid risk level: {risk_level}")
    
    # Validate risk score
    if "risk_score" in risk_data:
        risk_score = risk_data["risk_score"]
        if not isinstance(risk_score, (int, float)) or risk_score < 0 or risk_score > 1:
            errors.append(f"Risk score must be between 0 and 1, got {risk_score}")
    
    # Validate issue counts
    count_fields = ["critical_issues", "high_issues", "medium_issues", "low_issues", "total_issues"]
    
    for field in count_fields:
        if field in risk_data:
            value = risk_data[field]
            if not isinstance(value, int) or value < 0:
                errors.append(f"Field '{field}' must be non-negative integer, got {value}")
    
    return len(errors) == 0, errors

def validate_confidence_value(confidence: Any) -> bool:
    """
    Validate confidence value.
    
    Args:
        confidence: Confidence value to validate
        
    Returns:
        bool: True if valid confidence value
    """
    if not isinstance(confidence, (int, float)):
        return False
    
    return 0.0 <= confidence <= 1.0

def validate_severity_level(severity: str) -> bool:
    """
    Validate severity level.
    
    Args:
        severity: Severity level to validate
        
    Returns:
        bool: True if valid severity level
    """
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    return severity in valid_severities

def validate_file_path(file_path: str) -> bool:
    """
    Validate file path format.
    
    Args:
        file_path: File path to validate
        
    Returns:
        bool: True if valid file path
    """
    if not isinstance(file_path, str):
        return False
    
    if not file_path:
        return False
    
    # Check for invalid characters (basic validation)
    invalid_chars = ['<', '>', ':', '"', '|', '?', '*']
    for char in invalid_chars:
        if char in file_path:
            return False
    
    return True

def validate_package_name(package_name: str) -> bool:
    """
    Validate Android package name format.
    
    Args:
        package_name: Package name to validate
        
    Returns:
        bool: True if valid package name
    """
    if not isinstance(package_name, str) or not package_name:
        return False
    
    # Basic Android package name validation
    import re
    pattern = r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'
    return re.match(pattern, package_name) is not None

def validate_entropy_value(entropy: Any) -> bool:
    """
    Validate entropy value.
    
    Args:
        entropy: Entropy value to validate
        
    Returns:
        bool: True if valid entropy value
    """
    if not isinstance(entropy, (int, float)):
        return False
    
    return entropy >= 0.0

def sanitize_analysis_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize analysis results by removing/fixing invalid data.
    
    Args:
        results: Analysis results to sanitize
        
    Returns:
        Dict[str, Any]: Sanitized results
    """
    sanitized = {}
    
    # Copy valid sections
    valid_sections = [
        "secret_analysis",
        "security_findings",
        "manifest_analysis", 
        "code_quality_metrics",
        "risk_assessment",
        "analysis_metadata"
    ]
    
    for section in valid_sections:
        if section in results:
            sanitized[section] = results[section]
    
    # Sanitize secret analysis
    if "secret_analysis" in sanitized:
        sanitized["secret_analysis"] = sanitize_secret_data(sanitized["secret_analysis"])
    
    # Sanitize security findings
    if "security_findings" in sanitized:
        sanitized["security_findings"] = sanitize_security_findings(sanitized["security_findings"])
    
    # Sanitize risk assessment
    if "risk_assessment" in sanitized:
        sanitized["risk_assessment"] = sanitize_risk_assessment(sanitized["risk_assessment"])
    
    return sanitized

def sanitize_secret_data(secret_data: List[Any]) -> List[Any]:
    """
    Sanitize secret analysis data.
    
    Args:
        secret_data: Secret data to sanitize
        
    Returns:
        List[Any]: Sanitized secret data
    """
    if not isinstance(secret_data, list):
        return []
    
    sanitized = []
    
    for secret in secret_data:
        # Ensure confidence is valid
        if hasattr(secret, "confidence"):
            confidence = getattr(secret, "confidence", 0.0)
            if not validate_confidence_value(confidence):
                secret.confidence = 0.0
        
        # Ensure entropy is valid
        if hasattr(secret, "entropy"):
            entropy = getattr(secret, "entropy", 0.0)
            if not validate_entropy_value(entropy):
                secret.entropy = 0.0
        
        # Ensure pattern type is string
        if hasattr(secret, "pattern_type"):
            pattern_type = getattr(secret, "pattern_type", "")
            if not isinstance(pattern_type, str):
                secret.pattern_type = "unknown"
        
        sanitized.append(secret)
    
    return sanitized

def sanitize_security_findings(findings_data: List[Any]) -> List[Any]:
    """
    Sanitize security findings data.
    
    Args:
        findings_data: Security findings to sanitize
        
    Returns:
        List[Any]: Sanitized security findings
    """
    if not isinstance(findings_data, list):
        return []
    
    sanitized = []
    
    for finding in findings_data:
        # Ensure severity is valid
        if hasattr(finding, "severity"):
            severity = getattr(finding, "severity", "LOW")
            if not validate_severity_level(severity):
                finding.severity = "LOW"
        
        # Ensure confidence is valid
        if hasattr(finding, "confidence"):
            confidence = getattr(finding, "confidence", 0.0)
            if not validate_confidence_value(confidence):
                finding.confidence = 0.0
        
        # Ensure title is string
        if hasattr(finding, "title"):
            title = getattr(finding, "title", "")
            if not isinstance(title, str):
                finding.title = "Unknown Issue"
        
        sanitized.append(finding)
    
    return sanitized

def sanitize_risk_assessment(risk_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize risk assessment data.
    
    Args:
        risk_data: Risk assessment data to sanitize
        
    Returns:
        Dict[str, Any]: Sanitized risk assessment
    """
    if not isinstance(risk_data, dict):
        return {}
    
    sanitized = dict(risk_data)
    
    # Ensure risk level is valid
    if "overall_risk" in sanitized:
        risk_level = sanitized["overall_risk"]
        valid_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"}
        if risk_level not in valid_levels:
            sanitized["overall_risk"] = "UNKNOWN"
    
    # Ensure risk score is valid
    if "risk_score" in sanitized:
        risk_score = sanitized["risk_score"]
        if not isinstance(risk_score, (int, float)) or risk_score < 0 or risk_score > 1:
            sanitized["risk_score"] = 0.0
    
    # Ensure issue counts are valid
    count_fields = ["critical_issues", "high_issues", "medium_issues", "low_issues", "total_issues"]
    
    for field in count_fields:
        if field in sanitized:
            value = sanitized[field]
            if not isinstance(value, int) or value < 0:
                sanitized[field] = 0
    
    return sanitized 
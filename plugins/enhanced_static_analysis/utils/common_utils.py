"""
Common Utilities for Enhanced Static Analysis

This module provides common utility functions used across the enhanced static analysis plugin.
"""

import logging
import math
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        str: Formatted size (e.g., "1.5 MB")
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    
    return f"{s} {size_names[i]}"

def format_duration(seconds: float) -> str:
    """
    Format duration in human-readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        str: Formatted duration (e.g., "2m 30s")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        remaining_seconds = int(seconds % 60)
        return f"{minutes}m {remaining_seconds}s"
    else:
        hours = int(seconds // 3600)
        remaining_minutes = int((seconds % 3600) // 60)
        return f"{hours}h {remaining_minutes}m"

def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate text to specified length with suffix.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncating
        
    Returns:
        str: Truncated text
    """
    if not text:
        return ""
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

def sanitize_path(path: str) -> str:
    """
    Sanitize file path for safe display.
    
    Args:
        path: File path to sanitize
        
    Returns:
        str: Sanitized path
    """
    if not path:
        return "Unknown"
    
    # Remove common prefixes
    path = path.replace("\\", "/")
    
    # Remove absolute path prefixes
    if path.startswith("/"):
        path = path[1:]
    
    # Limit path length
    if len(path) > 60:
        parts = path.split("/")
        if len(parts) > 2:
            path = f"{parts[0]}/.../{parts[-1]}"
        else:
            path = truncate_text(path, 60)
    
    return path

def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Args:
        data: String to calculate entropy for
        
    Returns:
        float: Entropy value
    """
    if not data:
        return 0.0
    
    # Count character frequencies
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    data_length = len(data)
    
    for count in char_counts.values():
        probability = count / data_length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def normalize_confidence(confidence: float) -> float:
    """
    Normalize confidence value to 0-1 range.
    
    Args:
        confidence: Confidence value
        
    Returns:
        float: Normalized confidence (0.0 to 1.0)
    """
    if confidence < 0.0:
        return 0.0
    elif confidence > 1.0:
        return 1.0
    else:
        return confidence

def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from URL.
    
    Args:
        url: URL string
        
    Returns:
        Optional[str]: Domain name or None if invalid
    """
    if not url:
        return None
    
    # Simple domain extraction
    domain_pattern = r'(?:https?://)?(?:www\.)?([^/]+)'
    match = re.match(domain_pattern, url)
    
    if match:
        return match.group(1)
    
    return None

def is_valid_package_name(package_name: str) -> bool:
    """
    Check if package name is valid Android package name.
    
    Args:
        package_name: Package name to validate
        
    Returns:
        bool: True if valid package name
    """
    if not package_name:
        return False
    
    # Basic Android package name validation
    package_pattern = r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'
    return re.match(package_pattern, package_name) is not None

def clean_java_class_name(class_name: str) -> str:
    """
    Clean Java class name for display.
    
    Args:
        class_name: Full Java class name
        
    Returns:
        str: Cleaned class name
    """
    if not class_name:
        return "Unknown"
    
    # Remove package prefix, keep only class name
    if "." in class_name:
        parts = class_name.split(".")
        return parts[-1]
    
    return class_name

def format_confidence_percentage(confidence: float) -> str:
    """
    Format confidence as percentage with appropriate precision.
    
    Args:
        confidence: Confidence value (0.0 to 1.0)
        
    Returns:
        str: Formatted percentage
    """
    if confidence == 0.0:
        return "0%"
    elif confidence == 1.0:
        return "100%"
    elif confidence < 0.01:
        return "<1%"
    elif confidence >= 0.995:
        return ">99%"
    else:
        return f"{confidence:.1%}"

def get_severity_weight(severity: str) -> int:
    """
    Get numeric weight for severity level.
    
    Args:
        severity: Severity level string
        
    Returns:
        int: Numeric weight for sorting
    """
    weights = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1
    }
    
    return weights.get(severity.upper(), 0)

def mask_sensitive_data(data: str, mask_char: str = "*", show_chars: int = 3) -> str:
    """
    Mask sensitive data for safe display.
    
    Args:
        data: Sensitive data to mask
        mask_char: Character to use for masking
        show_chars: Number of characters to show at start/end
        
    Returns:
        str: Masked data
    """
    if not data:
        return ""
    
    data_length = len(data)
    
    if data_length <= show_chars * 2:
        return mask_char * data_length
    
    start = data[:show_chars]
    end = data[-show_chars:]
    middle_length = data_length - (show_chars * 2)
    
    return f"{start}{mask_char * min(middle_length, 10)}{end}"

def categorize_file_type(file_path: str) -> str:
    """
    Categorize file type based on extension.
    
    Args:
        file_path: File path
        
    Returns:
        str: File type category
    """
    if not file_path:
        return "UNKNOWN"
    
    extension = file_path.lower().split(".")[-1] if "." in file_path else ""
    
    categories = {
        "java": "CODE",
        "kt": "CODE",
        "xml": "CONFIG",
        "json": "CONFIG",
        "properties": "CONFIG",
        "yaml": "CONFIG",
        "yml": "CONFIG",
        "png": "RESOURCE",
        "jpg": "RESOURCE",
        "jpeg": "RESOURCE",
        "gif": "RESOURCE",
        "svg": "RESOURCE",
        "so": "NATIVE",
        "jar": "LIBRARY",
        "aar": "LIBRARY",
        "dex": "BYTECODE",
        "apk": "PACKAGE"
    }
    
    return categories.get(extension, "OTHER")

def validate_hex_string(hex_string: str) -> bool:
    """
    Validate if string is valid hexadecimal.
    
    Args:
        hex_string: String to validate
        
    Returns:
        bool: True if valid hex string
    """
    if not hex_string:
        return False
    
    try:
        int(hex_string, 16)
        return True
    except ValueError:
        return False

def calculate_risk_score(critical: int, high: int, medium: int, low: int) -> float:
    """
    Calculate overall risk score based on issue counts.
    
    Args:
        critical: Number of critical issues
        high: Number of high issues
        medium: Number of medium issues
        low: Number of low issues
        
    Returns:
        float: Risk score (0.0 to 1.0)
    """
    # Weighted scoring
    score = (
        critical * 0.4 +
        high * 0.3 +
        medium * 0.2 +
        low * 0.1
    )
    
    # Normalize to 0-1 range (assuming max 10 issues per category)
    max_possible = 10 * (0.4 + 0.3 + 0.2 + 0.1)
    normalized_score = min(1.0, score / max_possible)
    
    return normalized_score

def safe_get_attribute(obj: Any, attr_name: str, default: Any = None) -> Any:
    """
    Safely get attribute from object.
    
    Args:
        obj: Object to get attribute from
        attr_name: Attribute name
        default: Default value if attribute doesn't exist
        
    Returns:
        Any: Attribute value or default
    """
    try:
        return getattr(obj, attr_name, default)
    except (AttributeError, TypeError):
        return default

def is_obfuscated_name(name: str) -> bool:
    """
    Check if name appears to be obfuscated.
    
    Args:
        name: Name to check
        
    Returns:
        bool: True if name appears obfuscated
    """
    if not name:
        return False
    
    # Check for common obfuscation patterns
    if len(name) == 1:  # Single character names
        return True
    
    if re.match(r'^[a-z]{1,3}$', name):  # Very short lowercase names
        return True
    
    if re.match(r'^[A-Z]{1,3}$', name):  # Very short uppercase names
        return True
    
    # Check for random-looking character combinations
    if len(name) <= 4 and not re.match(r'^[a-zA-Z]+$', name):
        return True
    
    return False 
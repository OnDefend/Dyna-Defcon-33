#!/usr/bin/env python3
"""
Pattern Engine Data Models

Hardened data models with validation using Pydantic for the modular pattern engine.
Replaces basic dataclasses with validated, type-safe models.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field, field_validator
import re

class SeverityLevel(str, Enum):
    """Enumeration of vulnerability severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class PatternType(str, Enum):
    """Enumeration of vulnerability pattern types."""
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    CODE_INJECTION = "code_injection"
    HARDCODED_SECRETS = "hardcoded_secrets"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    INSECURE_DATA_STORAGE = "insecure_data_storage"
    INSECURE_COMMUNICATION = "insecure_communication"
    IMPROPER_PLATFORM_USAGE = "improper_platform_usage"
    WEBVIEW_SECURITY = "webview_security"
    INFORMATION_DISCLOSURE = "information_disclosure"
    XSS = "xss"
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"
    DATA_LEAKAGE = "data_leakage"
    TAINT_ANALYSIS = "taint_analysis"
    ANTI_ANALYSIS = "anti_analysis"
    REFLECTION_ABUSE = "reflection_abuse"
    NOVEL_ATTACK = "novel_attack"
    ATTACK_TECHNIQUE = "attack_technique"
    ASVS_COMPLIANCE = "asvs_compliance"
    FRAMEWORK_COMPLIANCE = "framework_compliance"
    STATIC_ANALYSIS = "static_analysis"
    CODE_REVIEW_FINDING = "code_review_finding"
    AUTHENTICATION_TESTING = "authentication_testing"
    CRYPTOGRAPHY_TESTING = "cryptography_testing"
    CLEARTEXT_COMMUNICATION = "cleartext_communication"
    GENERAL_VULNERABILITY = "general_vulnerability"

class LanguageSupport(str, Enum):
    """Enumeration of supported programming languages."""
    JAVA = "java"
    KOTLIN = "kotlin"
    SWIFT = "swift"
    OBJC = "objc"
    C = "c"
    CPP = "cpp"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    PYTHON = "python"

class VulnerabilityPattern(BaseModel):
    """
    Validated vulnerability pattern model.
    
    Replaces the basic dataclass with comprehensive validation,
    type safety, and business logic constraints.
    """
    
    pattern_id: str = Field(..., min_length=1, max_length=100, description="Unique pattern identifier")
    pattern_name: str = Field(..., min_length=1, max_length=200, description="Human-readable pattern name")
    pattern_regex: str = Field(..., min_length=1, description="Regular expression pattern")
    pattern_type: PatternType = Field(..., description="Type of vulnerability pattern")
    severity: SeverityLevel = Field(..., description="Severity level of the vulnerability")
    cwe_id: str = Field(..., description="CWE identifier (e.g., CWE-89)")
    masvs_category: str = Field(..., description="MASVS category (e.g., MSTG-CODE-8)")
    description: str = Field(..., min_length=1, max_length=500, description="Pattern description")
    confidence_base: float = Field(..., ge=0.0, le=1.0, description="Base confidence score (0.0-1.0)")
    language_support: List[LanguageSupport] = Field(default_factory=list, description="Supported programming languages")
    context_requirements: List[str] = Field(default_factory=list, description="Required context for pattern matching")
    false_positive_indicators: List[str] = Field(default_factory=list, description="Indicators that suggest false positive")
    validation_score: float = Field(..., ge=0.0, le=1.0, description="Pattern validation score (0.0-1.0)")
    usage_count: int = Field(default=0, ge=0, description="Number of times pattern has been used")
    effectiveness_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Pattern effectiveness score")
    last_updated: datetime = Field(default_factory=datetime.now, description="Last update timestamp")
    source: str = Field(..., min_length=1, max_length=100, description="Pattern source identifier")
    source_data: Dict[str, Any] = Field(default_factory=dict, description="Source-specific metadata")
    references: List[str] = Field(default_factory=list, description="Reference URLs or documentation")
    
    @field_validator('pattern_regex')
    @classmethod
    def validate_regex(cls, v):
        """Validate that the regex pattern is syntactically correct."""
        try:
            re.compile(v)
            return v
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
    
    @field_validator('cwe_id')
    @classmethod
    def validate_cwe_id(cls, v):
        """Validate CWE ID format."""
        if not re.match(r"^CWE-\d+$", v):
            raise ValueError("CWE ID must be in format 'CWE-123'")
        return v
    
    @field_validator('masvs_category')
    @classmethod
    def validate_masvs_category(cls, v):
        """Validate MASVS category format."""
        if not re.match(r"^MSTG-[A-Z]+-\d+$", v):
            raise ValueError("MASVS category must be in format 'MSTG-CODE-8'")
        return v
    
    @field_validator('confidence_base', 'validation_score', 'effectiveness_score')
    @classmethod
    def validate_scores(cls, v):
        """Ensure scores are within valid range."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("Score must be between 0.0 and 1.0")
        return v
    
    @field_validator('references')
    @classmethod
    def validate_references(cls, v):
        """Validate that references are valid URLs if provided."""
        for ref in v:
            if ref and not (ref.startswith('http://') or ref.startswith('https://')):
                raise ValueError(f"Reference must be a valid URL: {ref}")
        return v
    
    class Config:
        """Pydantic configuration."""
        validate_assignment = True
        extra = "forbid"
        json_schema_extra = {
            "example": {
                "pattern_id": "sql_001",
                "pattern_name": "SQL Injection in rawQuery",
                "pattern_regex": r"(?i)rawQuery\s*\(\s*[^)]*\+[^)]*\)",
                "pattern_type": "sql_injection",
                "severity": "HIGH",
                "cwe_id": "CWE-89",
                "masvs_category": "MSTG-CODE-8",
                "description": "SQL injection vulnerability in Android rawQuery calls",
                "confidence_base": 0.9,
                "language_support": ["java", "kotlin"],
                "context_requirements": ["database", "user_input"],
                "false_positive_indicators": ["test", "example"],
                "validation_score": 0.85,
                "source": "CVE Database",
                "references": ["https://cwe.mitre.org/data/definitions/89.html"]
            }
        }

class PatternTemplate(BaseModel):
    """
    Validated pattern template model for generating multiple pattern variations.
    """
    
    template_id: str = Field(..., min_length=1, max_length=100, description="Unique template identifier")
    template_name: str = Field(..., min_length=1, max_length=200, description="Human-readable template name")
    base_regex: str = Field(..., min_length=1, description="Base regex template with placeholders")
    vulnerability_type: PatternType = Field(..., description="Type of vulnerability this template generates")
    severity: SeverityLevel = Field(..., description="Default severity level")
    cwe_id: str = Field(..., description="CWE identifier")
    variations: List[Dict[str, Any]] = Field(..., min_length=1, description="Template variations")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Template metadata")
    
    @field_validator('base_regex')
    @classmethod
    def validate_base_regex_has_placeholders(cls, v):
        """Ensure base regex contains placeholders for substitution."""
        if '{' not in v or '}' not in v:
            raise ValueError("Base regex must contain placeholders (e.g., {method}, {class})")
        return v
    
    @field_validator('cwe_id')
    @classmethod
    def validate_cwe_id(cls, v):
        """Validate CWE ID format."""
        if not re.match(r"^CWE-\d+$", v):
            raise ValueError("CWE ID must be in format 'CWE-123'")
        return v
    
    @field_validator('variations')
    @classmethod
    def validate_variations_not_empty(cls, v):
        """Ensure each variation has content."""
        for variation in v:
            if not variation:
                raise ValueError("Variations cannot be empty")
        return v
    
    class Config:
        """Pydantic configuration."""
        validate_assignment = True
        extra = "forbid"
        json_schema_extra = {
            "example": {
                "template_id": "sql_injection_template",
                "template_name": "SQL Injection Pattern Template",
                "base_regex": r"(?i){method}\s*\(\s*[^)]*\+[^)]*\)",
                "vulnerability_type": "sql_injection",
                "severity": "HIGH",
                "cwe_id": "CWE-89",
                "variations": [
                    {"method": "rawQuery", "context": "Android SQLite"},
                    {"method": "execSQL", "context": "Android SQLite"}
                ]
            }
        }

class PatternMatch(BaseModel):
    """
    Validated pattern match result model.
    """
    
    match_id: str = Field(..., min_length=1, description="Unique match identifier")
    pattern_id: str = Field(..., min_length=1, description="ID of the pattern that matched")
    file_path: str = Field(..., min_length=1, description="Path to the file containing the match")
    line_number: int = Field(..., ge=1, description="Line number of the match")
    matched_text: str = Field(..., min_length=1, description="Text that matched the pattern")
    context_before: str = Field(default="", description="Text before the match")
    context_after: str = Field(default="", description="Text after the match")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence score for this match")
    severity: SeverityLevel = Field(..., description="Severity of the matched vulnerability")
    explanation: str = Field(..., min_length=1, description="Explanation of the vulnerability")
    suggested_fix: str = Field(default="", description="Suggested fix for the vulnerability")
    false_positive_likelihood: float = Field(default=0.0, ge=0.0, le=1.0, description="Likelihood this is a false positive")
    validation_data: Dict[str, Any] = Field(default_factory=dict, description="Additional validation data")
    
    class Config:
        """Pydantic configuration."""
        validate_assignment = True
        extra = "forbid"

class PatternSourceConfig(BaseModel):
    """
    Configuration model for pattern sources.
    """
    
    source_id: str = Field(..., min_length=1, description="Unique source identifier")
    source_name: str = Field(..., min_length=1, description="Human-readable source name")
    enabled: bool = Field(default=True, description="Whether this source is enabled")
    priority: int = Field(default=1, ge=1, le=10, description="Source priority (1=highest, 10=lowest)")
    max_patterns: Optional[int] = Field(default=None, ge=1, description="Maximum patterns to load from this source")
    timeout_seconds: int = Field(default=30, ge=1, le=300, description="Timeout for loading patterns")
    retry_count: int = Field(default=3, ge=0, le=10, description="Number of retries on failure")
    cache_duration_hours: int = Field(default=24, ge=1, le=168, description="Cache duration in hours")
    config_data: Dict[str, Any] = Field(default_factory=dict, description="Source-specific configuration")
    
    class Config:
        """Pydantic configuration."""
        validate_assignment = True
        extra = "forbid"

class PatternEngineConfig(BaseModel):
    """
    Main configuration model for the pattern engine.
    """
    
    max_workers: int = Field(default=4, ge=1, le=20, description="Maximum worker threads")
    enable_parallel_loading: bool = Field(default=True, description="Enable parallel pattern loading")
    enable_semantic_analysis: bool = Field(default=True, description="Enable semantic analysis")
    match_timeout_seconds: int = Field(default=30, ge=1, le=300, description="Timeout for pattern matching")
    enable_caching: bool = Field(default=True, description="Enable pattern caching")
    cache_size_limit: int = Field(default=10000, ge=100, description="Maximum cache size")
    log_level: str = Field(default="INFO", description="Logging level")
    pattern_sources: List[PatternSourceConfig] = Field(default_factory=list, description="Pattern source configurations")
    
    @field_validator('log_level')
    @classmethod
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()
    
    class Config:
        """Pydantic configuration."""
        validate_assignment = True
        extra = "forbid"

# Type aliases for backwards compatibility
Pattern = VulnerabilityPattern
Template = PatternTemplate
Match = PatternMatch
SourceConfig = PatternSourceConfig
EngineConfig = PatternEngineConfig 
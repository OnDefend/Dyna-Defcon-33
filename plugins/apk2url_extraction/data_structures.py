#!/usr/bin/env python3
"""
APK2URL Extraction Plugin - Data Structures

Core data structures, enums, and type definitions for APK2URL endpoint discovery.
Provides standardized data models for URL findings, security assessments,
and extraction metadata with comprehensive categorization.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Union
from datetime import datetime
from pathlib import Path

class EndpointType(Enum):
    """Types of endpoints that can be discovered."""
    URL = "url"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    API_ENDPOINT = "api_endpoint"
    DEEP_LINK = "deep_link"
    FILE_URL = "file_url"
    CERTIFICATE = "certificate"
    SECRET = "secret"

class ExtractionMethod(Enum):
    """Methods used for endpoint extraction."""
    MANIFEST_ANALYSIS = "manifest_analysis"
    RESOURCE_ANALYSIS = "resource_analysis"
    DEX_ANALYSIS = "dex_analysis"
    CONFIG_ANALYSIS = "config_analysis"
    NATIVE_LIB_ANALYSIS = "native_lib_analysis"
    CERTIFICATE_ANALYSIS = "certificate_analysis"
    BINARY_PATTERN_MATCHING = "binary_pattern_matching"
    JSON_ANALYSIS = "json_analysis"

class SecurityRisk(Enum):
    """Security risk levels for discovered endpoints."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ProtocolType(Enum):
    """Network protocol types."""
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    WEBSOCKET = "websocket"
    WEBSOCKET_SECURE = "websocket_secure"
    CUSTOM = "custom"

class DomainCategory(Enum):
    """Domain categorization for security assessment."""
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    LOCALHOST = "localhost"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"

@dataclass
class EndpointFinding:
    """Represents a discovered endpoint with metadata."""
    value: str
    endpoint_type: EndpointType
    extraction_method: ExtractionMethod
    source_file: str
    risk_level: SecurityRisk
    confidence: float = 0.0
    protocol: Optional[ProtocolType] = None
    domain_category: Optional[DomainCategory] = None
    is_hardcoded: bool = True
    is_encrypted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    context: str = ""

@dataclass
class ExtractionStatistics:
    """Statistics for endpoint extraction process."""
    total_files_processed: int
    dex_files_processed: int
    resource_files_processed: int
    native_libs_processed: int
    certificates_processed: int
    extraction_duration: float
    total_findings: int
    unique_endpoints: int
    noise_filtered: int
    processing_errors: int = 0

@dataclass
class SecurityAssessment:
    """Security assessment results for discovered endpoints."""
    overall_risk: SecurityRisk
    risk_score: float
    critical_findings: int
    high_risk_findings: int
    medium_risk_findings: int
    low_risk_findings: int
    info_findings: int
    
    # Specific security concerns
    cleartext_communications: int = 0
    hardcoded_credentials: int = 0
    development_endpoints: int = 0
    suspicious_domains: int = 0
    certificate_issues: int = 0
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    mitigation_priority: str = ""
    compliance_notes: List[str] = field(default_factory=list)

@dataclass
class ExtractionContext:
    """Context information for extraction process."""
    apk_path: Path
    apk_size: int
    is_large_apk: bool
    max_processing_time: int
    extraction_timestamp: datetime
    plugin_version: str
    enhanced_analyzer_available: bool = False
    processing_limits: Dict[str, int] = field(default_factory=dict)

@dataclass
class PatternMatch:
    """Represents a pattern match with context."""
    pattern_name: str
    matched_text: str
    file_path: str
    line_number: Optional[int] = None
    confidence: float = 0.0
    context_before: str = ""
    context_after: str = ""
    is_noise: bool = False

@dataclass
class NoiseFilterResult:
    """Result of noise filtering operation."""
    original_count: int
    filtered_count: int
    noise_count: int
    filter_efficiency: float
    noise_patterns_matched: List[str] = field(default_factory=list)
    excluded_files: List[str] = field(default_factory=list)

@dataclass
class ExtractionResults:
    """Complete extraction results with categorized findings."""
    # Core findings by category
    urls: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    api_endpoints: Set[str] = field(default_factory=set)
    deep_links: Set[str] = field(default_factory=set)
    file_urls: Set[str] = field(default_factory=set)
    certificates: Set[str] = field(default_factory=set)
    secrets: Set[str] = field(default_factory=set)
    
    # Detailed findings with metadata
    detailed_findings: List[EndpointFinding] = field(default_factory=list)
    
    # Analysis metadata
    statistics: Optional[ExtractionStatistics] = None
    security_assessment: Optional[SecurityAssessment] = None
    noise_filter_result: Optional[NoiseFilterResult] = None
    
    # Processing information
    extraction_context: Optional[ExtractionContext] = None
    processing_errors: List[str] = field(default_factory=list)

# Type aliases for better code readability
FindingsDict = Dict[str, Set[str]]
PatternDict = Dict[str, Any]
ConfigDict = Dict[str, Any]

# Constants for APK2URL extraction
DEFAULT_PROCESSING_LIMITS = {
    'max_file_size_mb': 50,
    'max_dex_files': 5,
    'max_processing_time': 300,
    'max_resource_files': 100,
    'max_native_libs': 20,
    'max_strings_per_file': 10000
}

# Protocol mappings
PROTOCOL_MAPPINGS = {
    'http://': ProtocolType.HTTP,
    'https://': ProtocolType.HTTPS,
    'ftp://': ProtocolType.FTP,
    'ws://': ProtocolType.WEBSOCKET,
    'wss://': ProtocolType.WEBSOCKET_SECURE
}

# Risk level mappings for different endpoint types
RISK_LEVEL_MAPPINGS = {
    EndpointType.SECRET: SecurityRisk.CRITICAL,
    EndpointType.API_ENDPOINT: SecurityRisk.HIGH,
    EndpointType.IP_ADDRESS: SecurityRisk.MEDIUM,
    EndpointType.URL: SecurityRisk.MEDIUM,
    EndpointType.DOMAIN: SecurityRisk.LOW,
    EndpointType.DEEP_LINK: SecurityRisk.LOW,
    EndpointType.FILE_URL: SecurityRisk.LOW,
    EndpointType.CERTIFICATE: SecurityRisk.INFO
}

# Domain category patterns
DOMAIN_CATEGORY_PATTERNS = {
    DomainCategory.DEVELOPMENT: ['dev', 'development', 'devel'],
    DomainCategory.TESTING: ['test', 'testing', 'qa', 'quality'],
    DomainCategory.STAGING: ['staging', 'stage', 'uat', 'pre-prod'],
    DomainCategory.LOCALHOST: ['localhost', '127.0.0.1', '0.0.0.0'],
    DomainCategory.SUSPICIOUS: ['debug', 'temp', 'tmp', 'admin', 'backdoor']
}

# MASVS control mappings
MASVS_MAPPINGS = {
    EndpointType.URL: "MSTG-NETWORK-01",
    EndpointType.IP_ADDRESS: "MSTG-NETWORK-02", 
    EndpointType.API_ENDPOINT: "MSTG-NETWORK-01",
    EndpointType.SECRET: "MSTG-CRYPTO-01",
    EndpointType.CERTIFICATE: "MSTG-NETWORK-03"
}

# Valid TLDs for domain validation
VALID_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'biz', 'info', 'name',
    'pro', 'aero', 'coop', 'museum', 'travel', 'jobs', 'mobi', 'tel', 'asia',
    'cat', 'post', 'xxx', 'arpa', 'root', 'onion', 'local', 'localhost',
    # Country codes (sample)
    'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'ru', 'br', 'in', 'mx',
    'es', 'it', 'nl', 'se', 'no', 'dk', 'fi', 'ch', 'at', 'be', 'pl', 'cz',
    'hu', 'ro', 'bg', 'hr', 'si', 'sk', 'lt', 'lv', 'ee', 'ie', 'pt', 'gr',
    'tr', 'il', 'za', 'eg', 'ma', 'ng', 'ke', 'tz', 'ug', 'zw', 'bw', 'mw',
    'zm', 'mz', 'ao', 'cd', 'cf', 'td', 'cm', 'ga', 'gq', 'st', 'cv', 'gw',
    'gn', 'sl', 'lr', 'ci', 'gh', 'tg', 'bj', 'ne', 'bf', 'ml', 'sn', 'gm',
    'mr', 'dz', 'tn', 'ly', 'sd', 'ss', 'et', 'er', 'dj', 'so', 'mg', 'mu',
    'sc', 'km', 're', 'yt', 'io', 'ac', 'sh', 'tc', 'vg', 'ai', 'ms', 'gd',
    'lc', 'vc', 'bb', 'ag', 'dm', 'kn', 'jm', 'ht', 'do', 'cu', 'bs', 'bz',
    'gt', 'sv', 'hn', 'ni', 'cr', 'pa', 'co', 've', 'gy', 'sr', 'fk', 'cl',
    'ar', 'uy', 'py', 'bo', 'pe', 'ec', 'gf', 'aw', 'cw', 'sx', 'bq', 'tt',
    'pr', 'vi', 'as', 'gu', 'mp', 'pw', 'fm', 'mh', 'ki', 'nr', 'tv', 'to',
    'ws', 'vu', 'sb', 'nc', 'nf', 'pf', 'wf', 'ck', 'nu', 'tk', 'pn', 'fj'
}

# Framework noise indicators
FRAMEWORK_NOISE_INDICATORS = [
    'flutter', 'react-native', 'xamarin', 'ionic', 'cordova', 'phonegap',
    'node_modules', 'webpack', 'babel', 'typescript', 'javascript', 'dart',
    'gradle', 'maven', 'cocoapods', 'carthage', 'spm', 'npm', 'yarn', 'bower'
]

# Security assessment thresholds
SECURITY_THRESHOLDS = {
    'critical_risk_threshold': 1,     # 1+ critical findings = critical risk
    'high_risk_threshold': 3,         # 3+ high findings = high risk  
    'medium_risk_threshold': 5,       # 5+ medium findings = medium risk
    'cleartext_warning_threshold': 1, # 1+ HTTP URLs = warning
    'ip_hardcoding_threshold': 3,     # 3+ IPs = concern
    'development_endpoint_threshold': 1 # 1+ dev endpoints = warning
}

# Output formatting constants
DISPLAY_LIMITS = {
    'max_displayed_items': 20,
    'max_item_length': 80,
    'max_context_length': 100,
    'truncation_suffix': '...'
} 
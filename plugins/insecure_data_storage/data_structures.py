"""
Insecure Data Storage Analysis Data Structures

Standardized data structures for insecure data storage security analysis results.
Provides type-safe data containers for all analysis components.

Features:
- Type-safe data classes with comprehensive field validation
- Enum-based classifications for consistency
- Structured vulnerability and analysis result containers
- MASVS control mapping integration
- confidence scoring support
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Union, Any
from pathlib import Path

class StorageVulnerabilitySeverity(Enum):
    """Severity levels for storage vulnerabilities."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class StorageSecurityLevel(Enum):
    """Storage security levels based on protection mechanisms."""
    EXCELLENT = "Excellent"
    GOOD = "Good"
    FAIR = "Fair"
    POOR = "Poor"
    CRITICAL = "Critical"

class StorageType(Enum):
    """Types of data storage mechanisms."""
    SHARED_PREFERENCES = "shared_preferences"
    INTERNAL_STORAGE = "internal_storage"
    EXTERNAL_STORAGE = "external_storage"
    DATABASE = "database"
    FILE_STORAGE = "file_storage"
    CACHE = "cache"
    TEMP_FILES = "temp_files"
    LOG_FILES = "log_files"
    BACKUP_FILES = "backup_files"
    BACKUP = "backup"  # **FIX**: Added missing BACKUP storage type for compatibility
    CONFIGURATION_FILES = "configuration_files"
    UNKNOWN = "unknown"

class SecretType(Enum):
    """Types of detected secrets."""
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    ENCRYPTION_KEY = "encryption_key"
    DATABASE_CREDENTIAL = "database_credential"
    ROOT_DETECTION_PATTERN = "root_detection_pattern"
    PII_DATA = "pii_data"
    BIOMETRIC_DATA = "biometric_data"
    UNKNOWN = "unknown"

class RootDetectionCategory(Enum):
    """Categories of root detection patterns."""
    NATIVE_BINARY_ANALYSIS = "native_binary_analysis"
    FILE_SYSTEM_PERMISSION_ANALYSIS = "file_system_permission_analysis"
    PROCESS_EXECUTION_ANALYSIS = "process_execution_analysis"
    SYSTEM_PROPERTY_ANALYSIS = "system_property_analysis"
    PACKAGE_MANAGER_ANALYSIS = "package_manager_analysis"
    BYPASS_DETECTION = "bypass_detection"
    HARDWARE_SECURITY = "hardware_security"
    DYNAMIC_CORRELATION = "dynamic_correlation"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_engine_category(cls, engine_category):
        """Convert engine RootDetectionCategory to local RootDetectionCategory."""
        # Map from core engine categories to local categories
        mapping = {
            'BINARY_ANALYSIS': cls.NATIVE_BINARY_ANALYSIS,
            'FILE_SYSTEM_ANALYSIS': cls.FILE_SYSTEM_PERMISSION_ANALYSIS,
            'PROCESS_ANALYSIS': cls.PROCESS_EXECUTION_ANALYSIS,
            'PROPERTY_ANALYSIS': cls.SYSTEM_PROPERTY_ANALYSIS,
            'PACKAGE_ANALYSIS': cls.PACKAGE_MANAGER_ANALYSIS,
            'NATIVE_LIBRARY_ANALYSIS': cls.NATIVE_BINARY_ANALYSIS,
            'BYPASS_DETECTION': cls.BYPASS_DETECTION,
            'HARDWARE_SECURITY': cls.HARDWARE_SECURITY,
        }
        
        # Handle string or enum input
        category_str = str(engine_category).split('.')[-1] if hasattr(engine_category, 'value') else str(engine_category)
        return mapping.get(category_str, cls.UNKNOWN)
    
    @classmethod 
    def from_string(cls, category_string):
        """Convert string to RootDetectionCategory."""
        for category in cls:
            if category.value == category_string or category.name == category_string.upper():
                return category
        return cls.UNKNOWN

class BackupVulnerabilityType(Enum):
    """Types of backup vulnerabilities."""
    ALLOW_BACKUP_ENABLED = "allow_backup_enabled"
    WEAK_BACKUP_AGENT = "weak_backup_agent"
    INSECURE_BACKUP_DATA = "insecure_backup_data"
    BACKUP_ENCRYPTION_MISSING = "backup_encryption_missing"
    UNKNOWN = "unknown"

@dataclass
class StorageVulnerability:
    """Data class for storage security vulnerabilities."""
    id: str
    title: str
    description: str
    severity: StorageVulnerabilitySeverity
    storage_type: StorageType
    masvs_control: str
    file_path: str = ""  # **FIX**: Added missing file_path field
    location: str = ""  # **FIX**: Added missing location field  
    line_number: int = 0  # **FIX**: Added missing line_number field
    affected_files: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: Optional[float] = None
    context: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate vulnerability data after initialization."""
        if not self.id:
            raise ValueError("Vulnerability ID is required")
        if not self.title:
            raise ValueError("Vulnerability title is required")
        if not isinstance(self.severity, StorageVulnerabilitySeverity):
            raise ValueError("Invalid vulnerability severity")
        if not isinstance(self.storage_type, StorageType):
            raise ValueError("Invalid storage type")
        if self.cvss_score is not None and not (0.0 <= self.cvss_score <= 10.0):
            raise ValueError("CVSS score must be between 0.0 and 10.0")
        if self.confidence is not None and not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")

@dataclass
class SecretFinding:
    """Data class for detected secrets."""
    id: str
    secret_type: SecretType
    value: str
    location: str
    context: str
    confidence: float
    severity: StorageVulnerabilitySeverity = StorageVulnerabilitySeverity.MEDIUM
    is_hashed: bool = False
    entropy_score: Optional[float] = None
    pattern_name: str = ""
    file_path: str = ""
    line_number: int = 0
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate secret finding data."""
        if not self.id:
            raise ValueError("Secret finding ID is required")
        if not isinstance(self.secret_type, SecretType):
            raise ValueError("Invalid secret type")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")
        if self.entropy_score is not None and not (0.0 <= self.entropy_score <= 8.0):
            raise ValueError("Entropy score must be between 0.0 and 8.0")

@dataclass
class RootDetectionFinding:
    """Data class for root detection pattern findings."""
    id: str
    category: RootDetectionCategory
    pattern: str
    pattern_id: str = ""  # **FIX**: Added missing pattern_id attribute
    pattern_name: str = ""  # **FIX**: Added missing pattern_name attribute
    description: str = ""  # **FIX**: Added missing description attribute
    match: str = ""
    match_text: str = ""  # **FIX**: Added missing match_text attribute
    location: str = ""
    confidence: float = 0.0
    severity: StorageVulnerabilitySeverity = StorageVulnerabilitySeverity.HIGH
    file_path: str = ""
    line_number: int = 0
    context: str = ""
    evidence: List[str] = field(default_factory=list)
    bypass_methods: List[str] = field(default_factory=list)
    bypass_resistance: float = 0.0  # **FIX**: Added missing bypass_resistance attribute
    detection_method: str = ""  # **FIX**: Added missing detection_method attribute
    recommendations: List[str] = field(default_factory=list)  # **FIX**: Added missing recommendations attribute
    masvs_refs: List[str] = field(default_factory=list)  # **FIX**: Added missing masvs_refs attribute
    
    def __post_init__(self):
        """Validate root detection finding data."""
        if not self.id:
            raise ValueError("Root detection finding ID is required")
        if not isinstance(self.category, RootDetectionCategory):
            raise ValueError("Invalid root detection category")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")

@dataclass
class DatabaseAnalysis:
    """Data class for database security analysis results."""
    database_path: str
    database_type: str
    encryption_status: str
    encryption_algorithm: Optional[str] = None
    key_management: str = "unknown"
    access_permissions: List[str] = field(default_factory=list)
    backup_enabled: bool = False
    sql_injection_risks: List[str] = field(default_factory=list)
    sensitive_data_found: List[str] = field(default_factory=list)
    security_score: float = 0.0
    vulnerabilities: List[StorageVulnerability] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate database analysis data."""
        if not self.database_path:
            raise ValueError("Database path is required")
        if not (0.0 <= self.security_score <= 100.0):
            raise ValueError("Security score must be between 0.0 and 100.0")

@dataclass
class SharedPreferencesAnalysis:
    """Data class for shared preferences security analysis results."""
    preferences_file: str
    encryption_status: str
    mode: str = "unknown"
    sensitive_keys: List[str] = field(default_factory=list)
    weak_values: List[str] = field(default_factory=list)
    backup_eligible: bool = True
    world_readable: bool = False
    security_score: float = 0.0
    vulnerabilities: List[StorageVulnerability] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate shared preferences analysis data."""
        if not self.preferences_file:
            raise ValueError("Preferences file path is required")
        if not (0.0 <= self.security_score <= 100.0):
            raise ValueError("Security score must be between 0.0 and 100.0")

@dataclass
class FileStorageAnalysis:
    """Data class for file storage security analysis results."""
    file_path: str
    storage_location: StorageType
    encryption_status: str
    file_permissions: str = "unknown"
    world_accessible: bool = False
    contains_sensitive_data: bool = False
    backup_eligible: bool = True
    deletion_security: str = "unknown"
    security_score: float = 0.0
    vulnerabilities: List[StorageVulnerability] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate file storage analysis data."""
        if not self.file_path:
            raise ValueError("File path is required")
        if not isinstance(self.storage_location, StorageType):
            raise ValueError("Invalid storage location type")
        if not (0.0 <= self.security_score <= 100.0):
            raise ValueError("Security score must be between 0.0 and 100.0")

@dataclass
class BackupVulnerabilityAnalysis:
    """Data class for backup vulnerability analysis results."""
    backup_enabled: bool = False  # **FIX**: Made optional with default value
    backup_agent_type: str = "default"
    backup_type: str = "unknown"  # **FIX**: Added missing backup_type parameter
    backup_location: str = "unknown"  # **FIX**: Added missing backup_location parameter
    backup_data_types: List[str] = field(default_factory=list)
    encryption_in_transit: bool = False
    encryption_at_rest: bool = False
    data_filtering: bool = False
    vulnerability_type: Optional[BackupVulnerabilityType] = None
    security_score: float = 0.0
    vulnerabilities: List[StorageVulnerability] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate backup vulnerability analysis data."""
        if not (0.0 <= self.security_score <= 100.0):
            raise ValueError("Security score must be between 0.0 and 100.0")

@dataclass
class ScanStatistics:
    """Data class for scan statistics and metrics."""
    files_analyzed: int = 0
    secrets_found: int = 0
    databases_checked: int = 0
    preferences_checked: int = 0
    static_resources_scanned: int = 0
    root_patterns_detected: int = 0
    total_scan_time: float = 0.0
    analysis_depth: str = "balanced"
    
    def __post_init__(self):
        """Validate scan statistics data."""
        if self.files_analyzed < 0:
            raise ValueError("Files analyzed count cannot be negative")
        if self.total_scan_time < 0:
            raise ValueError("Total scan time cannot be negative")

@dataclass
class InsecureDataStorageAnalysisResult:
    """Comprehensive insecure data storage analysis result."""
    package_name: str
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    
    # Analysis results from each component
    database_analyses: List[DatabaseAnalysis] = field(default_factory=list)
    shared_preferences_analyses: List[SharedPreferencesAnalysis] = field(default_factory=list)
    file_storage_analyses: List[FileStorageAnalysis] = field(default_factory=list)
    backup_analyses: List[BackupVulnerabilityAnalysis] = field(default_factory=list)
    secret_findings: List[SecretFinding] = field(default_factory=list)
    root_detection_findings: List[RootDetectionFinding] = field(default_factory=list)
    
    # Overall analysis metrics
    overall_security_score: float = 0.0
    storage_security_level: StorageSecurityLevel = StorageSecurityLevel.CRITICAL
    scan_statistics: Optional[ScanStatistics] = None
    
    # Analysis metadata
    analysis_time: float = 0.0
    analysis_version: str = "2.0.0"
    recommendations: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate analysis result data."""
        if not self.package_name:
            raise ValueError("Package name is required")
        if self.total_vulnerabilities < 0:
            raise ValueError("Total vulnerabilities count cannot be negative")
        if not (0.0 <= self.overall_security_score <= 100.0):
            raise ValueError("Overall security score must be between 0.0 and 100.0")

@dataclass
class StoragePatternMatch:
    """Data class for storage security pattern matching results."""
    pattern_id: str
    pattern_name: str
    pattern_type: str
    matched_content: str
    match_location: str
    confidence: float
    storage_type: StorageType
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate pattern match data."""
        if not self.pattern_id:
            raise ValueError("Pattern ID is required")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")
        if not isinstance(self.storage_type, StorageType):
            raise ValueError("Invalid storage type")

@dataclass
class StorageAnalysisConfig:
    """Configuration for storage analysis operations."""
    max_files_total: int = 200
    max_scan_time: int = 180
    max_content_size_mb: int = 2
    enable_root_detection: bool = True
    enable_secret_detection: bool = True
    enable_database_analysis: bool = True
    enable_backup_analysis: bool = True
    analysis_depth: str = "balanced"  # fast, balanced, thorough, comprehensive
    pattern_config_path: Optional[Path] = None
    cache_analysis_results: bool = True
    
    def __post_init__(self):
        """Validate configuration parameters."""
        if self.max_files_total <= 0:
            raise ValueError("Max files total must be positive")
        if self.max_scan_time <= 0:
            raise ValueError("Max scan time must be positive")
        if self.max_content_size_mb <= 0:
            raise ValueError("Max content size must be positive")
        if self.analysis_depth not in ["fast", "balanced", "thorough", "comprehensive"]:
            raise ValueError("Invalid analysis depth")

@dataclass
class StorageSecurityEvidence:
    """Evidence container for storage security analysis confidence calculation."""
    
    # Pattern evidence
    pattern_matches: List[StoragePatternMatch] = field(default_factory=list)
    pattern_reliability_score: float = 0.0
    
    # Storage characteristics
    storage_types: List[StorageType] = field(default_factory=list)
    encryption_methods: List[str] = field(default_factory=list)
    access_permissions: List[str] = field(default_factory=list)
    
    # Analysis depth
    analysis_methods: List[str] = field(default_factory=list)
    analysis_tools: List[str] = field(default_factory=list)
    analysis_depth: str = "balanced"
    
    # Context factors
    storage_location: str = "internal"  # internal, external, cache
    data_sensitivity: str = "medium"   # low, medium, high, critical
    app_context: str = "production"    # production, test, debug
    
    # Validation sources
    static_analysis: bool = False
    dynamic_analysis: bool = False
    file_system_analysis: bool = False
    manifest_analysis: bool = False
    
    # Cross-validation
    multiple_patterns: bool = False
    pattern_consistency: float = 0.0
    
    def __post_init__(self):
        """Validate evidence data."""
        if self.pattern_reliability_score < 0.0 or self.pattern_reliability_score > 1.0:
            raise ValueError("Pattern reliability score must be between 0.0 and 1.0")
        if self.pattern_consistency < 0.0 or self.pattern_consistency > 1.0:
            raise ValueError("Pattern consistency must be between 0.0 and 1.0") 
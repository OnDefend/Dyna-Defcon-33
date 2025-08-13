"""
Native Binary Analysis Data Structures

Standardized data structures for native binary security analysis results.
Provides type-safe data containers for all analysis components.

Features:
- Type-safe data classes with comprehensive field validation
- Enum-based classifications for consistency
- Structured vulnerability and analysis result containers
- MASVS control mapping integration
- Evidence-based confidence scoring support
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Union, Any
from pathlib import Path

class VulnerabilitySeverity(Enum):
    """Severity levels for native binary vulnerabilities."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class BinaryProtectionLevel(Enum):
    """Binary protection levels based on hardening features."""
    EXCELLENT = "Excellent"
    GOOD = "Good"
    FAIR = "Fair"
    POOR = "Poor"
    CRITICAL = "Critical"

class BinaryArchitecture(Enum):
    """Binary architecture types."""
    ARM = "arm"
    ARM64 = "arm64"
    X86 = "x86"
    X86_64 = "x86_64"
    MIPS = "mips"
    UNKNOWN = "unknown"

class JNISecurityRisk(Enum):
    """JNI security risk levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NEGLIGIBLE = "Negligible"

class MemoryProtectionType(Enum):
    """Memory protection mechanism types."""
    STACK_CANARY = "stack_canary"
    NX_BIT = "nx_bit"
    ASLR = "aslr"
    DEP = "dep"
    CFI = "cfi"
    FORTIFY = "fortify"
    RELRO = "relro"
    PIE = "pie"

class MemoryProtectionLevel(Enum):
    """Memory protection levels based on security mechanisms."""
    MAXIMUM = "Maximum"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    MINIMAL = "Minimal"

class CryptographicStrength(Enum):
    """Cryptographic implementation strength levels."""
    STRONG = "Strong"
    ADEQUATE = "Adequate"
    WEAK = "Weak"
    VERY_WEAK = "Very Weak"

class MalwareRiskLevel(Enum):
    """Malware risk levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    CLEAN = "Clean"

# Phase 2.5.2 Enhancement: Anti-debugging analysis enums
class AntiDebuggingTechnique(Enum):
    """Anti-debugging technique types."""
    DEBUGGER_DETECTION = "debugger_detection"
    PROCESS_MONITORING = "process_monitoring"
    TIMING_CHECKS = "timing_checks"
    EXCEPTION_BASED = "exception_based"
    NATIVE_CALLS = "native_calls"
    REGISTER_MANIPULATION = "register_manipulation"
    INSTRUCTION_LEVEL = "instruction_level"
    VM_DETECTION = "vm_detection"
    TOOL_DETECTION = "tool_detection"
    SYMBOL_ANALYSIS = "symbol_analysis"
    ADVANCED_DETECTION = "advanced_detection"
    SYSTEM_CALL_MONITORING = "system_call_monitoring"
    RUNTIME_PREVENTION = "runtime_prevention"

class DetectionMethod(Enum):
    """Detection method types for anti-debugging analysis."""
    PATTERN_MATCHING = "pattern_matching"
    SYMBOL_TABLE_ANALYSIS = "symbol_table_analysis"
    ENHANCED_PATTERN_ANALYSIS = "enhanced_pattern_analysis"
    SYSCALL_ANALYSIS = "syscall_analysis"
    RUNTIME_ANALYSIS = "runtime_analysis"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"

class AntiDebuggingStrength(Enum):
    """Anti-debugging mechanism strength levels."""
    BASIC = "Basic"
    MODERATE = "Moderate"
    ADVANCED = "Advanced"
    EXPERT = "Expert"

class ProtectionLevel(Enum):
    """Overall protection level assessment."""
    MINIMAL = "Minimal"
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    MAXIMUM = "Maximum"

@dataclass
class NativeBinaryVulnerability:
    """Data class for native binary vulnerabilities."""
    id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    masvs_control: str
    affected_files: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: Optional[float] = None  # Evidence-based confidence calculation
    context: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate vulnerability data after initialization."""
        if not self.id:
            raise ValueError("Vulnerability ID is required")
        if not self.title:
            raise ValueError("Vulnerability title is required")
        if not isinstance(self.severity, VulnerabilitySeverity):
            raise ValueError("Invalid vulnerability severity")
        if self.cvss_score is not None and not (0.0 <= self.cvss_score <= 10.0):
            raise ValueError("CVSS score must be between 0.0 and 10.0")
        if self.confidence is not None and not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")

@dataclass
class BinaryHardeningAnalysis:
    """Data class for binary hardening analysis results."""
    library_name: str
    architecture: BinaryArchitecture
    pie_enabled: bool
    nx_enabled: bool
    relro_enabled: bool
    canary_enabled: bool
    stripped: bool
    fortify_enabled: bool
    cfi_enabled: bool
    protection_level: BinaryProtectionLevel
    protection_score: float = 0.0
    vulnerabilities: List[NativeBinaryVulnerability] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate hardening analysis data."""
        if not self.library_name:
            raise ValueError("Library name is required")
        if not (0.0 <= self.protection_score <= 100.0):
            raise ValueError("Protection score must be between 0.0 and 100.0")

@dataclass
class SymbolAnalysis:
    """Data class for symbol analysis results."""
    library_name: str
    dangerous_functions: List[str] = field(default_factory=list)
    crypto_functions: List[str] = field(default_factory=list)
    network_functions: List[str] = field(default_factory=list)
    file_operations: List[str] = field(default_factory=list)
    debug_symbols: List[str] = field(default_factory=list)
    imported_libraries: List[str] = field(default_factory=list)
    exported_functions: List[str] = field(default_factory=list)
    symbol_count: int = 0
    stripped_symbols: bool = False
    security_score: float = 0.0
    vulnerabilities: List[NativeBinaryVulnerability] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate symbol analysis data."""
        if not self.library_name:
            raise ValueError("Library name is required")
        if not (0.0 <= self.security_score <= 100.0):
            raise ValueError("Security score must be between 0.0 and 100.0")

@dataclass
class MalwarePatternAnalysis:
    """Data class for malware pattern analysis results."""
    library_name: str
    suspicious_strings: List[str] = field(default_factory=list)
    packer_signatures: List[str] = field(default_factory=list)
    anti_analysis_techniques: List[str] = field(default_factory=list)
    obfuscation_indicators: List[str] = field(default_factory=list)
    persistence_mechanisms: List[str] = field(default_factory=list)
    command_control_indicators: List[str] = field(default_factory=list)
    risk_level: MalwareRiskLevel = MalwareRiskLevel.CLEAN
    risk_score: float = 0.0
    threat_confidence: float = 0.0
    vulnerabilities: List[NativeBinaryVulnerability] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate malware analysis data."""
        if not self.library_name:
            raise ValueError("Library name is required")
        if not (0.0 <= self.risk_score <= 100.0):
            raise ValueError("Risk score must be between 0.0 and 100.0")
        if not (0.0 <= self.threat_confidence <= 1.0):
            raise ValueError("Threat confidence must be between 0.0 and 1.0")

@dataclass
class JNISecurityAnalysis:
    """Data class for JNI security analysis results."""
    library_name: str
    jni_functions_found: List[str] = field(default_factory=list)
    unsafe_jni_calls: List[str] = field(default_factory=list)
    reference_leaks: List[str] = field(default_factory=list)
    exception_handling_issues: List[str] = field(default_factory=list)
    boundary_violations: List[str] = field(default_factory=list)
    privilege_escalation_risks: List[str] = field(default_factory=list)
    
    # Enhanced JNI deep inspection fields
    jni_method_signatures: List[str] = field(default_factory=list)
    invalid_signatures: List[str] = field(default_factory=list)
    dependency_graph: Dict[str, List[str]] = field(default_factory=dict)
    cross_compilation_issues: List[str] = field(default_factory=list)
    obfuscation_indicators: List[str] = field(default_factory=list)
    attack_surface_vectors: List[str] = field(default_factory=list)
    vulnerability_patterns: List[str] = field(default_factory=list)
    runtime_monitoring_hooks: List[str] = field(default_factory=list)
    integrity_violations: List[str] = field(default_factory=list)
    
    risk_level: JNISecurityRisk = JNISecurityRisk.NEGLIGIBLE
    security_score: float = 100.0
    vulnerabilities: List[NativeBinaryVulnerability] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate JNI analysis data."""
        if not self.library_name:
            raise ValueError("Library name is required")
        if not (0.0 <= self.security_score <= 100.0):
            raise ValueError("Security score must be between 0.0 and 100.0")

@dataclass
class MemorySecurityAnalysis:
    """Data class for comprehensive memory security analysis results."""
    library_name: str
    
    # Enhanced memory protection analysis
    stack_protection_mechanisms: List[str] = field(default_factory=list)
    heap_protection_mechanisms: List[str] = field(default_factory=list)
    memory_hardening_features: List[str] = field(default_factory=list)
    memory_sanitizers: List[str] = field(default_factory=list)
    missing_protections: List[str] = field(default_factory=list)
    
    # Enhanced vulnerability detection
    buffer_overflow_vulnerabilities: List[str] = field(default_factory=list)
    stack_overflow_vulnerabilities: List[str] = field(default_factory=list)
    heap_corruption_vulnerabilities: List[str] = field(default_factory=list)
    use_after_free_vulnerabilities: List[str] = field(default_factory=list)
    memory_leak_patterns: List[str] = field(default_factory=list)
    format_string_vulnerabilities: List[str] = field(default_factory=list)
    integer_overflow_vulnerabilities: List[str] = field(default_factory=list)
    memory_vulnerabilities: List[str] = field(default_factory=list)
    
    # Legacy compatibility fields
    stack_protection: Dict[str, bool] = field(default_factory=dict)
    heap_protection: Dict[str, bool] = field(default_factory=dict)
    memory_leaks: List[str] = field(default_factory=list)
    buffer_overflow_risks: List[str] = field(default_factory=list)
    use_after_free_risks: List[str] = field(default_factory=list)
    double_free_risks: List[str] = field(default_factory=list)
    integer_overflow_risks: List[str] = field(default_factory=list)
    control_flow_integrity: bool = False
    address_sanitizer_enabled: bool = False
    memory_sections: Dict[str, List[str]] = field(default_factory=dict)
    protection_mechanisms: List[str] = field(default_factory=list)
    
    # Analysis results
    protection_level: MemoryProtectionLevel = MemoryProtectionLevel.MINIMAL
    security_score: float = 0.0
    vulnerabilities: List[NativeBinaryVulnerability] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate memory analysis data."""
        if not self.library_name:
            raise ValueError("Library name is required")
        if not (0.0 <= self.security_score <= 100.0):
            raise ValueError("Security score must be between 0.0 and 100.0")

@dataclass
class NativeCryptoAnalysis:
    """Data class for comprehensive native cryptographic implementation analysis."""
    library_name: str
    
    # Enhanced crypto detection
    crypto_functions_detected: List[str] = field(default_factory=list)
    crypto_libraries_detected: List[str] = field(default_factory=list)
    crypto_library_versions: List[str] = field(default_factory=list)
    vulnerable_crypto_libraries: List[str] = field(default_factory=list)
    
    # Weakness analysis
    weak_algorithms: List[str] = field(default_factory=list)
    weak_keys: List[str] = field(default_factory=list)
    weak_modes: List[str] = field(default_factory=list)
    weak_randomness: List[str] = field(default_factory=list)
    
    # Security features
    hsm_integration: List[str] = field(default_factory=list)
    hardware_crypto_usage: List[str] = field(default_factory=list)
    key_storage_mechanisms: List[str] = field(default_factory=list)
    key_derivation_functions: List[str] = field(default_factory=list)
    randomness_sources: List[str] = field(default_factory=list)
    
    # Certificate and PKI
    certificate_usage: List[str] = field(default_factory=list)
    certificate_validation_issues: List[str] = field(default_factory=list)
    
    # Legacy compatibility fields
    crypto_libraries: List[str] = field(default_factory=list)
    crypto_functions: List[str] = field(default_factory=list)
    key_storage_methods: List[str] = field(default_factory=list)
    weak_crypto_usage: List[str] = field(default_factory=list)
    strong_crypto_usage: List[str] = field(default_factory=list)
    hardware_crypto_usage_flag: bool = False
    random_generation_quality: str = "unknown"
    crypto_compliance: Dict[str, bool] = field(default_factory=dict)
    
    # Analysis results
    crypto_strength: CryptographicStrength = CryptographicStrength.VERY_WEAK
    security_score: float = 0.0
    vulnerabilities: List[NativeBinaryVulnerability] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate crypto analysis data."""
        if not self.library_name:
            raise ValueError("Library name is required")
        if not (0.0 <= self.security_score <= 100.0):
            raise ValueError("Security score must be between 0.0 and 100.0")

@dataclass
class BinaryExtractionResult:
    """Data class for binary extraction results."""
    total_libraries: int
    extracted_libraries: List[Path] = field(default_factory=list)
    failed_extractions: List[str] = field(default_factory=list)
    architectures: List[BinaryArchitecture] = field(default_factory=list)
    extraction_time: float = 0.0
    
    def __post_init__(self):
        """Validate extraction result data."""
        if self.total_libraries < 0:
            raise ValueError("Total libraries count cannot be negative")
        if self.extraction_time < 0:
            raise ValueError("Extraction time cannot be negative")

@dataclass
class NativeBinaryAnalysisResult:
    """Comprehensive native binary analysis result."""
    package_name: str
    total_libraries: int
    analyzed_libraries: int
    
    # Analysis results from each component
    hardening_analyses: List[BinaryHardeningAnalysis] = field(default_factory=list)
    symbol_analyses: List[SymbolAnalysis] = field(default_factory=list)
    malware_analyses: List[MalwarePatternAnalysis] = field(default_factory=list)
    jni_analyses: List[JNISecurityAnalysis] = field(default_factory=list)
    memory_analyses: List[MemorySecurityAnalysis] = field(default_factory=list)
    crypto_analyses: List[NativeCryptoAnalysis] = field(default_factory=list)
    
    # Overall analysis metrics
    overall_security_score: float = 0.0
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    
    # Analysis metadata
    analysis_time: float = 0.0
    analysis_version: str = "1.0.0"
    recommendations: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate analysis result data."""
        if not self.package_name:
            raise ValueError("Package name is required")
        if self.total_libraries < 0:
            raise ValueError("Total libraries count cannot be negative")
        if self.analyzed_libraries < 0:
            raise ValueError("Analyzed libraries count cannot be negative")
        if self.analyzed_libraries > self.total_libraries:
            raise ValueError("Analyzed libraries cannot exceed total libraries")
        if not (0.0 <= self.overall_security_score <= 100.0):
            raise ValueError("Overall security score must be between 0.0 and 100.0")

@dataclass
class BinaryPatternMatch:
    """Data class for pattern matching results."""
    pattern_id: str
    pattern_name: str
    pattern_type: str
    matched_content: str
    match_location: str
    confidence: float
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate pattern match data."""
        if not self.pattern_id:
            raise ValueError("Pattern ID is required")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")

@dataclass
class BinaryAnalysisConfig:
    """Configuration for binary analysis operations."""
    max_libraries: int = 50
    max_file_size_mb: int = 100
    analysis_timeout: int = 300
    parallel_analysis: bool = True
    max_workers: int = 4
    enable_deep_analysis: bool = True
    pattern_config_path: Optional[Path] = None
    cache_analysis_results: bool = True
    
    def __post_init__(self):
        """Validate configuration parameters."""
        if self.max_libraries <= 0:
            raise ValueError("Max libraries must be positive")
        if self.max_file_size_mb <= 0:
            raise ValueError("Max file size must be positive")
        if self.analysis_timeout <= 0:
            raise ValueError("Analysis timeout must be positive")
        if self.max_workers <= 0:
            raise ValueError("Max workers must be positive") 
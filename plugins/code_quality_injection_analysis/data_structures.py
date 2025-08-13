"""
Data Structures for Code Quality & Injection Analysis Plugin

This module defines the core data structures used throughout the code quality
and injection analysis plugin for consistent data handling and type safety.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

class VulnerabilityType(Enum):
    """Type of injection vulnerability"""
    SQL_INJECTION = "sql_injection"
    XSS_WEBVIEW = "xss_webview"
    CODE_INJECTION = "code_injection"
    OBJECT_INJECTION = "object_injection"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    UNSAFE_PATTERN = "unsafe_pattern"

class SeverityLevel(Enum):
    """Severity level classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class MastgTestId(Enum):
    """MASTG test identifiers"""
    MASTG_TEST_0019 = "MASTG-TEST-0019"  # SQL Injection
    MASTG_TEST_0020 = "MASTG-TEST-0020"  # XSS in WebViews
    MASTG_TEST_0021 = "MASTG-TEST-0021"  # Object Injection
    MASTG_TEST_0022 = "MASTG-TEST-0022"  # Code Injection
    MASTG_TEST_0023 = "MASTG-TEST-0023"  # Path Traversal
    MASTG_TEST_0024 = "MASTG-TEST-0024"  # Command Injection

class CweId(Enum):
    """Common Weakness Enumeration identifiers"""
    CWE_89 = "CWE-89"    # SQL Injection
    CWE_79 = "CWE-79"    # Cross-site Scripting
    CWE_94 = "CWE-94"    # Code Injection
    CWE_502 = "CWE-502"  # Object Injection
    CWE_22 = "CWE-22"    # Path Traversal
    CWE_78 = "CWE-78"    # Command Injection
    CWE_691 = "CWE-691"  # Insufficient Control Flow Management

@dataclass
class CodeVulnerability:
    """Detailed code vulnerability with exact location and values"""
    
    vuln_type: str
    location: str
    value: str
    line_number: Optional[int] = None
    severity: str = "HIGH"
    description: Optional[str] = None
    payload: Optional[str] = None
    context: Optional[str] = None
    confidence: float = 0.8
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.description is None:
            self.description = f"{self.vuln_type} vulnerability found"
    
    def _get_mastg_test_id(self) -> str:
        """Get corresponding MASTG test ID for vulnerability type"""
        mastg_mapping = {
            "sql_injection": MastgTestId.MASTG_TEST_0019.value,
            "xss_webview": MastgTestId.MASTG_TEST_0020.value,
            "object_injection": MastgTestId.MASTG_TEST_0021.value,
            "code_injection": MastgTestId.MASTG_TEST_0022.value,
            "path_traversal": MastgTestId.MASTG_TEST_0023.value,
            "command_injection": MastgTestId.MASTG_TEST_0024.value,
        }
        return mastg_mapping.get(self.vuln_type, "MASTG-TEST-UNKNOWN")
    
    def _get_cwe_id(self) -> str:
        """Get corresponding CWE ID for vulnerability type"""
        cwe_mapping = {
            "sql_injection": CweId.CWE_89.value,
            "xss_webview": CweId.CWE_79.value,
            "code_injection": CweId.CWE_94.value,
            "object_injection": CweId.CWE_502.value,
            "path_traversal": CweId.CWE_22.value,
            "command_injection": CweId.CWE_78.value,
            "unsafe_pattern": CweId.CWE_691.value,
        }
        return cwe_mapping.get(self.vuln_type, "CWE-UNKNOWN")
    
    def get_mastg_test_id(self) -> str:
        """Public method to get MASTG test ID"""
        return self._get_mastg_test_id()
    
    def get_cwe_id(self) -> str:
        """Public method to get CWE ID"""
        return self._get_cwe_id()

@dataclass
class AnalysisResult:
    """Complete analysis result structure"""
    vulnerabilities: List[CodeVulnerability]
    total_files_analyzed: int
    analysis_duration: float
    patterns_matched: Dict[str, int]
    summary: Dict[str, Any]
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
    
    def add_vulnerability(self, vulnerability: CodeVulnerability):
        """Add a vulnerability to the results"""
        self.vulnerabilities.append(vulnerability)
    
    def get_vulnerabilities_by_type(self, vuln_type: str) -> List[CodeVulnerability]:
        """Get vulnerabilities filtered by type"""
        return [v for v in self.vulnerabilities if v.vuln_type == vuln_type]
    
    def get_vulnerabilities_by_severity(self, severity: str) -> List[CodeVulnerability]:
        """Get vulnerabilities filtered by severity"""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_severity_summary(self) -> Dict[str, int]:
        """Get summary of vulnerabilities by severity"""
        severity_counts = {level.value: 0 for level in SeverityLevel}
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity.lower()] += 1
        return severity_counts
    
    def get_type_summary(self) -> Dict[str, int]:
        """Get summary of vulnerabilities by type"""
        type_counts = {}
        for vuln in self.vulnerabilities:
            type_counts[vuln.vuln_type] = type_counts.get(vuln.vuln_type, 0) + 1
        return type_counts

@dataclass
class AnalysisConfig:
    """Configuration for code quality injection analysis"""
    enable_sql_injection: bool = True
    enable_xss_analysis: bool = True
    enable_code_injection: bool = True
    enable_object_injection: bool = True
    enable_path_traversal: bool = True
    enable_command_injection: bool = True
    enable_unsafe_patterns: bool = True
    max_file_size: int = 1024 * 1024  # 1MB
    timeout_per_file: int = 30
    include_test_files: bool = False
    confidence_threshold: float = 0.5
    custom_patterns: Optional[Dict[str, List[str]]] = None
    
    def __post_init__(self):
        if self.custom_patterns is None:
            self.custom_patterns = {}

# Pattern detection metadata
@dataclass
class PatternMatch:
    """Represents a pattern match with context"""
    pattern: str
    line: str
    line_number: int
    file_path: str
    context_before: List[str] = None
    context_after: List[str] = None
    confidence: float = 0.8
    
    def __post_init__(self):
        if self.context_before is None:
            self.context_before = []
        if self.context_after is None:
            self.context_after = []

# Common constants
DEFAULT_CONFIDENCE = 0.8
DEFAULT_SEVERITY = SeverityLevel.HIGH.value
DEFAULT_TIMEOUT = 30

# MASTG control mappings
MASTG_CONTROLS = {
    MastgTestId.MASTG_TEST_0019.value: "Testing SQL Injection",
    MastgTestId.MASTG_TEST_0020.value: "Testing XSS in WebViews",
    MastgTestId.MASTG_TEST_0021.value: "Testing Object Injection",
    MastgTestId.MASTG_TEST_0022.value: "Testing Code Injection",
    MastgTestId.MASTG_TEST_0023.value: "Testing Path Traversal",
    MastgTestId.MASTG_TEST_0024.value: "Testing Command Injection",
}

# Severity level colors for display
SEVERITY_COLORS = {
    SeverityLevel.CRITICAL: "red",
    SeverityLevel.HIGH: "orange",
    SeverityLevel.MEDIUM: "yellow",
    SeverityLevel.LOW: "green",
    SeverityLevel.INFO: "blue"
} 
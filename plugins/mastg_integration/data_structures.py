#!/usr/bin/env python3
"""
MASTG Integration Data Structures Module

Core data structures, enums, and configuration classes for the MASTG Integration plugin.
Provides type-safe data handling and comprehensive configuration management.

Features:
- MASTG test case representation
- Test execution tracking and results
- Configuration management with validation
- MASVS control mapping structures
- Risk assessment and compliance data structures
"""

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pathlib import Path

class MASTGRiskLevel(Enum):
    """Risk levels for MASTG test findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

class MASTGTestStatus(Enum):
    """Execution status for MASTG tests."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    SKIPPED = "SKIPPED"

class MASTGCategory(Enum):
    """MASTG test categories."""
    CRYPTO = "CRYPTO"
    AUTH = "AUTH"
    NETWORK = "NETWORK"
    PLATFORM = "PLATFORM"
    CODE = "CODE"
    RESILIENCE = "RESILIENCE"
    STORAGE = "STORAGE"
    GENERAL = "GENERAL"

class MASTGExecutionMode(Enum):
    """Execution modes for MASTG tests."""
    SEQUENTIAL = "SEQUENTIAL"
    PARALLEL = "PARALLEL"
    HYBRID = "HYBRID"

@dataclass
class MASTGConfiguration:
    """Configuration for MASTG Integration analysis."""
    
    # Execution configuration
    execution_mode: MASTGExecutionMode = MASTGExecutionMode.HYBRID
    max_execution_time: int = 300  # 5 minutes total
    timeout_per_test: int = 30     # 30 seconds per test
    max_concurrent_tests: int = 5
    
    # Test selection configuration
    enabled_categories: List[MASTGCategory] = field(default_factory=lambda: list(MASTGCategory))
    excluded_test_ids: List[str] = field(default_factory=list)
    minimum_risk_level: MASTGRiskLevel = MASTGRiskLevel.LOW
    
    # Plugin integration configuration
    require_all_plugins: bool = False
    fallback_on_plugin_failure: bool = True
    plugin_timeout: int = 45
    
    # Reporting configuration
    detailed_reporting: bool = True
    export_results: bool = False
    output_path: Optional[str] = None
    export_format: str = "json"  # json, xml, csv
    
    # Performance configuration
    enable_caching: bool = True
    cache_ttl: int = 300  # 5 minutes
    parallel_test_limit: int = 3
    
    # Logging configuration
    verbose_logging: bool = False
    log_test_details: bool = True
    
    def __post_init__(self):
        """Validate configuration parameters."""
        if self.max_execution_time <= 0:
            raise ValueError("max_execution_time must be positive")
        if self.timeout_per_test <= 0:
            raise ValueError("timeout_per_test must be positive")
        if self.max_concurrent_tests <= 0:
            raise ValueError("max_concurrent_tests must be positive")
        if self.output_path and not Path(self.output_path).parent.exists():
            raise ValueError(f"Output directory does not exist: {Path(self.output_path).parent}")

@dataclass
class MASTGTestCase:
    """Represents a MASTG test case with metadata and execution parameters."""
    
    # Test identification
    test_id: str
    title: str
    description: str
    
    # Test categorization
    category: MASTGCategory
    masvs_controls: List[str]
    mastg_sections: List[str] = field(default_factory=list)
    
    # Execution configuration
    plugin_mapping: Optional[str] = None
    execution_method: str = "plugin"  # plugin, custom, manual
    timeout_override: Optional[int] = None
    
    # Test metadata
    difficulty: str = "MEDIUM"  # EASY, MEDIUM, HARD
    automation_level: str = "FULL"  # FULL, PARTIAL, MANUAL
    prerequisites: List[str] = field(default_factory=list)
    
    # Risk assessment
    base_risk_level: MASTGRiskLevel = MASTGRiskLevel.MEDIUM
    impact_description: str = ""
    
    # Validation
    expected_findings: List[str] = field(default_factory=list)
    false_positive_indicators: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate test case parameters."""
        if not self.test_id or not self.test_id.strip():
            raise ValueError("test_id cannot be empty")
        if not self.title or not self.title.strip():
            raise ValueError("title cannot be empty")
        if not self.masvs_controls:
            raise ValueError("masvs_controls cannot be empty")

@dataclass
class MASTGTestEvidence:
    """Evidence collected during MASTG test execution."""
    
    # Evidence data
    evidence_type: str  # file, log, screenshot, data
    evidence_content: str
    evidence_path: Optional[str] = None
    
    # Evidence metadata
    collection_timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)
    relevance_score: float = 1.0
    confidence_level: float = 1.0
    
    # Evidence classification
    is_primary_evidence: bool = True
    supports_finding: bool = True
    contradicts_finding: bool = False
    
    # Additional context
    collection_method: str = "automated"
    validation_status: str = "pending"  # pending, validated, invalid
    notes: str = ""

@dataclass
class MASTGFinding:
    """Represents a security finding from MASTG test execution."""
    
    # Finding identification
    finding_id: str
    finding_type: str
    title: str
    description: str
    
    # Risk assessment
    risk_level: MASTGRiskLevel
    confidence_score: float
    impact_assessment: str
    
    # Technical details
    affected_components: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    cwe_references: List[str] = field(default_factory=list)
    
    # Evidence
    evidence: List[MASTGTestEvidence] = field(default_factory=list)
    technical_details: Dict[str, Any] = field(default_factory=dict)
    
    # Remediation
    remediation_guidance: str = ""
    remediation_effort: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    remediation_priority: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Compliance mapping
    masvs_violations: List[str] = field(default_factory=list)
    compliance_impact: str = ""

@dataclass
class MASTGTestExecution:
    """Represents the execution and results of a MASTG test case."""
    
    # Test reference
    test_case: MASTGTestCase
    
    # Execution metadata
    execution_id: str
    start_time: datetime.datetime
    end_time: Optional[datetime.datetime] = None
    execution_duration: Optional[float] = None
    
    # Execution status
    status: MASTGTestStatus = MASTGTestStatus.PENDING
    result: str = "UNKNOWN"
    
    # Results data
    findings: List[MASTGFinding] = field(default_factory=list)
    evidence: List[MASTGTestEvidence] = field(default_factory=list)
    
    # Plugin integration
    plugin_used: Optional[str] = None
    plugin_version: Optional[str] = None
    plugin_execution_time: Optional[float] = None
    
    # Error handling
    error_message: Optional[str] = None
    error_details: Dict[str, Any] = field(default_factory=dict)
    warning_messages: List[str] = field(default_factory=list)
    
    # Quality metrics
    execution_quality: str = "GOOD"  # EXCELLENT, GOOD, FAIR, POOR
    result_confidence: float = 1.0
    validation_status: str = "pending"  # pending, validated, disputed
    
    # Additional metadata
    execution_context: Dict[str, Any] = field(default_factory=dict)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    
    def mark_completed(self, status: MASTGTestStatus, result: str = ""):
        """Mark test execution as completed with status and result."""
        self.end_time = datetime.datetime.now()
        self.execution_duration = (self.end_time - self.start_time).total_seconds()
        self.status = status
        if result:
            self.result = result
    
    def add_finding(self, finding: MASTGFinding):
        """Add a security finding to the test execution."""
        self.findings.append(finding)
        
        # Update overall result based on findings
        if finding.risk_level in [MASTGRiskLevel.CRITICAL, MASTGRiskLevel.HIGH]:
            self.result = "SECURITY_ISSUES_FOUND"
        elif self.result == "UNKNOWN":
            self.result = "FINDINGS_DETECTED"
    
    def add_evidence(self, evidence: MASTGTestEvidence):
        """Add evidence to the test execution."""
        self.evidence.append(evidence)
    
    def get_highest_risk_level(self) -> MASTGRiskLevel:
        """Get the highest risk level among all findings."""
        if not self.findings:
            return MASTGRiskLevel.UNKNOWN
        
        risk_order = {
            MASTGRiskLevel.CRITICAL: 5,
            MASTGRiskLevel.HIGH: 4,
            MASTGRiskLevel.MEDIUM: 3,
            MASTGRiskLevel.LOW: 2,
            MASTGRiskLevel.INFO: 1,
            MASTGRiskLevel.UNKNOWN: 0
        }
        
        highest_risk = max(self.findings, key=lambda f: risk_order.get(f.risk_level, 0))
        return highest_risk.risk_level
    
    def get_total_findings_count(self) -> int:
        """Get total number of findings."""
        return len(self.findings)
    
    def get_findings_by_risk_level(self, risk_level: MASTGRiskLevel) -> List[MASTGFinding]:
        """Get findings filtered by risk level."""
        return [finding for finding in self.findings if finding.risk_level == risk_level]

@dataclass
class MASTGComplianceSummary:
    """Summary of MASTG compliance analysis results."""
    
    # Test execution summary
    total_tests: int
    executed_tests: int
    passed_tests: int
    failed_tests: int
    error_tests: int
    skipped_tests: int
    
    # Risk assessment summary
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    
    # MASVS compliance
    masvs_controls_tested: List[str]
    masvs_controls_passed: List[str]
    masvs_controls_failed: List[str]
    
    # Execution metadata
    total_execution_time: float
    average_test_time: float
    plugin_availability: Dict[str, bool]
    
    # Overall assessment
    overall_compliance_score: float
    compliance_level: str  # EXCELLENT, GOOD, FAIR, POOR
    recommendation_summary: List[str]
    
    # Detailed breakdown
    category_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    execution_details: Dict[str, Any] = field(default_factory=dict)

@dataclass 
class PluginAvailabilityInfo:
    """Information about plugin availability and status."""
    
    plugin_name: str
    is_available: bool
    version: Optional[str] = None
    load_error: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    last_test_time: Optional[datetime.datetime] = None
    performance_rating: str = "UNKNOWN"  # EXCELLENT, GOOD, FAIR, POOR, UNKNOWN

# Helper functions for data structure manipulation
def create_test_execution(test_case: MASTGTestCase, execution_id: str) -> MASTGTestExecution:
    """Create a new test execution instance."""
    return MASTGTestExecution(
        test_case=test_case,
        execution_id=execution_id,
        start_time=datetime.datetime.now()
    )

def create_finding(finding_id: str, title: str, description: str, 
                  risk_level: MASTGRiskLevel, confidence_score: float) -> MASTGFinding:
    """Create a new security finding instance."""
    return MASTGFinding(
        finding_id=finding_id,
        finding_type="security_vulnerability",
        title=title,
        description=description,
        risk_level=risk_level,
        confidence_score=confidence_score,
        impact_assessment="Security vulnerability detected"
    )

def create_evidence(evidence_type: str, content: str, path: Optional[str] = None) -> MASTGTestEvidence:
    """Create a new evidence instance."""
    return MASTGTestEvidence(
        evidence_type=evidence_type,
        evidence_content=content,
        evidence_path=path
    ) 
#!/usr/bin/env python3
"""
Data Structures for Network Communication Tests Plugin

This module defines the core data structures used throughout the network communication
tests plugin for consistent data handling and type safety.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

class TestStatus(Enum):
    """Test execution status"""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    ERROR = "error"
    SKIPPED = "skipped"

class SeverityLevel(Enum):
    """Severity level classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class NetworkTestType(Enum):
    """Type of network communication test"""
    NETWORK_SECURITY_CONFIG = "network_security_config"
    CERTIFICATE_PINNING = "certificate_pinning"
    CLEARTEXT_TRAFFIC = "cleartext_traffic"
    URL_SCHEMES = "url_schemes"
    TLS_CONFIGURATION = "tls_configuration"

class MasvsControl(Enum):
    """MASVS Network control identifiers"""
    MASVS_NETWORK_1 = "MASVS-NETWORK-1"
    MASVS_NETWORK_2 = "MASVS-NETWORK-2"

@dataclass
class NetworkTestFinding:
    """Individual network security test finding"""
    test_type: NetworkTestType
    title: str
    description: str
    severity: SeverityLevel
    status: TestStatus
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    masvs_control: Optional[MasvsControl] = None
    confidence: float = 0.0
    cwe_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary format"""
        return {
            'test_type': self.test_type.value,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'status': self.status.value,
            'evidence': self.evidence,
            'recommendations': self.recommendations,
            'masvs_control': self.masvs_control.value if self.masvs_control else None,
            'confidence': self.confidence,
            'cwe_id': self.cwe_id
        }

@dataclass
class NetworkTestResult:
    """Individual network test result"""
    test: str
    test_type: NetworkTestType
    status: TestStatus
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format"""
        return {
            'test': self.test,
            'test_type': self.test_type.value,
            'status': self.status.value,
            'issues': self.issues,
            'recommendations': self.recommendations,
            'evidence': self.evidence,
            'execution_time': self.execution_time,
            'error_message': self.error_message
        }

@dataclass
class NetworkCommunicationAnalysisResult:
    """Complete network communication analysis results"""
    overall_status: TestStatus
    overall_severity: SeverityLevel
    test_results: List[NetworkTestResult] = field(default_factory=list)
    findings: List[NetworkTestFinding] = field(default_factory=list)
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    warning_tests: int = 0
    error_tests: int = 0
    skipped_tests: int = 0
    execution_time: float = 0.0
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    
    def calculate_statistics(self):
        """Calculate test statistics from results"""
        self.total_tests = len(self.test_results)
        self.passed_tests = len([r for r in self.test_results if r.status == TestStatus.PASS])
        self.failed_tests = len([r for r in self.test_results if r.status == TestStatus.FAIL])
        self.warning_tests = len([r for r in self.test_results if r.status == TestStatus.WARNING])
        self.error_tests = len([r for r in self.test_results if r.status == TestStatus.ERROR])
        self.skipped_tests = len([r for r in self.test_results if r.status == TestStatus.SKIPPED])
        
        # Determine overall status and severity
        if self.failed_tests > 0 or self.error_tests > 0:
            self.overall_status = TestStatus.FAIL
            if any(f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] for f in self.findings):
                self.overall_severity = SeverityLevel.HIGH
            else:
                self.overall_severity = SeverityLevel.MEDIUM
        elif self.warning_tests > 0:
            self.overall_status = TestStatus.WARNING
            self.overall_severity = SeverityLevel.MEDIUM
        else:
            self.overall_status = TestStatus.PASS
            self.overall_severity = SeverityLevel.INFO
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format"""
        return {
            'overall_status': self.overall_status.value,
            'overall_severity': self.overall_severity.value,
            'test_results': [result.to_dict() for result in self.test_results],
            'findings': [finding.to_dict() for finding in self.findings],
            'statistics': {
                'total_tests': self.total_tests,
                'passed_tests': self.passed_tests,
                'failed_tests': self.failed_tests,
                'warning_tests': self.warning_tests,
                'error_tests': self.error_tests,
                'skipped_tests': self.skipped_tests
            },
            'execution_time': self.execution_time,
            'analysis_timestamp': self.analysis_timestamp.isoformat()
        }

@dataclass
class NetworkCommunicationConfig:
    """Configuration for network communication tests"""
    enable_network_security_config_test: bool = True
    enable_certificate_pinning_test: bool = True
    enable_cleartext_traffic_test: bool = True
    enable_url_schemes_test: bool = True
    enable_tls_configuration_test: bool = True
    timeout_seconds: int = 45
    max_evidence_items: int = 10
    confidence_threshold: float = 0.5
    enable_dynamic_testing: bool = False
    require_device_access: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary format"""
        return {
            'enable_network_security_config_test': self.enable_network_security_config_test,
            'enable_certificate_pinning_test': self.enable_certificate_pinning_test,
            'enable_cleartext_traffic_test': self.enable_cleartext_traffic_test,
            'enable_url_schemes_test': self.enable_url_schemes_test,
            'enable_tls_configuration_test': self.enable_tls_configuration_test,
            'timeout_seconds': self.timeout_seconds,
            'max_evidence_items': self.max_evidence_items,
            'confidence_threshold': self.confidence_threshold,
            'enable_dynamic_testing': self.enable_dynamic_testing,
            'require_device_access': self.require_device_access
        } 
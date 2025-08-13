"""
Data structures for external service analysis.

This module defines the core data structures used throughout the external service
analysis plugin for cloud services, credentials, network security, and configuration analysis.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

class ServiceType(Enum):
    """Types of external services that can be detected."""
    AWS_S3 = "aws_s3"
    FIREBASE = "firebase"
    GOOGLE_CLOUD = "google_cloud"
    AZURE = "azure"
    DROPBOX = "dropbox"
    BOX = "box"
    ONEDRIVE = "onedrive"
    PAYMENT_GATEWAY = "payment_gateway"
    SOCIAL_MEDIA = "social_media"
    ANALYTICS = "analytics"
    ADVERTISING = "advertising"
    REST_API = "rest_api"
    SOAP_API = "soap_api"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    UNKNOWN = "unknown"

class SeverityLevel(Enum):
    """Severity levels for external service vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class CredentialType(Enum):
    """Types of credentials that can be exposed."""
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    SECRET_KEY = "secret_key"
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    CONNECTION_STRING = "connection_string"
    OAUTH_TOKEN = "oauth_token"
    JWT_TOKEN = "jwt_token"
    DATABASE_URL = "database_url"

class NetworkSecurityLevel(Enum):
    """Network security levels for external service connections."""
    SECURE = "secure"
    INSECURE = "insecure"
    MIXED = "mixed"
    UNKNOWN = "unknown"

@dataclass
class ServicePattern:
    """Represents a pattern for detecting external services."""
    service_type: ServiceType
    patterns: List[str]
    description: str
    risk_factors: List[str]
    confidence_base: float = 0.8
    severity: SeverityLevel = SeverityLevel.MEDIUM

@dataclass
class CredentialExposure:
    """Represents exposed credentials in the application."""
    credential_type: CredentialType
    value: str
    location: str
    file_path: str
    line_number: Optional[int] = None
    context: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.HIGH
    confidence: float = 0.0

@dataclass
class ServiceEndpoint:
    """Represents an external service endpoint."""
    url: str
    service_type: ServiceType
    method: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    authentication: Optional[str] = None
    encryption: Optional[str] = None
    location: str = ""
    confidence: float = 0.0

@dataclass
class NetworkSecurityIssue:
    """Represents a network security issue."""
    issue_type: str
    description: str
    endpoint: str
    severity: SeverityLevel
    recommendation: str
    cwe: Optional[str] = None
    masvs_control: Optional[str] = None
    confidence: float = 0.0

@dataclass
class ConfigurationIssue:
    """Represents a configuration security issue."""
    config_type: str
    file_path: str
    issue_description: str
    severity: SeverityLevel
    recommendation: str
    line_number: Optional[int] = None
    context: Optional[str] = None
    confidence: float = 0.0

@dataclass
class ServicePermission:
    """Represents service-related permissions."""
    permission_name: str
    service_type: ServiceType
    description: str
    risk_level: SeverityLevel
    justification: Optional[str] = None
    manifest_location: Optional[str] = None

@dataclass
class RiskAssessment:
    """Represents overall risk assessment for external services."""
    risk_score: int = 0
    risk_level: str = "LOW"
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    recommendations: List[str] = field(default_factory=list)
    masvs_controls: List[str] = field(default_factory=list)

@dataclass
class ExternalServiceVulnerability:
    """Represents a comprehensive external service vulnerability."""
    vulnerability_id: str
    title: str
    description: str
    severity: SeverityLevel
    service_type: ServiceType
    location: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    masvs_control: Optional[str] = None
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class ExternalServiceAnalysisResult:
    """Complete result of external service analysis."""
    # Service detection results
    detected_services: List[ServiceEndpoint] = field(default_factory=list)
    service_patterns_matched: Dict[ServiceType, int] = field(default_factory=dict)
    
    # Security issues
    vulnerabilities: List[ExternalServiceVulnerability] = field(default_factory=list)
    credential_exposures: List[CredentialExposure] = field(default_factory=list)
    network_security_issues: List[NetworkSecurityIssue] = field(default_factory=list)
    configuration_issues: List[ConfigurationIssue] = field(default_factory=list)
    
    # Permissions and compliance
    service_permissions: List[ServicePermission] = field(default_factory=list)
    masvs_controls: List[str] = field(default_factory=list)
    
    # Risk assessment
    risk_assessment: RiskAssessment = field(default_factory=RiskAssessment)
    
    # Analysis metadata
    analysis_duration: float = 0.0
    files_analyzed: int = 0
    total_findings: int = 0
    package_name: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    def add_vulnerability(self, vulnerability: ExternalServiceVulnerability):
        """Add a vulnerability to the analysis results."""
        self.vulnerabilities.append(vulnerability)
        self.total_findings += 1
        
        # Update risk assessment counters
        if vulnerability.severity == SeverityLevel.CRITICAL:
            self.risk_assessment.critical_issues += 1
        elif vulnerability.severity == SeverityLevel.HIGH:
            self.risk_assessment.high_issues += 1
        elif vulnerability.severity == SeverityLevel.MEDIUM:
            self.risk_assessment.medium_issues += 1
        elif vulnerability.severity == SeverityLevel.LOW:
            self.risk_assessment.low_issues += 1
    
    def add_credential_exposure(self, credential: CredentialExposure):
        """Add a credential exposure to the analysis results."""
        self.credential_exposures.append(credential)
        self.total_findings += 1
    
    def add_network_security_issue(self, issue: NetworkSecurityIssue):
        """Add a network security issue to the analysis results."""
        self.network_security_issues.append(issue)
        self.total_findings += 1
    
    def add_configuration_issue(self, issue: ConfigurationIssue):
        """Add a configuration issue to the analysis results."""
        self.configuration_issues.append(issue)
        self.total_findings += 1
    
    def get_total_issues_by_severity(self) -> Dict[str, int]:
        """Get total issues count by severity level."""
        return {
            "critical": self.risk_assessment.critical_issues,
            "high": self.risk_assessment.high_issues,
            "medium": self.risk_assessment.medium_issues,
            "low": self.risk_assessment.low_issues
        }
    
    def get_service_summary(self) -> Dict[str, Any]:
        """Get a summary of detected services."""
        service_counts = {}
        for endpoint in self.detected_services:
            service_type = endpoint.service_type.value
            service_counts[service_type] = service_counts.get(service_type, 0) + 1
        
        return {
            "total_services": len(self.detected_services),
            "service_types": len(service_counts),
            "service_breakdown": service_counts
        }

# Confidence calculation context
@dataclass
class AnalysisContext:
    """Context information for confidence calculation."""
    file_type: str = ""
    file_path: str = ""
    analysis_depth: str = "basic"  # basic, medium, deep
    validation_sources: List[str] = field(default_factory=list)
    cross_references: int = 0
    pattern_matches: int = 0

# Error handling
class ExternalServiceAnalysisError(Exception):
    """Exception raised during external service analysis."""
    
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.context = context or {} 
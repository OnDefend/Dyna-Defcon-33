"""
MITMProxy Network Analysis Data Structures

This module contains all data structures, dataclasses, and enums used
throughout the mitmproxy network analysis plugin components.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum
from datetime import datetime

class TrafficType(Enum):
    """Types of network traffic."""
    HTTP = "http"
    HTTPS = "https"
    API = "api"
    WEBSOCKET = "websocket"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    STREAMING = "streaming"
    OTHER = "other"

class SecurityLevel(Enum):
    """Security levels for network communications."""
    SECURE = "secure"
    ACCEPTABLE = "acceptable"
    SUSPICIOUS = "suspicious"
    INSECURE = "insecure"
    CRITICAL = "critical"

class CertificateStatus(Enum):
    """SSL/TLS certificate status."""
    VALID = "valid"
    EXPIRED = "expired"
    SELF_SIGNED = "self_signed"
    INVALID_CHAIN = "invalid_chain"
    WEAK_CIPHER = "weak_cipher"
    MISSING = "missing"

class PinningStrength(Enum):
    """Certificate pinning strength levels."""
    NONE = "none"
    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"
    VERY_STRONG = "very_strong"

class VulnerabilityType(Enum):
    """Network vulnerability types."""
    INSECURE_HTTP = "insecure_http"
    WEAK_TLS = "weak_tls"
    CERTIFICATE_ISSUES = "certificate_issues"
    DATA_EXPOSURE = "data_exposure"
    INJECTION_RISK = "injection_risk"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    NO_PINNING = "no_pinning"
    WEAK_PINNING = "weak_pinning"

@dataclass
class NetworkFlow:
    """Network traffic flow data."""
    id: str
    method: str
    url: str
    host: str
    port: int
    scheme: str
    path: str
    timestamp: datetime
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_body: str = ""
    response_code: int = 0
    response_size: int = 0
    duration: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'id': self.id,
            'method': self.method,
            'url': self.url,
            'host': self.host,
            'port': self.port,
            'scheme': self.scheme,
            'path': self.path,
            'timestamp': self.timestamp.isoformat(),
            'request_headers': self.request_headers,
            'response_headers': self.response_headers,
            'request_body': self.request_body,
            'response_body': self.response_body,
            'response_code': self.response_code,
            'response_size': self.response_size,
            'duration': self.duration
        }

@dataclass
class CertificateInfo:
    """SSL/TLS certificate information."""
    host: str
    subject: str
    issuer: str
    valid_from: datetime
    valid_to: datetime
    serial_number: str
    fingerprint: str
    algorithm: str
    key_size: int
    status: str
    chain_length: int
    vulnerabilities: List[str] = field(default_factory=list)
    security_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'host': self.host,
            'subject': self.subject,
            'issuer': self.issuer,
            'valid_from': self.valid_from.isoformat(),
            'valid_to': self.valid_to.isoformat(),
            'serial_number': self.serial_number,
            'fingerprint': self.fingerprint,
            'algorithm': self.algorithm,
            'key_size': self.key_size,
            'status': self.status,
            'chain_length': self.chain_length,
            'vulnerabilities': self.vulnerabilities,
            'security_score': self.security_score
        }

@dataclass
class APIEndpoint:
    """API endpoint information."""
    url: str
    method: str
    host: str
    path: str
    parameters: List[str]
    authentication_type: str
    security_score: float
    vulnerabilities: List[str] = field(default_factory=list)
    request_count: int = 1
    response_codes: List[int] = field(default_factory=list)
    data_types: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'url': self.url,
            'method': self.method,
            'host': self.host,
            'path': self.path,
            'parameters': self.parameters,
            'authentication_type': self.authentication_type,
            'security_score': self.security_score,
            'vulnerabilities': self.vulnerabilities,
            'request_count': self.request_count,
            'response_codes': self.response_codes,
            'data_types': self.data_types
        }

@dataclass
class SecurityIssue:
    """Network security issue."""
    issue_type: str
    severity: str
    description: str
    affected_urls: List[str]
    evidence: List[str]
    confidence: float
    impact: str
    remediation: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'issue_type': self.issue_type,
            'severity': self.severity,
            'description': self.description,
            'affected_urls': self.affected_urls,
            'evidence': self.evidence,
            'confidence': self.confidence,
            'impact': self.impact,
            'remediation': self.remediation
        }

@dataclass
class TrafficSummary:
    """Network traffic analysis summary."""
    total_requests: int
    unique_hosts: int
    http_requests: int
    https_requests: int
    api_requests: int
    data_uploaded: int
    data_downloaded: int
    average_response_time: float
    security_score: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'total_requests': self.total_requests,
            'unique_hosts': self.unique_hosts,
            'http_requests': self.http_requests,
            'https_requests': self.https_requests,
            'api_requests': self.api_requests,
            'data_uploaded': self.data_uploaded,
            'data_downloaded': self.data_downloaded,
            'average_response_time': self.average_response_time,
            'security_score': self.security_score
        }

@dataclass
class PinningAnalysis:
    """Certificate pinning analysis results."""
    pinning_detected: bool
    pinning_methods: List[str]
    pinning_strength: str
    bypassed: bool
    vulnerabilities: List[str] = field(default_factory=list)
    security_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'pinning_detected': self.pinning_detected,
            'pinning_methods': self.pinning_methods,
            'pinning_strength': self.pinning_strength,
            'bypassed': self.bypassed,
            'vulnerabilities': self.vulnerabilities,
            'security_score': self.security_score
        }

@dataclass
class NetworkAnalysisResult:
    """Complete network analysis results."""
    traffic_summary: TrafficSummary
    flows: List[NetworkFlow]
    certificates: List[CertificateInfo]
    api_endpoints: List[APIEndpoint]
    security_issues: List[SecurityIssue]
    pinning_analysis: PinningAnalysis
    har_file_path: Optional[str]
    risk_score: int
    recommendations: List[str]
    masvs_controls: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'traffic_summary': self.traffic_summary.to_dict(),
            'flows': [flow.to_dict() for flow in self.flows],
            'certificates': [cert.to_dict() for cert in self.certificates],
            'api_endpoints': [endpoint.to_dict() for endpoint in self.api_endpoints],
            'security_issues': [issue.to_dict() for issue in self.security_issues],
            'pinning_analysis': self.pinning_analysis.to_dict(),
            'har_file_path': self.har_file_path,
            'risk_score': self.risk_score,
            'recommendations': self.recommendations,
            'masvs_controls': self.masvs_controls
        }

@dataclass
class MitmproxyConfig:
    """MITMProxy configuration."""
    proxy_port: int = 8080
    listen_host: str = "0.0.0.0"
    capture_file: str = ""
    har_file: str = ""
    script_file: str = ""
    capture_duration: int = 30
    max_flows: int = 1000
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'proxy_port': self.proxy_port,
            'listen_host': self.listen_host,
            'capture_file': self.capture_file,
            'har_file': self.har_file,
            'script_file': self.script_file,
            'capture_duration': self.capture_duration,
            'max_flows': self.max_flows
        }

class NetworkPatterns:
    """Network security pattern types for configuration."""
    HTTP_URLS = "http_urls"
    API_KEYS = "api_keys"
    TOKENS = "tokens"
    PASSWORDS = "passwords"
    SECRETS = "secrets"
    PRIVATE_IPS = "private_ips"
    SQL_INJECTION = "sql_injection"
    XSS_PATTERNS = "xss_patterns"

class MAVSNetworkControls:
    """MASVS control mappings for network security."""
    NETWORK_1 = "MSTG-NETWORK-01"  # Secure network communication
    NETWORK_2 = "MSTG-NETWORK-02"  # TLS settings
    NETWORK_3 = "MSTG-NETWORK-03"  # Certificate pinning
    NETWORK_4 = "MSTG-NETWORK-04"  # Certificate validation
    CODE_8 = "MSTG-CODE-8"         # Code injection via network
    PLATFORM_1 = "MSTG-PLATFORM-01"  # Platform APIs

class CWENetworkCategories:
    """Common Weakness Enumeration categories for network vulnerabilities."""
    CLEARTEXT_TRANSMISSION = "CWE-319"        # Cleartext Transmission of Sensitive Information
    IMPROPER_CERT_VALIDATION = "CWE-295"      # Improper Certificate Validation
    WEAK_CRYPTO = "CWE-326"                   # Inadequate Encryption Strength
    MISSING_ENCRYPTION = "CWE-311"            # Missing Encryption of Sensitive Data
    INJECTION = "CWE-74"                      # Improper Neutralization of Special Elements
    XSS = "CWE-79"                           # Cross-site Scripting
    SQL_INJECTION = "CWE-89"                  # SQL Injection
    SENSITIVE_INFO_EXPOSURE = "CWE-200"       # Information Exposure

class TrafficClassification:
    """Traffic classification categories."""
    SECURE = "secure"
    ACCEPTABLE = "acceptable"
    SUSPICIOUS = "suspicious"
    INSECURE = "insecure"
    CRITICAL = "critical" 
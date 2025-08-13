"""
Token Replay Analysis Data Structures

This module contains all data structures, dataclasses, and enums used
throughout the token replay analysis plugin components.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum
from datetime import datetime

class TokenType(Enum):
    """Types of authentication tokens."""
    JWT = "jwt"
    BEARER = "bearer"
    OAUTH = "oauth"
    SESSION_ID = "session_id"
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    CSRF_TOKEN = "csrf_token"
    SAML_TOKEN = "saml_token"
    CUSTOM = "custom"

class TokenStrength(Enum):
    """Token strength levels."""
    VERY_WEAK = "very_weak"
    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"
    VERY_STRONG = "very_strong"

class TokenVulnerabilityType(Enum):
    """Types of token vulnerabilities."""
    REPLAY_ATTACK = "replay_attack"
    WEAK_TOKEN = "weak_token"
    NO_EXPIRY = "no_expiry"
    EXCESSIVE_EXPIRY = "excessive_expiry"
    INSECURE_STORAGE = "insecure_storage"
    PREDICTABLE_TOKEN = "predictable_token"
    INSUFFICIENT_ENTROPY = "insufficient_entropy"
    WEAK_SIGNING = "weak_signing"
    MISSING_SIGNATURE = "missing_signature"
    HARDCODED_SECRET = "hardcoded_secret"

class SessionSecurityLevel(Enum):
    """Session security levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

class JWTVulnerabilityType(Enum):
    """JWT-specific vulnerability types."""
    NONE_ALGORITHM = "none_algorithm"
    WEAK_ALGORITHM = "weak_algorithm"
    MISSING_SIGNATURE = "missing_signature"
    WEAK_SECRET = "weak_secret"
    EXCESSIVE_CLAIMS = "excessive_claims"
    NO_EXPIRY = "no_expiry"
    ALGORITHM_CONFUSION = "algorithm_confusion"

@dataclass
class TokenInfo:
    """Information about a discovered token."""
    token_type: str
    value: str
    location: str
    source: str
    security_issues: List[str] = field(default_factory=list)
    strength: str = "unknown"
    entropy: float = 0.0
    length: int = 0
    character_set: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'token_type': self.token_type,
            'value': self.value,
            'location': self.location,
            'source': self.source,
            'security_issues': self.security_issues,
            'strength': self.strength,
            'entropy': self.entropy,
            'length': self.length,
            'character_set': self.character_set
        }

@dataclass
class JWTAnalysis:
    """JWT token analysis results."""
    token: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    algorithm: str
    expiry: Optional[datetime]
    issued_at: Optional[datetime]
    not_before: Optional[datetime]
    vulnerabilities: List[str] = field(default_factory=list)
    security_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'token': self.token,
            'header': self.header,
            'payload': self.payload,
            'signature': self.signature,
            'algorithm': self.algorithm,
            'expiry': self.expiry.isoformat() if self.expiry else None,
            'issued_at': self.issued_at.isoformat() if self.issued_at else None,
            'not_before': self.not_before.isoformat() if self.not_before else None,
            'vulnerabilities': self.vulnerabilities,
            'security_score': self.security_score
        }

@dataclass
class SessionAnalysis:
    """Session management analysis results."""
    session_id: str
    session_tokens: List[TokenInfo]
    timeout_configured: bool
    secure_flags: List[str]
    vulnerabilities: List[str] = field(default_factory=list)
    security_level: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'session_id': self.session_id,
            'session_tokens': [token.to_dict() for token in self.session_tokens],
            'timeout_configured': self.timeout_configured,
            'secure_flags': self.secure_flags,
            'vulnerabilities': self.vulnerabilities,
            'security_level': self.security_level
        }

@dataclass
class TokenReplayVulnerability:
    """Token replay vulnerability details."""
    token_info: TokenInfo
    vulnerability_type: str
    attack_vector: str
    impact: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    mitigation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'token_info': self.token_info.to_dict(),
            'vulnerability_type': self.vulnerability_type,
            'attack_vector': self.attack_vector,
            'impact': self.impact,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'mitigation': self.mitigation
        }

@dataclass
class TokenExpiryIssue:
    """Token expiry related security issue."""
    token_info: TokenInfo
    issue_type: str
    expiry_time: Optional[datetime]
    recommended_expiry: str
    risk_level: str
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'token_info': self.token_info.to_dict(),
            'issue_type': self.issue_type,
            'expiry_time': self.expiry_time.isoformat() if self.expiry_time else None,
            'recommended_expiry': self.recommended_expiry,
            'risk_level': self.risk_level,
            'description': self.description
        }

@dataclass
class WeakTokenIssue:
    """Weak token security issue."""
    token_info: TokenInfo
    weakness_type: str
    weakness_description: str
    entropy_score: float
    strength_score: float
    remediation: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'token_info': self.token_info.to_dict(),
            'weakness_type': self.weakness_type,
            'weakness_description': self.weakness_description,
            'entropy_score': self.entropy_score,
            'strength_score': self.strength_score,
            'remediation': self.remediation
        }

@dataclass
class TokenSecurityAnalysisResult:
    """Complete token security analysis results."""
    discovered_tokens: List[TokenInfo]
    jwt_analysis: List[JWTAnalysis]
    session_analysis: List[SessionAnalysis]
    replay_vulnerabilities: List[TokenReplayVulnerability]
    expiry_issues: List[TokenExpiryIssue]
    weak_tokens: List[WeakTokenIssue]
    risk_score: int
    recommendations: List[str]
    masvs_controls: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'discovered_tokens': [token.to_dict() for token in self.discovered_tokens],
            'jwt_analysis': [analysis.to_dict() for analysis in self.jwt_analysis],
            'session_analysis': [analysis.to_dict() for analysis in self.session_analysis],
            'replay_vulnerabilities': [vuln.to_dict() for vuln in self.replay_vulnerabilities],
            'expiry_issues': [issue.to_dict() for issue in self.expiry_issues],
            'weak_tokens': [token.to_dict() for token in self.weak_tokens],
            'risk_score': self.risk_score,
            'recommendations': self.recommendations,
            'masvs_controls': self.masvs_controls
        }

@dataclass
class TokenAnalysisContext:
    """Context information for token analysis."""
    apk_path: str
    package_name: str
    can_capture_traffic: bool = False
    has_network_permission: bool = False
    deep_analysis_mode: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'apk_path': self.apk_path,
            'package_name': self.package_name,
            'can_capture_traffic': self.can_capture_traffic,
            'has_network_permission': self.has_network_permission,
            'deep_analysis_mode': self.deep_analysis_mode
        }

class TokenPatterns:
    """Token pattern types for configuration."""
    JWT = "jwt"
    BEARER = "bearer"
    OAUTH = "oauth"
    SESSION_ID = "session_id"
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    CSRF_TOKEN = "csrf_token"
    SAML_TOKEN = "saml_token"

class MAVSAuthControls:
    """MASVS control mappings for authentication."""
    AUTH_1 = "MSTG-AUTH-01"  # Authentication architecture
    AUTH_2 = "MSTG-AUTH-02"  # Remote authentication
    AUTH_3 = "MSTG-AUTH-03"  # Session management
    AUTH_4 = "MSTG-AUTH-04"  # Token-based authentication
    AUTH_5 = "MSTG-AUTH-05"  # Session timeout
    NETWORK_1 = "MSTG-NETWORK-01"  # Secure network communication

class CWEAuthCategories:
    """Common Weakness Enumeration categories for authentication vulnerabilities."""
    WEAK_AUTHENTICATION = "CWE-287"           # Improper Authentication
    SESSION_FIXATION = "CWE-384"              # Session Fixation
    INSUFFICIENT_SESSION_EXPIRY = "CWE-613"   # Insufficient Session Expiration
    SESSION_ID_NOT_RENEWED = "CWE-384"        # Session Fixation
    WEAK_SESSION_ID = "CWE-330"               # Use of Insufficiently Random Values
    PREDICTABLE_TOKEN = "CWE-340"             # Generation of Predictable Numbers or Identifiers
    WEAK_CRYPTO = "CWE-326"                   # Inadequate Encryption Strength
    HARDCODED_CREDENTIALS = "CWE-798"         # Use of Hard-coded Credentials

class TokenWeaknessPatterns:
    """Patterns for detecting weak tokens."""
    SEQUENTIAL = "sequential"
    TIMESTAMP = "timestamp"
    SIMPLE_HASH = "simple_hash"
    PREDICTABLE = "predictable"
    LOW_ENTROPY = "low_entropy"
    SHORT_LENGTH = "short_length" 
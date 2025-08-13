"""
Privacy Controls Analysis Data Structures

Core data classes for privacy vulnerability representation and configuration.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum

class PrivacyDataType(Enum):
    """Privacy-sensitive data types"""
    LOCATION = "location"
    CONTACTS = "contacts"
    CALENDAR = "calendar"
    CAMERA = "camera"
    MICROPHONE = "microphone"
    SMS = "sms"
    PHONE = "phone"
    STORAGE = "storage"
    DEVICE_ID = "device_id"
    ACCOUNT = "account"
    BIOMETRIC = "biometric"
    CALL_LOG = "call_log"
    BROWSER_HISTORY = "browser_history"
    UNKNOWN = "unknown"

class ConsentType(Enum):
    """Types of privacy consent mechanisms"""
    EXPLICIT = "explicit"
    IMPLIED = "implied"
    OPT_IN = "opt_in"
    OPT_OUT = "opt_out"
    NONE = "none"

class PrivacySeverity(Enum):
    """Privacy violation severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class PrivacyVulnerability:
    """
    Represents a privacy control vulnerability with MASTG and GDPR compliance mapping.
    """
    vuln_type: str
    location: str
    value: str
    privacy_data: Optional[str] = None
    third_party: Optional[str] = None
    line_number: Optional[int] = None
    severity: str = "HIGH"
    data_type: PrivacyDataType = PrivacyDataType.UNKNOWN
    consent_type: ConsentType = ConsentType.NONE
    processing_purpose: Optional[str] = None
    retention_period: Optional[str] = None
    gdpr_lawful_basis: Optional[str] = None
    
    def _get_mastg_test_id(self) -> str:
        """Get MASTG test ID based on vulnerability type"""
        mastg_mapping = {
            "consent_missing": "MASTG-TEST-0026",
            "consent_insufficient": "MASTG-TEST-0026", 
            "personal_data_excessive": "MASTG-TEST-0027",
            "personal_data_unencrypted": "MASTG-TEST-0027",
            "third_party_sharing": "MASTG-TEST-0028",
            "tracking_without_consent": "MASTG-TEST-0025",
            "privacy_controls_missing": "MASTG-TEST-0025",
            "data_retention_unlimited": "MASTG-TEST-0029",
            "user_rights_unavailable": "MASTG-TEST-0030"
        }
        return mastg_mapping.get(self.vuln_type, "MASTG-TEST-0025")
    
    def _get_gdpr_article(self) -> str:
        """Get relevant GDPR article based on vulnerability type"""
        gdpr_mapping = {
            "consent_missing": "Article 7",
            "consent_insufficient": "Article 7",
            "personal_data_excessive": "Article 5(1)(c)",
            "personal_data_unencrypted": "Article 32",
            "third_party_sharing": "Article 6",
            "tracking_without_consent": "Article 6",
            "privacy_controls_missing": "Article 12",
            "data_retention_unlimited": "Article 5(1)(e)",
            "user_rights_unavailable": "Article 15-22"
        }
        return gdpr_mapping.get(self.vuln_type, "Article 5")

@dataclass
class PrivacyAnalysisConfig:
    """Configuration for privacy analysis parameters"""
    enable_deep_analysis: bool = True
    check_third_party_sdks: bool = True
    analyze_tracking_patterns: bool = True
    validate_consent_mechanisms: bool = True
    check_data_retention: bool = True
    scan_encrypted_data: bool = False
    max_file_size_mb: int = 10
    excluded_paths: List[str] = None
    
    def __post_init__(self):
        if self.excluded_paths is None:
            self.excluded_paths = ["test/", "tests/", "mock/", "sample/"]

@dataclass
class PrivacyPattern:
    """Privacy-related pattern for vulnerability detection"""
    pattern: str
    pattern_type: str  # regex, keyword, api_call
    data_type: PrivacyDataType
    severity: PrivacySeverity
    description: str
    gdpr_article: str
    mastg_test: str
    requires_consent: bool = True
    
    
@dataclass
class ThirdPartySDK:
    """Third-party SDK privacy information"""
    name: str
    package_patterns: List[str]
    data_collected: List[PrivacyDataType]
    privacy_policy_url: Optional[str] = None
    consent_required: bool = True
    data_sharing: bool = True
    tracking_enabled: bool = True

@dataclass
class PrivacyAnalysisResult:
    """Complete privacy analysis result"""
    vulnerabilities: List[PrivacyVulnerability]
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    gdpr_compliance_score: float
    mastg_compliance_score: float
    third_party_sdks_detected: List[str]
    privacy_controls_present: bool
    consent_mechanisms_found: bool
    
    @classmethod
    def from_vulnerabilities(cls, vulnerabilities: List[PrivacyVulnerability]):
        """Create result from vulnerability list"""
        critical = sum(1 for v in vulnerabilities if v.severity == "CRITICAL")
        high = sum(1 for v in vulnerabilities if v.severity == "HIGH") 
        medium = sum(1 for v in vulnerabilities if v.severity == "MEDIUM")
        low = sum(1 for v in vulnerabilities if v.severity == "LOW")
        
        # Calculate compliance scores (simplified)
        total_checks = len(vulnerabilities) if vulnerabilities else 1
        gdpr_score = max(0, 100 - (critical * 25 + high * 15 + medium * 10 + low * 5))
        mastg_score = max(0, 100 - (critical * 20 + high * 12 + medium * 8 + low * 3))
        
        return cls(
            vulnerabilities=vulnerabilities,
            total_issues=len(vulnerabilities),
            critical_issues=critical,
            high_issues=high,
            medium_issues=medium,
            low_issues=low,
            gdpr_compliance_score=gdpr_score,
            mastg_compliance_score=mastg_score,
            third_party_sdks_detected=[],  # To be populated by analyzer
            privacy_controls_present=False,  # To be determined by analyzer
            consent_mechanisms_found=False   # To be determined by analyzer
        ) 
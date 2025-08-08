"""
Data structures for privacy leak detection.
Defines privacy findings, risk assessments, enums, and constants.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Any

class PrivacyDataType(Enum):
    """Types of privacy-sensitive data."""
    LOCATION = "location"
    CONTACTS = "contacts"
    CALL_LOG = "call_log"
    SMS = "sms"
    EMAIL = "email"
    PHONE = "phone"
    DEVICE_ID = "device_id"
    ADVERTISING_ID = "advertising_id"
    BIOMETRIC = "biometric"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    PASSWORD = "password"
    CLIPBOARD = "clipboard"
    SCREENSHOT = "screenshot"
    USAGE_ANALYTICS = "usage_analytics"
    CALENDAR = "calendar"
    PHOTOS = "photos"
    MICROPHONE = "microphone"
    CAMERA = "camera"

class PrivacyCategory(Enum):
    """Categories of privacy analysis."""
    CLIPBOARD = "CLIPBOARD"
    SCREENSHOT = "SCREENSHOT"
    LOCATION = "LOCATION"
    ANALYTICS = "ANALYTICS"
    CONTACTS = "CONTACTS"
    SMS = "SMS"
    DEVICE_INFO = "DEVICE_INFO"
    NETWORK = "NETWORK"
    BIOMETRIC = "BIOMETRIC"
    STORAGE = "STORAGE"

class PrivacySeverity(Enum):
    """Severity levels for privacy findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class MASTGPrivacyTest(Enum):
    """MASTG privacy test categories."""
    PRIVACY_01 = "MSTG-PRIVACY-01"  # App Permissions and Data Collection
    PRIVACY_02 = "MSTG-PRIVACY-02"  # Data Sharing and Third-Party Services
    PRIVACY_03 = "MSTG-PRIVACY-03"  # Privacy Policy Compliance
    PRIVACY_04 = "MSTG-PRIVACY-04"  # Location Data Handling
    PRIVACY_05 = "MSTG-PRIVACY-05"  # Device Identifiers and Analytics

class PrivacyRiskLevel(Enum):
    """Risk levels for privacy assessment."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class ComplianceFramework(Enum):
    """Privacy compliance frameworks."""
    GDPR = "GDPR"
    CCPA = "CCPA"
    COPPA = "COPPA"
    HIPAA = "HIPAA"
    PIPEDA = "PIPEDA"

@dataclass
class PrivacyRiskFactors:
    """Privacy risk assessment factors."""
    data_sensitivity: float
    exposure_scope: float
    user_awareness: float
    regulatory_impact: float
    
    @property
    def overall_risk_score(self) -> float:
        """Calculate overall risk score."""
        return (self.data_sensitivity + self.exposure_scope + 
                self.user_awareness + self.regulatory_impact) / 4.0
    
    @property
    def risk_level(self) -> PrivacyRiskLevel:
        """Determine risk level based on score."""
        score = self.overall_risk_score
        if score >= 0.7:
            return PrivacyRiskLevel.HIGH
        elif score >= 0.4:
            return PrivacyRiskLevel.MEDIUM
        else:
            return PrivacyRiskLevel.LOW

@dataclass
class ComplianceImpact:
    """Compliance framework impact assessment."""
    framework: ComplianceFramework
    impact_level: str
    description: str
    required_actions: List[str]

@dataclass
class PrivacyFinding:
    """Privacy leak detection finding."""
    
    finding_id: str
    category: PrivacyCategory
    data_types: List[PrivacyDataType]
    severity: PrivacySeverity
    title: str
    description: str
    evidence: List[str]
    affected_components: List[str]
    risk_factors: PrivacyRiskFactors
    compliance_impacts: List[ComplianceImpact]
    mastg_test_id: MASTGPrivacyTest
    recommendations: List[str]
    confidence: float
    payload_used: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    
    def __post_init__(self):
        """Post-initialization processing."""
        if not self.finding_id:
            self.finding_id = f"{self.category.value}_{hash(self.title)}"

@dataclass
class ClipboardFinding(PrivacyFinding):
    """Clipboard-specific privacy finding."""
    clipboard_operations: List[str] = None
    sensitive_data_detected: bool = False
    automatic_access: bool = False
    
    def __post_init__(self):
        super().__post_init__()
        self.category = PrivacyCategory.CLIPBOARD
        if self.clipboard_operations is None:
            self.clipboard_operations = []

@dataclass
class LocationFinding(PrivacyFinding):
    """Location-specific privacy finding."""
    location_permissions: List[str] = None
    precision_level: str = "unknown"  # coarse, fine, background
    tracking_frequency: str = "unknown"
    third_party_sharing: bool = False
    
    def __post_init__(self):
        super().__post_init__()
        self.category = PrivacyCategory.LOCATION
        if self.location_permissions is None:
            self.location_permissions = []

@dataclass
class AnalyticsFinding(PrivacyFinding):
    """Analytics-specific privacy finding."""
    analytics_sdks: List[str] = None
    tracking_identifiers: List[str] = None
    behavioral_tracking: bool = False
    cross_app_tracking: bool = False
    
    def __post_init__(self):
        super().__post_init__()
        self.category = PrivacyCategory.ANALYTICS
        if self.analytics_sdks is None:
            self.analytics_sdks = []
        if self.tracking_identifiers is None:
            self.tracking_identifiers = []

@dataclass
class ScreenshotFinding(PrivacyFinding):
    """Screenshot security finding."""
    flag_secure_missing: bool = False
    sensitive_screens: List[str] = None
    screenshot_prevention: bool = False
    
    def __post_init__(self):
        super().__post_init__()
        self.category = PrivacyCategory.SCREENSHOT
        if self.sensitive_screens is None:
            self.sensitive_screens = []

@dataclass
class PrivacyAnalysisResult:
    """Result of privacy analysis."""
    
    findings: List[PrivacyFinding]
    privacy_score: float
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    masvs_compliance: Dict[str, bool]
    compliance_frameworks: Dict[ComplianceFramework, str]
    
    @classmethod
    def create_from_findings(cls, findings: List[PrivacyFinding]) -> 'PrivacyAnalysisResult':
        """Create analysis result from findings list."""
        severity_counts = {
            PrivacySeverity.CRITICAL: 0,
            PrivacySeverity.HIGH: 0,
            PrivacySeverity.MEDIUM: 0,
            PrivacySeverity.LOW: 0
        }
        
        for finding in findings:
            severity_counts[finding.severity] += 1
        
        # Calculate privacy score (0-100, higher is better)
        total_findings = len(findings)
        if total_findings == 0:
            privacy_score = 100.0
        else:
            # Weight by severity
            weighted_issues = (
                severity_counts[PrivacySeverity.CRITICAL] * 4 +
                severity_counts[PrivacySeverity.HIGH] * 3 +
                severity_counts[PrivacySeverity.MEDIUM] * 2 +
                severity_counts[PrivacySeverity.LOW] * 1
            )
            # Score decreases with more issues
            privacy_score = max(0, 100 - (weighted_issues * 5))
        
        # Check MASTG compliance (fails if any findings exist for that test)
        masvs_compliance = {
            test.value: not any(f.mastg_test_id == test for f in findings)
            for test in MASTGPrivacyTest
        }
        
        # Assess compliance framework impacts
        compliance_frameworks = {}
        for framework in ComplianceFramework:
            high_risk_findings = [
                f for f in findings 
                if any(ci.framework == framework and ci.impact_level == "HIGH" 
                       for ci in f.compliance_impacts)
            ]
            if high_risk_findings:
                compliance_frameworks[framework] = "HIGH_RISK"
            elif any(any(ci.framework == framework for ci in f.compliance_impacts) for f in findings):
                compliance_frameworks[framework] = "MEDIUM_RISK"
            else:
                compliance_frameworks[framework] = "COMPLIANT"
        
        return cls(
            findings=findings,
            privacy_score=privacy_score,
            total_issues=total_findings,
            critical_issues=severity_counts[PrivacySeverity.CRITICAL],
            high_issues=severity_counts[PrivacySeverity.HIGH],
            medium_issues=severity_counts[PrivacySeverity.MEDIUM],
            low_issues=severity_counts[PrivacySeverity.LOW],
            masvs_compliance=masvs_compliance,
            compliance_frameworks=compliance_frameworks
        )

# Privacy analysis patterns and constants
PRIVACY_DATA_SENSITIVITY_MAP = {
    PrivacyDataType.CREDIT_CARD: 1.0,
    PrivacyDataType.SSN: 1.0,
    PrivacyDataType.PASSWORD: 1.0,
    PrivacyDataType.LOCATION: 1.0,
    PrivacyDataType.BIOMETRIC: 1.0,
    PrivacyDataType.EMAIL: 0.7,
    PrivacyDataType.PHONE: 0.7,
    PrivacyDataType.CONTACTS: 0.7,
    PrivacyDataType.CALL_LOG: 0.7,
    PrivacyDataType.SMS: 0.7,
    PrivacyDataType.DEVICE_ID: 0.5,
    PrivacyDataType.ADVERTISING_ID: 0.5,
    PrivacyDataType.CLIPBOARD: 0.6,
    PrivacyDataType.SCREENSHOT: 0.4,
    PrivacyDataType.USAGE_ANALYTICS: 0.4,
    PrivacyDataType.CALENDAR: 0.6,
    PrivacyDataType.PHOTOS: 0.6,
    PrivacyDataType.MICROPHONE: 0.8,
    PrivacyDataType.CAMERA: 0.8
}

PRIVACY_EXPOSURE_SCOPE_MAP = {
    PrivacyCategory.ANALYTICS: 1.0,
    PrivacyCategory.LOCATION: 1.0,
    PrivacyCategory.CLIPBOARD: 1.0,
    PrivacyCategory.NETWORK: 0.9,
    PrivacyCategory.SCREENSHOT: 0.6,
    PrivacyCategory.CONTACTS: 0.6,
    PrivacyCategory.SMS: 0.6,
    PrivacyCategory.DEVICE_INFO: 0.5,
    PrivacyCategory.BIOMETRIC: 0.8,
    PrivacyCategory.STORAGE: 0.4
}

PRIVACY_USER_AWARENESS_MAP = {
    PrivacyCategory.CLIPBOARD: 1.0,  # High risk due to low user awareness
    PrivacyCategory.ANALYTICS: 1.0,
    PrivacyCategory.SCREENSHOT: 1.0,
    PrivacyCategory.NETWORK: 0.8,
    PrivacyCategory.DEVICE_INFO: 0.7,
    PrivacyCategory.LOCATION: 0.5,
    PrivacyCategory.CONTACTS: 0.5,
    PrivacyCategory.SMS: 0.4,
    PrivacyCategory.BIOMETRIC: 0.2,
    PrivacyCategory.STORAGE: 0.3
}

# GDPR sensitive data types
GDPR_SENSITIVE_DATA = [
    PrivacyDataType.LOCATION,
    PrivacyDataType.BIOMETRIC,
    PrivacyDataType.EMAIL,
    PrivacyDataType.PHONE,
    PrivacyDataType.CONTACTS
]

# COPPA sensitive data types (children's privacy)
COPPA_SENSITIVE_DATA = [
    PrivacyDataType.LOCATION,
    PrivacyDataType.CONTACTS,
    PrivacyDataType.USAGE_ANALYTICS,
    PrivacyDataType.PHOTOS,
    PrivacyDataType.MICROPHONE,
    PrivacyDataType.CAMERA
]

# Plugin metadata
PLUGIN_METADATA = {
    "name": "Privacy Leak Detection",
    "category": "PRIVACY",
    "mastg_tests": [test.value for test in MASTGPrivacyTest],
    "supported_frameworks": [framework.value for framework in ComplianceFramework],
    "version": "2.0.0"
} 
"""
Privacy Pattern Analyzer

GDPR and MASTG pattern definitions for comprehensive privacy vulnerability detection.
Provides external configuration of privacy patterns with reliability tracking.
"""

import re
from typing import Dict, List, Optional, Set
from .data_structures import PrivacyPattern, PrivacyDataType, PrivacySeverity

class PrivacyPatternAnalyzer:
    """
    Analyzes privacy-related patterns in mobile applications.
    Implements GDPR and MASTG compliance checking through pattern matching.
    """
    
    def __init__(self):
        self.privacy_patterns = self._initialize_privacy_patterns()
        self.tracking_patterns = self._initialize_tracking_patterns()
        self.third_party_patterns = self._initialize_third_party_patterns()
        self.consent_patterns = self._initialize_consent_patterns()
        self.data_retention_patterns = self._initialize_data_retention_patterns()
        
    def _initialize_privacy_patterns(self) -> Dict[str, List[PrivacyPattern]]:
        """Initialize privacy data collection patterns"""
        return {
            "location": [
                PrivacyPattern(
                    pattern=r"getLastKnownLocation|getCurrentLocation|requestLocationUpdates",
                    pattern_type="regex",
                    data_type=PrivacyDataType.LOCATION,
                    severity=PrivacySeverity.HIGH,
                    description="Location data access without proper consent",
                    gdpr_article="Article 7",
                    mastg_test="MASTG-TEST-0026"
                ),
                PrivacyPattern(
                    pattern=r"ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION",
                    pattern_type="regex",
                    data_type=PrivacyDataType.LOCATION,
                    severity=PrivacySeverity.HIGH,
                    description="Location permission declared",
                    gdpr_article="Article 7",
                    mastg_test="MASTG-TEST-0026"
                ),
                PrivacyPattern(
                    pattern=r"latitude|longitude|gps|coordinates",
                    pattern_type="regex",
                    data_type=PrivacyDataType.LOCATION,
                    severity=PrivacySeverity.MEDIUM,
                    description="Location data handling patterns",
                    gdpr_article="Article 5(1)(c)",
                    mastg_test="MASTG-TEST-0027"
                )
            ],
            "contacts": [
                PrivacyPattern(
                    pattern=r"ContactsContract|getContentResolver.*contacts",
                    pattern_type="regex",
                    data_type=PrivacyDataType.CONTACTS,
                    severity=PrivacySeverity.HIGH,
                    description="Contact data access",
                    gdpr_article="Article 7",
                    mastg_test="MASTG-TEST-0026"
                ),
                PrivacyPattern(
                    pattern=r"READ_CONTACTS|WRITE_CONTACTS",
                    pattern_type="regex",
                    data_type=PrivacyDataType.CONTACTS,
                    severity=PrivacySeverity.HIGH,
                    description="Contact permission declared",
                    gdpr_article="Article 7",
                    mastg_test="MASTG-TEST-0026"
                )
            ],
            "device_id": [
                PrivacyPattern(
                    pattern=r"getDeviceId|getImei|getSerialNumber|getAndroidId",
                    pattern_type="regex",
                    data_type=PrivacyDataType.DEVICE_ID,
                    severity=PrivacySeverity.CRITICAL,
                    description="Device identifier access",
                    gdpr_article="Article 7",
                    mastg_test="MASTG-TEST-0026"
                ),
                PrivacyPattern(
                    pattern=r"TelephonyManager|Settings\.Secure\.ANDROID_ID",
                    pattern_type="regex",
                    data_type=PrivacyDataType.DEVICE_ID,
                    severity=PrivacySeverity.HIGH,
                    description="Device ID collection patterns",
                    gdpr_article="Article 5(1)(c)",
                    mastg_test="MASTG-TEST-0027"
                )
            ],
            "camera": [
                PrivacyPattern(
                    pattern=r"Camera\.open|camera2|CameraX",
                    pattern_type="regex",
                    data_type=PrivacyDataType.CAMERA,
                    severity=PrivacySeverity.HIGH,
                    description="Camera access",
                    gdpr_article="Article 7",
                    mastg_test="MASTG-TEST-0026"
                ),
                PrivacyPattern(
                    pattern=r"CAMERA",
                    pattern_type="keyword",
                    data_type=PrivacyDataType.CAMERA,
                    severity=PrivacySeverity.HIGH,
                    description="Camera permission declared",
                    gdpr_article="Article 7",
                    mastg_test="MASTG-TEST-0026"
                )
            ],
            "microphone": [
                PrivacyPattern(
                    pattern=r"MediaRecorder|AudioRecord|RECORD_AUDIO",
                    pattern_type="regex",
                    data_type=PrivacyDataType.MICROPHONE,
                    severity=PrivacySeverity.HIGH,
                    description="Microphone access",
                    gdpr_article="Article 7",
                    mastg_test="MASTG-TEST-0026"
                )
            ]
        }
    
    def _initialize_tracking_patterns(self) -> Dict[str, List[PrivacyPattern]]:
        """Initialize user tracking patterns"""
        return {
            "analytics": [
                PrivacyPattern(
                    pattern=r"google\.analytics|firebase\.analytics|mixpanel|flurry",
                    pattern_type="regex",
                    data_type=PrivacyDataType.UNKNOWN,
                    severity=PrivacySeverity.MEDIUM,
                    description="Analytics tracking without consent",
                    gdpr_article="Article 6",
                    mastg_test="MASTG-TEST-0025"
                )
            ],
            "advertising": [
                PrivacyPattern(
                    pattern=r"getAdvertisingId|ADVERTISING_ID|adMob|admob",
                    pattern_type="regex",
                    data_type=PrivacyDataType.DEVICE_ID,
                    severity=PrivacySeverity.HIGH,
                    description="Advertising ID tracking",
                    gdpr_article="Article 6",
                    mastg_test="MASTG-TEST-0025"
                )
            ],
            "crash_reporting": [
                PrivacyPattern(
                    pattern=r"crashlytics|bugsnag|sentry|raygun",
                    pattern_type="regex",
                    data_type=PrivacyDataType.UNKNOWN,
                    severity=PrivacySeverity.LOW,
                    description="Crash reporting data collection",
                    gdpr_article="Article 6",
                    mastg_test="MASTG-TEST-0025"
                )
            ]
        }
    
    def _initialize_third_party_patterns(self) -> Dict[str, List[PrivacyPattern]]:
        """Initialize third-party data sharing patterns"""
        return {
            "social_media": [
                PrivacyPattern(
                    pattern=r"facebook\.com|twitter\.com|linkedin\.com|instagram\.com",
                    pattern_type="regex",
                    data_type=PrivacyDataType.UNKNOWN,
                    severity=PrivacySeverity.HIGH,
                    description="Social media integration data sharing",
                    gdpr_article="Article 28",
                    mastg_test="MASTG-TEST-0028"
                )
            ],
            "cloud_services": [
                PrivacyPattern(
                    pattern=r"amazonaws\.com|googleapis\.com|azure\.microsoft\.com",
                    pattern_type="regex",
                    data_type=PrivacyDataType.UNKNOWN,
                    severity=PrivacySeverity.MEDIUM,
                    description="Cloud service data sharing",
                    gdpr_article="Article 28",
                    mastg_test="MASTG-TEST-0028"
                )
            ],
            "payment_processors": [
                PrivacyPattern(
                    pattern=r"stripe\.com|paypal\.com|square\.com",
                    pattern_type="regex",
                    data_type=PrivacyDataType.UNKNOWN,
                    severity=PrivacySeverity.HIGH,
                    description="Payment processor data sharing",
                    gdpr_article="Article 28",
                    mastg_test="MASTG-TEST-0028"
                )
            ]
        }
    
    def _initialize_consent_patterns(self) -> Dict[str, List[PrivacyPattern]]:
        """Initialize consent mechanism patterns"""
        return {
            "explicit_consent": [
                PrivacyPattern(
                    pattern=r"consent.*dialog|privacy.*agreement|terms.*accept",
                    pattern_type="regex",
                    data_type=PrivacyDataType.UNKNOWN,
                    severity=PrivacySeverity.INFO,
                    description="Explicit consent mechanism found",
                    gdpr_article="Article 7",
                    mastg_test="MASTG-TEST-0026",
                    requires_consent=False
                )
            ],
            "privacy_policy": [
                PrivacyPattern(
                    pattern=r"privacy.*policy|data.*protection",
                    pattern_type="regex",
                    data_type=PrivacyDataType.UNKNOWN,
                    severity=PrivacySeverity.INFO,
                    description="Privacy policy reference",
                    gdpr_article="Article 12",
                    mastg_test="MASTG-TEST-0025",
                    requires_consent=False
                )
            ],
            "opt_out": [
                PrivacyPattern(
                    pattern=r"opt.*out|disable.*tracking|stop.*sharing",
                    pattern_type="regex",
                    data_type=PrivacyDataType.UNKNOWN,
                    severity=PrivacySeverity.INFO,
                    description="Opt-out mechanism found",
                    gdpr_article="Article 21",
                    mastg_test="MASTG-TEST-0025",
                    requires_consent=False
                )
            ]
        }
    
    def _initialize_data_retention_patterns(self) -> Dict[str, List[PrivacyPattern]]:
        """Initialize data retention patterns"""
        return {
            "unlimited_retention": [
                PrivacyPattern(
                    pattern=r"never.*delete|permanent.*storage|infinite.*retention",
                    pattern_type="regex",
                    data_type=PrivacyDataType.UNKNOWN,
                    severity=PrivacySeverity.HIGH,
                    description="Unlimited data retention policy",
                    gdpr_article="Article 5(1)(e)",
                    mastg_test="MASTG-TEST-0029"
                )
            ],
            "retention_period": [
                PrivacyPattern(
                    pattern=r"retention.*period|delete.*after|expire.*data",
                    pattern_type="regex",
                    data_type=PrivacyDataType.UNKNOWN,
                    severity=PrivacySeverity.INFO,
                    description="Data retention period defined",
                    gdpr_article="Article 5(1)(e)",
                    mastg_test="MASTG-TEST-0029",
                    requires_consent=False
                )
            ]
        }
    
    def get_all_patterns(self) -> Dict[str, Dict[str, List[PrivacyPattern]]]:
        """Get all privacy patterns organized by category"""
        return {
            "privacy": self.privacy_patterns,
            "tracking": self.tracking_patterns,
            "third_party": self.third_party_patterns,
            "consent": self.consent_patterns,
            "retention": self.data_retention_patterns
        }
    
    def find_patterns_in_content(self, content: str, category: str = None) -> List[tuple]:
        """
        Find privacy patterns in content
        
        Returns:
            List of tuples (pattern, match_start, match_end, pattern_obj)
        """
        matches = []
        
        patterns_to_check = self.get_all_patterns()
        if category:
            patterns_to_check = {category: patterns_to_check.get(category, {})}
        
        for cat, pattern_groups in patterns_to_check.items():
            for group, patterns in pattern_groups.items():
                for pattern_obj in patterns:
                    if pattern_obj.pattern_type == "regex":
                        for match in re.finditer(pattern_obj.pattern, content, re.IGNORECASE):
                            matches.append((
                                pattern_obj.pattern,
                                match.start(),
                                match.end(),
                                pattern_obj
                            ))
                    elif pattern_obj.pattern_type == "keyword":
                        # Simple keyword search
                        start = 0
                        while True:
                            pos = content.lower().find(pattern_obj.pattern.lower(), start)
                            if pos == -1:
                                break
                            matches.append((
                                pattern_obj.pattern,
                                pos,
                                pos + len(pattern_obj.pattern),
                                pattern_obj
                            ))
                            start = pos + 1
        
        return sorted(matches, key=lambda x: x[1])  # Sort by position
    
    def get_sensitive_permissions(self) -> Set[str]:
        """Get set of privacy-sensitive Android permissions"""
        return {
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.GET_ACCOUNTS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.USE_BIOMETRIC",
            "android.permission.USE_FINGERPRINT"
        }
    
    def classify_permission_data_type(self, permission: str) -> PrivacyDataType:
        """Classify Android permission to privacy data type"""
        permission_mapping = {
            "ACCESS_FINE_LOCATION": PrivacyDataType.LOCATION,
            "ACCESS_COARSE_LOCATION": PrivacyDataType.LOCATION,
            "READ_CONTACTS": PrivacyDataType.CONTACTS,
            "WRITE_CONTACTS": PrivacyDataType.CONTACTS,
            "READ_CALENDAR": PrivacyDataType.CALENDAR,
            "WRITE_CALENDAR": PrivacyDataType.CALENDAR,
            "CAMERA": PrivacyDataType.CAMERA,
            "RECORD_AUDIO": PrivacyDataType.MICROPHONE,
            "READ_SMS": PrivacyDataType.SMS,
            "SEND_SMS": PrivacyDataType.SMS,
            "READ_PHONE_STATE": PrivacyDataType.PHONE,
            "CALL_PHONE": PrivacyDataType.PHONE,
            "READ_CALL_LOG": PrivacyDataType.CALL_LOG,
            "WRITE_CALL_LOG": PrivacyDataType.CALL_LOG,
            "GET_ACCOUNTS": PrivacyDataType.ACCOUNT,
            "READ_EXTERNAL_STORAGE": PrivacyDataType.STORAGE,
            "WRITE_EXTERNAL_STORAGE": PrivacyDataType.STORAGE,
            "USE_BIOMETRIC": PrivacyDataType.BIOMETRIC,
            "USE_FINGERPRINT": PrivacyDataType.BIOMETRIC
        }
        
        for perm_key, data_type in permission_mapping.items():
            if perm_key in permission.upper():
                return data_type
        
        return PrivacyDataType.UNKNOWN 
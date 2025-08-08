"""
Pattern Library for Privacy Leak Detection
Comprehensive patterns for detecting privacy-sensitive data and operations.
"""

import re
from typing import Dict, List, Pattern
from dataclasses import dataclass

from .data_structures import PrivacyDataType, PrivacyCategory

@dataclass
class PrivacyPattern:
    """Privacy detection pattern with metadata."""
    
    pattern: Pattern[str]
    data_type: PrivacyDataType
    category: PrivacyCategory
    severity: str
    description: str
    confidence: float
    
    @classmethod
    def create(cls, pattern_str: str, data_type: PrivacyDataType, 
               category: PrivacyCategory, severity: str, description: str, 
               confidence: float = 0.8) -> 'PrivacyPattern':
        """Create compiled privacy pattern."""
        return cls(
            pattern=re.compile(pattern_str, re.IGNORECASE),
            data_type=data_type,
            category=category,
            severity=severity,
            description=description,
            confidence=confidence
        )

class PrivacyPatternLibrary:
    """Comprehensive privacy pattern library."""
    
    def __init__(self):
        """Initialize privacy patterns."""
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> Dict[str, List[PrivacyPattern]]:
        """Initialize all privacy detection patterns."""
        return {
            'clipboard_patterns': self._get_clipboard_patterns(),
            'location_patterns': self._get_location_patterns(),
            'contacts_patterns': self._get_contacts_patterns(),
            'analytics_patterns': self._get_analytics_patterns(),
            'device_id_patterns': self._get_device_id_patterns(),
            'screenshot_patterns': self._get_screenshot_patterns(),
            'biometric_patterns': self._get_biometric_patterns(),
            'network_privacy_patterns': self._get_network_privacy_patterns(),
            'storage_patterns': self._get_storage_patterns(),
            'sensitive_data_patterns': self._get_sensitive_data_patterns()
        }
    
    def _get_clipboard_patterns(self) -> List[PrivacyPattern]:
        """Get clipboard access patterns."""
        return [
            PrivacyPattern.create(
                r"ClipboardManager\.getText|getClipData|setPrimaryClip",
                PrivacyDataType.CLIPBOARD,
                PrivacyCategory.CLIPBOARD,
                "HIGH",
                "Direct clipboard access detected",
                0.9
            ),
            PrivacyPattern.create(
                r"clipboard\.addPrimaryClipChangedListener",
                PrivacyDataType.CLIPBOARD,
                PrivacyCategory.CLIPBOARD,
                "CRITICAL",
                "Clipboard monitoring detected",
                0.95
            ),
            PrivacyPattern.create(
                r"CLIPBOARD_SERVICE|Context\.CLIPBOARD_SERVICE",
                PrivacyDataType.CLIPBOARD,
                PrivacyCategory.CLIPBOARD,
                "MEDIUM",
                "Clipboard service access",
                0.8
            ),
            PrivacyPattern.create(
                r"ClipData\.newPlainText|ClipData\.newUri",
                PrivacyDataType.CLIPBOARD,
                PrivacyCategory.CLIPBOARD,
                "MEDIUM",
                "Clipboard data creation",
                0.7
            ),
            PrivacyPattern.create(
                r"setPrimaryClip.*password|setPrimaryClip.*token|setPrimaryClip.*secret",
                PrivacyDataType.CLIPBOARD,
                PrivacyCategory.CLIPBOARD,
                "CRITICAL",
                "Sensitive data copied to clipboard",
                0.95
            )
        ]
    
    def _get_location_patterns(self) -> List[PrivacyPattern]:
        """Get location access patterns."""
        return [
            PrivacyPattern.create(
                r"LocationManager\.requestLocationUpdates|getLastKnownLocation",
                PrivacyDataType.LOCATION,
                PrivacyCategory.LOCATION,
                "HIGH",
                "Location access detected",
                0.9
            ),
            PrivacyPattern.create(
                r"ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION",
                PrivacyDataType.LOCATION,
                PrivacyCategory.LOCATION,
                "HIGH",
                "Location permission usage",
                0.85
            ),
            PrivacyPattern.create(
                r"GPS_PROVIDER|NETWORK_PROVIDER|PASSIVE_PROVIDER",
                PrivacyDataType.LOCATION,
                PrivacyCategory.LOCATION,
                "HIGH",
                "Location provider usage",
                0.8
            ),
            PrivacyPattern.create(
                r"FusedLocationProviderClient|LocationServices\.getFusedLocationProviderClient",
                PrivacyDataType.LOCATION,
                PrivacyCategory.LOCATION,
                "HIGH",
                "Google Play Services location access",
                0.9
            ),
            PrivacyPattern.create(
                r"Geocoder\.getFromLocation|getFromLocationName",
                PrivacyDataType.LOCATION,
                PrivacyCategory.LOCATION,
                "MEDIUM",
                "Geocoding operation",
                0.75
            ),
            PrivacyPattern.create(
                r"LocationRequest\.create|LocationRequest\.setInterval",
                PrivacyDataType.LOCATION,
                PrivacyCategory.LOCATION,
                "HIGH",
                "Location tracking configuration",
                0.85
            )
        ]
    
    def _get_contacts_patterns(self) -> List[PrivacyPattern]:
        """Get contacts access patterns."""
        return [
            PrivacyPattern.create(
                r"ContactsContract\.CommonDataKinds|ContactsContract\.Contacts",
                PrivacyDataType.CONTACTS,
                PrivacyCategory.CONTACTS,
                "HIGH",
                "Contacts database access",
                0.9
            ),
            PrivacyPattern.create(
                r"READ_CONTACTS|WRITE_CONTACTS",
                PrivacyDataType.CONTACTS,
                PrivacyCategory.CONTACTS,
                "HIGH",
                "Contacts permission usage",
                0.85
            ),
            PrivacyPattern.create(
                r"getContentResolver.*ContactsContract",
                PrivacyDataType.CONTACTS,
                PrivacyCategory.CONTACTS,
                "HIGH",
                "Contacts content resolver access",
                0.85
            ),
            PrivacyPattern.create(
                r"Phone\.NUMBER|Phone\.DISPLAY_NAME|Email\.ADDRESS",
                PrivacyDataType.CONTACTS,
                PrivacyCategory.CONTACTS,
                "MEDIUM",
                "Contact field access",
                0.75
            ),
            PrivacyPattern.create(
                r"CallLog\.Calls|CallLog\.CONTENT_URI",
                PrivacyDataType.CALL_LOG,
                PrivacyCategory.CONTACTS,
                "HIGH",
                "Call log access",
                0.9
            )
        ]
    
    def _get_analytics_patterns(self) -> List[PrivacyPattern]:
        """Get analytics and tracking patterns."""
        return [
            PrivacyPattern.create(
                r"GoogleAnalytics|Firebase.*Analytics|Crashlytics",
                PrivacyDataType.USAGE_ANALYTICS,
                PrivacyCategory.ANALYTICS,
                "MEDIUM",
                "Google analytics SDK detected",
                0.8
            ),
            PrivacyPattern.create(
                r"Facebook.*Analytics|FacebookSdk|FB\.AppEvents",
                PrivacyDataType.USAGE_ANALYTICS,
                PrivacyCategory.ANALYTICS,
                "HIGH",
                "Facebook analytics SDK detected",
                0.85
            ),
            PrivacyPattern.create(
                r"Mixpanel|Amplitude|Segment\.com|Flurry",
                PrivacyDataType.USAGE_ANALYTICS,
                PrivacyCategory.ANALYTICS,
                "MEDIUM",
                "Third-party analytics SDK detected",
                0.8
            ),
            PrivacyPattern.create(
                r"AdvertisingIdClient\.getAdvertisingIdInfo|getIdForAdvertising",
                PrivacyDataType.ADVERTISING_ID,
                PrivacyCategory.ANALYTICS,
                "HIGH",
                "Advertising ID access",
                0.9
            ),
            PrivacyPattern.create(
                r"TelephonyManager\.getDeviceId|getSubscriberId|getSimSerialNumber",
                PrivacyDataType.DEVICE_ID,
                PrivacyCategory.ANALYTICS,
                "HIGH",
                "Device identifier access",
                0.9
            ),
            PrivacyPattern.create(
                r"Settings\.Secure\.ANDROID_ID|Secure\.getString.*ANDROID_ID",
                PrivacyDataType.DEVICE_ID,
                PrivacyCategory.ANALYTICS,
                "MEDIUM",
                "Android ID access",
                0.8
            )
        ]
    
    def _get_device_id_patterns(self) -> List[PrivacyPattern]:
        """Get device identification patterns."""
        return [
            PrivacyPattern.create(
                r"Build\.SERIAL|Build\.getSerial",
                PrivacyDataType.DEVICE_ID,
                PrivacyCategory.DEVICE_INFO,
                "MEDIUM",
                "Device serial number access",
                0.8
            ),
            PrivacyPattern.create(
                r"WifiInfo\.getMacAddress|BluetoothAdapter\.getAddress",
                PrivacyDataType.DEVICE_ID,
                PrivacyCategory.DEVICE_INFO,
                "HIGH",
                "Hardware address access",
                0.85
            ),
            PrivacyPattern.create(
                r"getSystemService.*TELEPHONY_SERVICE.*getDeviceId",
                PrivacyDataType.DEVICE_ID,
                PrivacyCategory.DEVICE_INFO,
                "HIGH",
                "IMEI/device ID access",
                0.9
            ),
            PrivacyPattern.create(
                r"getSystemService.*WIFI_SERVICE.*getConnectionInfo",
                PrivacyDataType.DEVICE_ID,
                PrivacyCategory.DEVICE_INFO,
                "MEDIUM",
                "WiFi information access",
                0.7
            )
        ]
    
    def _get_screenshot_patterns(self) -> List[PrivacyPattern]:
        """Get screenshot security patterns."""
        return [
            PrivacyPattern.create(
                r"FLAG_SECURE",
                PrivacyDataType.SCREENSHOT,
                PrivacyCategory.SCREENSHOT,
                "LOW",
                "Screenshot protection enabled",
                0.9
            ),
            PrivacyPattern.create(
                r"getWindow\(\)\.setFlags.*WindowManager\.LayoutParams\.FLAG_SECURE",
                PrivacyDataType.SCREENSHOT,
                PrivacyCategory.SCREENSHOT,
                "LOW",
                "Window screenshot protection",
                0.85
            ),
            PrivacyPattern.create(
                r"MediaProjection|ImageReader|PixelCopy",
                PrivacyDataType.SCREENSHOT,
                PrivacyCategory.SCREENSHOT,
                "HIGH",
                "Screenshot/screen recording capability",
                0.8
            ),
            PrivacyPattern.create(
                r"View\.draw\(|Canvas\.drawBitmap|Bitmap\.createBitmap",
                PrivacyDataType.SCREENSHOT,
                PrivacyCategory.SCREENSHOT,
                "MEDIUM",
                "View capture potential",
                0.6
            )
        ]
    
    def _get_biometric_patterns(self) -> List[PrivacyPattern]:
        """Get biometric data patterns."""
        return [
            PrivacyPattern.create(
                r"BiometricPrompt|FingerprintManager|BiometricManager",
                PrivacyDataType.BIOMETRIC,
                PrivacyCategory.BIOMETRIC,
                "HIGH",
                "Biometric authentication usage",
                0.9
            ),
            PrivacyPattern.create(
                r"USE_BIOMETRIC|USE_FINGERPRINT",
                PrivacyDataType.BIOMETRIC,
                PrivacyCategory.BIOMETRIC,
                "HIGH",
                "Biometric permission usage",
                0.85
            ),
            PrivacyPattern.create(
                r"FaceDetector|TextRecognizer|BarcodeDetector",
                PrivacyDataType.BIOMETRIC,
                PrivacyCategory.BIOMETRIC,
                "MEDIUM",
                "Biometric analysis capability",
                0.7
            )
        ]
    
    def _get_network_privacy_patterns(self) -> List[PrivacyPattern]:
        """Get network privacy patterns."""
        return [
            PrivacyPattern.create(
                r"HttpURLConnection|OkHttpClient|Retrofit",
                PrivacyDataType.USAGE_ANALYTICS,
                PrivacyCategory.NETWORK,
                "MEDIUM",
                "Network communication framework",
                0.6
            ),
            PrivacyPattern.create(
                r"\.addHeader\(.*User-Agent|\.addHeader\(.*Authorization",
                PrivacyDataType.DEVICE_ID,
                PrivacyCategory.NETWORK,
                "MEDIUM",
                "Identifying headers in network requests",
                0.7
            ),
            PrivacyPattern.create(
                r"tracking|analytics|telemetry",
                PrivacyDataType.USAGE_ANALYTICS,
                PrivacyCategory.NETWORK,
                "MEDIUM",
                "Tracking-related network activity",
                0.7
            )
        ]
    
    def _get_storage_patterns(self) -> List[PrivacyPattern]:
        """Get storage privacy patterns."""
        return [
            PrivacyPattern.create(
                r"SharedPreferences.*putString.*(?:email|phone|password|token)",
                PrivacyDataType.EMAIL,
                PrivacyCategory.STORAGE,
                "HIGH",
                "Sensitive data in shared preferences",
                0.8
            ),
            PrivacyPattern.create(
                r"SQLiteDatabase.*INSERT.*(?:email|phone|password|location)",
                PrivacyDataType.EMAIL,
                PrivacyCategory.STORAGE,
                "HIGH",
                "Sensitive data in database",
                0.8
            ),
            PrivacyPattern.create(
                r"FileOutputStream.*write.*(?:password|token|credential)",
                PrivacyDataType.PASSWORD,
                PrivacyCategory.STORAGE,
                "CRITICAL",
                "Sensitive data written to file",
                0.9
            )
        ]
    
    def _get_sensitive_data_patterns(self) -> List[PrivacyPattern]:
        """Get sensitive data value patterns."""
        return [
            PrivacyPattern.create(
                r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
                PrivacyDataType.CREDIT_CARD,
                PrivacyCategory.STORAGE,
                "CRITICAL",
                "Credit card number pattern",
                0.85
            ),
            PrivacyPattern.create(
                r"\b\d{3}-\d{2}-\d{4}\b",
                PrivacyDataType.SSN,
                PrivacyCategory.STORAGE,
                "CRITICAL",
                "Social Security Number pattern",
                0.9
            ),
            PrivacyPattern.create(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                PrivacyDataType.EMAIL,
                PrivacyCategory.STORAGE,
                "MEDIUM",
                "Email address pattern",
                0.8
            ),
            PrivacyPattern.create(
                r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                PrivacyDataType.PHONE,
                PrivacyCategory.STORAGE,
                "MEDIUM",
                "Phone number pattern",
                0.75
            ),
            PrivacyPattern.create(
                r"password\s*[=:]\s*[\"'][^\"']{6,}[\"']",
                PrivacyDataType.PASSWORD,
                PrivacyCategory.STORAGE,
                "CRITICAL",
                "Hardcoded password pattern",
                0.9
            )
        ]
    
    def get_patterns_by_category(self, category: PrivacyCategory) -> List[PrivacyPattern]:
        """Get patterns for a specific privacy category."""
        all_patterns = []
        for pattern_list in self.patterns.values():
            all_patterns.extend([p for p in pattern_list if p.category == category])
        return all_patterns
    
    def get_patterns_by_data_type(self, data_type: PrivacyDataType) -> List[PrivacyPattern]:
        """Get patterns for a specific data type."""
        all_patterns = []
        for pattern_list in self.patterns.values():
            all_patterns.extend([p for p in pattern_list if p.data_type == data_type])
        return all_patterns
    
    def get_all_patterns(self) -> List[PrivacyPattern]:
        """Get all privacy patterns."""
        all_patterns = []
        for pattern_list in self.patterns.values():
            all_patterns.extend(pattern_list)
        return all_patterns
    
    def search_patterns(self, content: str, category: PrivacyCategory = None) -> List[tuple]:
        """
        Search for privacy patterns in content.
        
        Returns:
            List of tuples: (match, pattern, line_number)
        """
        matches = []
        lines = content.split('\n')
        
        patterns_to_search = (
            self.get_patterns_by_category(category) if category 
            else self.get_all_patterns()
        )
        
        for line_num, line in enumerate(lines, 1):
            for pattern in patterns_to_search:
                for match in pattern.pattern.finditer(line):
                    matches.append((match, pattern, line_num))
        
        return matches 
"""
PII Pattern Library for Network Traffic Analysis.

This module contains comprehensive patterns for detecting personally identifiable
information (PII) in network communications, configurations, and source code.
"""

import re
from typing import Dict, List, Optional, Tuple, Any
from .data_structures import (
    PIIPattern, PIIType, SeverityLevel, AnalysisCategory,
    TransmissionMethod, NetworkEndpoint
)

class PIIPatternLibrary:
    """Comprehensive library of PII detection patterns with enhanced validation."""
    
    def __init__(self):
        """Initialize the PII pattern library."""
        self.patterns = self._initialize_patterns()
        self.network_patterns = self._initialize_network_patterns()
        self.compiled_patterns = self._compile_patterns()
        
        # Enhanced validation systems
        self.validation_cache = {}
        self.context_validators = self._initialize_context_validators()
        self.false_positive_filters = self._initialize_false_positive_filters()
        
    def _initialize_patterns(self) -> Dict[str, PIIPattern]:
        """Initialize all PII detection patterns."""
        patterns = {}
        
        # Device identifier patterns
        patterns.update(self._get_device_identifier_patterns())
        
        # Location data patterns
        patterns.update(self._get_location_data_patterns())
        
        # Network identifier patterns
        patterns.update(self._get_network_identifier_patterns())
        
        # Personal identifier patterns
        patterns.update(self._get_personal_identifier_patterns())
        
        # Authentication data patterns
        patterns.update(self._get_authentication_data_patterns())
        
        # Biometric data patterns
        patterns.update(self._get_biometric_data_patterns())
        
        # Behavioral data patterns
        patterns.update(self._get_behavioral_data_patterns())
        
        # System identifier patterns
        patterns.update(self._get_system_identifier_patterns())
        
        return patterns
    
    def _get_device_identifier_patterns(self) -> Dict[str, PIIPattern]:
        """Get device identifier patterns."""
        return {
            "android_id": PIIPattern(
                name="Android ID",
                pattern=r'(?i)(?:android[_\-]?id|device[_\-]?id|ANDROID_ID)["\'\s]*[:=]["\'\s]*([a-f0-9]{16})|android[_\-]?id["\'\s]*[:=]["\'\s]*["\']([a-f0-9]{16})["\']',
                description="Android unique device identifier",
                pii_type=PIIType.DEVICE_IDENTIFIER,
                severity=SeverityLevel.HIGH,
                examples=[
                    "android_id=1234567890abcdef",
                    "deviceId=a1b2c3d4e5f6789a",
                    "ANDROID_ID='9774d56d682e549c'"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-STORAGE-4", "MASVS-NETWORK-1"],
                owasp_categories=["A3:2021-Injection", "A8:2021-Software and Data Integrity Failures"]
            ),
            
            "imei": PIIPattern(
                name="IMEI/Device Serial",
                pattern=r'(?i)(?:imei|device[_\-]?serial|gsm[_\-]?serial)["\'\s]*[:=]["\'\s]*([0-9]{14,15})|(?:imei|serial)["\'\s]*[:=]["\'\s]*["\']([0-9]{14,15})["\']',
                description="International Mobile Equipment Identity",
                pii_type=PIIType.DEVICE_IDENTIFIER,
                severity=SeverityLevel.CRITICAL,
                examples=[
                    "imei=123456789012345",
                    "device_serial=987654321098765",
                    "getDeviceId()=359240051111110"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-STORAGE-4", "MASVS-NETWORK-1"],
                owasp_categories=["A3:2021-Injection", "A9:2021-Security Logging"]
            ),
            
            "device_fingerprint": PIIPattern(
                name="Device Fingerprint",
                pattern=r'(?i)(?:device[_\-]?fingerprint|hardware[_\-]?fingerprint|device[_\-]?hash)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9+/=]{20,})',
                description="Device hardware fingerprint or hash",
                pii_type=PIIType.DEVICE_IDENTIFIER,
                severity=SeverityLevel.HIGH,
                examples=[
                    "device_fingerprint=SGVhcHAhIEhlYXBwIQ==",
                    "hardware_hash=d4c3b2a1e5f6789012345678"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-STORAGE-4"],
                owasp_categories=["A3:2021-Injection"]
            ),
            
            "advertising_id": PIIPattern(
                name="Advertising ID",
                pattern=r'(?i)(?:advertising[_\-]?id|ad[_\-]?id|gaid|idfa)["\'\s]*[:=]["\'\s]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
                description="Advertising identifier (GAID/IDFA)",
                pii_type=PIIType.DEVICE_IDENTIFIER,
                severity=SeverityLevel.MEDIUM,
                examples=[
                    "advertising_id=12345678-1234-1234-1234-123456789012",
                    "gaid=87654321-4321-4321-4321-210987654321"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-STORAGE-4"],
                owasp_categories=["A9:2021-Security Logging"]
            )
        }
    
    def _get_location_data_patterns(self) -> Dict[str, PIIPattern]:
        """Get location data patterns."""
        return {
            "gps_latitude": PIIPattern(
                name="GPS Latitude",
                pattern=r'(?i)(?:lat|latitude|geo[_\-]?lat)["\'\s]*[:=]["\'\s]*(-?(?:[0-9]{1,3}(?:\.[0-9]+)?))(?:[,\s&]|$)',
                description="GPS latitude coordinates",
                pii_type=PIIType.LOCATION_DATA,
                severity=SeverityLevel.HIGH,
                examples=[
                    "lat=37.7749",
                    "latitude=-122.4194",
                    "geo_lat=40.7128"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1", "MASVS-NETWORK-1"],
                owasp_categories=["A3:2021-Injection", "A9:2021-Security Logging"]
            ),
            
            "gps_longitude": PIIPattern(
                name="GPS Longitude",
                pattern=r'(?i)(?:lon|lng|longitude|geo[_\-]?lon)["\'\s]*[:=]["\'\s]*(-?(?:[0-9]{1,3}(?:\.[0-9]+)?))(?:[,\s&]|$)',
                description="GPS longitude coordinates",
                pii_type=PIIType.LOCATION_DATA,
                severity=SeverityLevel.HIGH,
                examples=[
                    "lon=-122.4194",
                    "longitude=40.7128",
                    "lng=-74.0060"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1", "MASVS-NETWORK-1"],
                owasp_categories=["A3:2021-Injection", "A9:2021-Security Logging"]
            ),
            
            "coordinates_pair": PIIPattern(
                name="Coordinate Pair",
                pattern=r'(?i)(?:coordinates?|coords?|location)["\'\s]*[:=]["\'\s]*[\[\(]?(-?[0-9]{1,3}\.[0-9]+)[,\s]+(-?[0-9]{1,3}\.[0-9]+)[\]\)]?',
                description="Latitude/longitude coordinate pairs",
                pii_type=PIIType.LOCATION_DATA,
                severity=SeverityLevel.HIGH,
                examples=[
                    "coordinates=[37.7749, -122.4194]",
                    "location=(40.7128, -74.0060)",
                    "coords=51.5074, -0.1278"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1", "MASVS-NETWORK-1"],
                owasp_categories=["A3:2021-Injection"]
            ),
            
            "address_location": PIIPattern(
                name="Physical Address",
                pattern=r'(?i)(?:address|street|location)["\'\s]*[:=]["\'\s]*([0-9]+\s+[A-Za-z\s,.-]+(?:street|st|avenue|ave|road|rd|lane|ln|drive|dr|way|blvd|boulevard))',
                description="Physical street address",
                pii_type=PIIType.LOCATION_DATA,
                severity=SeverityLevel.MEDIUM,
                examples=[
                    "address=123 Main Street",
                    "street=456 Oak Avenue",
                    "location=789 Pine Road"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1"],
                owasp_categories=["A3:2021-Injection"]
            ),
            
            "zip_postal_code": PIIPattern(
                name="ZIP/Postal Code",
                pattern=r'(?i)(?:zip|postal[_\-]?code|postcode)["\'\s]*[:=]["\'\s]*([0-9]{5}(?:-[0-9]{4})?|[A-Z0-9]{3,10})',
                description="ZIP or postal code",
                pii_type=PIIType.LOCATION_DATA,
                severity=SeverityLevel.MEDIUM,
                examples=[
                    "zip=12345",
                    "postal_code=90210-1234",
                    "postcode=SW1A 1AA"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1"],
                owasp_categories=["A3:2021-Injection"]
            )
        }
    
    def _get_network_identifier_patterns(self) -> Dict[str, PIIPattern]:
        """Get network identifier patterns."""
        return {
            "wifi_mac": PIIPattern(
                name="WiFi MAC Address",
                pattern=r'(?i)(?:wifi[_\-]?mac|mac[_\-]?address|bssid)["\'\s]*[:=]["\'\s]*([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})',
                description="WiFi MAC address identifier",
                pii_type=PIIType.NETWORK_IDENTIFIER,
                severity=SeverityLevel.MEDIUM,
                examples=[
                    "wifi_mac=aa:bb:cc:dd:ee:ff",
                    "mac_address=12-34-56-78-90-ab",
                    "bssid=00:11:22:33:44:55"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-NETWORK-1"],
                owasp_categories=["A3:2021-Injection"]
            ),
            
            "bluetooth_mac": PIIPattern(
                name="Bluetooth MAC Address",
                pattern=r'(?i)(?:bluetooth[_\-]?mac|bt[_\-]?mac|bt[_\-]?address)["\'\s]*[:=]["\'\s]*([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})',
                description="Bluetooth MAC address identifier",
                pii_type=PIIType.NETWORK_IDENTIFIER,
                severity=SeverityLevel.MEDIUM,
                examples=[
                    "bluetooth_mac=aa:bb:cc:dd:ee:ff",
                    "bt_address=12-34-56-78-90-ab",
                    "bt_mac=FF:EE:DD:CC:BB:AA"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-NETWORK-1"],
                owasp_categories=["A3:2021-Injection"]
            ),
            
            "ip_address": PIIPattern(
                name="IP Address",
                pattern=r'(?i)(?:ip[_\-]?address|local[_\-]?ip|device[_\-]?ip)["\'\s]*[:=]["\'\s]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                description="Device IP address",
                pii_type=PIIType.NETWORK_IDENTIFIER,
                severity=SeverityLevel.LOW,
                examples=[
                    "ip_address=192.168.1.100",
                    "local_ip=10.0.0.50",
                    "device_ip=172.16.0.25"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-NETWORK-1"],
                owasp_categories=["A3:2021-Injection"]
            ),
            
            "dns_address": PIIPattern(
                name="DNS Address",
                pattern=r'(?i)(?:dns[_\-]?server|dns[_\-]?address|nameserver)["\'\s]*[:=]["\'\s]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                description="DNS server address",
                pii_type=PIIType.NETWORK_IDENTIFIER,
                severity=SeverityLevel.LOW,
                examples=[
                    "dns_server=8.8.8.8",
                    "dns_address=1.1.1.1",
                    "nameserver=208.67.222.222"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-NETWORK-1"],
                owasp_categories=["A5:2021-Security Misconfiguration"]
            ),
            
            "ssid": PIIPattern(
                name="WiFi SSID",
                pattern=r'(?i)(?:ssid|wifi[_\-]?name|network[_\-]?name)["\'\s]*[:=]["\'\s]*["\']([^"\']{1,32})["\']',
                description="WiFi network SSID",
                pii_type=PIIType.NETWORK_IDENTIFIER,
                severity=SeverityLevel.LOW,
                examples=[
                    'ssid="MyHomeNetwork"',
                    'wifi_name="CompanyWiFi"',
                    'network_name="CoffeeShop_Guest"'
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-NETWORK-1"],
                owasp_categories=["A5:2021-Security Misconfiguration"]
            )
        }
    
    def _get_personal_identifier_patterns(self) -> Dict[str, PIIPattern]:
        """Get personal identifier patterns."""
        return {
            "phone_number": PIIPattern(
                name="Phone Number",
                pattern=r'(?i)(?:phone|mobile|tel|telephone)["\'\s]*[:=]["\'\s]*(\+?[0-9\-\(\)\s]{10,15})',
                description="Phone number",
                pii_type=PIIType.PERSONAL_IDENTIFIER,
                severity=SeverityLevel.HIGH,
                examples=[
                    "phone=+1-555-123-4567",
                    "mobile=5551234567",
                    "tel=(555) 987-6543"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1", "MASVS-STORAGE-4"],
                owasp_categories=["A3:2021-Injection", "A9:2021-Security Logging"]
            ),
            
            "email_address": PIIPattern(
                name="Email Address",
                pattern=r'(?i)(?:email|mail|e-mail)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                description="Email address",
                pii_type=PIIType.PERSONAL_IDENTIFIER,
                severity=SeverityLevel.MEDIUM,
                examples=[
                    "email=user@example.com",
                    "mail=test@domain.org",
                    "e-mail=contact@company.co.uk"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1", "MASVS-STORAGE-4"],
                owasp_categories=["A3:2021-Injection"]
            ),
            
            "full_name": PIIPattern(
                name="Full Name",
                pattern=r'(?i)(?:full[_\-]?name|user[_\-]?name|display[_\-]?name|real[_\-]?name)["\'\s]*[:=]["\'\s]*["\']([A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)["\']',
                description="Person's full name",
                pii_type=PIIType.PERSONAL_IDENTIFIER,
                severity=SeverityLevel.MEDIUM,
                examples=[
                    'full_name="John Doe"',
                    'user_name="Jane Smith"',
                    'display_name="Robert Johnson"'
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1"],
                owasp_categories=["A3:2021-Injection"]
            ),
            
            "date_of_birth": PIIPattern(
                name="Date of Birth",
                pattern=r'(?i)(?:date[_\-]?of[_\-]?birth|dob|birth[_\-]?date)["\'\s]*[:=]["\'\s]*([0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{4}|[0-9]{4}[/-][0-9]{1,2}[/-][0-9]{1,2})',
                description="Date of birth",
                pii_type=PIIType.PERSONAL_IDENTIFIER,
                severity=SeverityLevel.HIGH,
                examples=[
                    "date_of_birth=01/15/1990",
                    "dob=1990-01-15",
                    "birth_date=15/01/1990"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1", "MASVS-STORAGE-4"],
                owasp_categories=["A3:2021-Injection"]
            ),
            
            "social_security": PIIPattern(
                name="Social Security Number",
                pattern=r'(?i)(?:ssn|social[_\-]?security|social[_\-]?security[_\-]?number)["\'\s]*[:=]["\'\s]*([0-9]{3}-?[0-9]{2}-?[0-9]{4})',
                description="Social Security Number",
                pii_type=PIIType.PERSONAL_IDENTIFIER,
                severity=SeverityLevel.CRITICAL,
                examples=[
                    "ssn=123-45-6789",
                    "social_security=123456789",
                    "social_security_number=123-45-6789"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1", "MASVS-STORAGE-4"],
                owasp_categories=["A3:2021-Injection", "A9:2021-Security Logging"]
            )
        }
    
    def _get_authentication_data_patterns(self) -> Dict[str, PIIPattern]:
        """Get authentication data patterns."""
        return {
            "session_token": PIIPattern(
                name="Session Token",
                pattern=r'(?i)(?:session[_\-]?token|auth[_\-]?token|access[_\-]?token)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9+/=]{20,})',
                description="Session or authentication token",
                pii_type=PIIType.AUTHENTICATION_DATA,
                severity=SeverityLevel.CRITICAL,
                examples=[
                    "session_token=eyJhbGciOiJIUzI1NiIs",
                    "auth_token=abc123def456ghi789",
                    "access_token=Bearer xyz789uvw456"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-AUTH-1", "MASVS-NETWORK-1"],
                owasp_categories=["A7:2021-Identification and Authentication Failures"]
            ),
            
            "api_key": PIIPattern(
                name="API Key",
                pattern=r'(?i)(?:api[_\-]?key|key|secret[_\-]?key)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9]{20,})',
                description="API key or secret key",
                pii_type=PIIType.AUTHENTICATION_DATA,
                severity=SeverityLevel.CRITICAL,
                examples=[
                    "api_key=sk_test_123456789abcdef",
                    "key=AIzaSyDxXxXxXxXxXxXxXxXxXxXxXxXx",
                    "secret_key=abc123def456789xyz"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-AUTH-1", "MASVS-CRYPTO-1"],
                owasp_categories=["A2:2021-Cryptographic Failures", "A7:2021-Identification and Authentication Failures"]
            ),
            
            "password": PIIPattern(
                name="Password",
                pattern=r'(?i)(?:password|passwd|pwd)["\'\s]*[:=]["\'\s]*["\']([^"\']{6,})["\']',
                description="User password",
                pii_type=PIIType.AUTHENTICATION_DATA,
                severity=SeverityLevel.CRITICAL,
                examples=[
                    'password="mySecret123"',
                    'passwd="strongPassword!"',
                    'pwd="userPass2021"'
                ],
                category=AnalysisCategory.HARDCODED_ENDPOINT,
                masvs_controls=["MASVS-AUTH-1", "MASVS-STORAGE-4"],
                owasp_categories=["A2:2021-Cryptographic Failures", "A7:2021-Identification and Authentication Failures"]
            ),
            
            "bearer_token": PIIPattern(
                name="Bearer Token",
                pattern=r'(?i)bearer\s+([a-zA-Z0-9\-._~+/]+=*)',
                description="OAuth Bearer token",
                pii_type=PIIType.AUTHENTICATION_DATA,
                severity=SeverityLevel.CRITICAL,
                examples=[
                    "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
                    "bearer abc123def456789xyz",
                    "Bearer token_12345abcdef"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-AUTH-1", "MASVS-NETWORK-1"],
                owasp_categories=["A7:2021-Identification and Authentication Failures"]
            ),
            
            "jwt_token": PIIPattern(
                name="JWT Token",
                pattern=r'(?i)(?:jwt|token)["\'\s]*[:=]["\'\s]*(eyJ[a-zA-Z0-9\-._~+/]*={0,2}\.[a-zA-Z0-9\-._~+/]*={0,2}\.[a-zA-Z0-9\-._~+/]*={0,2})',
                description="JSON Web Token",
                pii_type=PIIType.AUTHENTICATION_DATA,
                severity=SeverityLevel.HIGH,
                examples=[
                    "jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                    "token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-AUTH-1", "MASVS-CRYPTO-1"],
                owasp_categories=["A7:2021-Identification and Authentication Failures"]
            )
        }
    
    def _get_biometric_data_patterns(self) -> Dict[str, PIIPattern]:
        """Get biometric data patterns."""
        return {
            "fingerprint_data": PIIPattern(
                name="Fingerprint Data",
                pattern=r'(?i)(?:fingerprint|biometric)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9+/=]{40,})',
                description="Biometric fingerprint data",
                pii_type=PIIType.BIOMETRIC_DATA,
                severity=SeverityLevel.CRITICAL,
                examples=[
                    "fingerprint=iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAY",
                    "biometric=eyJmaW5nZXJwcmludCI6IjEyMzQ1Njc4OTAi"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1", "MASVS-STORAGE-4"],
                owasp_categories=["A3:2021-Injection", "A9:2021-Security Logging"]
            ),
            
            "face_recognition": PIIPattern(
                name="Face Recognition Data",
                pattern=r'(?i)(?:face[_\-]?recognition|facial[_\-]?data|face[_\-]?print)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9+/=]{40,})',
                description="Facial recognition biometric data",
                pii_type=PIIType.BIOMETRIC_DATA,
                severity=SeverityLevel.CRITICAL,
                examples=[
                    "face_recognition=data:image/jpeg;base64,/9j/4AAQSkZJ",
                    "facial_data=eyJmYWNlIjoiZGF0YSJ9"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1", "MASVS-STORAGE-4"],
                owasp_categories=["A3:2021-Injection", "A9:2021-Security Logging"]
            )
        }
    
    def _get_behavioral_data_patterns(self) -> Dict[str, PIIPattern]:
        """Get behavioral data patterns."""
        return {
            "usage_analytics": PIIPattern(
                name="Usage Analytics",
                pattern=r'(?i)(?:analytics|usage[_\-]?data|user[_\-]?behavior)["\'\s]*[:=]["\'\s]*\{.*(?:screen[_\-]?time|app[_\-]?usage|click[_\-]?count).*\}',
                description="User behavior and usage analytics",
                pii_type=PIIType.BEHAVIORAL_DATA,
                severity=SeverityLevel.MEDIUM,
                examples=[
                    'analytics={"screen_time": 3600, "app_usage": "high"}',
                    'usage_data={"clicks": 150, "session_duration": 1800}'
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1"],
                owasp_categories=["A9:2021-Security Logging"]
            ),
            
            "search_history": PIIPattern(
                name="Search History",
                pattern=r'(?i)(?:search[_\-]?history|query[_\-]?log|search[_\-]?terms)["\'\s]*[:=]["\'\s]*\[.*\]',
                description="User search history and query logs",
                pii_type=PIIType.BEHAVIORAL_DATA,
                severity=SeverityLevel.HIGH,
                examples=[
                    'search_history=["restaurants near me", "weather forecast"]',
                    'query_log=["how to", "what is", "where can I"]'
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-PRIVACY-1"],
                owasp_categories=["A9:2021-Security Logging"]
            )
        }
    
    def _get_system_identifier_patterns(self) -> Dict[str, PIIPattern]:
        """Get system identifier patterns."""
        return {
            "build_fingerprint": PIIPattern(
                name="Build Fingerprint",
                pattern=r'(?i)(?:build[_\-]?fingerprint|fingerprint)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9/_.:,-]{20,})',
                description="Android build fingerprint",
                pii_type=PIIType.SYSTEM_IDENTIFIER,
                severity=SeverityLevel.MEDIUM,
                examples=[
                    "build_fingerprint=google/crosshatch/crosshatch:10/QQ3A.200805.001",
                    "fingerprint=samsung/beyond1ltexx/beyond1:10/QP1A.190711.020"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-STORAGE-4"],
                owasp_categories=["A3:2021-Injection"]
            ),
            
            "hardware_model": PIIPattern(
                name="Hardware Model",
                pattern=r'(?i)(?:device[_\-]?model|hardware[_\-]?model|model)["\'\s]*[:=]["\'\s]*([A-Za-z0-9\-\s]+)',
                description="Device hardware model",
                pii_type=PIIType.SYSTEM_IDENTIFIER,
                severity=SeverityLevel.LOW,
                examples=[
                    "device_model=SM-G973F",
                    "hardware_model=Pixel 4",
                    "model=iPhone12,1"
                ],
                category=AnalysisCategory.NETWORK_TRANSMISSION,
                masvs_controls=["MASVS-STORAGE-4"],
                owasp_categories=["A3:2021-Injection"]
            )
        }
    
    def _initialize_network_patterns(self) -> Dict[str, re.Pattern]:
        """Initialize network transmission detection patterns."""
        return {
            # HTTP URL patterns
            "http_url": re.compile(r'http://[^\s\'"<>]+', re.IGNORECASE),
            "http_parameter": re.compile(r'http://[^\s\'"<>]*[?&]([^=]+)=([^&\s\'"<>]+)', re.IGNORECASE),
            
            # HTTPS URL patterns
            "https_url": re.compile(r'https://[^\s\'"<>]+', re.IGNORECASE),
            "https_parameter": re.compile(r'https://[^\s\'"<>]*[?&]([^=]+)=([^&\s\'"<>]+)', re.IGNORECASE),
            
            # Network configuration patterns
            "network_config": re.compile(r'(?:url|endpoint|api[_\-]?url|base[_\-]?url)\s*[:=]\s*["\']?(https?://[^"\'\s]+)', re.IGNORECASE),
            
            # JavaScript/WebView patterns
            "webview_url": re.compile(r'loadUrl\s*\(\s*["\']?(https?://[^"\'\)]+)', re.IGNORECASE),
            "ajax_request": re.compile(r'(?:ajax|fetch|xhr).*(?:url|endpoint)\s*[:=]\s*["\']?(https?://[^"\'\s]+)', re.IGNORECASE),
            
            # API endpoint patterns
            "rest_api": re.compile(r'(?:GET|POST|PUT|DELETE|PATCH)\s+["\']?(https?://[^"\'\s]+)', re.IGNORECASE),
            "graphql_endpoint": re.compile(r'(?:graphql|gql).*endpoint["\'\s]*[:=]["\'\s]*(https?://[^"\'\s]+)', re.IGNORECASE),
            
            # WebSocket patterns
            "websocket_url": re.compile(r'(?:ws|wss)://[^\s\'"<>]+', re.IGNORECASE),
            
            # Database connection patterns
            "database_url": re.compile(r'(?:jdbc|mongodb|mysql|postgresql|redis)://[^\s\'"<>]+', re.IGNORECASE),
        }
    
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile all regex patterns for better performance."""
        compiled = {}
        
        for pattern_id, pattern in self.patterns.items():
            if pattern.is_regex:
                flags = 0 if pattern.case_sensitive else re.IGNORECASE
                try:
                    compiled[pattern_id] = re.compile(pattern.pattern, flags)
                except re.error as e:
                    # Log error but don't fail completely
                    print(f"Warning: Failed to compile pattern {pattern_id}: {e}")
                    
        return compiled
    
    def get_pattern(self, pattern_name: str) -> Optional[PIIPattern]:
        """Get a pattern by name with enhanced validation."""
        pattern = self.patterns.get(pattern_name)
        if pattern and self._validate_pattern_integrity(pattern):
            return pattern
        return None
    
    def get_patterns_by_type(self, pii_type: PIIType) -> List[PIIPattern]:
        """Get all patterns for a specific PII type."""
        return [
            pattern for pattern in self.patterns.values()
            if pattern.pii_type == pii_type
        ]
    
    def get_patterns_by_severity(self, severity: SeverityLevel) -> List[PIIPattern]:
        """Get all patterns for a specific severity level."""
        return [
            pattern for pattern in self.patterns.values()
            if pattern.severity == severity
        ]
    
    def get_patterns_by_category(self, category: AnalysisCategory) -> List[PIIPattern]:
        """Get all patterns for a specific analysis category."""
        return [
            pattern for pattern in self.patterns.values()
            if pattern.category == category
        ]
    
    def get_compiled_pattern(self, pattern_id: str) -> Optional[re.Pattern]:
        """Get a compiled regex pattern."""
        return self.compiled_patterns.get(pattern_id)
    
    def get_network_pattern(self, pattern_name: str) -> Optional[re.Pattern]:
        """Get a network transmission pattern."""
        return self.network_patterns.get(pattern_name)
    
    def get_all_pattern_ids(self) -> List[str]:
        """Get all pattern IDs."""
        return list(self.patterns.keys())
    
    def get_all_patterns(self) -> List[PIIPattern]:
        """Get all patterns."""
        return list(self.patterns.values())

    def get_critical_patterns(self) -> List[PIIPattern]:
        """Get patterns with critical severity."""
        return [p for p in self.patterns.values() if p.severity == SeverityLevel.CRITICAL]

    def get_high_risk_patterns(self) -> List[PIIPattern]:
        """Get patterns with high or critical severity."""
        return [p for p in self.patterns.values() 
                if p.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]]
    
    def validate_all_patterns(self) -> Dict[str, List[str]]:
        """Validate all patterns and return issues."""
        from .data_structures import validate_pii_pattern
        
        validation_results = {}
        for pattern_id, pattern in self.patterns.items():
            issues = validate_pii_pattern(pattern)
            if issues:
                validation_results[pattern_id] = issues
        
        return validation_results
    
    def get_masvs_coverage(self) -> Dict[str, int]:
        """Get MASVS control coverage by patterns."""
        coverage = {}
        
        for pattern in self.patterns.values():
            for control in pattern.masvs_controls:
                coverage[control] = coverage.get(control, 0) + 1
        
        return coverage
    
    def get_owasp_coverage(self) -> Dict[str, int]:
        """Get OWASP category coverage by patterns."""
        coverage = {}
        
        for pattern in self.patterns.values():
            for category in pattern.owasp_categories:
                coverage[category] = coverage.get(category, 0) + 1
        
        return coverage
    
    def search_patterns(self, search_term: str) -> List[PIIPattern]:
        """Search patterns by name, description, or PII type."""
        search_term = search_term.lower()
        results = []
        
        for pattern in self.patterns.values():
            if (search_term in pattern.name.lower() or
                search_term in pattern.description.lower() or
                search_term in pattern.pii_type.value.lower()):
                results.append(pattern)
        
        return results
    
    def get_transmission_method_patterns(self, method: TransmissionMethod) -> List[PIIPattern]:
        """Get patterns relevant for a specific transmission method."""
        # This would be enhanced with metadata about which patterns
        # are most relevant for specific transmission methods
        if method in [TransmissionMethod.HTTP, TransmissionMethod.HTTPS]:
            return [
                pattern for pattern in self.patterns.values()
                if pattern.category in [
                    AnalysisCategory.NETWORK_TRANSMISSION,
                    AnalysisCategory.URL_PARAMETER,
                    AnalysisCategory.API_COMMUNICATION
                ]
            ]
        elif method == TransmissionMethod.WEBSOCKET:
            return [
                pattern for pattern in self.patterns.values()
                if pattern.category == AnalysisCategory.WEBVIEW_INJECTION
            ]
        else:
            return list(self.patterns.values())
    
    def export_patterns_config(self) -> Dict[str, Any]:
        """Export patterns as configuration for external tools."""
        config = {
            "patterns": {},
            "network_patterns": {},
            "metadata": {
                "total_patterns": len(self.patterns),
                "coverage": {
                    "masvs": self.get_masvs_coverage(),
                    "owasp": self.get_owasp_coverage()
                }
            }
        }
        
        # Export PII patterns
        for pattern_id, pattern in self.patterns.items():
            config["patterns"][pattern_id] = {
                "name": pattern.name,
                "pattern": pattern.pattern,
                "description": pattern.description,
                "pii_type": pattern.pii_type.value,
                "severity": pattern.severity.value,
                "category": pattern.category.value,
                "examples": pattern.examples,
                "masvs_controls": pattern.masvs_controls,
                "owasp_categories": pattern.owasp_categories
            }
        
        # Export network patterns
        for pattern_name, pattern in self.network_patterns.items():
            config["network_patterns"][pattern_name] = pattern.pattern
        
        return config

    def validate_pii_match(self, pattern: PIIPattern, matched_value: str, context: str) -> Tuple[bool, float]:
        """
        Enhanced validation for PII matches to reduce false positives.
        
        Args:
            pattern: The PII pattern that matched
            matched_value: The value that was matched
            context: Surrounding context for analysis
            
        Returns:
            Tuple of (is_valid, confidence_score)
        """
        # Check cache first
        cache_key = f"{pattern.name}:{hash(matched_value + context[:100])}"
        if cache_key in self.validation_cache:
            return self.validation_cache[cache_key]
        
        try:
            # Base validation - check minimum requirements
            if not self._basic_validation(pattern, matched_value):
                result = (False, 0.0)
                self.validation_cache[cache_key] = result
                return result
            
            # Enhanced context-aware validation
            context_score = self._validate_context(pattern, matched_value, context)
            if context_score < 0.3:  # Very low confidence from context
                result = (False, context_score)
                self.validation_cache[cache_key] = result
                return result
            
            # Pattern-specific validation
            pattern_score = self._validate_pattern_specific(pattern, matched_value, context)
            
            # False positive filtering
            fp_penalty = self._apply_false_positive_filters(pattern, matched_value, context)
            
            # Calculate final confidence
            final_confidence = min(1.0, (context_score + pattern_score) / 2.0 - fp_penalty)
            
            # Determine validity threshold
            is_valid = final_confidence >= 0.5
            
            result = (is_valid, final_confidence)
            self.validation_cache[cache_key] = result
            return result
            
        except Exception as e:
            # In case of validation error, return conservative result
            return (True, 0.6)
    
    def _basic_validation(self, pattern: PIIPattern, matched_value: str) -> bool:
        """Perform basic validation checks."""
        # Length validation
        if len(matched_value) < pattern.min_length or len(matched_value) > pattern.max_length:
            return False
        
        # Pattern-specific basic checks
        if pattern.pii_type == PIIType.DEVICE_IDENTIFIER:
            return self._validate_device_identifier(matched_value)
        elif pattern.pii_type == PIIType.LOCATION_DATA:
            return self._validate_location_data(matched_value)
        elif pattern.pii_type == PIIType.PERSONAL_IDENTIFIER:
            return self._validate_personal_identifier(matched_value, pattern.name)
        elif pattern.pii_type == PIIType.AUTHENTICATION_DATA:
            return self._validate_authentication_data(matched_value)
        
        return True
    
    def _validate_device_identifier(self, value: str) -> bool:
        """Enhanced validation for device identifiers."""
        # Android ID should be 16 hexadecimal characters
        if re.match(r'^[a-f0-9]{16}$', value, re.IGNORECASE):
            # Check if it's not a common fake/test value
            fake_values = ['0000000000000000', 'ffffffffffffffff', '9774d56d682e549c']
            return value.lower() not in fake_values
        
        # IMEI should be 14-15 digits and pass Luhn algorithm
        if re.match(r'^\d{14,15}$', value):
            return self._validate_imei_luhn(value)
        
        # UUID format for advertising IDs
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.IGNORECASE):
            # Check if it's not a null/test UUID
            null_uuids = ['00000000-0000-0000-0000-000000000000', '12345678-1234-1234-1234-123456789012']
            return value.lower() not in null_uuids
        
        return True
    
    def _validate_imei_luhn(self, imei: str) -> bool:
        """Validate IMEI using Luhn algorithm."""
        try:
            digits = [int(d) for d in imei]
            checksum = 0
            
            for i, digit in enumerate(reversed(digits)):
                if i % 2 == 1:  # Every second digit from right
                    digit *= 2
                    if digit > 9:
                        digit = digit // 10 + digit % 10
                checksum += digit
            
            return checksum % 10 == 0
        except:
            return False
    
    def _validate_location_data(self, value: str) -> bool:
        """Enhanced validation for location data."""
        try:
            coord = float(value)
            
            # Check if it's within valid coordinate ranges
            # This is a basic check - could be latitude or longitude
            if -180.0 <= coord <= 180.0:
                # Check if it's not obviously fake (like 0.0, 1.0, etc.)
                fake_coords = [0.0, 1.0, -1.0, 90.0, -90.0, 180.0, -180.0]
                return coord not in fake_coords
            
            return False
        except ValueError:
            return False
    
    def _validate_personal_identifier(self, value: str, pattern_name: str) -> bool:
        """Enhanced validation for personal identifiers."""
        if 'email' in pattern_name.lower():
            return self._validate_email_format(value)
        elif 'phone' in pattern_name.lower():
            return self._validate_phone_format(value)
        elif 'ssn' in pattern_name.lower():
            return self._validate_ssn_format(value)
        
        return True
    
    def _validate_email_format(self, email: str) -> bool:
        """Enhanced email validation."""
        # Basic format check
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return False
        
        # Check for obviously fake domains
        fake_domains = ['example.com', 'test.com', 'fake.com', 'localhost', 'invalid.com']
        domain = email.split('@')[1].lower()
        
        return domain not in fake_domains
    
    def _validate_phone_format(self, phone: str) -> bool:
        """Enhanced phone number validation."""
        # Remove common formatting
        cleaned = re.sub(r'[^\d]', '', phone)
        
        # Check length (most phone numbers are 7-15 digits)
        if not 7 <= len(cleaned) <= 15:
            return False
        
        # Check for obviously fake patterns
        fake_patterns = ['1234567890', '0000000000', '1111111111', '9999999999']
        return cleaned not in fake_patterns
    
    def _validate_ssn_format(self, ssn: str) -> bool:
        """Enhanced SSN validation."""
        # Remove formatting
        cleaned = re.sub(r'[^\d]', '', ssn)
        
        if len(cleaned) != 9:
            return False
        
        # Check for invalid SSN patterns
        invalid_patterns = [
            '000000000', '111111111', '222222222', '333333333',
            '444444444', '555555555', '666666666', '777777777',
            '888888888', '999999999', '123456789'
        ]
        
        return cleaned not in invalid_patterns
    
    def _validate_authentication_data(self, value: str) -> bool:
        """Enhanced validation for authentication data."""
        # API keys should have reasonable entropy
        if len(value) < 8:
            return False
        
        # Check for obvious test/fake values
        fake_auth_values = [
            'test', 'fake', 'demo', 'example', 'sample',
            '12345678', 'password', 'secret', 'key123'
        ]
        
        return value.lower() not in fake_auth_values
    
    def _validate_context(self, pattern: PIIPattern, matched_value: str, context: str) -> float:
        """Validate PII match based on surrounding context."""
        context_lower = context.lower()
        
        # Positive context indicators
        positive_indicators = {
            PIIType.DEVICE_IDENTIFIER: [
                'device', 'android', 'phone', 'hardware', 'identifier',
                'getdeviceid', 'telephonymanager', 'build.serial'
            ],
            PIIType.LOCATION_DATA: [
                'location', 'gps', 'coordinates', 'latitude', 'longitude',
                'locationmanager', 'getlocation', 'position'
            ],
            PIIType.PERSONAL_IDENTIFIER: [
                'email', 'name', 'phone', 'contact', 'profile',
                'user', 'account', 'personal'
            ],
            PIIType.AUTHENTICATION_DATA: [
                'api', 'key', 'token', 'auth', 'secret', 'password',
                'credential', 'authorization', 'bearer'
            ]
        }
        
        # Negative context indicators (reduce confidence)
        negative_indicators = [
            'test', 'mock', 'fake', 'demo', 'example', 'sample',
            'comment', '//', '/*', 'todo', 'fixme', 'debug',
            'placeholder', 'dummy', 'template'
        ]
        
        # Network transmission indicators (increase confidence for network analysis)
        network_indicators = [
            'http', 'https', 'url', 'request', 'post', 'get',
            'send', 'transmit', 'upload', 'api', 'endpoint',
            'socket', 'connection', 'network', 'web'
        ]
        
        # Calculate context score
        positive_score = 0.0
        negative_score = 0.0
        network_score = 0.0
        
        # Check positive indicators
        for indicator in positive_indicators.get(pattern.pii_type, []):
            if indicator in context_lower:
                positive_score += 0.1
        
        # Check negative indicators
        for indicator in negative_indicators:
            if indicator in context_lower:
                negative_score += 0.15
        
        # Check network indicators
        for indicator in network_indicators:
            if indicator in context_lower:
                network_score += 0.05
        
        # Base score
        base_score = 0.5
        
        # Calculate final context score
        context_score = base_score + positive_score + network_score - negative_score
        
        return max(0.0, min(1.0, context_score))
    
    def _validate_pattern_specific(self, pattern: PIIPattern, matched_value: str, context: str) -> float:
        """Pattern-specific validation for enhanced accuracy."""
        score = 0.7  # Base score
        
        # Enhanced validation based on pattern name
        if 'android_id' in pattern.name.lower():
            # Check if it's in proper Android ID context
            if any(keyword in context.lower() for keyword in [
                'settings.secure.android_id', 'getstring(secure.android_id)', 
                'telephonymanager', 'getdeviceid'
            ]):
                score += 0.2
        
        elif 'imei' in pattern.name.lower():
            # Check for IMEI-specific context
            if any(keyword in context.lower() for keyword in [
                'telephonymanager', 'getdeviceid', 'getimei', 'phone_state'
            ]):
                score += 0.2
        
        elif 'gps' in pattern.name.lower() or 'location' in pattern.name.lower():
            # Check for location-specific context
            if any(keyword in context.lower() for keyword in [
                'locationmanager', 'getlocation', 'fusedlocationapi',
                'gps_provider', 'network_provider'
            ]):
                score += 0.2
        
        elif 'email' in pattern.name.lower():
            # Check for email-specific context
            if any(keyword in context.lower() for keyword in [
                'intent.action.send', 'mailto:', 'email', 'contact'
            ]):
                score += 0.1
        
        return min(1.0, score)
    
    def _apply_false_positive_filters(self, pattern: PIIPattern, matched_value: str, context: str) -> float:
        """Apply false positive filters to reduce confidence for likely false positives."""
        penalty = 0.0
        context_lower = context.lower()
        
        # Common false positive patterns
        fp_patterns = {
            'test_data': ['test', 'demo', 'example', 'sample', 'mock', 'fake'],
            'documentation': ['readme', 'docs', 'comment', 'note', 'help'],
            'development': ['debug', 'dev', 'localhost', 'staging', 'qa'],
            'placeholder': ['placeholder', 'dummy', 'template', 'default', 'none'],
            'ui_strings': ['string.xml', 'values.xml', 'layout.xml', 'menu.xml']
        }
        
        for category, indicators in fp_patterns.items():
            for indicator in indicators:
                if indicator in context_lower:
                    penalty += 0.1
                    break  # Only count once per category
        
        # Check for repeated/pattern values that might be fake
        if self._is_likely_fake_data(matched_value):
            penalty += 0.2
        
        # Check for hardcoded string literals (less likely to be real PII in transmission)
        if '"' + matched_value + '"' in context or "'" + matched_value + "'" in context:
            # But only if it's not in a network call context
            if not any(net in context_lower for net in ['http', 'post', 'get', 'send', 'url']):
                penalty += 0.1
        
        return min(0.8, penalty)  # Cap maximum penalty
    
    def _is_likely_fake_data(self, value: str) -> bool:
        """Check if the value appears to be fake/test data."""
        # Check for repeating patterns
        if len(set(value)) <= 2 and len(value) > 4:  # Like "1111111111" or "abababab"
            return True
        
        # Check for sequential patterns
        if self._is_sequential(value):
            return True
        
        # Check for common test values
        common_fakes = [
            '123456789', '987654321', 'abcdefgh', '12345678',
            'test@test.com', 'admin@admin.com', '555-1234'
        ]
        
        return value.lower() in [fake.lower() for fake in common_fakes]
    
    def _is_sequential(self, value: str) -> bool:
        """Check if value contains sequential characters."""
        if len(value) < 4:
            return False
        
        # Check for ascending sequence
        ascending = all(ord(value[i]) == ord(value[i-1]) + 1 for i in range(1, len(value)))
        
        # Check for descending sequence
        descending = all(ord(value[i]) == ord(value[i-1]) - 1 for i in range(1, len(value)))
        
        return ascending or descending
    
    def _initialize_context_validators(self) -> Dict[str, Any]:
        """Initialize context-specific validators."""
        return {
            'network_transmission': self._validate_network_context,
            'storage_context': self._validate_storage_context,
            'ui_context': self._validate_ui_context
        }
    
    def _initialize_false_positive_filters(self) -> Dict[str, Any]:
        """Initialize false positive filter systems."""
        return {
            'test_data_filter': self._filter_test_data,
            'documentation_filter': self._filter_documentation,
            'development_filter': self._filter_development_code
        }
    
    def _validate_pattern_integrity(self, pattern: PIIPattern) -> bool:
        """Validate that a pattern is properly formed."""
        try:
            # Test compile the regex
            re.compile(pattern.pattern)
            
            # Check required fields
            return (pattern.name and pattern.pattern and 
                   pattern.pii_type and pattern.severity)
        except re.error:
            return False

    def _validate_network_context(self, pattern: PIIPattern, matched_value: str, context: str) -> float:
        """Validate PII match in network transmission context."""
        confidence = 0.7  # Base confidence
        
        # Check for network-related keywords in context
        network_indicators = ['http', 'url', 'post', 'get', 'api', 'endpoint', 'request']
        network_context = any(indicator in context.lower() for indicator in network_indicators)
        
        if network_context:
            confidence += 0.2
        
        # Check for transmission-related patterns
        if 'param' in context.lower() or 'query' in context.lower():
            confidence += 0.1
            
        return min(1.0, confidence)

    def _validate_storage_context(self, pattern: PIIPattern, matched_value: str, context: str) -> float:
        """Validate PII match in storage context."""
        confidence = 0.7  # Base confidence
        
        # Check for storage-related keywords
        storage_indicators = ['database', 'sqlite', 'prefs', 'shared', 'file', 'cache']
        storage_context = any(indicator in context.lower() for indicator in storage_indicators)
        
        if storage_context:
            confidence += 0.2
            
        return min(1.0, confidence)

    def _validate_ui_context(self, pattern: PIIPattern, matched_value: str, context: str) -> float:
        """Validate PII match in UI context."""
        confidence = 0.7  # Base confidence
        
        # Check for UI-related keywords
        ui_indicators = ['layout', 'view', 'button', 'text', 'input', 'field']
        ui_context = any(indicator in context.lower() for indicator in ui_indicators)
        
        if ui_context:
            confidence += 0.1  # Lower confidence for UI context as it's often just display
            
        return min(1.0, confidence)

    def _filter_test_data(self, pattern: PIIPattern, matched_value: str, context: str) -> float:
        """Filter potential false positives from test data."""
        penalty = 0.0
        
        # Check for test/example indicators in context
        test_indicators = ['test', 'example', 'demo', 'sample', 'mock', 'fake']
        test_context = any(indicator in context.lower() for indicator in test_indicators)
        
        if test_context:
            penalty += 0.4
            
        # Check for obvious fake patterns in the value
        if self._is_likely_fake_data(matched_value):
            penalty += 0.3
            
        return penalty

    def _filter_documentation(self, pattern: PIIPattern, matched_value: str, context: str) -> float:
        """Filter potential false positives from documentation."""
        penalty = 0.0
        
        # Check for documentation indicators
        doc_indicators = ['readme', 'documentation', 'comment', 'javadoc', 'todo', 'fixme']
        doc_context = any(indicator in context.lower() for indicator in doc_indicators)
        
        if doc_context:
            penalty += 0.5
            
        # Check for comment patterns
        if '//' in context or '/*' in context or '#' in context:
            penalty += 0.3
            
        return penalty

    def _filter_development_code(self, pattern: PIIPattern, matched_value: str, context: str) -> float:
        """Filter potential false positives from development code."""
        penalty = 0.0
        
        # Check for development indicators
        dev_indicators = ['debug', 'log', 'console', 'print', 'dump', 'trace']
        dev_context = any(indicator in context.lower() for indicator in dev_indicators)
        
        if dev_context:
            penalty += 0.3
            
        # Check for variable names that suggest development
        if 'var_' in matched_value.lower() or 'debug_' in matched_value.lower():
            penalty += 0.2
            
        return penalty

# Singleton instance
_pii_pattern_library = None

def get_pii_pattern_library() -> PIIPatternLibrary:
    """Get the singleton PII pattern library instance."""
    global _pii_pattern_library
    if _pii_pattern_library is None:
        _pii_pattern_library = PIIPatternLibrary()
    return _pii_pattern_library

# Utility functions
def find_pii_in_text(text: str, pattern_ids: Optional[List[str]] = None) -> List[Tuple[str, re.Match, PIIPattern]]:
    """Find PII patterns in text."""
    library = get_pii_pattern_library()
    results = []
    
    patterns_to_check = pattern_ids or library.get_all_pattern_ids()
    
    for pattern_id in patterns_to_check:
        compiled_pattern = library.get_compiled_pattern(pattern_id)
        pii_pattern = library.get_pattern(pattern_id)
        
        if compiled_pattern and pii_pattern:
            for match in compiled_pattern.finditer(text):
                results.append((pattern_id, match, pii_pattern))
    
    return results

def extract_network_endpoints(text: str) -> List[NetworkEndpoint]:
    """Extract network endpoints from text."""
    library = get_pii_pattern_library()
    endpoints = []
    
    # Extract HTTPS URLs
    https_pattern = library.get_network_pattern("https_url")
    if https_pattern:
        for match in https_pattern.finditer(text):
            url = match.group(0)
            endpoints.append(NetworkEndpoint(
                url=url,
                protocol="HTTPS",
                uses_tls=True
            ))
    
    # Extract HTTP URLs
    http_pattern = library.get_network_pattern("http_url")
    if http_pattern:
        for match in http_pattern.finditer(text):
            url = match.group(0)
            endpoints.append(NetworkEndpoint(
                url=url,
                protocol="HTTP",
                uses_tls=False
            ))
    
    return endpoints

def categorize_transmission_risk(pii_type: PIIType, transmission_method: TransmissionMethod) -> str:
    """Categorize the risk level for PII transmission."""
    from .data_structures import calculate_transmission_risk
    
    risk_score = calculate_transmission_risk(pii_type, transmission_method)
    
    if risk_score >= 0.9:
        return "CRITICAL"
    elif risk_score >= 0.7:
        return "HIGH"
    elif risk_score >= 0.5:
        return "MEDIUM"
    else:
        return "LOW" 
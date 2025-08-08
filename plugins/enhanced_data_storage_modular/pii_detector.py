"""
PII (Personally Identifiable Information) Detector

This module provides comprehensive PII detection capabilities for Android applications,
specializing in identifying and analyzing various types of personally identifiable
information including device identifiers, location data, and contact information.

Features:
- Multi-pattern PII detection (Android ID, IMEI, GPS, MAC addresses)
- Context-aware false positive reduction
- Confidence scoring based on pattern specificity
- Privacy compliance assessment
- Data sensitivity classification
"""

import logging
import re
import json
import base64
import hashlib
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path

from .data_structures import (
    PIIFinding, PIIType, VulnerabilitySeverity, ConfidenceEvidence,
    EnhancedDataStorageAnalysisConfig
)
from .confidence_calculator import EnhancedDataStorageConfidenceCalculator

logger = logging.getLogger(__name__)

class PIIDetector:
    """
    Comprehensive PII detector specializing in Android device identifiers
    and personal information detection with advanced pattern matching.
    """
    
    def __init__(self, config: EnhancedDataStorageAnalysisConfig):
        """Initialize the PII detector with configuration."""
        self.config = config
        self.confidence_calculator = EnhancedDataStorageConfidenceCalculator()
        
        # Initialize PII detection patterns
        self.pii_patterns = self._initialize_pii_patterns()
        self.context_patterns = self._initialize_context_patterns()
        self.false_positive_patterns = self._initialize_false_positive_patterns()
        
        # PII sensitivity weights
        self.pii_sensitivity_weights = self._initialize_sensitivity_weights()
        
        # Detection statistics
        self.detection_stats = {
            "files_analyzed": 0,
            "pii_instances_found": 0,
            "false_positives_filtered": 0,
            "high_confidence_findings": 0
        }
    
    def _initialize_pii_patterns(self) -> Dict[PIIType, Dict[str, Any]]:
        """Initialize comprehensive PII detection patterns."""
        return {
            PIIType.ANDROID_ID: {
                "patterns": [
                    r'\b[a-f0-9]{16}\b',  # 16-character hex string
                    r'android_id\s*[=:]\s*["\']?([a-f0-9]{16})["\']?',
                    r'Settings\.Secure\.ANDROID_ID',
                    r'getContentResolver\(\)\.query.*ANDROID_ID',
                    r'ANDROID_ID.*["\']([a-f0-9]{16})["\']'
                ],
                "context_keywords": [
                    "android_id", "device_id", "unique_id", "secure_android_id",
                    "Settings.Secure", "ANDROID_ID", "DeviceIdHelper"
                ],
                "false_positive_indicators": [
                    "example", "sample", "test", "demo", "0000000000000000",
                    "1111111111111111", "ffffffffffffffff"
                ],
                "validation_length": 16,
                "pattern_specificity": 0.85
            },
            
            PIIType.IMEI: {
                "patterns": [
                    r'\b\d{15}\b',  # 15-digit IMEI
                    r'\b\d{14}\b',  # 14-digit IMEI (without check digit)
                    r'imei\s*[=:]\s*["\']?(\d{14,15})["\']?',
                    r'getDeviceId\(\)',
                    r'TelephonyManager.*getDeviceId',
                    r'IMEI.*["\'](\d{14,15})["\']'
                ],
                "context_keywords": [
                    "imei", "device_id", "telephony", "TelephonyManager",
                    "getDeviceId", "phone_info", "mobile_id"
                ],
                "false_positive_indicators": [
                    "000000000000000", "111111111111111", "123456789012345",
                    "example", "sample", "test"
                ],
                "validation_length": [14, 15],
                "pattern_specificity": 0.90
            },
            
            PIIType.GPS_COORDINATES: {
                "patterns": [
                    r'[-+]?\d{1,3}\.\d+,\s*[-+]?\d{1,3}\.\d+',  # lat,lng format
                    r'lat\s*[=:]\s*[-+]?\d{1,3}\.\d+',
                    r'lng\s*[=:]\s*[-+]?\d{1,3}\.\d+',
                    r'longitude\s*[=:]\s*[-+]?\d{1,3}\.\d+',
                    r'latitude\s*[=:]\s*[-+]?\d{1,3}\.\d+',
                    r'location\s*[=:]\s*["\']?[-+]?\d{1,3}\.\d+,\s*[-+]?\d{1,3}\.\d+["\']?',
                    r'GPS\s*[=:]\s*["\']?[-+]?\d{1,3}\.\d+,\s*[-+]?\d{1,3}\.\d+["\']?'
                ],
                "context_keywords": [
                    "gps", "location", "coordinates", "latitude", "longitude",
                    "lat", "lng", "position", "LocationManager", "GPS"
                ],
                "false_positive_indicators": [
                    "0.0,0.0", "1.0,1.0", "example", "sample", "test"
                ],
                "validation_range": {"lat": (-90, 90), "lng": (-180, 180)},
                "pattern_specificity": 0.75
            },
            
            PIIType.MAC_ADDRESS: {
                "patterns": [
                    r'\b[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\b',
                    r'\b[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}\b',
                    r'\b[0-9a-fA-F]{12}\b',  # MAC without separators
                    r'mac\s*[=:]\s*["\']?([0-9a-fA-F:]{17})["\']?',
                    r'getMacAddress\(\)',
                    r'WifiInfo.*getMacAddress'
                ],
                "context_keywords": [
                    "mac", "mac_address", "wifi", "bluetooth", "ethernet",
                    "WifiInfo", "getMacAddress", "BluetoothAdapter"
                ],
                "false_positive_indicators": [
                    "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "example", "sample"
                ],
                "validation_format": "^[0-9a-fA-F]{2}([:-])[0-9a-fA-F]{2}(\\1[0-9a-fA-F]{2}){4}$",
                "pattern_specificity": 0.88
            },
            
            PIIType.PHONE_NUMBER: {
                "patterns": [
                    r'\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',  # US format
                    r'\+?\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}',  # International
                    r'phone\s*[=:]\s*["\']?([\+\d\-\.\s\(\)]{10,})["\']?',
                    r'tel\s*[=:]\s*["\']?([\+\d\-\.\s\(\)]{10,})["\']?',
                    r'mobile\s*[=:]\s*["\']?([\+\d\-\.\s\(\)]{10,})["\']?'
                ],
                "context_keywords": [
                    "phone", "tel", "mobile", "number", "contact", "call",
                    "TelephonyManager", "SMS", "PhoneStateListener"
                ],
                "false_positive_indicators": [
                    "1234567890", "0000000000", "example", "sample"
                ],
                "validation_length": [10, 15],  # Typical phone number lengths
                "pattern_specificity": 0.70
            },
            
            PIIType.EMAIL_ADDRESS: {
                "patterns": [
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                    r'email\s*[=:]\s*["\']?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})["\']?',
                    r'mail\s*[=:]\s*["\']?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})["\']?'
                ],
                "context_keywords": [
                    "email", "mail", "contact", "user", "account",
                    "EmailAddress", "MailTo", "@"
                ],
                "false_positive_indicators": [
                    "example@example.com", "test@test.com", "user@domain.com",
                    "sample@sample.com"
                ],
                "pattern_specificity": 0.80
            },
            
            PIIType.CREDIT_CARD: {
                "patterns": [
                    r'\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Visa
                    r'\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # MasterCard
                    r'\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b',  # Amex
                    r'\b6011[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Discover
                    r'card\s*[=:]\s*["\']?(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})["\']?'
                ],
                "context_keywords": [
                    "card", "credit", "payment", "billing", "visa", "mastercard",
                    "amex", "discover", "CardNumber", "CreditCard"
                ],
                "false_positive_indicators": [
                    "0000000000000000", "1111111111111111", "4444444444444444"
                ],
                "pattern_specificity": 0.95
            },
            
            PIIType.IP_ADDRESS: {
                "patterns": [
                    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IPv4
                    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',  # IPv6
                    r'ip\s*[=:]\s*["\']?((?:[0-9]{1,3}\.){3}[0-9]{1,3})["\']?'
                ],
                "context_keywords": [
                    "ip", "address", "server", "host", "network", "inet",
                    "InetAddress", "NetworkInterface"
                ],
                "false_positive_indicators": [
                    "0.0.0.0", "127.0.0.1", "192.168.1.1", "10.0.0.1"
                ],
                "pattern_specificity": 0.60
            },
            
            PIIType.DEVICE_ID: {
                "patterns": [
                    r'\b[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\b',  # UUID
                    r'device_id\s*[=:]\s*["\']?([A-Za-z0-9\-]{20,})["\']?',
                    r'uuid\s*[=:]\s*["\']?([A-Fa-f0-9\-]{36})["\']?',
                    r'Build\.SERIAL',
                    r'getSerialNumber\(\)'
                ],
                "context_keywords": [
                    "device_id", "uuid", "serial", "identifier", "Build.SERIAL",
                    "getSerialNumber", "DeviceInfo"
                ],
                "false_positive_indicators": [
                    "00000000-0000-0000-0000-000000000000", "example", "sample"
                ],
                "pattern_specificity": 0.82
            },
            
            PIIType.ADVERTISING_ID: {
                "patterns": [
                    r'advertising.*id\s*[=:]\s*["\']?([A-Fa-f0-9\-]{36})["\']?',
                    r'AdvertisingIdClient\.getAdvertisingIdInfo',
                    r'getId\(\).*advertising',
                    r'GAID\s*[=:]\s*["\']?([A-Fa-f0-9\-]{36})["\']?'
                ],
                "context_keywords": [
                    "advertising", "gaid", "ad_id", "AdvertisingIdClient",
                    "AdvertisingId", "AdInfo"
                ],
                "false_positive_indicators": [
                    "00000000-0000-0000-0000-000000000000", "example"
                ],
                "pattern_specificity": 0.90
            }
        }
    
    def _initialize_context_patterns(self) -> Dict[str, List[str]]:
        """Initialize context patterns for better detection accuracy."""
        return {
            "privacy_sensitive": [
                "privacy", "sensitive", "personal", "confidential", "private",
                "user_data", "personal_info", "pii", "gdpr", "ccpa"
            ],
            "logging_context": [
                "log", "debug", "trace", "console", "print", "output",
                "Log.d", "Log.i", "Log.w", "Log.e", "System.out"
            ],
            "storage_context": [
                "save", "store", "write", "persist", "database", "file",
                "preferences", "cache", "backup", "SharedPreferences"
            ],
            "transmission_context": [
                "send", "transmit", "post", "upload", "network", "http",
                "api", "server", "cloud", "analytics"
            ]
        }
    
    def _initialize_false_positive_patterns(self) -> List[str]:
        """Initialize patterns that indicate false positives."""
        return [
            r'example',
            r'sample',
            r'test',
            r'demo',
            r'placeholder',
            r'dummy',
            r'fake',
            r'mock',
            r'template',
            r'default',
            r'null',
            r'undefined',
            r'0+',  # All zeros
            r'1+',  # All ones
            r'f+',  # All F's (hex)
        ]
    
    def _initialize_sensitivity_weights(self) -> Dict[PIIType, float]:
        """Initialize sensitivity weights for different PII types."""
        return {
            PIIType.ANDROID_ID: 0.9,
            PIIType.IMEI: 0.95,
            PIIType.GPS_COORDINATES: 0.85,
            PIIType.MAC_ADDRESS: 0.80,
            PIIType.PHONE_NUMBER: 0.90,
            PIIType.EMAIL_ADDRESS: 0.85,
            PIIType.CREDIT_CARD: 1.0,
            PIIType.IP_ADDRESS: 0.60,
            PIIType.DEVICE_ID: 0.85,
            PIIType.ADVERTISING_ID: 0.75
        }
    
    def detect_pii(self, apk_ctx) -> List[PIIFinding]:
        """
        Perform comprehensive PII detection analysis.
        
        Args:
            apk_ctx: APK context containing app information
            
        Returns:
            List of PII findings with confidence scores
        """
        logger.info(f"Starting PII detection for {apk_ctx.package_name}")
        start_time = time.time()
        
        findings = []
        
        try:
            # Get analysis targets
            analysis_targets = self._get_analysis_targets(apk_ctx)
            
            for target in analysis_targets:
                try:
                    # Analyze each target for PII
                    target_findings = self._analyze_target_for_pii(target)
                    findings.extend(target_findings)
                    
                    self.detection_stats["files_analyzed"] += 1
                    
                except Exception as e:
                    logger.warning(f"PII detection failed for {target.get('file_path', 'unknown')}: {e}")
            
            # Filter false positives
            filtered_findings = self._filter_false_positives(findings)
            
            # Calculate confidence scores
            for finding in filtered_findings:
                finding.confidence = self._calculate_pii_confidence(finding)
            
            # Update statistics
            self.detection_stats["pii_instances_found"] = len(findings)
            self.detection_stats["false_positives_filtered"] = len(findings) - len(filtered_findings)
            self.detection_stats["high_confidence_findings"] = len([
                f for f in filtered_findings if f.confidence >= 0.8
            ])
            
            duration = time.time() - start_time
            logger.info(f"PII detection completed: {len(filtered_findings)} findings in {duration:.2f}s")
            
            return filtered_findings
            
        except Exception as e:
            logger.error(f"PII detection failed: {e}")
            return []
    
    def _get_analysis_targets(self, apk_ctx) -> List[Dict[str, Any]]:
        """Get list of files and content to analyze for PII."""
        targets = []
        
        try:
            # Add source files
            if hasattr(apk_ctx, 'source_files'):
                for file_path, content in apk_ctx.source_files.items():
                    targets.append({
                        "file_path": file_path,
                        "content": content,
                        "type": "source"
                    })
            
            # Add resource files
            if hasattr(apk_ctx, 'resource_files'):
                for file_path, content in apk_ctx.resource_files.items():
                    targets.append({
                        "file_path": file_path,
                        "content": content,
                        "type": "resource"
                    })
            
            # Add string resources
            if hasattr(apk_ctx, 'string_resources'):
                for key, value in apk_ctx.string_resources.items():
                    targets.append({
                        "file_path": f"strings.xml#{key}",
                        "content": value,
                        "type": "string_resource"
                    })
                    
        except Exception as e:
            logger.warning(f"Failed to get analysis targets: {e}")
        
        return targets
    
    def _analyze_target_for_pii(self, target: Dict[str, Any]) -> List[PIIFinding]:
        """Analyze a single target for PII patterns."""
        findings = []
        content = target.get("content", "")
        file_path = target.get("file_path", "")
        
        if not content:
            return findings
        
        # Analyze for each PII type
        for pii_type, pattern_info in self.pii_patterns.items():
            type_findings = self._detect_pii_type(
                pii_type, pattern_info, content, file_path, target
            )
            findings.extend(type_findings)
        
        return findings
    
    def _detect_pii_type(self, pii_type: PIIType, pattern_info: Dict[str, Any],
                        content: str, file_path: str, target: Dict[str, Any]) -> List[PIIFinding]:
        """Detect a specific type of PII in content."""
        findings = []
        
        try:
            patterns = pattern_info.get("patterns", [])
            context_keywords = pattern_info.get("context_keywords", [])
            
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    # Extract the matched value
                    value = match.group(1) if match.groups() else match.group(0)
                    
                    # Basic validation
                    if not self._validate_pii_value(pii_type, value, pattern_info):
                        continue
                    
                    # Calculate line number
                    line_number = content[:match.start()].count('\n') + 1
                    
                    # Extract context
                    context = self._extract_context(content, match.start(), match.end())
                    
                    # Check for context keywords
                    context_relevance = self._calculate_context_relevance(
                        context, context_keywords
                    )
                    
                    # Create finding
                    finding = PIIFinding(
                        pii_type=pii_type,
                        value=value,
                        location=file_path,
                        file_path=file_path,
                        line_number=line_number,
                        context=context,
                        pattern_matched=pattern,
                        exposure_risk=self._assess_exposure_risk(pii_type, context),
                        data_sensitivity=self._assess_data_sensitivity(pii_type),
                        compliance_impact=self._assess_compliance_impact(pii_type),
                        remediation_advice=self._get_remediation_advice(pii_type)
                    )
                    
                    findings.append(finding)
                    
        except Exception as e:
            logger.warning(f"PII type detection failed for {pii_type}: {e}")
        
        return findings
    
    def _validate_pii_value(self, pii_type: PIIType, value: str, 
                           pattern_info: Dict[str, Any]) -> bool:
        """Validate a PII value based on type-specific rules."""
        try:
            # Length validation
            if "validation_length" in pattern_info:
                expected_lengths = pattern_info["validation_length"]
                if isinstance(expected_lengths, int):
                    if len(value.replace("-", "").replace(":", "").replace(" ", "")) != expected_lengths:
                        return False
                elif isinstance(expected_lengths, list):
                    clean_length = len(value.replace("-", "").replace(":", "").replace(" ", ""))
                    if clean_length not in expected_lengths:
                        return False
            
            # Format validation
            if "validation_format" in pattern_info:
                if not re.match(pattern_info["validation_format"], value):
                    return False
            
            # Range validation (for GPS coordinates)
            if pii_type == PIIType.GPS_COORDINATES and "validation_range" in pattern_info:
                coords = re.findall(r'[-+]?\d{1,3}\.\d+', value)
                if len(coords) >= 2:
                    try:
                        lat, lng = float(coords[0]), float(coords[1])
                        lat_range = pattern_info["validation_range"]["lat"]
                        lng_range = pattern_info["validation_range"]["lng"]
                        if not (lat_range[0] <= lat <= lat_range[1] and 
                               lng_range[0] <= lng <= lng_range[1]):
                            return False
                    except ValueError:
                        return False
            
            # Check against false positive indicators
            false_positive_indicators = pattern_info.get("false_positive_indicators", [])
            for indicator in false_positive_indicators:
                if indicator.lower() in value.lower():
                    return False
            
            return True
            
        except Exception:
            return True  # Conservative approach - allow if validation fails
    
    def _extract_context(self, content: str, start: int, end: int, 
                        context_size: int = 100) -> str:
        """Extract context around a match."""
        try:
            context_start = max(0, start - context_size)
            context_end = min(len(content), end + context_size)
            return content[context_start:context_end].strip()
        except Exception:
            return ""
    
    def _calculate_context_relevance(self, context: str, keywords: List[str]) -> float:
        """Calculate context relevance score based on keywords."""
        try:
            if not context or not keywords:
                return 0.5
            
            context_lower = context.lower()
            keyword_matches = sum(1 for keyword in keywords if keyword.lower() in context_lower)
            
            return min(1.0, keyword_matches / len(keywords))
            
        except Exception:
            return 0.5
    
    def _assess_exposure_risk(self, pii_type: PIIType, context: str) -> str:
        """Assess exposure risk based on PII type and context."""
        # Check for logging context
        logging_indicators = ["log", "debug", "trace", "console", "print"]
        if any(indicator in context.lower() for indicator in logging_indicators):
            return "HIGH - Found in logging context"
        
        # Check for transmission context
        transmission_indicators = ["send", "post", "upload", "transmit", "http"]
        if any(indicator in context.lower() for indicator in transmission_indicators):
            return "HIGH - Found in transmission context"
        
        # Check for storage context
        storage_indicators = ["save", "store", "write", "database", "file"]
        if any(indicator in context.lower() for indicator in storage_indicators):
            return "MEDIUM - Found in storage context"
        
        return "LOW - Limited exposure context"
    
    def _assess_data_sensitivity(self, pii_type: PIIType) -> str:
        """Assess data sensitivity level for PII type."""
        sensitivity_map = {
            PIIType.CREDIT_CARD: "CRITICAL",
            PIIType.IMEI: "HIGH",
            PIIType.ANDROID_ID: "HIGH",
            PIIType.PHONE_NUMBER: "HIGH",
            PIIType.GPS_COORDINATES: "HIGH",
            PIIType.EMAIL_ADDRESS: "MEDIUM",
            PIIType.MAC_ADDRESS: "MEDIUM",
            PIIType.DEVICE_ID: "MEDIUM",
            PIIType.ADVERTISING_ID: "LOW",
            PIIType.IP_ADDRESS: "LOW"
        }
        
        return sensitivity_map.get(pii_type, "MEDIUM")
    
    def _assess_compliance_impact(self, pii_type: PIIType) -> List[str]:
        """Assess compliance impact for PII type."""
        compliance_map = {
            PIIType.CREDIT_CARD: ["PCI-DSS", "GDPR", "CCPA"],
            PIIType.GPS_COORDINATES: ["GDPR", "CCPA", "Location Privacy"],
            PIIType.EMAIL_ADDRESS: ["GDPR", "CCPA", "CAN-SPAM"],
            PIIType.PHONE_NUMBER: ["GDPR", "CCPA", "TCPA"],
            PIIType.ANDROID_ID: ["GDPR", "Device Privacy"],
            PIIType.IMEI: ["GDPR", "Device Privacy"],
            PIIType.MAC_ADDRESS: ["Device Privacy"],
            PIIType.DEVICE_ID: ["Device Privacy"],
            PIIType.ADVERTISING_ID: ["Advertising Privacy"],
            PIIType.IP_ADDRESS: ["GDPR", "Data Privacy"]
        }
        
        return compliance_map.get(pii_type, ["Data Privacy"])
    
    def _get_remediation_advice(self, pii_type: PIIType) -> str:
        """Get remediation advice for PII type."""
        advice_map = {
            PIIType.ANDROID_ID: "Use application-specific identifiers or UUID instead of Android ID",
            PIIType.IMEI: "Use advertising ID or app-specific identifiers instead of IMEI",
            PIIType.GPS_COORDINATES: "Encrypt location data and implement user consent mechanisms",
            PIIType.MAC_ADDRESS: "Avoid collecting MAC addresses; use alternative identifiers",
            PIIType.PHONE_NUMBER: "Implement proper consent and secure storage for phone numbers",
            PIIType.EMAIL_ADDRESS: "Encrypt email addresses and implement opt-in consent",
            PIIType.CREDIT_CARD: "Use tokenization and PCI-compliant payment processors",
            PIIType.IP_ADDRESS: "Consider anonymization or avoid logging IP addresses",
            PIIType.DEVICE_ID: "Use app-specific UUIDs instead of device identifiers",
            PIIType.ADVERTISING_ID: "Respect user opt-out preferences for advertising tracking"
        }
        
        return advice_map.get(pii_type, "Implement appropriate privacy controls and user consent")
    
    def _filter_false_positives(self, findings: List[PIIFinding]) -> List[PIIFinding]:
        """Filter out likely false positives."""
        filtered_findings = []
        
        for finding in findings:
            is_false_positive = False
            
            # Check against false positive patterns
            for fp_pattern in self.false_positive_patterns:
                if re.search(fp_pattern, finding.value, re.IGNORECASE):
                    is_false_positive = True
                    break
            
            # Additional context-based filtering
            if not is_false_positive:
                context_lower = finding.context.lower()
                
                # Check for test/example context
                test_indicators = ["test", "example", "sample", "demo", "mock"]
                if any(indicator in context_lower for indicator in test_indicators):
                    finding.false_positive_likelihood = 0.8
                    
                # Check for configuration/template context
                config_indicators = ["config", "template", "default", "placeholder"]
                if any(indicator in context_lower for indicator in config_indicators):
                    finding.false_positive_likelihood = 0.6
            
            if not is_false_positive and finding.false_positive_likelihood < 0.7:
                filtered_findings.append(finding)
        
        return filtered_findings
    
    def _calculate_pii_confidence(self, finding: PIIFinding) -> float:
        """Calculate confidence score for PII finding."""
        try:
            # Get pattern info
            pattern_info = self.pii_patterns.get(finding.pii_type, {})
            pattern_specificity = pattern_info.get("pattern_specificity", 0.5)
            
            # Create evidence structure
            evidence = ConfidenceEvidence(
                pattern_match_quality=pattern_specificity,
                pattern_specificity=pattern_specificity,
                pattern_reliability=0.8,  # Base reliability
                file_context=finding.file_path,
                location_relevance=0.8,   # PII findings are generally location-relevant
                data_sensitivity=self.pii_sensitivity_weights.get(finding.pii_type, 0.5),
                cross_validation=len(finding.compliance_impact) > 1,
                manual_verification=False,
                false_positive_indicators=[],
                analysis_depth="standard"
            )
            
            # Calculate confidence using the confidence calculator
            confidence = self.confidence_calculator.calculate_pii_confidence(
                finding, evidence
            )
            
            # Adjust for false positive likelihood
            if finding.false_positive_likelihood > 0:
                confidence *= (1.0 - finding.false_positive_likelihood)
            
            return max(0.0, min(1.0, confidence))
            
        except Exception as e:
            logger.warning(f"Confidence calculation failed for PII finding: {e}")
            return 0.5  # Conservative fallback
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get PII detection statistics."""
        return {
            "detection_stats": self.detection_stats.copy(),
            "pii_types_configured": len(self.pii_patterns),
            "sensitivity_threshold": self.config.pii_sensitivity_threshold,
            "context_analysis_enabled": self.config.pii_context_analysis
        } 
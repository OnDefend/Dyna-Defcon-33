"""
Device Privacy Analyzer for AODS
Handles device information and analytics privacy analysis including device IDs, advertising IDs, and analytics tracking.
"""

import logging
import re
from typing import List, Dict, Optional

from core.apk_ctx import APKContext
from .data_structures import (
    AnalyticsFinding,
    PrivacyFinding,
    PrivacyDataType,
    PrivacyCategory,
    PrivacySeverity,
    MASTGPrivacyTest,
    PrivacyRiskFactors,
    ComplianceImpact,
    ComplianceFramework,
    PRIVACY_DATA_SENSITIVITY_MAP,
    PRIVACY_EXPOSURE_SCOPE_MAP,
    PRIVACY_USER_AWARENESS_MAP
)
from .pattern_library import PrivacyPatternLibrary

logger = logging.getLogger(__name__)

class DeviceAnalyzer:
    """Analyzer for device information and analytics privacy."""
    
    def __init__(self):
        """Initialize device analyzer."""
        self.findings = []
        self.pattern_library = PrivacyPatternLibrary()
        self.device_patterns = self.pattern_library.get_patterns_by_category(PrivacyCategory.DEVICE_INFO)
        self.analytics_patterns = self.pattern_library.get_patterns_by_category(PrivacyCategory.ANALYTICS)
    
    def analyze_device_privacy(self, apk_ctx: APKContext) -> List[PrivacyFinding]:
        """Analyze device information and analytics privacy."""
        logger.info("Analyzing device information and analytics privacy")
        
        self.findings = []
        
        # Analyze device ID access
        self._analyze_device_id_access(apk_ctx)
        
        # Analyze advertising ID access
        self._analyze_advertising_id_access(apk_ctx)
        
        # Analyze analytics SDKs
        self._analyze_analytics_sdks(apk_ctx)
        
        # Analyze behavioral tracking
        self._analyze_behavioral_tracking(apk_ctx)
        
        # Analyze cross-app tracking
        self._analyze_cross_app_tracking(apk_ctx)
        
        return self.findings
    
    def _analyze_device_id_access(self, apk_ctx: APKContext):
        """Analyze device ID access patterns."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        device_id_patterns = [
            (r"TelephonyManager\.getDeviceId|getSubscriberId|getSimSerialNumber", "IMEI/Device ID", "CRITICAL"),
            (r"Settings\.Secure\.ANDROID_ID|Secure\.getString.*ANDROID_ID", "Android ID", "HIGH"),
            (r"Build\.SERIAL|Build\.getSerial", "Serial Number", "HIGH"),
            (r"WifiInfo\.getMacAddress|BluetoothAdapter\.getAddress", "Hardware Address", "HIGH"),
            (r"getSystemService.*TELEPHONY_SERVICE", "Telephony Service", "MEDIUM")
        ]
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern, desc, severity in device_id_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line = content.split('\n')[line_num - 1]
                        
                        # Check for persistent storage
                        context = self._get_context_around_line(content, line_num)
                        persistent_storage = self._check_persistent_storage(context)
                        
                        # Check for network transmission
                        network_transmission = self._check_network_transmission(context)
                        
                        risk_factors = self._calculate_device_risk_factors(
                            PrivacyDataType.DEVICE_ID, persistent_storage, network_transmission
                        )
                        
                        compliance_impacts = self._get_device_compliance_impacts(
                            PrivacyDataType.DEVICE_ID, persistent_storage
                        )
                        
                        finding = PrivacyFinding(
                            finding_id="",
                            category=PrivacyCategory.DEVICE_INFO,
                            data_types=[PrivacyDataType.DEVICE_ID],
                            severity=getattr(PrivacySeverity, severity),
                            title=f"Device ID Access: {desc}",
                            description=f"Device identifier access detected: {desc}",
                            evidence=[
                                f"Line {line_num}: {line.strip()}", 
                                f"Pattern: {pattern}",
                                f"Persistent storage: {persistent_storage}",
                                f"Network transmission: {network_transmission}"
                            ],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_05,
                            recommendations=self._get_device_id_recommendations(desc, persistent_storage, network_transmission),
                            confidence=0.85,
                            file_path=file_path,
                            line_number=line_num
                        )
                        
                        self.findings.append(finding)
    
    def _analyze_advertising_id_access(self, apk_ctx: APKContext):
        """Analyze advertising ID access patterns."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        advertising_patterns = [
            r"AdvertisingIdClient\.getAdvertisingIdInfo|getIdForAdvertising",
            r"GooglePlayServicesUtil\.isGooglePlayServicesAvailable",
            r"AdvertisingIdClient\.Info\.getId|Info\.isLimitAdTrackingEnabled",
            r"com\.google\.android\.gms\.ads\.identifier"
        ]
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern in advertising_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line = content.split('\n')[line_num - 1]
                        
                        # Check for tracking limitation respect
                        context = self._get_context_around_line(content, line_num)
                        respects_limit = self._check_tracking_limit_respect(context)
                        
                        # Check for cross-app tracking
                        cross_app_tracking = self._check_cross_app_tracking_indicators(context)
                        
                        risk_factors = self._calculate_device_risk_factors(
                            PrivacyDataType.ADVERTISING_ID, True, cross_app_tracking
                        )
                        
                        compliance_impacts = self._get_device_compliance_impacts(
                            PrivacyDataType.ADVERTISING_ID, True
                        )
                        
                        severity = PrivacySeverity.HIGH if not respects_limit else PrivacySeverity.MEDIUM
                        
                        finding = AnalyticsFinding(
                            finding_id="",
                            category=PrivacyCategory.ANALYTICS,
                            data_types=[PrivacyDataType.ADVERTISING_ID],
                            severity=severity,
                            title="Advertising ID Access Detected",
                            description="App accesses advertising identifier",
                            evidence=[
                                f"Line {line_num}: {line.strip()}", 
                                f"Pattern: {pattern}",
                                f"Respects tracking limit: {respects_limit}",
                                f"Cross-app tracking: {cross_app_tracking}"
                            ],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_05,
                            recommendations=self._get_advertising_id_recommendations(respects_limit, cross_app_tracking),
                            confidence=0.9,
                            file_path=file_path,
                            line_number=line_num,
                            analytics_sdks=["Google Ads"],
                            tracking_identifiers=["advertising_id"],
                            behavioral_tracking=True,
                            cross_app_tracking=cross_app_tracking
                        )
                        
                        self.findings.append(finding)
    
    def _analyze_analytics_sdks(self, apk_ctx: APKContext):
        """Analyze analytics SDK usage."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        analytics_sdks = [
            ("GoogleAnalytics|Firebase.*Analytics", "Google Analytics", "MEDIUM"),
            (r"Facebook.*Analytics|FacebookSdk|FB\.AppEvents", "Facebook Analytics", "HIGH"),
            (r"Mixpanel|amplitude|segment\.com", "Third-party Analytics", "MEDIUM"),
            (r"Crashlytics|Fabric\.with", "Crashlytics", "LOW"),
            ("Flurry|Yahoo.*Analytics", "Flurry Analytics", "MEDIUM"),
            ("Adobe.*Analytics|Omniture", "Adobe Analytics", "MEDIUM")
        ]
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern, sdk_name, severity in analytics_sdks:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line = content.split('\n')[line_num - 1]
                        
                        # Check for PII tracking
                        context = self._get_context_around_line(content, line_num)
                        pii_tracking = self._check_pii_tracking(context)
                        
                        # Check for behavioral tracking
                        behavioral_tracking = self._check_behavioral_tracking_indicators(context)
                        
                        risk_factors = self._calculate_device_risk_factors(
                            PrivacyDataType.USAGE_ANALYTICS, True, behavioral_tracking
                        )
                        
                        compliance_impacts = self._get_device_compliance_impacts(
                            PrivacyDataType.USAGE_ANALYTICS, True
                        )
                        
                        finding = AnalyticsFinding(
                            finding_id="",
                            category=PrivacyCategory.ANALYTICS,
                            data_types=[PrivacyDataType.USAGE_ANALYTICS],
                            severity=getattr(PrivacySeverity, severity),
                            title=f"Analytics SDK Detected: {sdk_name}",
                            description=f"App uses {sdk_name} for analytics tracking",
                            evidence=[
                                f"Line {line_num}: {line.strip()}", 
                                f"SDK: {sdk_name}",
                                f"PII tracking: {pii_tracking}",
                                f"Behavioral tracking: {behavioral_tracking}"
                            ],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_02,
                            recommendations=self._get_analytics_sdk_recommendations(sdk_name, pii_tracking),
                            confidence=0.8,
                            file_path=file_path,
                            line_number=line_num,
                            analytics_sdks=[sdk_name],
                            tracking_identifiers=["analytics_id"],
                            behavioral_tracking=behavioral_tracking,
                            cross_app_tracking=False
                        )
                        
                        self.findings.append(finding)
    
    def _analyze_behavioral_tracking(self, apk_ctx: APKContext):
        """Analyze behavioral tracking patterns."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        behavioral_patterns = [
            r"track.*Event|log.*Event|analytics.*track",
            r"user.*behavior|user.*action|user.*interaction",
            r"session.*track|session.*analytics",
            r"screen.*view|page.*view|activity.*track"
        ]
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern in behavioral_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line = content.split('\n')[line_num - 1]
                        
                        context = self._get_context_around_line(content, line_num)
                        
                        # Check for sensitive data collection
                        sensitive_data = self._check_sensitive_behavior_data(context)
                        
                        risk_factors = self._calculate_device_risk_factors(
                            PrivacyDataType.USAGE_ANALYTICS, True, True
                        )
                        
                        compliance_impacts = self._get_device_compliance_impacts(
                            PrivacyDataType.USAGE_ANALYTICS, True
                        )
                        
                        finding = AnalyticsFinding(
                            finding_id="",
                            category=PrivacyCategory.ANALYTICS,
                            data_types=[PrivacyDataType.USAGE_ANALYTICS],
                            severity=PrivacySeverity.HIGH if sensitive_data else PrivacySeverity.MEDIUM,
                            title="Behavioral Tracking Detected",
                            description="App tracks user behavior patterns",
                            evidence=[
                                f"Line {line_num}: {line.strip()}", 
                                f"Pattern: {pattern}",
                                f"Sensitive data: {sensitive_data}"
                            ],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_02,
                            recommendations=self._get_behavioral_tracking_recommendations(sensitive_data),
                            confidence=0.75,
                            file_path=file_path,
                            line_number=line_num,
                            analytics_sdks=["Unknown"],
                            tracking_identifiers=["behavior_id"],
                            behavioral_tracking=True,
                            cross_app_tracking=False
                        )
                        
                        self.findings.append(finding)
    
    def _analyze_cross_app_tracking(self, apk_ctx: APKContext):
        """Analyze cross-app tracking patterns."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        cross_app_patterns = [
            r"shared.*preference.*cross|global.*preference",
            r"external.*storage.*tracking|sdcard.*tracking",
            r"install.*referrer|referrer.*tracking",
            r"attribution.*tracking|campaign.*tracking"
        ]
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern in cross_app_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line = content.split('\n')[line_num - 1]
                        
                        risk_factors = self._calculate_device_risk_factors(
                            PrivacyDataType.USAGE_ANALYTICS, True, True
                        )
                        
                        compliance_impacts = self._get_device_compliance_impacts(
                            PrivacyDataType.USAGE_ANALYTICS, True
                        )
                        
                        finding = AnalyticsFinding(
                            finding_id="",
                            category=PrivacyCategory.ANALYTICS,
                            data_types=[PrivacyDataType.USAGE_ANALYTICS],
                            severity=PrivacySeverity.HIGH,
                            title="Cross-App Tracking Detected",
                            description="App may track user across multiple applications",
                            evidence=[
                                f"Line {line_num}: {line.strip()}", 
                                f"Pattern: {pattern}"
                            ],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_02,
                            recommendations=self._get_cross_app_tracking_recommendations(),
                            confidence=0.7,
                            file_path=file_path,
                            line_number=line_num,
                            analytics_sdks=["Unknown"],
                            tracking_identifiers=["cross_app_id"],
                            behavioral_tracking=True,
                            cross_app_tracking=True
                        )
                        
                        self.findings.append(finding)
    
    def _get_context_around_line(self, content: str, line_num: int, context_size: int = 5) -> str:
        """Get context around a specific line."""
        lines = content.split('\n')
        start = max(0, line_num - context_size)
        end = min(len(lines), line_num + context_size)
        return '\n'.join(lines[start:end])
    
    def _check_persistent_storage(self, context: str) -> bool:
        """Check if data is stored persistently."""
        storage_patterns = [
            r"SharedPreferences|PreferenceManager",
            r"SQLite|DatabaseHelper|ContentResolver",
            r"FileOutputStream|FileWriter|write.*file"
        ]
        
        for pattern in storage_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _check_network_transmission(self, context: str) -> bool:
        """Check if data is transmitted over network."""
        network_patterns = [
            r"HttpURLConnection|OkHttp|Retrofit",
            r"POST|PUT|upload|send.*server",
            r"analytics.*send|track.*send"
        ]
        
        for pattern in network_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _check_tracking_limit_respect(self, context: str) -> bool:
        """Check if tracking limitation is respected."""
        limit_patterns = [
            r"isLimitAdTrackingEnabled|limitAdTracking",
            r"opt.*out|user.*consent|privacy.*setting"
        ]
        
        for pattern in limit_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _check_cross_app_tracking_indicators(self, context: str) -> bool:
        """Check for cross-app tracking indicators."""
        cross_app_patterns = [
            r"external.*storage|sdcard|shared.*preference",
            r"install.*referrer|campaign.*tracking",
            r"attribution|cross.*app"
        ]
        
        for pattern in cross_app_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _check_pii_tracking(self, context: str) -> bool:
        """Check for PII tracking."""
        pii_patterns = [
            r"email|phone|name|address",
            r"user.*id|user.*info|personal.*data",
            r"profile|demographic|identity"
        ]
        
        for pattern in pii_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _check_behavioral_tracking_indicators(self, context: str) -> bool:
        """Check for behavioral tracking indicators."""
        behavioral_patterns = [
            r"behavior|action|interaction|engagement",
            r"session|screen.*view|page.*view",
            r"click|tap|swipe|scroll"
        ]
        
        for pattern in behavioral_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _check_sensitive_behavior_data(self, context: str) -> bool:
        """Check for sensitive behavioral data collection."""
        sensitive_patterns = [
            r"location.*behavior|geo.*behavior",
            r"financial.*behavior|purchase.*behavior",
            r"health.*behavior|medical.*behavior",
            r"biometric.*behavior|security.*behavior"
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _calculate_device_risk_factors(self, data_type: PrivacyDataType, 
                                     persistent: bool, network_sharing: bool) -> PrivacyRiskFactors:
        """Calculate privacy risk factors for device data."""
        
        # Data sensitivity
        data_sensitivity = PRIVACY_DATA_SENSITIVITY_MAP.get(data_type, 0.5)
        
        # Exposure scope
        exposure_scope = PRIVACY_EXPOSURE_SCOPE_MAP.get(PrivacyCategory.DEVICE_INFO, 0.5)
        if network_sharing:
            exposure_scope = min(1.0, exposure_scope + 0.3)
        if persistent:
            exposure_scope = min(1.0, exposure_scope + 0.1)
        
        # User awareness
        user_awareness = PRIVACY_USER_AWARENESS_MAP.get(PrivacyCategory.DEVICE_INFO, 0.7)
        
        # Regulatory impact
        regulatory_impact = 0.8 if data_type == PrivacyDataType.DEVICE_ID else 0.6
        
        return PrivacyRiskFactors(
            data_sensitivity=data_sensitivity,
            exposure_scope=exposure_scope,
            user_awareness=user_awareness,
            regulatory_impact=regulatory_impact
        )
    
    def _get_device_compliance_impacts(self, data_type: PrivacyDataType, 
                                     persistent: bool) -> List[ComplianceImpact]:
        """Get compliance impacts for device data usage."""
        impacts = []
        
        # GDPR impact
        if data_type == PrivacyDataType.DEVICE_ID and persistent:
            impacts.append(ComplianceImpact(
                framework=ComplianceFramework.GDPR,
                impact_level="HIGH",
                description="Persistent device identifiers may require consent under GDPR",
                required_actions=["Obtain consent", "Provide purpose limitation", "Enable data deletion"]
            ))
        
        # CCPA impact
        if data_type in [PrivacyDataType.ADVERTISING_ID, PrivacyDataType.USAGE_ANALYTICS]:
            impacts.append(ComplianceImpact(
                framework=ComplianceFramework.CCPA,
                impact_level="MEDIUM",
                description="Analytics data may require disclosure under CCPA",
                required_actions=["Disclose data collection", "Provide opt-out mechanism"]
            ))
        
        return impacts
    
    def _get_device_id_recommendations(self, id_type: str, persistent: bool, 
                                     network_transmission: bool) -> List[str]:
        """Get recommendations for device ID usage."""
        recommendations = [
            f"Ensure {id_type} access is essential for app functionality",
            f"Implement user consent mechanisms for {id_type} access",
            f"Consider using less identifying alternatives where possible"
        ]
        
        if persistent:
            recommendations.extend([
                "Implement secure storage for device identifiers",
                "Provide user controls for identifier deletion",
                "Consider using session-based identifiers instead"
            ])
        
        if network_transmission:
            recommendations.extend([
                "Use secure transmission methods for device identifiers",
                "Implement identifier hashing or encryption",
                "Minimize identifier sharing with third parties"
            ])
        
        return recommendations
    
    def _get_advertising_id_recommendations(self, respects_limit: bool, 
                                          cross_app_tracking: bool) -> List[str]:
        """Get recommendations for advertising ID usage."""
        recommendations = [
            "Implement proper handling of advertising ID",
            "Provide clear disclosure of advertising tracking",
            "Allow users to control advertising tracking preferences"
        ]
        
        if not respects_limit:
            recommendations.extend([
                "Respect user's limit ad tracking setting",
                "Implement proper checks for tracking limitations",
                "Provide alternative functionality when tracking is disabled"
            ])
        
        if cross_app_tracking:
            recommendations.extend([
                "Disclose cross-app tracking in privacy policy",
                "Provide opt-out mechanisms for cross-app tracking",
                "Implement tracking consent mechanisms"
            ])
        
        return recommendations
    
    def _get_analytics_sdk_recommendations(self, sdk_name: str, pii_tracking: bool) -> List[str]:
        """Get recommendations for analytics SDK usage."""
        recommendations = [
            f"Review {sdk_name} privacy policy and data handling practices",
            f"Configure {sdk_name} with appropriate privacy settings",
            f"Provide user controls for {sdk_name} analytics"
        ]
        
        if pii_tracking:
            recommendations.extend([
                "Avoid collecting PII in analytics data",
                "Implement data anonymization techniques",
                "Obtain explicit consent for PII collection"
            ])
        
        return recommendations
    
    def _get_behavioral_tracking_recommendations(self, sensitive_data: bool) -> List[str]:
        """Get recommendations for behavioral tracking."""
        recommendations = [
            "Implement user consent for behavioral tracking",
            "Provide clear disclosure of behavioral data collection",
            "Allow users to opt-out of behavioral tracking",
            "Implement data minimization for behavioral data"
        ]
        
        if sensitive_data:
            recommendations.extend([
                "Avoid collecting sensitive behavioral data",
                "Implement additional security measures for sensitive data",
                "Consider using differential privacy techniques"
            ])
        
        return recommendations
    
    def _get_cross_app_tracking_recommendations(self) -> List[str]:
        """Get recommendations for cross-app tracking."""
        return [
            "Disclose cross-app tracking in privacy policy",
            "Implement explicit consent mechanisms for cross-app tracking",
            "Provide granular controls for cross-app data sharing",
            "Use privacy-preserving techniques for cross-app analytics",
            "Regularly audit cross-app tracking practices",
            "Implement secure data sharing protocols"
        ] 
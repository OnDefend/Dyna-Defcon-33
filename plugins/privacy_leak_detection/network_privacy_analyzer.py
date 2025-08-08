"""
Network Privacy Analyzer for AODS
Handles network-based privacy analysis including clipboard monitoring, screenshot security, and network data transmission.
"""

import logging
import re
from typing import List, Dict, Optional

from core.apk_ctx import APKContext
from .data_structures import (
    ClipboardFinding,
    ScreenshotFinding,
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

class NetworkPrivacyAnalyzer:
    """Analyzer for network-based privacy concerns."""
    
    def __init__(self):
        """Initialize network privacy analyzer."""
        self.findings = []
        self.pattern_library = PrivacyPatternLibrary()
    
    def analyze_network_privacy(self, apk_ctx: APKContext) -> List[PrivacyFinding]:
        """Analyze network-based privacy concerns."""
        logger.info("Analyzing network privacy patterns")
        
        self.findings = []
        
        # Analyze clipboard monitoring
        self._analyze_clipboard_monitoring(apk_ctx)
        
        # Analyze screenshot security
        self._analyze_screenshot_security(apk_ctx)
        
        # Analyze network data transmission
        self._analyze_network_transmission(apk_ctx)
        
        return self.findings
    
    def _analyze_clipboard_monitoring(self, apk_ctx: APKContext):
        """Analyze clipboard monitoring patterns."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        clipboard_patterns = self.pattern_library.get_patterns_by_category(PrivacyCategory.CLIPBOARD)
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern in clipboard_patterns:
                    matches = pattern.pattern.finditer(content)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line = content.split('\n')[line_num - 1]
                        
                        # Analyze clipboard operation type
                        context = self._get_context_around_line(content, line_num)
                        clipboard_ops = self._analyze_clipboard_operations(context)
                        
                        # Check for sensitive data detection
                        sensitive_data = self._check_sensitive_clipboard_data(context)
                        
                        # Check for automatic access
                        automatic_access = self._check_automatic_clipboard_access(context)
                        
                        risk_factors = self._calculate_clipboard_risk_factors(
                            sensitive_data, automatic_access
                        )
                        
                        compliance_impacts = self._get_clipboard_compliance_impacts(
                            sensitive_data, automatic_access
                        )
                        
                        finding = ClipboardFinding(
                            finding_id="",
                            category=PrivacyCategory.CLIPBOARD,
                            data_types=[PrivacyDataType.CLIPBOARD],
                            severity=self._determine_clipboard_severity(pattern, sensitive_data, automatic_access),
                            title=f"Clipboard Access: {pattern.description}",
                            description=f"Clipboard access detected in {file_path}",
                            evidence=[
                                f"Line {line_num}: {line.strip()}", 
                                f"Pattern: {pattern.description}",
                                f"Operations: {clipboard_ops}",
                                f"Sensitive data: {sensitive_data}",
                                f"Automatic access: {automatic_access}"
                            ],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_01,
                            recommendations=self._get_clipboard_recommendations(clipboard_ops, sensitive_data),
                            confidence=pattern.confidence,
                            file_path=file_path,
                            line_number=line_num,
                            clipboard_operations=clipboard_ops,
                            sensitive_data_detected=sensitive_data,
                            automatic_access=automatic_access
                        )
                        
                        self.findings.append(finding)
    
    def _analyze_screenshot_security(self, apk_ctx: APKContext):
        """Analyze screenshot security patterns."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        screenshot_patterns = self.pattern_library.get_patterns_by_category(PrivacyCategory.SCREENSHOT)
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern in screenshot_patterns:
                    matches = pattern.pattern.finditer(content)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line = content.split('\n')[line_num - 1]
                        
                        # Analyze screenshot protection
                        context = self._get_context_around_line(content, line_num)
                        flag_secure_missing = self._check_flag_secure_missing(context)
                        
                        # Check for sensitive screens
                        sensitive_screens = self._identify_sensitive_screens(context)
                        
                        # Check for prevention mechanisms
                        prevention_enabled = self._check_screenshot_prevention(context)
                        
                        risk_factors = self._calculate_screenshot_risk_factors(
                            flag_secure_missing, len(sensitive_screens) > 0
                        )
                        
                        compliance_impacts = self._get_screenshot_compliance_impacts(
                            flag_secure_missing, sensitive_screens
                        )
                        
                        finding = ScreenshotFinding(
                            finding_id="",
                            category=PrivacyCategory.SCREENSHOT,
                            data_types=[PrivacyDataType.SCREENSHOT],
                            severity=self._determine_screenshot_severity(pattern, flag_secure_missing, sensitive_screens),
                            title=f"Screenshot Security: {pattern.description}",
                            description=f"Screenshot security analysis in {file_path}",
                            evidence=[
                                f"Line {line_num}: {line.strip()}", 
                                f"Pattern: {pattern.description}",
                                f"FLAG_SECURE missing: {flag_secure_missing}",
                                f"Sensitive screens: {sensitive_screens}",
                                f"Prevention enabled: {prevention_enabled}"
                            ],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_01,
                            recommendations=self._get_screenshot_recommendations(flag_secure_missing, sensitive_screens),
                            confidence=pattern.confidence,
                            file_path=file_path,
                            line_number=line_num,
                            flag_secure_missing=flag_secure_missing,
                            sensitive_screens=sensitive_screens,
                            screenshot_prevention=prevention_enabled
                        )
                        
                        self.findings.append(finding)
    
    def _analyze_network_transmission(self, apk_ctx: APKContext):
        """Analyze network transmission of privacy data."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        network_patterns = self.pattern_library.get_patterns_by_category(PrivacyCategory.NETWORK)
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                # Look for network transmission with privacy data
                network_privacy_patterns = [
                    (r"HttpURLConnection.*(?:location|contact|sms|email)", "Location/Contact Data Transmission"),
                    (r"POST.*(?:device_id|android_id|advertising_id)", "Device ID Transmission"),
                    (r"analytics.*(?:personal|private|sensitive)", "Analytics Data Transmission"),
                    (r"upload.*(?:clipboard|screenshot|camera)", "Media Data Transmission")
                ]
                
                for pattern, description in network_privacy_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line = content.split('\n')[line_num - 1]
                        
                        # Check for encryption
                        context = self._get_context_around_line(content, line_num)
                        encrypted_transmission = self._check_encrypted_transmission(context)
                        
                        # Check for consent
                        user_consent = self._check_user_consent(context)
                        
                        risk_factors = self._calculate_network_risk_factors(
                            encrypted_transmission, user_consent
                        )
                        
                        compliance_impacts = self._get_network_compliance_impacts(
                            encrypted_transmission, user_consent
                        )
                        
                        finding = PrivacyFinding(
                            finding_id="",
                            category=PrivacyCategory.NETWORK,
                            data_types=[PrivacyDataType.USAGE_ANALYTICS],
                            severity=self._determine_network_severity(encrypted_transmission, user_consent),
                            title=f"Network Privacy: {description}",
                            description=f"Privacy data network transmission in {file_path}",
                            evidence=[
                                f"Line {line_num}: {line.strip()}", 
                                f"Pattern: {pattern}",
                                f"Encrypted: {encrypted_transmission}",
                                f"User consent: {user_consent}"
                            ],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_02,
                            recommendations=self._get_network_recommendations(encrypted_transmission, user_consent),
                            confidence=0.7,
                            file_path=file_path,
                            line_number=line_num
                        )
                        
                        self.findings.append(finding)
    
    def _get_context_around_line(self, content: str, line_num: int, context_size: int = 5) -> str:
        """Get context around a specific line."""
        lines = content.split('\n')
        start = max(0, line_num - context_size)
        end = min(len(lines), line_num + context_size)
        return '\n'.join(lines[start:end])
    
    def _analyze_clipboard_operations(self, context: str) -> List[str]:
        """Analyze clipboard operations in context."""
        operations = []
        
        if re.search(r"getText|getClipData", context, re.IGNORECASE):
            operations.append("read")
        if re.search(r"setText|setPrimaryClip", context, re.IGNORECASE):
            operations.append("write")
        if re.search(r"addPrimaryClipChangedListener", context, re.IGNORECASE):
            operations.append("monitor")
        if re.search(r"clear|clearPrimaryClip", context, re.IGNORECASE):
            operations.append("clear")
        
        return operations if operations else ["unknown"]
    
    def _check_sensitive_clipboard_data(self, context: str) -> bool:
        """Check if clipboard contains sensitive data."""
        sensitive_patterns = [
            r"password|secret|token|key",
            r"credit.*card|ssn|social.*security",
            r"email|phone|address|personal"
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _check_automatic_clipboard_access(self, context: str) -> bool:
        """Check if clipboard access is automatic."""
        automatic_patterns = [
            r"onResume|onStart|onCreate.*clipboard",
            r"timer.*clipboard|schedule.*clipboard",
            r"automatic.*clipboard|auto.*clipboard"
        ]
        
        for pattern in automatic_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _check_flag_secure_missing(self, context: str) -> bool:
        """Check if FLAG_SECURE is missing."""
        # If we find FLAG_SECURE usage, it's not missing
        if re.search(r"FLAG_SECURE", context, re.IGNORECASE):
            return False
        
        # If we find window/activity creation without FLAG_SECURE, it's missing
        if re.search(r"setContentView|onCreate.*Activity", context, re.IGNORECASE):
            return True
        
        return False
    
    def _identify_sensitive_screens(self, context: str) -> List[str]:
        """Identify sensitive screens in context."""
        sensitive_screens = []
        
        screen_patterns = [
            (r"login|signin|authentication", "login_screen"),
            (r"payment|credit.*card|billing", "payment_screen"),
            (r"settings|preferences|profile", "settings_screen"),
            (r"password|security|pin", "security_screen")
        ]
        
        for pattern, screen_type in screen_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                sensitive_screens.append(screen_type)
        
        return sensitive_screens
    
    def _check_screenshot_prevention(self, context: str) -> bool:
        """Check if screenshot prevention is enabled."""
        prevention_patterns = [
            r"FLAG_SECURE|SECURE_FLAG",
            r"setSecure|secure.*window",
            r"screenshot.*prevent|prevent.*screenshot"
        ]
        
        for pattern in prevention_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _check_encrypted_transmission(self, context: str) -> bool:
        """Check if network transmission is encrypted."""
        encryption_patterns = [
            r"https|ssl|tls",
            r"encrypt|cipher|secure",
            r"certificate|keystore"
        ]
        
        for pattern in encryption_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _check_user_consent(self, context: str) -> bool:
        """Check if user consent is obtained."""
        consent_patterns = [
            r"consent|permission|allow",
            r"user.*agree|accept.*terms",
            r"opt.*in|opt.*out"
        ]
        
        for pattern in consent_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _calculate_clipboard_risk_factors(self, sensitive_data: bool, automatic_access: bool) -> PrivacyRiskFactors:
        """Calculate clipboard risk factors."""
        data_sensitivity = 0.8 if sensitive_data else 0.6
        exposure_scope = PRIVACY_EXPOSURE_SCOPE_MAP[PrivacyCategory.CLIPBOARD]
        user_awareness = PRIVACY_USER_AWARENESS_MAP[PrivacyCategory.CLIPBOARD]
        if automatic_access:
            user_awareness = min(1.0, user_awareness + 0.2)
        regulatory_impact = 0.7 if sensitive_data else 0.5
        
        return PrivacyRiskFactors(
            data_sensitivity=data_sensitivity,
            exposure_scope=exposure_scope,
            user_awareness=user_awareness,
            regulatory_impact=regulatory_impact
        )
    
    def _calculate_screenshot_risk_factors(self, flag_secure_missing: bool, sensitive_screens: bool) -> PrivacyRiskFactors:
        """Calculate screenshot risk factors."""
        data_sensitivity = 0.7 if sensitive_screens else 0.4
        exposure_scope = PRIVACY_EXPOSURE_SCOPE_MAP[PrivacyCategory.SCREENSHOT]
        if flag_secure_missing:
            exposure_scope = min(1.0, exposure_scope + 0.3)
        user_awareness = PRIVACY_USER_AWARENESS_MAP[PrivacyCategory.SCREENSHOT]
        regulatory_impact = 0.6 if sensitive_screens else 0.4
        
        return PrivacyRiskFactors(
            data_sensitivity=data_sensitivity,
            exposure_scope=exposure_scope,
            user_awareness=user_awareness,
            regulatory_impact=regulatory_impact
        )
    
    def _calculate_network_risk_factors(self, encrypted: bool, user_consent: bool) -> PrivacyRiskFactors:
        """Calculate network transmission risk factors."""
        data_sensitivity = 0.6 if not encrypted else 0.4
        exposure_scope = PRIVACY_EXPOSURE_SCOPE_MAP[PrivacyCategory.NETWORK]
        if not encrypted:
            exposure_scope = min(1.0, exposure_scope + 0.2)
        user_awareness = PRIVACY_USER_AWARENESS_MAP[PrivacyCategory.NETWORK]
        if not user_consent:
            user_awareness = min(1.0, user_awareness + 0.2)
        regulatory_impact = 0.8 if not (encrypted and user_consent) else 0.5
        
        return PrivacyRiskFactors(
            data_sensitivity=data_sensitivity,
            exposure_scope=exposure_scope,
            user_awareness=user_awareness,
            regulatory_impact=regulatory_impact
        )
    
    def _get_clipboard_compliance_impacts(self, sensitive_data: bool, automatic_access: bool) -> List[ComplianceImpact]:
        """Get clipboard compliance impacts."""
        impacts = []
        
        if sensitive_data or automatic_access:
            impacts.append(ComplianceImpact(
                framework=ComplianceFramework.GDPR,
                impact_level="MEDIUM",
                description="Clipboard access may require user consent under GDPR",
                required_actions=["Obtain user consent", "Provide clear purpose", "Enable data deletion"]
            ))
        
        return impacts
    
    def _get_screenshot_compliance_impacts(self, flag_secure_missing: bool, sensitive_screens: List[str]) -> List[ComplianceImpact]:
        """Get screenshot compliance impacts."""
        impacts = []
        
        if flag_secure_missing and sensitive_screens:
            impacts.append(ComplianceImpact(
                framework=ComplianceFramework.GDPR,
                impact_level="HIGH",
                description="Screenshot vulnerability on sensitive screens violates data protection requirements",
                required_actions=["Implement FLAG_SECURE", "Protect sensitive screens", "Audit screenshot vulnerabilities"]
            ))
        
        return impacts
    
    def _get_network_compliance_impacts(self, encrypted: bool, user_consent: bool) -> List[ComplianceImpact]:
        """Get network transmission compliance impacts."""
        impacts = []
        
        if not encrypted or not user_consent:
            impacts.append(ComplianceImpact(
                framework=ComplianceFramework.GDPR,
                impact_level="HIGH",
                description="Unencrypted or non-consensual data transmission violates GDPR requirements",
                required_actions=["Implement encryption", "Obtain user consent", "Secure data transmission"]
            ))
        
        return impacts
    
    def _determine_clipboard_severity(self, pattern, sensitive_data: bool, automatic_access: bool) -> PrivacySeverity:
        """Determine clipboard severity."""
        if sensitive_data and automatic_access:
            return PrivacySeverity.CRITICAL
        elif sensitive_data or automatic_access:
            return PrivacySeverity.HIGH
        else:
            return PrivacySeverity.MEDIUM
    
    def _determine_screenshot_severity(self, pattern, flag_secure_missing: bool, sensitive_screens: List[str]) -> PrivacySeverity:
        """Determine screenshot severity."""
        if flag_secure_missing and sensitive_screens:
            return PrivacySeverity.HIGH
        elif flag_secure_missing or sensitive_screens:
            return PrivacySeverity.MEDIUM
        else:
            return PrivacySeverity.LOW
    
    def _determine_network_severity(self, encrypted: bool, user_consent: bool) -> PrivacySeverity:
        """Determine network transmission severity."""
        if not encrypted and not user_consent:
            return PrivacySeverity.CRITICAL
        elif not encrypted or not user_consent:
            return PrivacySeverity.HIGH
        else:
            return PrivacySeverity.MEDIUM
    
    def _get_clipboard_recommendations(self, operations: List[str], sensitive_data: bool) -> List[str]:
        """Get clipboard recommendations."""
        recommendations = [
            "Implement user consent before clipboard access",
            "Provide clear indication of clipboard usage",
            "Minimize clipboard data retention"
        ]
        
        if sensitive_data:
            recommendations.extend([
                "Avoid storing sensitive data in clipboard",
                "Clear clipboard after use",
                "Implement clipboard data encryption"
            ])
        
        if "monitor" in operations:
            recommendations.append("Provide user controls for clipboard monitoring")
        
        return recommendations
    
    def _get_screenshot_recommendations(self, flag_secure_missing: bool, sensitive_screens: List[str]) -> List[str]:
        """Get screenshot recommendations."""
        recommendations = [
            "Implement FLAG_SECURE for sensitive screens",
            "Audit screenshot vulnerabilities regularly",
            "Provide user controls for screenshot prevention"
        ]
        
        if flag_secure_missing:
            recommendations.extend([
                "Add FLAG_SECURE to window flags",
                "Implement secure window configuration",
                "Test screenshot prevention effectiveness"
            ])
        
        if sensitive_screens:
            recommendations.extend([
                "Identify all sensitive screens in app",
                "Implement screen-specific security measures",
                "Monitor screenshot attempts on sensitive screens"
            ])
        
        return recommendations
    
    def _get_network_recommendations(self, encrypted: bool, user_consent: bool) -> List[str]:
        """Get network transmission recommendations."""
        recommendations = [
            "Implement secure network transmission",
            "Obtain user consent for data transmission",
            "Minimize data transmission frequency"
        ]
        
        if not encrypted:
            recommendations.extend([
                "Use HTTPS for all network communications",
                "Implement proper SSL/TLS configuration",
                "Encrypt sensitive data before transmission"
            ])
        
        if not user_consent:
            recommendations.extend([
                "Implement consent mechanisms before data transmission",
                "Provide clear data usage disclosure",
                "Allow users to control data transmission"
            ])
        
        return recommendations 
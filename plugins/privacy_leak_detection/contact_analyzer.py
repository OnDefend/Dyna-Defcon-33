"""
Contact Privacy Analyzer for AODS
Handles contact data privacy analysis including contacts access, call log access, and SMS privacy.
"""

import logging
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional

from core.apk_ctx import APKContext
from .data_structures import (
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

class ContactAnalyzer:
    """Analyzer for contact data privacy."""
    
    def __init__(self):
        """Initialize contact analyzer."""
        self.findings = []
        self.pattern_library = PrivacyPatternLibrary()
        self.contact_patterns = self.pattern_library.get_patterns_by_category(PrivacyCategory.CONTACTS)
    
    def analyze_contact_privacy(self, apk_ctx: APKContext) -> List[PrivacyFinding]:
        """Analyze contact data privacy."""
        logger.info("Analyzing contact data privacy")
        
        self.findings = []
        
        # Analyze manifest permissions
        self._analyze_contact_permissions(apk_ctx)
        
        # Analyze contact access patterns
        self._analyze_contact_access(apk_ctx)
        
        # Analyze call log access
        self._analyze_call_log_access(apk_ctx)
        
        # Analyze SMS access
        self._analyze_sms_access(apk_ctx)
        
        # Analyze contact data sharing
        self._analyze_contact_sharing(apk_ctx)
        
        return self.findings
    
    def _analyze_contact_permissions(self, apk_ctx: APKContext):
        """Analyze contact-related permissions in manifest."""
        if not hasattr(apk_ctx, 'manifest_path') or not apk_ctx.manifest_path:
            return
        
        try:
            tree = ET.parse(apk_ctx.manifest_path)
            root = tree.getroot()
            
            permissions = root.findall('.//uses-permission')
            contact_permissions = []
            
            permission_map = {
                'android.permission.READ_CONTACTS': ('contacts', 'HIGH'),
                'android.permission.WRITE_CONTACTS': ('contacts', 'HIGH'),
                'android.permission.GET_ACCOUNTS': ('accounts', 'MEDIUM'),
                'android.permission.READ_CALL_LOG': ('call_log', 'HIGH'),
                'android.permission.WRITE_CALL_LOG': ('call_log', 'HIGH'),
                'android.permission.READ_SMS': ('sms', 'HIGH'),
                'android.permission.SEND_SMS': ('sms', 'HIGH'),
                'android.permission.RECEIVE_SMS': ('sms', 'HIGH'),
                'android.permission.READ_PHONE_STATE': ('phone', 'MEDIUM'),
                'android.permission.CALL_PHONE': ('phone', 'MEDIUM')
            }
            
            for perm in permissions:
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
                if perm_name in permission_map:
                    contact_permissions.append(perm_name)
            
            if contact_permissions:
                for perm in contact_permissions:
                    data_type, severity = permission_map[perm]
                    
                    # Map to appropriate data types
                    if data_type == 'contacts':
                        privacy_data_type = PrivacyDataType.CONTACTS
                    elif data_type == 'call_log':
                        privacy_data_type = PrivacyDataType.CALL_LOG
                    elif data_type == 'sms':
                        privacy_data_type = PrivacyDataType.SMS
                    elif data_type == 'phone':
                        privacy_data_type = PrivacyDataType.PHONE
                    else:
                        privacy_data_type = PrivacyDataType.CONTACTS
                    
                    risk_factors = self._calculate_contact_risk_factors(
                        privacy_data_type, False
                    )
                    
                    compliance_impacts = self._get_contact_compliance_impacts(
                        privacy_data_type
                    )
                    
                    finding = PrivacyFinding(
                        finding_id="",
                        category=PrivacyCategory.CONTACTS,
                        data_types=[privacy_data_type],
                        severity=PrivacySeverity.HIGH if severity == "HIGH" else PrivacySeverity.MEDIUM,
                        title=f"Contact Permission Usage: {perm}",
                        description=f"App requests {data_type} permission",
                        evidence=[f"Permission: {perm}"],
                        affected_components=[apk_ctx.manifest_path],
                        risk_factors=risk_factors,
                        compliance_impacts=compliance_impacts,
                        mastg_test_id=MASTGPrivacyTest.PRIVACY_01,
                        recommendations=self._get_permission_recommendations(data_type),
                        confidence=0.9
                    )
                    
                    self.findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error analyzing contact permissions: {e}")
    
    def _analyze_contact_access(self, apk_ctx: APKContext):
        """Analyze contact access patterns in source code."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                self._check_contact_access_patterns(file_path, content)
    
    def _check_contact_access_patterns(self, file_path: str, content: str):
        """Check for contact access patterns in source code."""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.contact_patterns:
                matches = pattern.pattern.finditer(line)
                for match in matches:
                    # Analyze context for contact access
                    context_lines = lines[max(0, line_num-3):min(len(lines), line_num+3)]
                    context = '\n'.join(context_lines)
                    
                    # Check for bulk contact access
                    bulk_access = self._check_bulk_contact_access(context)
                    
                    # Check for sensitive field access
                    sensitive_fields = self._check_sensitive_fields(context)
                    
                    # Determine data sharing
                    data_sharing = self._check_contact_data_sharing(context)
                    
                    risk_factors = self._calculate_contact_risk_factors(
                        pattern.data_type, data_sharing
                    )
                    
                    compliance_impacts = self._get_contact_compliance_impacts(
                        pattern.data_type
                    )
                    
                    severity = self._determine_contact_severity(
                        pattern, bulk_access, sensitive_fields, data_sharing
                    )
                    
                    finding = PrivacyFinding(
                        finding_id="",
                        category=PrivacyCategory.CONTACTS,
                        data_types=[pattern.data_type],
                        severity=severity,
                        title=f"Contact Access: {pattern.description}",
                        description=f"Contact data access detected in {file_path}",
                        evidence=[
                            f"Line {line_num}: {line.strip()}", 
                            f"Pattern: {pattern.description}",
                            f"Bulk access: {bulk_access}",
                            f"Sensitive fields: {sensitive_fields}"
                        ],
                        affected_components=[file_path],
                        risk_factors=risk_factors,
                        compliance_impacts=compliance_impacts,
                        mastg_test_id=MASTGPrivacyTest.PRIVACY_01,
                        recommendations=self._get_contact_access_recommendations(
                            pattern.data_type, bulk_access, sensitive_fields
                        ),
                        confidence=pattern.confidence,
                        file_path=file_path,
                        line_number=line_num
                    )
                    
                    self.findings.append(finding)
    
    def _analyze_call_log_access(self, apk_ctx: APKContext):
        """Analyze call log access patterns."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        call_log_patterns = [
            r"CallLog\.Calls|CallLog\.CONTENT_URI",
            r"Calls\.NUMBER|Calls\.TYPE|Calls\.DURATION",
            r"getContentResolver.*call_log",
            r"CallLogColumns|CallLogProvider"
        ]
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern in call_log_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line = content.split('\n')[line_num - 1]
                        
                        # Check for sensitive call log data access
                        sensitive_access = self._check_sensitive_call_log_access(content)
                        
                        risk_factors = self._calculate_contact_risk_factors(
                            PrivacyDataType.CALL_LOG, False
                        )
                        
                        compliance_impacts = self._get_contact_compliance_impacts(
                            PrivacyDataType.CALL_LOG
                        )
                        
                        finding = PrivacyFinding(
                            finding_id="",
                            category=PrivacyCategory.CONTACTS,
                            data_types=[PrivacyDataType.CALL_LOG],
                            severity=PrivacySeverity.HIGH if sensitive_access else PrivacySeverity.MEDIUM,
                            title="Call Log Access Detected",
                            description=f"Call log access detected in {file_path}",
                            evidence=[
                                f"Line {line_num}: {line.strip()}", 
                                f"Pattern: {pattern}",
                                f"Sensitive access: {sensitive_access}"
                            ],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_01,
                            recommendations=self._get_call_log_recommendations(sensitive_access),
                            confidence=0.85,
                            file_path=file_path,
                            line_number=line_num
                        )
                        
                        self.findings.append(finding)
    
    def _analyze_sms_access(self, apk_ctx: APKContext):
        """Analyze SMS access patterns."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        sms_patterns = [
            r"SmsManager|SmsMessage|TelephonyManager",
            r"SMS_RECEIVED|SMS_SENT|SMS_DELIVERED",
            r"getContentResolver.*sms",
            r"Sms\.Inbox|Sms\.Sent|Sms\.Draft"
        ]
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern in sms_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line = content.split('\n')[line_num - 1]
                        
                        # Check for SMS content access
                        content_access = self._check_sms_content_access(content)
                        
                        # Check for SMS sending capability
                        sending_capability = self._check_sms_sending_capability(content)
                        
                        risk_factors = self._calculate_contact_risk_factors(
                            PrivacyDataType.SMS, False
                        )
                        
                        compliance_impacts = self._get_contact_compliance_impacts(
                            PrivacyDataType.SMS
                        )
                        
                        severity = PrivacySeverity.HIGH if (content_access or sending_capability) else PrivacySeverity.MEDIUM
                        
                        finding = PrivacyFinding(
                            finding_id="",
                            category=PrivacyCategory.CONTACTS,
                            data_types=[PrivacyDataType.SMS],
                            severity=severity,
                            title="SMS Access Detected",
                            description=f"SMS access detected in {file_path}",
                            evidence=[
                                f"Line {line_num}: {line.strip()}", 
                                f"Pattern: {pattern}",
                                f"Content access: {content_access}",
                                f"Sending capability: {sending_capability}"
                            ],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_01,
                            recommendations=self._get_sms_recommendations(content_access, sending_capability),
                            confidence=0.8,
                            file_path=file_path,
                            line_number=line_num
                        )
                        
                        self.findings.append(finding)
    
    def _analyze_contact_sharing(self, apk_ctx: APKContext):
        """Analyze contact data sharing with third parties."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        sharing_indicators = [
            r"upload.*contact|send.*contact|share.*contact",
            r"analytics.*contact|tracking.*contact",
            r"api.*contact|server.*contact|cloud.*contact",
            r"facebook.*contact|google.*contact|linkedin.*contact"
        ]
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for indicator in sharing_indicators:
                    matches = re.finditer(indicator, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line = content.split('\n')[line_num - 1]
                        
                        risk_factors = self._calculate_contact_risk_factors(
                            PrivacyDataType.CONTACTS, True
                        )
                        
                        compliance_impacts = self._get_contact_compliance_impacts(
                            PrivacyDataType.CONTACTS
                        )
                        
                        finding = PrivacyFinding(
                            finding_id="",
                            category=PrivacyCategory.CONTACTS,
                            data_types=[PrivacyDataType.CONTACTS],
                            severity=PrivacySeverity.HIGH,
                            title="Contact Data Sharing Detected",
                            description="Contact data may be shared with third parties",
                            evidence=[
                                f"Line {line_num}: {line.strip()}", 
                                f"Sharing indicator: {indicator}"
                            ],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_02,
                            recommendations=self._get_contact_sharing_recommendations(),
                            confidence=0.7,
                            file_path=file_path,
                            line_number=line_num
                        )
                        
                        self.findings.append(finding)
    
    def _calculate_contact_risk_factors(self, data_type: PrivacyDataType, 
                                      data_sharing: bool) -> PrivacyRiskFactors:
        """Calculate privacy risk factors for contact data."""
        
        # Data sensitivity
        data_sensitivity = PRIVACY_DATA_SENSITIVITY_MAP.get(data_type, 0.5)
        
        # Exposure scope
        exposure_scope = PRIVACY_EXPOSURE_SCOPE_MAP[PrivacyCategory.CONTACTS]
        if data_sharing:
            exposure_scope = min(1.0, exposure_scope + 0.2)
        
        # User awareness
        user_awareness = PRIVACY_USER_AWARENESS_MAP[PrivacyCategory.CONTACTS]
        
        # Regulatory impact
        regulatory_impact = 0.8 if data_type in [PrivacyDataType.CONTACTS, PrivacyDataType.CALL_LOG] else 0.6
        
        return PrivacyRiskFactors(
            data_sensitivity=data_sensitivity,
            exposure_scope=exposure_scope,
            user_awareness=user_awareness,
            regulatory_impact=regulatory_impact
        )
    
    def _get_contact_compliance_impacts(self, data_type: PrivacyDataType) -> List[ComplianceImpact]:
        """Get compliance impacts for contact data usage."""
        impacts = []
        
        # GDPR impact
        if data_type in [PrivacyDataType.CONTACTS, PrivacyDataType.CALL_LOG]:
            impacts.append(ComplianceImpact(
                framework=ComplianceFramework.GDPR,
                impact_level="HIGH",
                description="Contact data is personal data under GDPR requiring consent",
                required_actions=["Obtain explicit consent", "Provide data access rights", "Enable data deletion"]
            ))
        
        # CCPA impact
        impacts.append(ComplianceImpact(
            framework=ComplianceFramework.CCPA,
            impact_level="MEDIUM",
            description="Contact data collection may require disclosure under CCPA",
            required_actions=["Disclose data collection", "Provide opt-out mechanism"]
        ))
        
        return impacts
    
    def _check_bulk_contact_access(self, context: str) -> bool:
        """Check if bulk contact access is detected."""
        bulk_indicators = [
            r"query.*null.*null|query.*ContactsContract.*null",
            r"cursor.*getCount|cursor.*moveToNext.*while",
            r"bulkInsert|bulkQuery|batch.*contact"
        ]
        
        for indicator in bulk_indicators:
            if re.search(indicator, context, re.IGNORECASE):
                return True
        return False
    
    def _check_sensitive_fields(self, context: str) -> bool:
        """Check if sensitive contact fields are accessed."""
        sensitive_fields = [
            r"Phone\.NUMBER|Email\.ADDRESS|StructuredName",
            r"DISPLAY_NAME|PHOTO_URI|PHOTO_THUMBNAIL_URI",
            r"Organization\.COMPANY|Organization\.TITLE",
            r"Note\.NOTE|Website\.URL"
        ]
        
        for field in sensitive_fields:
            if re.search(field, context, re.IGNORECASE):
                return True
        return False
    
    def _check_contact_data_sharing(self, context: str) -> bool:
        """Check if contact data is shared."""
        sharing_patterns = [
            r"http.*contact|api.*contact|upload.*contact",
            r"json.*contact|xml.*contact|serialize.*contact",
            r"analytics.*contact|tracking.*contact"
        ]
        
        for pattern in sharing_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _check_sensitive_call_log_access(self, content: str) -> bool:
        """Check if sensitive call log data is accessed."""
        sensitive_patterns = [
            r"Calls\.NUMBER|Calls\.CACHED_NAME|Calls\.CACHED_PHOTO_URI",
            r"Calls\.DURATION|Calls\.TYPE|Calls\.DATE",
            r"Calls\.GEOCODED_LOCATION|Calls\.CACHED_LOOKUP_URI"
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def _check_sms_content_access(self, content: str) -> bool:
        """Check if SMS content is accessed."""
        content_patterns = [
            r"Sms\.BODY|Sms\.ADDRESS|Sms\.SUBJECT",
            r"SmsMessage\.getMessageBody|SmsMessage\.getDisplayOriginatingAddress",
            r"cursor.*body|cursor.*address.*sms"
        ]
        
        for pattern in content_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def _check_sms_sending_capability(self, content: str) -> bool:
        """Check if SMS sending capability is detected."""
        sending_patterns = [
            r"SmsManager\.sendTextMessage|SmsManager\.sendMultipartTextMessage",
            r"sendSms|sendTextMessage|sendMultipartMessage"
        ]
        
        for pattern in sending_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def _determine_contact_severity(self, pattern, bulk_access: bool, 
                                  sensitive_fields: bool, data_sharing: bool) -> PrivacySeverity:
        """Determine severity based on contact access patterns."""
        if data_sharing or (bulk_access and sensitive_fields):
            return PrivacySeverity.CRITICAL
        elif bulk_access or sensitive_fields:
            return PrivacySeverity.HIGH
        elif pattern.severity == "HIGH":
            return PrivacySeverity.HIGH
        else:
            return PrivacySeverity.MEDIUM
    
    def _get_permission_recommendations(self, data_type: str) -> List[str]:
        """Get recommendations for contact permissions."""
        recommendations = [
            f"Ensure {data_type} access is essential for app functionality",
            f"Implement user consent mechanisms for {data_type} access",
            f"Provide clear explanation of {data_type} data usage",
            f"Allow users to revoke {data_type} permissions"
        ]
        
        if data_type == "contacts":
            recommendations.extend([
                "Implement contact selection instead of full access",
                "Cache contact data locally to reduce repeated access"
            ])
        
        return recommendations
    
    def _get_contact_access_recommendations(self, data_type: PrivacyDataType, 
                                         bulk_access: bool, sensitive_fields: bool) -> List[str]:
        """Get recommendations for contact access."""
        recommendations = [
            "Implement user consent before accessing contact data",
            "Use ContactsContract.CommonDataKinds for specific field access",
            "Handle contact access failures gracefully"
        ]
        
        if bulk_access:
            recommendations.extend([
                "Implement pagination for large contact datasets",
                "Consider using ContactsContract.Directory for search",
                "Optimize contact queries to reduce performance impact"
            ])
        
        if sensitive_fields:
            recommendations.extend([
                "Minimize sensitive field access to essential data only",
                "Implement data anonymization where possible",
                "Provide granular permissions for different contact fields"
            ])
        
        return recommendations
    
    def _get_call_log_recommendations(self, sensitive_access: bool) -> List[str]:
        """Get recommendations for call log access."""
        recommendations = [
            "Ensure call log access is essential for app functionality",
            "Implement user consent mechanisms for call log access",
            "Handle call log access failures gracefully",
            "Consider using CallLogContract for standardized access"
        ]
        
        if sensitive_access:
            recommendations.extend([
                "Minimize sensitive call log data access",
                "Implement data encryption for stored call log data",
                "Provide user controls for call log data retention"
            ])
        
        return recommendations
    
    def _get_sms_recommendations(self, content_access: bool, sending_capability: bool) -> List[str]:
        """Get recommendations for SMS access."""
        recommendations = [
            "Ensure SMS access is essential for app functionality",
            "Implement user consent mechanisms for SMS access",
            "Handle SMS access failures gracefully"
        ]
        
        if content_access:
            recommendations.extend([
                "Minimize SMS content access to essential data only",
                "Implement data encryption for stored SMS data",
                "Provide user controls for SMS data retention"
            ])
        
        if sending_capability:
            recommendations.extend([
                "Implement user confirmation for SMS sending",
                "Provide clear indication of SMS charges",
                "Allow users to disable SMS sending functionality"
            ])
        
        return recommendations
    
    def _get_contact_sharing_recommendations(self) -> List[str]:
        """Get recommendations for contact data sharing."""
        return [
            "Disclose contact data sharing in privacy policy",
            "Obtain explicit consent for contact data sharing",
            "Provide opt-out mechanisms for contact data sharing",
            "Ensure third-party partners have adequate privacy protections",
            "Implement data minimization for shared contact data",
            "Use secure transmission methods for contact data sharing"
        ] 
"""
Location Privacy Analyzer for AODS
Handles location data privacy analysis including permission analysis, tracking detection, and location sharing.
"""

import logging
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional

from core.apk_ctx import APKContext
from .data_structures import (
    LocationFinding,
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

class LocationAnalyzer:
    """Analyzer for location data privacy."""
    
    def __init__(self):
        """Initialize location analyzer."""
        self.findings = []
        self.pattern_library = PrivacyPatternLibrary()
        self.location_patterns = self.pattern_library.get_patterns_by_category(PrivacyCategory.LOCATION)
    
    def analyze_location_privacy(self, apk_ctx: APKContext) -> List[LocationFinding]:
        """Analyze location data privacy."""
        logger.info("Analyzing location data privacy")
        
        self.findings = []
        
        # Analyze manifest permissions
        self._analyze_location_permissions(apk_ctx)
        
        # Analyze source code for location usage
        self._analyze_location_usage(apk_ctx)
        
        # Analyze location tracking patterns
        self._analyze_location_tracking(apk_ctx)
        
        # Analyze background location access
        self._analyze_background_location(apk_ctx)
        
        # Analyze third-party location sharing
        self._analyze_third_party_sharing(apk_ctx)
        
        return self.findings
    
    def _analyze_location_permissions(self, apk_ctx: APKContext):
        """Analyze location permissions in manifest."""
        if not hasattr(apk_ctx, 'manifest_path') or not apk_ctx.manifest_path:
            return
        
        try:
            tree = ET.parse(apk_ctx.manifest_path)
            root = tree.getroot()
            
            permissions = root.findall('.//uses-permission')
            location_permissions = []
            
            for perm in permissions:
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
                if 'LOCATION' in perm_name:
                    location_permissions.append(perm_name)
            
            if location_permissions:
                # Check for appropriate permission usage
                if 'android.permission.ACCESS_FINE_LOCATION' in location_permissions:
                    precision_level = 'fine'
                    severity = PrivacySeverity.HIGH
                elif 'android.permission.ACCESS_COARSE_LOCATION' in location_permissions:
                    precision_level = 'coarse'
                    severity = PrivacySeverity.MEDIUM
                else:
                    precision_level = 'unknown'
                    severity = PrivacySeverity.MEDIUM
                
                # Check for background location permission
                background_location = 'android.permission.ACCESS_BACKGROUND_LOCATION' in location_permissions
                if background_location:
                    severity = PrivacySeverity.CRITICAL
                    precision_level = 'background'
                
                risk_factors = self._calculate_location_risk_factors(
                    precision_level, background_location, False
                )
                
                compliance_impacts = self._get_location_compliance_impacts(
                    precision_level, background_location
                )
                
                finding = LocationFinding(
                    finding_id="",
                    category=PrivacyCategory.LOCATION,
                    data_types=[PrivacyDataType.LOCATION],
                    severity=severity,
                    title="Location Permission Usage Detected",
                    description=f"App requests {precision_level} location permissions",
                    evidence=[f"Permissions: {', '.join(location_permissions)}"],
                    affected_components=[apk_ctx.manifest_path],
                    risk_factors=risk_factors,
                    compliance_impacts=compliance_impacts,
                    mastg_test_id=MASTGPrivacyTest.PRIVACY_04,
                    recommendations=self._get_location_recommendations(precision_level, background_location),
                    confidence=0.9,
                    location_permissions=location_permissions,
                    precision_level=precision_level,
                    tracking_frequency="unknown",
                    third_party_sharing=False
                )
                
                self.findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error analyzing location permissions: {e}")
    
    def _analyze_location_usage(self, apk_ctx: APKContext):
        """Analyze location usage in source code."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                self._check_location_usage_patterns(file_path, content)
    
    def _check_location_usage_patterns(self, file_path: str, content: str):
        """Check for location usage patterns in source code."""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.location_patterns:
                matches = pattern.pattern.finditer(line)
                for match in matches:
                    # Analyze context for location usage
                    context_lines = lines[max(0, line_num-3):min(len(lines), line_num+3)]
                    context = '\n'.join(context_lines)
                    
                    # Determine tracking frequency
                    tracking_frequency = self._determine_tracking_frequency(context)
                    
                    # Check for third-party sharing
                    third_party_sharing = self._check_third_party_sharing(context)
                    
                    # Determine precision level from API usage
                    precision_level = self._determine_precision_from_api(line, context)
                    
                    risk_factors = self._calculate_location_risk_factors(
                        precision_level, False, third_party_sharing
                    )
                    
                    compliance_impacts = self._get_location_compliance_impacts(
                        precision_level, False
                    )
                    
                    finding = LocationFinding(
                        finding_id="",
                        category=PrivacyCategory.LOCATION,
                        data_types=[PrivacyDataType.LOCATION],
                        severity=PrivacySeverity.HIGH if pattern.severity == "HIGH" else PrivacySeverity.MEDIUM,
                        title=f"Location API Usage: {pattern.description}",
                        description=f"Location access detected in {file_path}",
                        evidence=[f"Line {line_num}: {line.strip()}", f"Pattern: {pattern.description}"],
                        affected_components=[file_path],
                        risk_factors=risk_factors,
                        compliance_impacts=compliance_impacts,
                        mastg_test_id=MASTGPrivacyTest.PRIVACY_04,
                        recommendations=self._get_location_api_recommendations(pattern.description),
                        confidence=pattern.confidence,
                        file_path=file_path,
                        line_number=line_num,
                        location_permissions=[],
                        precision_level=precision_level,
                        tracking_frequency=tracking_frequency,
                        third_party_sharing=third_party_sharing
                    )
                    
                    self.findings.append(finding)
    
    def _analyze_location_tracking(self, apk_ctx: APKContext):
        """Analyze location tracking patterns."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                # Look for continuous location tracking patterns
                if re.search(r"requestLocationUpdates.*\d+.*\d+", content, re.IGNORECASE):
                    # Extract tracking intervals
                    intervals = re.findall(r"requestLocationUpdates.*?(\d+).*?(\d+)", content, re.IGNORECASE)
                    
                    for interval_match in intervals:
                        min_time = int(interval_match[0]) if interval_match[0].isdigit() else 0
                        min_distance = int(interval_match[1]) if interval_match[1].isdigit() else 0
                        
                        # Assess tracking frequency
                        if min_time < 60000:  # Less than 1 minute
                            tracking_frequency = "high_frequency"
                            severity = PrivacySeverity.CRITICAL
                        elif min_time < 300000:  # Less than 5 minutes
                            tracking_frequency = "medium_frequency"
                            severity = PrivacySeverity.HIGH
                        else:
                            tracking_frequency = "low_frequency"
                            severity = PrivacySeverity.MEDIUM
                        
                        risk_factors = self._calculate_location_risk_factors(
                            "fine", False, False
                        )
                        
                        compliance_impacts = self._get_location_compliance_impacts(
                            "fine", False
                        )
                        
                        finding = LocationFinding(
                            finding_id="",
                            category=PrivacyCategory.LOCATION,
                            data_types=[PrivacyDataType.LOCATION],
                            severity=severity,
                            title="Continuous Location Tracking Detected",
                            description=f"App tracks location every {min_time}ms with {min_distance}m accuracy",
                            evidence=[f"Tracking interval: {min_time}ms", f"Distance threshold: {min_distance}m"],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_04,
                            recommendations=self._get_tracking_recommendations(tracking_frequency),
                            confidence=0.85,
                            file_path=file_path,
                            location_permissions=[],
                            precision_level="fine",
                            tracking_frequency=tracking_frequency,
                            third_party_sharing=False
                        )
                        
                        self.findings.append(finding)
    
    def _analyze_background_location(self, apk_ctx: APKContext):
        """Analyze background location access."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                # Look for background location patterns
                background_patterns = [
                    r"Service.*Location|LocationService",
                    r"WorkManager.*Location|JobScheduler.*Location",
                    r"AlarmManager.*Location|BroadcastReceiver.*Location"
                ]
                
                for pattern in background_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        risk_factors = self._calculate_location_risk_factors(
                            "background", True, False
                        )
                        
                        compliance_impacts = self._get_location_compliance_impacts(
                            "background", True
                        )
                        
                        finding = LocationFinding(
                            finding_id="",
                            category=PrivacyCategory.LOCATION,
                            data_types=[PrivacyDataType.LOCATION],
                            severity=PrivacySeverity.CRITICAL,
                            title="Background Location Access Detected",
                            description="App may access location in background",
                            evidence=[f"Background pattern: {pattern}"],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_04,
                            recommendations=self._get_background_location_recommendations(),
                            confidence=0.8,
                            file_path=file_path,
                            location_permissions=[],
                            precision_level="background",
                            tracking_frequency="continuous",
                            third_party_sharing=False
                        )
                        
                        self.findings.append(finding)
    
    def _analyze_third_party_sharing(self, apk_ctx: APKContext):
        """Analyze third-party location sharing."""
        if not hasattr(apk_ctx, 'source_files'):
            return
        
        third_party_indicators = [
            r"google.*maps|maps\.google",
            r"facebook.*location|fb.*location",
            r"analytics.*location|tracking.*location",
            r"ads.*location|advertising.*location"
        ]
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for indicator in third_party_indicators:
                    if re.search(indicator, content, re.IGNORECASE):
                        risk_factors = self._calculate_location_risk_factors(
                            "fine", False, True
                        )
                        
                        compliance_impacts = self._get_location_compliance_impacts(
                            "fine", False
                        )
                        
                        finding = LocationFinding(
                            finding_id="",
                            category=PrivacyCategory.LOCATION,
                            data_types=[PrivacyDataType.LOCATION],
                            severity=PrivacySeverity.HIGH,
                            title="Third-Party Location Sharing Detected",
                            description="Location data may be shared with third parties",
                            evidence=[f"Third-party indicator: {indicator}"],
                            affected_components=[file_path],
                            risk_factors=risk_factors,
                            compliance_impacts=compliance_impacts,
                            mastg_test_id=MASTGPrivacyTest.PRIVACY_02,
                            recommendations=self._get_third_party_sharing_recommendations(),
                            confidence=0.75,
                            file_path=file_path,
                            location_permissions=[],
                            precision_level="fine",
                            tracking_frequency="unknown",
                            third_party_sharing=True
                        )
                        
                        self.findings.append(finding)
    
    def _calculate_location_risk_factors(self, precision_level: str, 
                                       background_access: bool, 
                                       third_party_sharing: bool) -> PrivacyRiskFactors:
        """Calculate privacy risk factors for location."""
        
        # Data sensitivity based on precision
        if precision_level == "fine" or precision_level == "background":
            data_sensitivity = 1.0
        elif precision_level == "coarse":
            data_sensitivity = 0.7
        else:
            data_sensitivity = 0.5
        
        # Exposure scope
        exposure_scope = PRIVACY_EXPOSURE_SCOPE_MAP[PrivacyCategory.LOCATION]
        if background_access:
            exposure_scope = min(1.0, exposure_scope + 0.2)
        if third_party_sharing:
            exposure_scope = min(1.0, exposure_scope + 0.1)
        
        # User awareness
        user_awareness = PRIVACY_USER_AWARENESS_MAP[PrivacyCategory.LOCATION]
        if background_access:
            user_awareness = min(1.0, user_awareness + 0.3)
        
        # Regulatory impact
        regulatory_impact = 1.0 if precision_level in ["fine", "background"] else 0.8
        
        return PrivacyRiskFactors(
            data_sensitivity=data_sensitivity,
            exposure_scope=exposure_scope,
            user_awareness=user_awareness,
            regulatory_impact=regulatory_impact
        )
    
    def _get_location_compliance_impacts(self, precision_level: str, 
                                       background_access: bool) -> List[ComplianceImpact]:
        """Get compliance impacts for location usage."""
        impacts = []
        
        # GDPR impact
        if precision_level in ["fine", "background"]:
            impacts.append(ComplianceImpact(
                framework=ComplianceFramework.GDPR,
                impact_level="HIGH",
                description="Precise location data requires explicit consent under GDPR",
                required_actions=["Obtain explicit consent", "Provide clear purpose", "Enable data deletion"]
            ))
        
        # CCPA impact
        if background_access:
            impacts.append(ComplianceImpact(
                framework=ComplianceFramework.CCPA,
                impact_level="HIGH",
                description="Background location tracking may require disclosure under CCPA",
                required_actions=["Disclose data collection", "Provide opt-out mechanism"]
            ))
        
        return impacts
    
    def _determine_tracking_frequency(self, context: str) -> str:
        """Determine location tracking frequency from context."""
        if re.search(r"\d+.*(?:second|millisecond)", context, re.IGNORECASE):
            return "high_frequency"
        elif re.search(r"\d+.*minute", context, re.IGNORECASE):
            return "medium_frequency"
        elif re.search(r"\d+.*(?:hour|day)", context, re.IGNORECASE):
            return "low_frequency"
        else:
            return "unknown"
    
    def _check_third_party_sharing(self, context: str) -> bool:
        """Check if location data is shared with third parties."""
        third_party_patterns = [
            r"analytics|tracking|ads|advertising",
            r"google|facebook|twitter|instagram",
            r"sdk|api.*location"
        ]
        
        for pattern in third_party_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    def _determine_precision_from_api(self, line: str, context: str) -> str:
        """Determine location precision from API usage."""
        if re.search(r"ACCESS_FINE_LOCATION|GPS_PROVIDER|FusedLocation", line + context, re.IGNORECASE):
            return "fine"
        elif re.search(r"ACCESS_COARSE_LOCATION|NETWORK_PROVIDER", line + context, re.IGNORECASE):
            return "coarse"
        elif re.search(r"BACKGROUND_LOCATION|background.*location", line + context, re.IGNORECASE):
            return "background"
        else:
            return "unknown"
    
    def _get_location_recommendations(self, precision_level: str, background_access: bool) -> List[str]:
        """Get recommendations for location privacy."""
        recommendations = [
            "Implement user consent mechanisms for location access",
            "Provide clear explanation of location data usage",
            "Allow users to revoke location permissions"
        ]
        
        if precision_level == "fine":
            recommendations.append("Consider using coarse location if fine precision is not required")
        
        if background_access:
            recommendations.extend([
                "Minimize background location access to essential features only",
                "Provide clear notification when accessing location in background",
                "Implement location access controls in app settings"
            ])
        
        return recommendations
    
    def _get_location_api_recommendations(self, api_description: str) -> List[str]:
        """Get recommendations for specific location API usage."""
        recommendations = [
            "Ensure appropriate user permissions before location access",
            "Handle location access failures gracefully",
            "Cache location data locally when possible to reduce API calls"
        ]
        
        if "FusedLocation" in api_description:
            recommendations.append("Configure appropriate location request parameters")
        
        return recommendations
    
    def _get_tracking_recommendations(self, frequency: str) -> List[str]:
        """Get recommendations for location tracking."""
        recommendations = [
            "Provide user controls for tracking frequency",
            "Implement battery optimization for location tracking",
            "Allow users to disable tracking completely"
        ]
        
        if frequency == "high_frequency":
            recommendations.extend([
                "Consider reducing tracking frequency to improve battery life",
                "Implement intelligent tracking based on user activity"
            ])
        
        return recommendations
    
    def _get_background_location_recommendations(self) -> List[str]:
        """Get recommendations for background location access."""
        return [
            "Request background location permission only when necessary",
            "Provide clear justification for background location access",
            "Implement location access indicators for user awareness",
            "Allow users to restrict background location access",
            "Use foreground services with persistent notifications"
        ]
    
    def _get_third_party_sharing_recommendations(self) -> List[str]:
        """Get recommendations for third-party location sharing."""
        return [
            "Disclose third-party location data sharing in privacy policy",
            "Obtain explicit consent for location data sharing",
            "Provide opt-out mechanisms for third-party sharing",
            "Ensure third-party partners have adequate privacy protections",
            "Implement data minimization for shared location data"
        ] 
#!/usr/bin/env python3
"""
Network Cleartext Traffic Analyzer - Risk Assessor

This module provides comprehensive risk assessment and security recommendation
generation for network cleartext traffic analysis results.

Features:
- Overall security risk assessment
- Multi-factor risk scoring
- Security recommendation generation  
- Verification command generation
- MASVS compliance assessment

Classes:
    RiskAssessor: Main risk assessment and recommendation engine
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from .data_structures import (
    CleartextTrafficAnalysisResult, ManifestAnalysisResult, NSCAnalysisResult,
    ResourceAnalysisResult, NetworkSecurityFinding, SecurityRecommendation,
    VerificationCommand, RiskLevel, AnalysisStatus, HttpUrlType
)

class RiskAssessor:
    """
    Risk assessment engine for network cleartext traffic analysis.
    
    Performs comprehensive risk assessment based on manifest configuration,
    Network Security Configuration, and resource analysis results.
    """
    
    def __init__(self):
        """Initialize risk assessor"""
        self.logger = logging.getLogger(__name__)
        
        # Risk scoring weights
        self.risk_weights = {
            'manifest_config': 0.30,      # AndroidManifest.xml configuration
            'nsc_config': 0.25,           # Network Security Configuration
            'http_urls_found': 0.25,      # HTTP URLs in resources
            'target_sdk_impact': 0.20     # Target SDK version impact
        }
        
        # Risk thresholds
        self.risk_thresholds = {
            'critical': 85,
            'high': 70,
            'medium': 40,
            'low': 20
        }
    
    def assess_overall_risk(
        self,
        result: CleartextTrafficAnalysisResult,
        manifest_analysis: ManifestAnalysisResult,
        nsc_analysis: NSCAnalysisResult,
        resource_analysis: ResourceAnalysisResult
    ) -> None:
        """
        Assess overall security risk based on all analysis results.
        
        Args:
            result: Main analysis result to update
            manifest_analysis: AndroidManifest.xml analysis results
            nsc_analysis: Network Security Configuration analysis results
            resource_analysis: Resource analysis results
        """
        try:
            # Calculate individual risk components
            manifest_risk = self._assess_manifest_risk(manifest_analysis)
            nsc_risk = self._assess_nsc_risk(nsc_analysis)
            resource_risk = self._assess_resource_risk(resource_analysis)
            sdk_risk = self._assess_sdk_risk(manifest_analysis)
            
            # Calculate weighted overall risk score (0-100)
            overall_risk_score = (
                manifest_risk * self.risk_weights['manifest_config'] +
                nsc_risk * self.risk_weights['nsc_config'] +
                resource_risk * self.risk_weights['http_urls_found'] +
                sdk_risk * self.risk_weights['target_sdk_impact']
            )
            
            # Determine risk level
            risk_level = self._score_to_risk_level(overall_risk_score)
            
            # Determine analysis status
            status = self._determine_analysis_status(overall_risk_score, result.findings)
            
            # Update result
            result.risk_level = risk_level
            result.overall_status = status
            result.confidence_score = self._calculate_overall_confidence(result.findings)
            
            # Store risk assessment metadata
            result.analysis_metadata.update({
                'overall_risk_score': overall_risk_score,
                'manifest_risk_score': manifest_risk,
                'nsc_risk_score': nsc_risk,
                'resource_risk_score': resource_risk,
                'sdk_risk_score': sdk_risk,
                'risk_factors': self._identify_risk_factors(
                    manifest_analysis, nsc_analysis, resource_analysis
                )
            })
            
            self.logger.info(
                f"Risk assessment completed: {risk_level.value} risk "
                f"(score: {overall_risk_score:.1f})"
            )
            
        except Exception as e:
            self.logger.error(f"Error in risk assessment: {e}")
            result.overall_status = AnalysisStatus.ERROR
            result.risk_level = RiskLevel.UNKNOWN
    
    def _assess_manifest_risk(self, manifest_analysis: ManifestAnalysisResult) -> float:
        """Assess risk from AndroidManifest.xml configuration (0-100)"""
        risk_score = 0.0
        
        if not manifest_analysis.manifest_found:
            return 50.0  # Medium risk for missing manifest
        
        # Target SDK version impact
        if manifest_analysis.target_sdk:
            if manifest_analysis.target_sdk < 23:
                risk_score += 30  # High risk for very old SDK
            elif manifest_analysis.target_sdk < 28:
                risk_score += 15  # Medium risk for older SDK
            # SDK 28+ gets 0 additional risk
        else:
            risk_score += 20  # Risk for unknown target SDK
        
        # usesCleartextTraffic configuration
        cleartext_status = manifest_analysis.get_cleartext_status()
        if cleartext_status == "true":
            if manifest_analysis.target_sdk and manifest_analysis.target_sdk >= 28:
                risk_score += 40  # Critical: explicit cleartext on secure SDK
            else:
                risk_score += 25  # High: explicit cleartext on legacy SDK
        elif cleartext_status == "false":
            risk_score -= 10  # Good: explicit cleartext disabled
        
        # Network Security Configuration presence
        if manifest_analysis.network_security_config:
            risk_score -= 15  # Good: NSC configured
        elif manifest_analysis.target_sdk and manifest_analysis.target_sdk >= 24:
            risk_score += 10  # Risk: no NSC on supported SDK
        
        # Internet permission check
        if 'android.permission.INTERNET' not in manifest_analysis.permissions:
            risk_score -= 20  # Lower risk without internet permission
        
        return max(0.0, min(100.0, risk_score))
    
    def _assess_nsc_risk(self, nsc_analysis: NSCAnalysisResult) -> float:
        """Assess risk from Network Security Configuration (0-100)"""
        if not nsc_analysis.config_found:
            return 60.0  # Medium-high risk for missing NSC
        
        risk_score = 0.0
        
        # Cleartext traffic configuration
        if nsc_analysis.cleartext_permitted is True:
            risk_score += 50  # High risk for NSC allowing cleartext
        elif nsc_analysis.cleartext_permitted is False:
            risk_score -= 15  # Good: NSC blocks cleartext
        
        # Certificate pinning
        if nsc_analysis.certificate_pinning:
            risk_score -= 20  # Good: certificate pinning configured
        else:
            risk_score += 15  # Risk: no certificate pinning
        
        # Trust anchors
        if nsc_analysis.trust_anchors_configured:
            risk_score += 10  # Potential risk: custom trust anchors
        
        # Debug overrides
        if nsc_analysis.debug_overrides:
            risk_score += 15  # Risk: debug overrides in NSC
        
        # Validation errors
        if nsc_analysis.validation_errors:
            risk_score += 10  # Risk: NSC parsing/validation issues
        
        return max(0.0, min(100.0, risk_score))
    
    def _assess_resource_risk(self, resource_analysis: ResourceAnalysisResult) -> float:
        """Assess risk from HTTP URLs found in resources (0-100)"""
        if not resource_analysis.http_urls_found:
            return 0.0  # No risk if no HTTP URLs found
        
        risk_score = 0.0
        
        # Base risk from HTTP URL count
        url_count = len(resource_analysis.http_urls_found)
        if url_count > 20:
            risk_score += 40  # High risk for many HTTP URLs
        elif url_count > 10:
            risk_score += 25  # Medium risk
        elif url_count > 5:
            risk_score += 15  # Low-medium risk
        else:
            risk_score += 5   # Low risk
        
        # Risk from high-risk URLs
        high_risk_urls = resource_analysis.get_high_risk_urls()
        if high_risk_urls:
            risk_score += len(high_risk_urls) * 5  # 5 points per high-risk URL
        
        # Risk from URL types
        url_types = {}
        for detection in resource_analysis.http_urls_found:
            url_type = detection.url_type
            url_types[url_type] = url_types.get(url_type, 0) + 1
        
        # API endpoints are highest risk
        if HttpUrlType.HARDCODED_API in url_types:
            risk_score += url_types[HttpUrlType.HARDCODED_API] * 8
        
        # External services are medium risk
        if HttpUrlType.EXTERNAL_SERVICE in url_types:
            risk_score += url_types[HttpUrlType.EXTERNAL_SERVICE] * 4
        
        # Config URLs are medium risk
        if HttpUrlType.CONFIG_URL in url_types:
            risk_score += url_types[HttpUrlType.CONFIG_URL] * 3
        
        # Test URLs are lower risk
        if HttpUrlType.TEST_URL in url_types:
            risk_score += url_types[HttpUrlType.TEST_URL] * 1
        
        # Unique domains risk
        unique_domains = resource_analysis.get_unique_domains()
        if len(unique_domains) > 10:
            risk_score += 10  # Risk for many different domains
        
        return max(0.0, min(100.0, risk_score))
    
    def _assess_sdk_risk(self, manifest_analysis: ManifestAnalysisResult) -> float:
        """Assess risk impact from target SDK version (0-100)"""
        if not manifest_analysis.target_sdk:
            return 50.0  # Medium risk for unknown SDK
        
        target_sdk = manifest_analysis.target_sdk
        
        if target_sdk < 16:
            return 90.0   # Critical: very old SDK
        elif target_sdk < 23:
            return 70.0   # High: old SDK
        elif target_sdk < 28:
            return 40.0   # Medium: cleartext enabled by default
        elif target_sdk < 30:
            return 15.0   # Low: secure defaults
        else:
            return 5.0    # Very low: modern SDK
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert risk score to risk level"""
        if score >= self.risk_thresholds['critical']:
            return RiskLevel.CRITICAL
        elif score >= self.risk_thresholds['high']:
            return RiskLevel.HIGH
        elif score >= self.risk_thresholds['medium']:
            return RiskLevel.MEDIUM
        elif score >= self.risk_thresholds['low']:
            return RiskLevel.LOW
        else:
            return RiskLevel.LOW
    
    def _determine_analysis_status(self, risk_score: float, findings: List[NetworkSecurityFinding]) -> AnalysisStatus:
        """Determine overall analysis status"""
        # Check for critical findings
        critical_findings = [f for f in findings if f.severity == RiskLevel.CRITICAL]
        if critical_findings:
            return AnalysisStatus.FAIL
        
        # Check for high-risk score
        if risk_score >= self.risk_thresholds['high']:
            return AnalysisStatus.FAIL
        
        # Check for high-severity findings
        high_findings = [f for f in findings if f.severity == RiskLevel.HIGH]
        if len(high_findings) > 2:
            return AnalysisStatus.FAIL
        
        # Check for medium risk with multiple findings
        if risk_score >= self.risk_thresholds['medium'] and len(findings) > 5:
            return AnalysisStatus.MANUAL
        
        # Otherwise pass
        return AnalysisStatus.PASS
    
    def _calculate_overall_confidence(self, findings: List[NetworkSecurityFinding]) -> float:
        """Calculate overall analysis confidence"""
        if not findings:
            return 0.9  # High confidence when no issues found
        
        # Average confidence across all findings
        total_confidence = sum(finding.confidence for finding in findings)
        avg_confidence = total_confidence / len(findings)
        
        # Adjust based on finding count (more findings = higher confidence)
        finding_count_factor = min(1.0, len(findings) / 10.0)
        
        return min(1.0, avg_confidence + (finding_count_factor * 0.1))
    
    def _identify_risk_factors(
        self,
        manifest_analysis: ManifestAnalysisResult,
        nsc_analysis: NSCAnalysisResult,
        resource_analysis: ResourceAnalysisResult
    ) -> List[Dict[str, Any]]:
        """Identify specific risk factors"""
        risk_factors = []
        
        # Manifest risk factors
        if manifest_analysis.manifest_found:
            cleartext_status = manifest_analysis.get_cleartext_status()
            if cleartext_status == "true":
                risk_factors.append({
                    'category': 'manifest',
                    'factor': 'cleartext_enabled',
                    'description': 'Cleartext traffic enabled in manifest',
                    'severity': 'HIGH'
                })
            
            if manifest_analysis.target_sdk and manifest_analysis.target_sdk < 28:
                risk_factors.append({
                    'category': 'manifest',
                    'factor': 'legacy_sdk',
                    'description': f'Target SDK {manifest_analysis.target_sdk} has insecure defaults',
                    'severity': 'MEDIUM'
                })
        
        # NSC risk factors
        if nsc_analysis.config_found:
            if nsc_analysis.cleartext_permitted is True:
                risk_factors.append({
                    'category': 'nsc',
                    'factor': 'nsc_cleartext_enabled',
                    'description': 'NSC explicitly permits cleartext traffic',
                    'severity': 'HIGH'
                })
            
            if not nsc_analysis.certificate_pinning:
                risk_factors.append({
                    'category': 'nsc',
                    'factor': 'no_certificate_pinning',
                    'description': 'No certificate pinning configured',
                    'severity': 'MEDIUM'
                })
        
        # Resource risk factors
        high_risk_urls = resource_analysis.get_high_risk_urls()
        if high_risk_urls:
            risk_factors.append({
                'category': 'resources',
                'factor': 'high_risk_http_urls',
                'description': f'{len(high_risk_urls)} high-risk HTTP URLs found',
                'severity': 'HIGH'
            })
        
        # Check for API endpoints
        api_urls = [
            url for url in resource_analysis.http_urls_found
            if url.url_type == HttpUrlType.HARDCODED_API
        ]
        if api_urls:
            risk_factors.append({
                'category': 'resources',
                'factor': 'http_api_endpoints',
                'description': f'{len(api_urls)} HTTP API endpoints detected',
                'severity': 'HIGH'
            })
        
        return risk_factors
    
    def generate_recommendations(
        self,
        manifest_analysis: ManifestAnalysisResult,
        nsc_analysis: NSCAnalysisResult,
        resource_analysis: ResourceAnalysisResult,
        risk_score: float
    ) -> List[SecurityRecommendation]:
        """Generate security recommendations based on analysis results"""
        recommendations = []
        
        try:
            # High priority recommendations
            recommendations.extend(self._generate_high_priority_recommendations(
                manifest_analysis, nsc_analysis, resource_analysis
            ))
            
            # Medium priority recommendations
            recommendations.extend(self._generate_medium_priority_recommendations(
                manifest_analysis, nsc_analysis, resource_analysis
            ))
            
            # General best practices
            if risk_score > self.risk_thresholds['medium']:
                recommendations.extend(self._generate_general_recommendations())
            
            # Sort by priority
            priority_order = {
                RiskLevel.CRITICAL: 0,
                RiskLevel.HIGH: 1,
                RiskLevel.MEDIUM: 2,
                RiskLevel.LOW: 3,
                RiskLevel.INFO: 4
            }
            recommendations.sort(key=lambda r: priority_order.get(r.priority, 5))
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
        
        return recommendations
    
    def _generate_high_priority_recommendations(
        self,
        manifest_analysis: ManifestAnalysisResult,
        nsc_analysis: NSCAnalysisResult,
        resource_analysis: ResourceAnalysisResult
    ) -> List[SecurityRecommendation]:
        """Generate high priority security recommendations"""
        recommendations = []
        
        # Cleartext traffic disabled
        cleartext_status = manifest_analysis.get_cleartext_status() if manifest_analysis.manifest_found else "unknown"
        if cleartext_status == "true":
            recommendations.append(SecurityRecommendation(
                priority=RiskLevel.CRITICAL,
                category="Network Security",
                title="Disable Cleartext Traffic",
                description="Application allows cleartext HTTP traffic which can be intercepted",
                implementation_steps=[
                    'Set android:usesCleartextTraffic="false" in AndroidManifest.xml',
                    'Update target SDK to 28 or higher for secure defaults',
                    'Replace all HTTP URLs with HTTPS equivalents',
                    'Implement proper certificate validation'
                ],
                code_examples=[
                    '<application android:usesCleartextTraffic="false">',
                    'URL url = new URL("https://api.example.com/data");'
                ],
                masvs_control="MASVS-NETWORK-1"
            ))
        
        # HTTP API endpoints
        api_urls = [url for url in resource_analysis.http_urls_found if url.url_type == HttpUrlType.HARDCODED_API]
        if api_urls:
            recommendations.append(SecurityRecommendation(
                priority=RiskLevel.HIGH,
                category="API Security",
                title="Secure API Endpoints",
                description=f"Found {len(api_urls)} HTTP API endpoints that should use HTTPS",
                implementation_steps=[
                    'Replace HTTP API endpoints with HTTPS equivalents',
                    'Implement certificate pinning for API connections',
                    'Add proper error handling for certificate validation',
                    'Use secure HTTP client configurations'
                ],
                code_examples=[
                    'String apiUrl = "https://api.example.com/v1/data";',
                    'HttpsURLConnection.setDefaultHostnameVerifier(...);'
                ],
                masvs_control="MASVS-NETWORK-1"
            ))
        
        return recommendations
    
    def _generate_medium_priority_recommendations(
        self,
        manifest_analysis: ManifestAnalysisResult,
        nsc_analysis: NSCAnalysisResult,
        resource_analysis: ResourceAnalysisResult
    ) -> List[SecurityRecommendation]:
        """Generate medium priority security recommendations"""
        recommendations = []
        
        # Network Security Configuration
        if not nsc_analysis.config_found and manifest_analysis.target_sdk and manifest_analysis.target_sdk >= 24:
            recommendations.append(SecurityRecommendation(
                priority=RiskLevel.MEDIUM,
                category="Network Security",
                title="Implement Network Security Configuration",
                description="Network Security Configuration not found, recommended for API 24+",
                implementation_steps=[
                    'Create res/xml/network_security_config.xml',
                    'Reference NSC in AndroidManifest.xml application element',
                    'Configure certificate pinning for critical domains',
                    'Set appropriate cleartext traffic policies'
                ],
                code_examples=[
                    'android:networkSecurityConfig="@xml/network_security_config"',
                    '<network-security-config><base-config cleartextTrafficPermitted="false"/></network-security-config>'
                ],
                masvs_control="MASVS-NETWORK-2"
            ))
        
        # Certificate pinning
        if nsc_analysis.config_found and not nsc_analysis.certificate_pinning:
            recommendations.append(SecurityRecommendation(
                priority=RiskLevel.MEDIUM,
                category="Certificate Security",
                title="Implement Certificate Pinning",
                description="Certificate pinning not configured in Network Security Configuration",
                implementation_steps=[
                    'Add pin-set elements to Network Security Configuration',
                    'Generate certificate pins for critical domains',
                    'Set appropriate pin expiration dates',
                    'Test certificate pinning implementation'
                ],
                code_examples=[
                    '<pin-set><pin digest="SHA-256">base64-encoded-pin</pin></pin-set>'
                ],
                masvs_control="MASVS-NETWORK-2"
            ))
        
        # Target SDK upgrade
        if manifest_analysis.target_sdk and manifest_analysis.target_sdk < 28:
            recommendations.append(SecurityRecommendation(
                priority=RiskLevel.MEDIUM,
                category="Platform Security",
                title="Upgrade Target SDK Version",
                description=f"Target SDK {manifest_analysis.target_sdk} has insecure network defaults",
                implementation_steps=[
                    'Update targetSdkVersion to 28 or higher',
                    'Test application compatibility with new SDK',
                    'Update deprecated API usage',
                    'Verify cleartext traffic is properly disabled'
                ],
                code_examples=[
                    'android:targetSdkVersion="30"'
                ],
                masvs_control="MASVS-NETWORK-1"
            ))
        
        return recommendations
    
    def _generate_general_recommendations(self) -> List[SecurityRecommendation]:
        """Generate general security best practice recommendations"""
        return [
            SecurityRecommendation(
                priority=RiskLevel.LOW,
                category="Best Practices",
                title="Implement Certificate Validation",
                description="Ensure proper certificate validation for all HTTPS connections",
                implementation_steps=[
                    'Use system default certificate validation',
                    'Avoid custom TrustManager implementations',
                    'Implement certificate pinning for high-value endpoints',
                    'Handle certificate validation errors appropriately'
                ],
                masvs_control="MASVS-NETWORK-1"
            ),
            SecurityRecommendation(
                priority=RiskLevel.LOW,
                category="Testing",
                title="Network Security Testing",
                description="Implement comprehensive network security testing",
                implementation_steps=[
                    'Test with network traffic analysis tools',
                    'Verify cleartext traffic is blocked',
                    'Test certificate pinning bypass resistance',
                    'Validate error handling for network failures'
                ],
                masvs_control="MASVS-NETWORK-1"
            )
        ]
    
    def generate_verification_commands(
        self,
        manifest_analysis: ManifestAnalysisResult,
        nsc_analysis: NSCAnalysisResult,
        resource_analysis: ResourceAnalysisResult
    ) -> List[VerificationCommand]:
        """Generate verification commands for manual testing"""
        commands = []
        
        try:
            # Static analysis commands
            commands.extend(self._generate_static_verification_commands())
            
            # Dynamic analysis commands
            commands.extend(self._generate_dynamic_verification_commands())
            
            # Configuration-specific commands
            if nsc_analysis.config_found:
                commands.extend(self._generate_nsc_verification_commands())
            
        except Exception as e:
            self.logger.error(f"Error generating verification commands: {e}")
        
        return commands
    
    def _generate_static_verification_commands(self) -> List[VerificationCommand]:
        """Generate static analysis verification commands"""
        return [
            VerificationCommand(
                category="Static Analysis",
                title="Check Cleartext Traffic Setting",
                command="grep -r 'usesCleartextTraffic' AndroidManifest.xml",
                description="Verify cleartext traffic configuration in manifest",
                expected_output="Should show usesCleartextTraffic=\"false\" or no attribute"
            ),
            VerificationCommand(
                category="Static Analysis",
                title="Find HTTP URLs",
                command="find . -name '*.java' -o -name '*.kt' | xargs grep -i 'http://'",
                description="Search for hardcoded HTTP URLs in source code",
                expected_output="Should find minimal or no HTTP URLs"
            ),
            VerificationCommand(
                category="Static Analysis",
                title="Check Network Security Config",
                command="find res/xml -name '*network*' -o -name '*security*'",
                description="Locate Network Security Configuration files",
                expected_output="Should show network_security_config.xml if configured"
            )
        ]
    
    def _generate_dynamic_verification_commands(self) -> List[VerificationCommand]:
        """Generate dynamic analysis verification commands"""
        return [
            VerificationCommand(
                category="Dynamic Testing",
                title="Monitor Network Traffic",
                command="adb shell tcpdump -i any -s 0 -w /sdcard/capture.pcap",
                description="Capture network traffic for analysis",
                expected_output="Network capture file for analysis",
                requires_device=True
            ),
            VerificationCommand(
                category="Dynamic Testing",
                title="Test HTTP Connection Blocking",
                command="adb shell am start -a android.intent.action.VIEW -d http://example.com",
                description="Test if HTTP connections are blocked",
                expected_output="Connection should be blocked or fail",
                requires_device=True
            )
        ]
    
    def _generate_nsc_verification_commands(self) -> List[VerificationCommand]:
        """Generate NSC-specific verification commands"""
        return [
            VerificationCommand(
                category="NSC Validation",
                title="Validate NSC Syntax",
                command="xmllint --noout res/xml/network_security_config.xml",
                description="Validate Network Security Configuration XML syntax",
                expected_output="No output indicates valid XML"
            ),
            VerificationCommand(
                category="NSC Analysis",
                title="Check NSC Cleartext Policy",
                command="grep -i 'cleartextTrafficPermitted' res/xml/network_security_config.xml",
                description="Check cleartext traffic policy in NSC",
                expected_output="Should show cleartextTrafficPermitted=\"false\""
            )
        ] 
#!/usr/bin/env python3
"""
APK2URL Extraction Plugin - Security Assessor

Security risk assessment and threat analysis system for discovered endpoints.
Implements comprehensive security evaluation, risk scoring, MASVS compliance
mapping, and mitigation recommendations for endpoint security vulnerabilities.
"""

import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from urllib.parse import urlparse

from .data_structures import (
    SecurityAssessment, SecurityRisk, EndpointFinding, EndpointType, 
    ProtocolType, DomainCategory, ExtractionResults, MASVS_MAPPINGS,
    SECURITY_THRESHOLDS
)

logger = logging.getLogger(__name__)

class SecurityAssessor:
    """
    Security risk assessment system for discovered endpoints.
    
    Provides comprehensive security evaluation, risk scoring,
    and mitigation recommendations based on endpoint characteristics.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize security assessor with configuration."""
        self.config = config
        
        # Security risk rules from configuration
        self.risk_rules = config.get('security_risk_rules', {})
        
        # Security thresholds
        self.thresholds = SECURITY_THRESHOLDS.copy()
        if 'security_thresholds' in config:
            self.thresholds.update(config['security_thresholds'])
        
        # Domain categorization rules
        self.domain_rules = config.get('domain_categorization', {})
        
        # MASVS control mappings
        self.masvs_mappings = MASVS_MAPPINGS
        
        logger.info("Initialized SecurityAssessor with risk assessment rules")
    
    def assess_security(self, results: ExtractionResults) -> SecurityAssessment:
        """
        Perform comprehensive security assessment of extraction results.
        
        Args:
            results: Complete extraction results
            
        Returns:
            SecurityAssessment with risk analysis and recommendations
        """
        try:
            # Count findings by risk level
            risk_counts = self._count_findings_by_risk(results)
            
            # Analyze specific security concerns
            security_concerns = self._analyze_security_concerns(results)
            
            # Calculate overall risk score
            risk_score = self._calculate_risk_score(risk_counts, security_concerns)
            
            # Determine overall risk level
            overall_risk = self._determine_overall_risk(risk_score, risk_counts)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(results, security_concerns)
            
            # Generate compliance notes
            compliance_notes = self._generate_compliance_notes(results)
            
            # Determine mitigation priority
            mitigation_priority = self._determine_mitigation_priority(overall_risk, security_concerns)
            
            # Create security assessment
            assessment = SecurityAssessment(
                overall_risk=overall_risk,
                risk_score=risk_score,
                critical_findings=risk_counts.get(SecurityRisk.CRITICAL, 0),
                high_risk_findings=risk_counts.get(SecurityRisk.HIGH, 0),
                medium_risk_findings=risk_counts.get(SecurityRisk.MEDIUM, 0),
                low_risk_findings=risk_counts.get(SecurityRisk.LOW, 0),
                info_findings=risk_counts.get(SecurityRisk.INFO, 0),
                cleartext_communications=security_concerns['cleartext_communications'],
                hardcoded_credentials=security_concerns['hardcoded_credentials'],
                development_endpoints=security_concerns['development_endpoints'],
                suspicious_domains=security_concerns['suspicious_domains'],
                certificate_issues=security_concerns['certificate_issues'],
                recommendations=recommendations,
                mitigation_priority=mitigation_priority,
                compliance_notes=compliance_notes
            )
            
            logger.info(f"Security assessment completed: {overall_risk.value} risk with score {risk_score:.2f}")
            return assessment
            
        except Exception as e:
            logger.error(f"Error performing security assessment: {e}")
            
            # Return minimal assessment on error
            return SecurityAssessment(
                overall_risk=SecurityRisk.MEDIUM,
                risk_score=0.5,
                critical_findings=0,
                high_risk_findings=0,
                medium_risk_findings=0,
                low_risk_findings=0,
                info_findings=0,
                recommendations=["Review endpoint discovery results manually due to assessment error"],
                mitigation_priority="manual_review"
            )
    
    def assess_endpoint_risk(self, endpoint: str, endpoint_type: EndpointType,
                           protocol: Optional[ProtocolType] = None,
                           domain_category: Optional[DomainCategory] = None) -> SecurityRisk:
        """
        Assess security risk level for a specific endpoint.
        
        Args:
            endpoint: Endpoint value
            endpoint_type: Type of endpoint
            protocol: Protocol type if applicable
            domain_category: Domain category if applicable
            
        Returns:
            SecurityRisk level for the endpoint
        """
        try:
            # Start with base risk from endpoint type
            if endpoint_type == EndpointType.SECRET:
                return SecurityRisk.CRITICAL
            
            # Check for high-risk indicators
            if self._has_critical_indicators(endpoint):
                return SecurityRisk.CRITICAL
            
            if self._has_high_risk_indicators(endpoint, protocol):
                return SecurityRisk.HIGH
            
            # Check protocol-specific risks
            if protocol == ProtocolType.HTTP:
                return SecurityRisk.HIGH  # Cleartext communication
            
            # Check domain category risks
            if domain_category in [DomainCategory.DEVELOPMENT, DomainCategory.TESTING]:
                return SecurityRisk.MEDIUM
            
            if domain_category == DomainCategory.SUSPICIOUS:
                return SecurityRisk.HIGH
            
            # Default risk based on endpoint type
            type_risks = {
                EndpointType.API_ENDPOINT: SecurityRisk.HIGH,
                EndpointType.IP_ADDRESS: SecurityRisk.MEDIUM,
                EndpointType.URL: SecurityRisk.MEDIUM,
                EndpointType.DOMAIN: SecurityRisk.LOW,
                EndpointType.DEEP_LINK: SecurityRisk.LOW,
                EndpointType.FILE_URL: SecurityRisk.LOW,
                EndpointType.CERTIFICATE: SecurityRisk.INFO
            }
            
            return type_risks.get(endpoint_type, SecurityRisk.LOW)
            
        except Exception as e:
            logger.error(f"Error assessing endpoint risk: {e}")
            return SecurityRisk.MEDIUM  # Conservative default
    
    def _count_findings_by_risk(self, results: ExtractionResults) -> Dict[SecurityRisk, int]:
        """Count findings by risk level."""
        risk_counts = {
            SecurityRisk.CRITICAL: 0,
            SecurityRisk.HIGH: 0,
            SecurityRisk.MEDIUM: 0,
            SecurityRisk.LOW: 0,
            SecurityRisk.INFO: 0
        }
        
        # Count from detailed findings if available
        if results.detailed_findings:
            for finding in results.detailed_findings:
                risk_level = finding.risk_level
                if risk_level in risk_counts:
                    risk_counts[risk_level] += 1
        else:
            # Estimate from raw findings
            for endpoint in results.secrets:
                risk_counts[SecurityRisk.CRITICAL] += 1
            
            for endpoint in results.api_endpoints:
                risk_counts[SecurityRisk.HIGH] += 1
            
            # Check for HTTP URLs
            http_urls = [url for url in results.urls if url.startswith('http://')]
            risk_counts[SecurityRisk.HIGH] += len(http_urls)
            
            # Count IPs as medium risk
            risk_counts[SecurityRisk.MEDIUM] += len(results.ips)
            
            # Count domains and other endpoints as low risk
            risk_counts[SecurityRisk.LOW] += len(results.domains) + len(results.deep_links) + len(results.file_urls)
            
            # Count certificates as info
            risk_counts[SecurityRisk.INFO] += len(results.certificates)
        
        return risk_counts
    
    def _analyze_security_concerns(self, results: ExtractionResults) -> Dict[str, int]:
        """Analyze specific security concerns in the findings."""
        concerns = {
            'cleartext_communications': 0,
            'hardcoded_credentials': 0,
            'development_endpoints': 0,
            'suspicious_domains': 0,
            'certificate_issues': 0
        }
        
        # Analyze cleartext communications
        http_urls = [url for url in results.urls if url.startswith('http://')]
        concerns['cleartext_communications'] = len(http_urls)
        
        # Analyze hardcoded credentials (secrets)
        concerns['hardcoded_credentials'] = len(results.secrets)
        
        # Analyze development endpoints
        dev_keywords = ['test', 'dev', 'debug', 'staging', 'localhost']
        for category in [results.urls, results.domains, results.api_endpoints]:
            for endpoint in category:
                if any(keyword in endpoint.lower() for keyword in dev_keywords):
                    concerns['development_endpoints'] += 1
        
        # Analyze suspicious domains
        suspicious_keywords = ['admin', 'backdoor', 'internal', 'temp']
        for domain in results.domains:
            if any(keyword in domain.lower() for keyword in suspicious_keywords):
                concerns['suspicious_domains'] += 1
        
        # Certificate issues (placeholder - would need deeper analysis)
        concerns['certificate_issues'] = 0
        
        return concerns
    
    def _calculate_risk_score(self, risk_counts: Dict[SecurityRisk, int],
                            security_concerns: Dict[str, int]) -> float:
        """Calculate overall risk score (0.0 to 1.0)."""
        # Weight different risk levels
        risk_weights = {
            SecurityRisk.CRITICAL: 1.0,
            SecurityRisk.HIGH: 0.8,
            SecurityRisk.MEDIUM: 0.6,
            SecurityRisk.LOW: 0.3,
            SecurityRisk.INFO: 0.1
        }
        
        # Calculate base score from risk counts
        total_weighted_risk = 0.0
        total_findings = sum(risk_counts.values())
        
        if total_findings > 0:
            for risk_level, count in risk_counts.items():
                weight = risk_weights.get(risk_level, 0.5)
                total_weighted_risk += count * weight
            
            base_score = total_weighted_risk / total_findings
        else:
            base_score = 0.0
        
        # Apply security concern modifiers
        concern_modifier = 0.0
        
        # Critical concerns
        if security_concerns['hardcoded_credentials'] > 0:
            concern_modifier += 0.3
        
        # High concerns
        if security_concerns['cleartext_communications'] >= self.thresholds['cleartext_warning_threshold']:
            concern_modifier += 0.2
        
        # Medium concerns
        if security_concerns['development_endpoints'] >= self.thresholds['development_endpoint_threshold']:
            concern_modifier += 0.1
        
        if security_concerns['suspicious_domains'] > 0:
            concern_modifier += 0.1
        
        # Combine base score and modifiers
        final_score = min(1.0, base_score + concern_modifier)
        
        return final_score
    
    def _determine_overall_risk(self, risk_score: float, 
                              risk_counts: Dict[SecurityRisk, int]) -> SecurityRisk:
        """Determine overall risk level."""
        # Critical if any critical findings or very high score
        if (risk_counts.get(SecurityRisk.CRITICAL, 0) >= self.thresholds['critical_risk_threshold'] or
            risk_score >= 0.9):
            return SecurityRisk.CRITICAL
        
        # High if multiple high findings or high score
        if (risk_counts.get(SecurityRisk.HIGH, 0) >= self.thresholds['high_risk_threshold'] or
            risk_score >= 0.7):
            return SecurityRisk.HIGH
        
        # Medium if multiple medium findings or medium score
        if (risk_counts.get(SecurityRisk.MEDIUM, 0) >= self.thresholds['medium_risk_threshold'] or
            risk_score >= 0.5):
            return SecurityRisk.MEDIUM
        
        # Low if mostly low findings
        if risk_score >= 0.3:
            return SecurityRisk.LOW
        
        # Info level for minimal findings
        return SecurityRisk.INFO
    
    def _generate_recommendations(self, results: ExtractionResults,
                                security_concerns: Dict[str, int]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Critical recommendations
        if security_concerns['hardcoded_credentials'] > 0:
            recommendations.append(
                f"CRITICAL: Remove {security_concerns['hardcoded_credentials']} hardcoded credentials/secrets from the application"
            )
        
        # High priority recommendations
        if security_concerns['cleartext_communications'] > 0:
            recommendations.append(
                f"HIGH: Replace {security_concerns['cleartext_communications']} HTTP URLs with HTTPS for encrypted communication"
            )
        
        if len(results.api_endpoints) > 0:
            recommendations.append(
                "HIGH: Implement proper authentication and authorization for API endpoints"
            )
        
        # Medium priority recommendations
        if len(results.ips) >= self.thresholds['ip_hardcoding_threshold']:
            recommendations.append(
                f"MEDIUM: Replace {len(results.ips)} hardcoded IP addresses with domain names or configuration"
            )
        
        if security_concerns['development_endpoints'] > 0:
            recommendations.append(
                f"MEDIUM: Remove {security_concerns['development_endpoints']} development/test endpoints from production build"
            )
        
        # General recommendations
        if len(results.urls) > 0 or len(results.api_endpoints) > 0:
            recommendations.extend([
                "Implement certificate pinning for critical endpoints",
                "Use network security configuration to restrict cleartext traffic",
                "Implement proper error handling for network operations",
                "Consider using dynamic configuration instead of hardcoded endpoints"
            ])
        
        if len(results.deep_links) > 0:
            recommendations.append(
                "Validate and sanitize all deep link parameters to prevent attacks"
            )
        
        # Domain-specific recommendations
        if security_concerns['suspicious_domains'] > 0:
            recommendations.append(
                "Review suspicious domain references for potential security issues"
            )
        
        return recommendations
    
    def _generate_compliance_notes(self, results: ExtractionResults) -> List[str]:
        """Generate MASVS compliance notes."""
        compliance_notes = []
        
        # Map findings to MASVS controls
        masvs_controls = set()
        
        if results.urls or results.api_endpoints:
            masvs_controls.add("MSTG-NETWORK-01 (Network Communication)")
        
        if results.ips:
            masvs_controls.add("MSTG-NETWORK-02 (Network Requests)")
        
        if results.deep_links or results.file_urls:
            masvs_controls.add("MSTG-PLATFORM-03 (Platform APIs)")
        
        if results.secrets:
            masvs_controls.add("MSTG-CRYPTO-01 (Cryptographic Key Management)")
        
        if masvs_controls:
            compliance_notes.append(
                f"MASVS Controls: {', '.join(sorted(masvs_controls))}"
            )
        
        # Specific compliance recommendations
        if results.secrets:
            compliance_notes.append(
                "MSTG-CRYPTO-01: Ensure cryptographic keys are stored securely"
            )
        
        if any(url.startswith('http://') for url in results.urls):
            compliance_notes.append(
                "MSTG-NETWORK-01: Ensure all network communication uses secure protocols"
            )
        
        return compliance_notes
    
    def _determine_mitigation_priority(self, overall_risk: SecurityRisk,
                                     security_concerns: Dict[str, int]) -> str:
        """Determine mitigation priority level."""
        if overall_risk == SecurityRisk.CRITICAL:
            return "immediate"
        elif overall_risk == SecurityRisk.HIGH:
            return "high"
        elif overall_risk == SecurityRisk.MEDIUM:
            return "medium"
        elif overall_risk == SecurityRisk.LOW:
            return "low"
        else:
            return "informational"
    
    def _has_critical_indicators(self, endpoint: str) -> bool:
        """Check for critical security indicators."""
        critical_patterns = self.risk_rules.get('critical_indicators', {})
        
        # Check secret patterns
        secret_patterns = critical_patterns.get('secret_patterns', [])
        for pattern in secret_patterns:
            if self._matches_pattern(endpoint, pattern):
                return True
        
        # Check credential patterns
        credential_patterns = critical_patterns.get('credentials', [])
        for pattern in credential_patterns:
            if self._matches_pattern(endpoint, pattern):
                return True
        
        return False
    
    def _has_high_risk_indicators(self, endpoint: str, 
                                protocol: Optional[ProtocolType]) -> bool:
        """Check for high-risk security indicators."""
        # Cleartext protocols
        if protocol == ProtocolType.HTTP:
            return True
        
        high_risk_patterns = self.risk_rules.get('high_risk_indicators', {})
        
        # Check cleartext protocol patterns
        cleartext_patterns = high_risk_patterns.get('cleartext_protocols', [])
        for pattern in cleartext_patterns:
            if pattern in endpoint.lower():
                return True
        
        # Check hardcoded IP patterns
        ip_patterns = high_risk_patterns.get('hardcoded_ips', [])
        for pattern in ip_patterns:
            if self._matches_pattern(endpoint, pattern):
                return True
        
        return False
    
    def _matches_pattern(self, text: str, pattern: str) -> bool:
        """Check if text matches a regex pattern."""
        try:
            import re
            return bool(re.search(pattern, text))
        except Exception:
            return False
    
    def assess_finding_security(self, finding: EndpointFinding) -> Dict[str, Any]:
        """Assess security implications of a specific finding."""
        assessment = {
            'risk_level': finding.risk_level,
            'security_issues': [],
            'masvs_controls': [],
            'recommendations': []
        }
        
        # Check for specific security issues
        if finding.endpoint_type == EndpointType.SECRET:
            assessment['security_issues'].append('Hardcoded credentials detected')
            assessment['masvs_controls'].append('MSTG-CRYPTO-01')
            assessment['recommendations'].append('Store credentials securely using Android Keystore')
        
        if finding.protocol == ProtocolType.HTTP:
            assessment['security_issues'].append('Cleartext communication')
            assessment['masvs_controls'].append('MSTG-NETWORK-01')
            assessment['recommendations'].append('Use HTTPS for encrypted communication')
        
        if finding.domain_category == DomainCategory.DEVELOPMENT:
            assessment['security_issues'].append('Development endpoint in production')
            assessment['recommendations'].append('Remove development endpoints from production build')
        
        return assessment
    
    def create_security_report(self, assessment: SecurityAssessment) -> Dict[str, Any]:
        """Create detailed security assessment report."""
        total_findings = (assessment.critical_findings + assessment.high_risk_findings +
                         assessment.medium_risk_findings + assessment.low_risk_findings +
                         assessment.info_findings)
        
        report = {
            'overall_assessment': {
                'risk_level': assessment.overall_risk.value,
                'risk_score': assessment.risk_score,
                'total_findings': total_findings
            },
            'risk_distribution': {
                'critical': assessment.critical_findings,
                'high': assessment.high_risk_findings,
                'medium': assessment.medium_risk_findings,
                'low': assessment.low_risk_findings,
                'info': assessment.info_findings
            },
            'security_concerns': {
                'cleartext_communications': assessment.cleartext_communications,
                'hardcoded_credentials': assessment.hardcoded_credentials,
                'development_endpoints': assessment.development_endpoints,
                'suspicious_domains': assessment.suspicious_domains,
                'certificate_issues': assessment.certificate_issues
            },
            'mitigation': {
                'priority': assessment.mitigation_priority,
                'recommendations': assessment.recommendations
            },
            'compliance': {
                'notes': assessment.compliance_notes
            }
        }
        
        return report 
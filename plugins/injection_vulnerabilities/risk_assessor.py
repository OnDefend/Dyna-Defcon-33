"""
Injection Vulnerabilities - Risk Assessor Component

This module provides risk assessment capabilities for injection vulnerabilities
including overall risk scoring, risk factor analysis, and mitigation recommendations.
"""

import logging
from typing import Dict, List, Optional, Any

from plugins.injection_vulnerabilities.data_structures import (
    InjectionVulnerabilityResult, RiskAssessment, RiskLevel, SeverityLevel,
    InjectionAnalysisConfiguration, ProviderSecurityLevel
)

class InjectionRiskAssessor:
    """Risk assessor for injection vulnerabilities."""
    
    def __init__(self, config: Optional[InjectionAnalysisConfiguration] = None):
        """Initialize the risk assessor."""
        self.config = config or InjectionAnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
    
    def assess_risk(self, result: InjectionVulnerabilityResult) -> RiskAssessment:
        """Assess overall risk based on injection vulnerability analysis."""
        try:
            # Count vulnerabilities by severity
            severity_counts = self._count_vulnerabilities_by_severity(result.vulnerabilities)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(severity_counts, result)
            
            # Determine overall risk level
            overall_risk = self._determine_overall_risk(risk_score, severity_counts)
            
            # Identify risk factors
            risk_factors = self._identify_risk_factors(result)
            
            # Generate mitigations
            mitigations = self._generate_mitigations(result, risk_factors)
            
            # Count provider information
            provider_counts = self._count_providers(result)
            
            return RiskAssessment(
                overall_risk=overall_risk,
                risk_score=risk_score,
                critical_vulnerabilities=severity_counts.get('CRITICAL', 0),
                high_vulnerabilities=severity_counts.get('HIGH', 0),
                medium_vulnerabilities=severity_counts.get('MEDIUM', 0),
                low_vulnerabilities=severity_counts.get('LOW', 0),
                exported_providers=provider_counts['exported'],
                vulnerable_providers=provider_counts['vulnerable'],
                risk_factors=risk_factors,
                mitigations=mitigations
            )
            
        except Exception as e:
            self.logger.error(f"Risk assessment failed: {e}")
            return RiskAssessment(
                overall_risk=RiskLevel.UNKNOWN,
                risk_score=0.0,
                risk_factors=[f"Risk assessment failed: {e}"]
            )
    
    def _count_vulnerabilities_by_severity(self, vulnerabilities: List) -> Dict[str, int]:
        """Count vulnerabilities by severity level."""
        counts = {}
        
        for vulnerability in vulnerabilities:
            severity = vulnerability.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        
        return counts
    
    def _calculate_risk_score(self, severity_counts: Dict[str, int], result: InjectionVulnerabilityResult) -> float:
        """Calculate overall risk score (0.0 to 1.0)."""
        base_score = 0.0
        
        # Weight vulnerabilities by severity
        severity_weights = {
            'CRITICAL': 1.0,
            'HIGH': 0.7,
            'MEDIUM': 0.4,
            'LOW': 0.1
        }
        
        for severity, count in severity_counts.items():
            weight = severity_weights.get(severity, 0.0)
            base_score += count * weight
        
        # Normalize based on maximum possible score
        # Assume worst case of 10 critical vulnerabilities = 1.0 score
        max_score = 10.0
        normalized_score = min(1.0, base_score / max_score)
        
        # Adjust score based on analysis quality
        quality_multiplier = self._calculate_quality_multiplier(result)
        adjusted_score = normalized_score * quality_multiplier
        
        # Adjust for provider security
        provider_multiplier = self._calculate_provider_multiplier(result)
        final_score = adjusted_score * provider_multiplier
        
        return min(1.0, final_score)
    
    def _calculate_quality_multiplier(self, result: InjectionVulnerabilityResult) -> float:
        """Calculate quality multiplier based on analysis completeness."""
        multiplier = 1.0
        
        # Increase confidence if both dynamic and static analysis were performed
        if result.dynamic_analysis and result.static_analysis:
            multiplier *= 1.1
        
        # Increase confidence for successful dynamic analysis
        if result.dynamic_analysis and result.dynamic_analysis.success:
            multiplier *= 1.05
        
        # Increase confidence for comprehensive static analysis
        if result.static_analysis and result.static_analysis.total_files_analyzed > 100:
            multiplier *= 1.05
        
        return min(1.2, multiplier)
    
    def _calculate_provider_multiplier(self, result: InjectionVulnerabilityResult) -> float:
        """Calculate provider-based risk multiplier."""
        multiplier = 1.0
        
        if result.static_analysis and result.static_analysis.manifest_analysis:
            providers = result.static_analysis.manifest_analysis
            
            # Count different provider security levels
            exported_unprotected = sum(
                1 for p in providers 
                if p.security_level == ProviderSecurityLevel.EXPORTED_UNPROTECTED
            )
            
            vulnerable_providers = sum(
                1 for p in providers 
                if p.security_level == ProviderSecurityLevel.VULNERABLE
            )
            
            # Increase risk for exported unprotected providers
            multiplier += exported_unprotected * 0.1
            
            # Increase risk significantly for vulnerable providers
            multiplier += vulnerable_providers * 0.2
        
        return min(1.5, multiplier)
    
    def _determine_overall_risk(self, risk_score: float, severity_counts: Dict[str, int]) -> RiskLevel:
        """Determine overall risk level based on score and vulnerabilities."""
        # Critical vulnerabilities automatically raise risk
        if severity_counts.get('CRITICAL', 0) > 0:
            return RiskLevel.CRITICAL
        
        # High vulnerabilities with high score
        if severity_counts.get('HIGH', 0) > 0 and risk_score > 0.7:
            return RiskLevel.CRITICAL
        
        # Risk score based determination
        if risk_score >= 0.8:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            return RiskLevel.HIGH
        elif risk_score >= 0.3:
            return RiskLevel.MEDIUM
        elif risk_score > 0.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.LOW
    
    def _identify_risk_factors(self, result: InjectionVulnerabilityResult) -> List[str]:
        """Identify specific risk factors based on analysis results."""
        risk_factors = []
        
        # Check for high-confidence vulnerabilities
        high_confidence_vulns = [
            v for v in result.vulnerabilities 
            if v.confidence >= 0.8
        ]
        
        if high_confidence_vulns:
            risk_factors.append(f"{len(high_confidence_vulns)} high-confidence SQL injection vulnerabilities")
        
        # Check for critical vulnerabilities
        critical_vulns = [
            v for v in result.vulnerabilities 
            if v.severity == SeverityLevel.CRITICAL
        ]
        
        if critical_vulns:
            risk_factors.append(f"{len(critical_vulns)} critical SQL injection vulnerabilities")
        
        # Check for exported providers
        if result.static_analysis and result.static_analysis.manifest_analysis:
            exported_providers = [
                p for p in result.static_analysis.manifest_analysis 
                if p.exported
            ]
            
            if exported_providers:
                risk_factors.append(f"{len(exported_providers)} exported content providers")
            
            # Check for unprotected exported providers
            unprotected_providers = [
                p for p in exported_providers 
                if not p.permissions
            ]
            
            if unprotected_providers:
                risk_factors.append(f"{len(unprotected_providers)} exported providers without permissions")
        
        # Check for dynamic analysis vulnerabilities
        if result.dynamic_analysis and result.dynamic_analysis.vulnerabilities_found:
            risk_factors.append("SQL injection vulnerabilities confirmed through dynamic testing")
        
        # Check for code-level vulnerabilities
        if result.static_analysis and result.static_analysis.code_patterns:
            high_risk_patterns = [
                p for p in result.static_analysis.code_patterns 
                if p.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
            ]
            
            if high_risk_patterns:
                risk_factors.append(f"{len(high_risk_patterns)} high-risk SQL patterns in code")
        
        # Check for string concatenation patterns
        if result.static_analysis and result.static_analysis.code_patterns:
            concat_patterns = [
                p for p in result.static_analysis.code_patterns 
                if 'concatenation' in p.description.lower()
            ]
            
            if concat_patterns:
                risk_factors.append(f"{len(concat_patterns)} string concatenation patterns in SQL queries")
        
        return risk_factors
    
    def _generate_mitigations(self, result: InjectionVulnerabilityResult, risk_factors: List[str]) -> List[str]:
        """Generate mitigation recommendations based on risk factors."""
        mitigations = []
        
        # General SQL injection mitigations
        if result.vulnerabilities:
            mitigations.extend([
                "Use parameterized queries or prepared statements for all SQL operations",
                "Implement comprehensive input validation and sanitization",
                "Apply the principle of least privilege for database access"
            ])
        
        # Provider-specific mitigations
        if result.static_analysis and result.static_analysis.manifest_analysis:
            exported_providers = [
                p for p in result.static_analysis.manifest_analysis 
                if p.exported
            ]
            
            if exported_providers:
                mitigations.extend([
                    "Implement proper permissions for exported content providers",
                    "Consider making content providers non-exported if possible",
                    "Implement URI validation and access controls"
                ])
        
        # Code-level mitigations
        if result.static_analysis and result.static_analysis.code_patterns:
            mitigations.extend([
                "Replace string concatenation with parameterized queries",
                "Implement proper error handling to prevent information disclosure",
                "Use allowlists for acceptable input values"
            ])
        
        # Dynamic analysis mitigations
        if result.dynamic_analysis and result.dynamic_analysis.vulnerabilities_found:
            mitigations.extend([
                "Implement runtime application self-protection (RASP)",
                "Add comprehensive logging and monitoring for suspicious activities",
                "Perform regular security testing and vulnerability assessments"
            ])
        
        # Risk-specific mitigations
        if any("high-confidence" in factor for factor in risk_factors):
            mitigations.append("Prioritize immediate remediation of high-confidence vulnerabilities")
        
        if any("critical" in factor for factor in risk_factors):
            mitigations.append("Implement emergency patching process for critical vulnerabilities")
        
        if any("exported" in factor for factor in risk_factors):
            mitigations.append("Conduct thorough security review of all exported components")
        
        return mitigations
    
    def _count_providers(self, result: InjectionVulnerabilityResult) -> Dict[str, int]:
        """Count different types of providers."""
        counts = {
            'total': 0,
            'exported': 0,
            'vulnerable': 0
        }
        
        if result.static_analysis and result.static_analysis.manifest_analysis:
            providers = result.static_analysis.manifest_analysis
            counts['total'] = len(providers)
            counts['exported'] = sum(1 for p in providers if p.exported)
            counts['vulnerable'] = sum(1 for p in providers if p.vulnerabilities)
        
        return counts 
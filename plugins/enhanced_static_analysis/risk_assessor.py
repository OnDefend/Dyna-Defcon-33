"""
Enhanced Static Analysis - Risk Assessor Component

This module provides comprehensive risk assessment capabilities including
vulnerability scoring, risk level determination, and mitigation strategies.
"""

import logging
from typing import Dict, List, Optional, Any
from .data_structures import (
    RiskAssessment, RiskLevel, SeverityLevel, StaticAnalysisResult,
    AnalysisConfiguration, SecurityFinding
)

class RiskAssessor:
    """Advanced risk assessor for security vulnerability analysis."""
    
    def __init__(self, config: Optional[AnalysisConfiguration] = None):
        """Initialize the risk assessor with configuration."""
        self.config = config or AnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        
        # Risk scoring weights
        self.severity_weights = {
            SeverityLevel.CRITICAL: 10.0,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5,
            SeverityLevel.INFO: 1.0
        }
        
        # Risk threshold mappings
        self.risk_thresholds = {
            RiskLevel.CRITICAL: 80.0,
            RiskLevel.HIGH: 60.0,
            RiskLevel.MEDIUM: 40.0,
            RiskLevel.LOW: 20.0,
            RiskLevel.INFO: 0.0
        }
    
    def assess_risk(self, result: StaticAnalysisResult) -> RiskAssessment:
        """
        Assess overall risk based on analysis results.
        
        Args:
            result: StaticAnalysisResult containing analysis findings
            
        Returns:
            RiskAssessment with overall risk evaluation
        """
        try:
            assessment = RiskAssessment()
            
            # Collect all findings for analysis
            all_findings = list(result.security_findings)
            
            # Add secret analysis findings to the main findings list for risk assessment
            if result.secret_analysis:
                all_findings.extend(result.secret_analysis)
        
            # Add manifest analysis findings if available
            if result.manifest_analysis:
                # Extract findings from manifest analysis if it has findings
                if hasattr(result.manifest_analysis, 'security_findings'):
                    all_findings.extend(result.manifest_analysis.security_findings)
                elif hasattr(result.manifest_analysis, 'findings'):
                    all_findings.extend(result.manifest_analysis.findings)
            
            # Count issues by severity
            self._count_issues_by_severity(all_findings, assessment)
            
            # Calculate risk score
            assessment.risk_score = self._calculate_risk_score(assessment)
            
            # Determine overall risk level
            assessment.overall_risk = self._determine_risk_level(assessment.risk_score)
            
            # Calculate security score (inverse of risk)
            assessment.security_score = max(0, 100 - assessment.risk_score)
            
            # Identify risk factors
            assessment.risk_factors = self._identify_risk_factors(all_findings)
            
            # Generate mitigation strategies
            assessment.mitigation_strategies = self._generate_mitigation_strategies(all_findings)
            
            # Assess compliance status
            assessment.compliance_status = self._assess_compliance_status(all_findings)
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Risk assessment failed: {e}")
            # Return default assessment
            return RiskAssessment()
    
    def _count_issues_by_severity(self, findings: List[SecurityFinding], assessment: RiskAssessment) -> None:
        """Count issues by severity level."""
        for finding in findings:
            severity = getattr(finding, 'severity', SeverityLevel.INFO)
            if severity == SeverityLevel.CRITICAL:
                assessment.critical_issues += 1
            elif severity == SeverityLevel.HIGH:
                assessment.high_issues += 1
            elif severity == SeverityLevel.MEDIUM:
                assessment.medium_issues += 1
            elif severity == SeverityLevel.LOW:
                assessment.low_issues += 1
            else:
                assessment.info_issues += 1
    
    def _calculate_risk_score(self, assessment: RiskAssessment) -> float:
        """Calculate overall risk score (0-100)."""
        total_score = 0.0
        
        # Weight by severity
        total_score += assessment.critical_issues * self.severity_weights[SeverityLevel.CRITICAL]
        total_score += assessment.high_issues * self.severity_weights[SeverityLevel.HIGH]
        total_score += assessment.medium_issues * self.severity_weights[SeverityLevel.MEDIUM]
        total_score += assessment.low_issues * self.severity_weights[SeverityLevel.LOW]
        total_score += assessment.info_issues * self.severity_weights[SeverityLevel.INFO]
        
        # Normalize to 0-100 scale
        if assessment.total_issues > 0:
            # Consider density of issues
            density_factor = min(1.0, assessment.total_issues / 10.0)
            risk_score = min(100.0, total_score * density_factor)
        else:
            risk_score = 0.0
        
        return risk_score
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level based on score."""
        if risk_score >= self.risk_thresholds[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif risk_score >= self.risk_thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif risk_score >= self.risk_thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif risk_score >= self.risk_thresholds[RiskLevel.LOW]:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _identify_risk_factors(self, findings: List[SecurityFinding]) -> List[str]:
        """Identify key risk factors from findings."""
        risk_factors = []
        
        # Count findings by type
        finding_types = {}
        for finding in findings:
            finding_type = getattr(finding, 'category', 'unknown')
            finding_types[finding_type] = finding_types.get(finding_type, 0) + 1
        
        # Identify significant risk factors
        for finding_type, count in finding_types.items():
            if count >= 3:  # Threshold for significant risk
                risk_factors.append(f"Multiple {finding_type} issues detected ({count} instances)")
        
        # Check for critical vulnerabilities
        critical_count = sum(1 for f in findings if getattr(f, 'severity', None) == SeverityLevel.CRITICAL)
        if critical_count > 0:
            risk_factors.append(f"Critical security vulnerabilities present ({critical_count} found)")
        
        # Check for high severity issues
        high_count = sum(1 for f in findings if getattr(f, 'severity', None) == SeverityLevel.HIGH)
        if high_count >= 5:
            risk_factors.append(f"High concentration of high-severity issues ({high_count} found)")
        
        return risk_factors
    
    def _generate_mitigation_strategies(self, findings: List[SecurityFinding]) -> List[str]:
        """Generate mitigation strategies based on findings."""
        strategies = []
        
        # Generic mitigation strategies
        if findings:
            strategies.append("Implement comprehensive security code review process")
            strategies.append("Integrate security testing into CI/CD pipeline")
            strategies.append("Apply security-focused static analysis tools")
            strategies.append("Conduct regular security training for development team")
        
        # Specific mitigation based on finding types
        finding_types = set(getattr(f, 'category', 'unknown') for f in findings)
        
        if 'security_vulnerability' in finding_types:
            strategies.append("Implement secure coding guidelines and enforcement")
            strategies.append("Use security-focused libraries and frameworks")
        
        if 'code_quality_issue' in finding_types:
            strategies.append("Establish code quality standards and automated checks")
            strategies.append("Implement code review processes focusing on maintainability")
        
        # Critical finding mitigation
        critical_findings = [f for f in findings if getattr(f, 'severity', None) == SeverityLevel.CRITICAL]
        if critical_findings:
            strategies.insert(0, "Immediately address critical security vulnerabilities")
            strategies.insert(1, "Implement emergency security patches and updates")
        
        return strategies
    
    def _assess_compliance_status(self, findings: List[SecurityFinding]) -> Dict[str, str]:
        """Assess compliance status based on findings."""
        compliance = {}
        
        # OWASP Top 10 compliance
        critical_count = sum(1 for f in findings if getattr(f, 'severity', None) == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if getattr(f, 'severity', None) == SeverityLevel.HIGH)
        
        if critical_count == 0 and high_count <= 2:
            compliance['OWASP_TOP_10'] = 'COMPLIANT'
        elif critical_count == 0 and high_count <= 5:
            compliance['OWASP_TOP_10'] = 'PARTIALLY_COMPLIANT'
        else:
            compliance['OWASP_TOP_10'] = 'NON_COMPLIANT'
        
        # General security compliance
        total_issues = len(findings)
        if total_issues == 0:
            compliance['GENERAL_SECURITY'] = 'EXCELLENT'
        elif total_issues <= 5:
            compliance['GENERAL_SECURITY'] = 'GOOD'
        elif total_issues <= 15:
            compliance['GENERAL_SECURITY'] = 'FAIR'
        else:
            compliance['GENERAL_SECURITY'] = 'POOR'
        
        return compliance 
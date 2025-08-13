#!/usr/bin/env python3
"""
NIST Compliance Assessor

Assesses compliance levels against NIST Cybersecurity Framework.
"""

import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class ComplianceAssessor:
    """Assesses NIST CSF compliance levels from vulnerability findings."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the compliance assessor."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
    
    def assess_compliance(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall compliance based on findings."""
        total_findings = len(findings)
        
        if total_findings == 0:
            return {
                'compliance_level': 'HIGH',
                'score': 95.0,
                'recommendations': ['Continue monitoring for new vulnerabilities']
            }
        
        # Simple scoring based on severity
        high_severity = len([f for f in findings if f.get('severity') == 'HIGH'])
        medium_severity = len([f for f in findings if f.get('severity') == 'MEDIUM'])
        low_severity = len([f for f in findings if f.get('severity') == 'LOW'])
        
        score = max(0, 100 - (high_severity * 20 + medium_severity * 10 + low_severity * 5))
        
        if score >= 80:
            level = 'HIGH'
        elif score >= 60:
            level = 'MEDIUM'
        else:
            level = 'LOW'
        
        return {
            'compliance_level': level,
            'score': score,
            'high_severity_count': high_severity,
            'medium_severity_count': medium_severity,
            'low_severity_count': low_severity,
            'recommendations': self._generate_recommendations(findings)
        }
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate compliance recommendations."""
        recommendations = []
        
        high_severity = [f for f in findings if f.get('severity') == 'HIGH']
        if high_severity:
            recommendations.append(f"Address {len(high_severity)} high-severity findings immediately")
        
        if len(findings) > 10:
            recommendations.append("Consider implementing automated security testing")
        
        if not recommendations:
            recommendations.append("Maintain current security practices")
        
        return recommendations 
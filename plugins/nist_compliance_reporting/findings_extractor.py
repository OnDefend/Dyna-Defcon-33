#!/usr/bin/env python3
"""
AODS Findings Extractor

Extracts and normalizes vulnerability findings from AODS for NIST compliance reporting.
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class AODSFindingsExtractor:
    """Extracts and processes AODS vulnerability findings for NIST compliance analysis."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the AODS findings extractor."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
    
    def extract_findings(self, apk_ctx) -> List[Dict[str, Any]]:
        """Extract and normalize AODS findings for NIST analysis from APKContext."""
        try:
            normalized_findings = []
            
            # Extract findings from APKContext
            raw_findings = []
            
            # Check if APKContext has findings attribute
            if hasattr(apk_ctx, 'findings') and apk_ctx.findings:
                raw_findings = apk_ctx.findings
            elif hasattr(apk_ctx, 'vulnerabilities') and apk_ctx.vulnerabilities:
                raw_findings = apk_ctx.vulnerabilities
            else:
                # If no direct findings, return empty list
                self.logger.warning("No findings found in APKContext")
                return []
            
            for finding in raw_findings:
                normalized_finding = {
                    'id': finding.get('id', 'unknown'),
                    'title': finding.get('title', 'Unknown Finding'),
                    'description': finding.get('description', ''),
                    'severity': finding.get('severity', 'MEDIUM'),
                    'category': finding.get('category', 'UNKNOWN'),
                    'confidence': finding.get('confidence_score', 0.5),
                    'masvs_controls': finding.get('masvs_controls', []),
                    'owasp_category': finding.get('owasp_category', ''),
                    'file_path': finding.get('file_path', ''),
                    'line_number': finding.get('line_number', 0),
                    'evidence': finding.get('evidence', {}),
                    'remediation': finding.get('remediation', ''),
                    'references': finding.get('references', [])
                }
                normalized_findings.append(normalized_finding)
            
            self.logger.info(f"Extracted {len(normalized_findings)} findings for NIST analysis")
            return normalized_findings
            
        except Exception as e:
            self.logger.error(f"Error extracting AODS findings: {e}")
            return []
    
    def categorize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize findings by NIST CSF functions."""
        categories = {
            'IDENTIFY': [],
            'PROTECT': [],
            'DETECT': [],
            'RESPOND': [],
            'RECOVER': []
        }
        
        for finding in findings:
            # Map finding categories to NIST functions
            category = finding.get('category', '').upper()
            
            if any(term in category for term in ['MANIFEST', 'INVENTORY', 'ASSET']):
                categories['IDENTIFY'].append(finding)
            elif any(term in category for term in ['CRYPTO', 'AUTH', 'ACCESS', 'PERMISSION']):
                categories['PROTECT'].append(finding)
            elif any(term in category for term in ['MONITOR', 'LOG', 'DETECT']):
                categories['DETECT'].append(finding)
            elif any(term in category for term in ['INCIDENT', 'RESPONSE']):
                categories['RESPOND'].append(finding)
            else:
                categories['PROTECT'].append(finding)  # Default to PROTECT
        
        return categories
    
    def calculate_compliance_metrics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate compliance metrics from findings."""
        total_findings = len(findings)
        
        if total_findings == 0:
            return {
                'total_findings': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0,
                'compliance_score': 100.0,
                'risk_level': 'LOW'
            }
        
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate compliance score (inverse of risk)
        high_weight = 10
        medium_weight = 3
        low_weight = 1
        
        risk_score = (
            severity_counts['HIGH'] * high_weight +
            severity_counts['MEDIUM'] * medium_weight +
            severity_counts['LOW'] * low_weight
        )
        
        max_risk = total_findings * high_weight
        compliance_score = max(0, 100 - (risk_score / max_risk * 100)) if max_risk > 0 else 100
        
        if compliance_score >= 80:
            risk_level = 'LOW'
        elif compliance_score >= 60:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'HIGH'
        
        return {
            'total_findings': total_findings,
            'high_severity': severity_counts['HIGH'],
            'medium_severity': severity_counts['MEDIUM'],
            'low_severity': severity_counts['LOW'],
            'compliance_score': round(compliance_score, 2),
            'risk_level': risk_level
        } 
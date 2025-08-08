#!/usr/bin/env python3
"""
NIST CSF Mapper

Maps AODS findings to NIST Cybersecurity Framework subcategories.
"""

import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class NISTFrameworkMapper:
    """Maps vulnerability findings to NIST CSF subcategories."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the NIST CSF mapper."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # NIST CSF subcategory mappings
        self.subcategory_mappings = {
            'ID.AM': ['MANIFEST', 'ASSET', 'INVENTORY'],
            'ID.BE': ['BUSINESS', 'ENVIRONMENT'],
            'ID.GV': ['GOVERNANCE', 'POLICY'],
            'ID.RA': ['RISK', 'ASSESSMENT'],
            'ID.RM': ['RISK', 'MANAGEMENT'],
            'ID.SC': ['SUPPLY', 'CHAIN'],
            'PR.AC': ['ACCESS', 'PERMISSION', 'AUTH'],
            'PR.AT': ['AWARENESS', 'TRAINING'],
            'PR.DS': ['DATA', 'STORAGE', 'PROTECTION'],
            'PR.IP': ['PROTECTION', 'PROCESS'],
            'PR.MA': ['MAINTENANCE'],
            'PR.PT': ['PROTECTIVE', 'TECHNOLOGY'],
            'DE.AE': ['ANOMALY', 'EVENT'],
            'DE.CM': ['MONITORING', 'CONTINUOUS'],
            'DE.DP': ['DETECTION', 'PROCESS'],
            'RS.RP': ['RESPONSE', 'PLANNING'],
            'RS.CO': ['COMMUNICATION'],
            'RS.AN': ['ANALYSIS'],
            'RS.MI': ['MITIGATION'],
            'RS.IM': ['IMPROVEMENT'],
            'RC.RP': ['RECOVERY', 'PLANNING'],
            'RC.IM': ['RECOVERY', 'IMPROVEMENT'],
            'RC.CO': ['RECOVERY', 'COMMUNICATION']
        }
    
    def map_finding_to_subcategories(self, finding: Dict[str, Any]) -> List[str]:
        """Map a single finding to NIST CSF subcategories."""
        category = finding.get('category', '').upper()
        title = finding.get('title', '').upper()
        description = finding.get('description', '').upper()
        
        text_to_analyze = f"{category} {title} {description}"
        matched_subcategories = []
        
        for subcategory, keywords in self.subcategory_mappings.items():
            if any(keyword in text_to_analyze for keyword in keywords):
                matched_subcategories.append(subcategory)
        
        # Default mapping if no matches
        if not matched_subcategories:
            if 'AUTH' in text_to_analyze or 'PERMISSION' in text_to_analyze:
                matched_subcategories = ['PR.AC']
            elif 'CRYPTO' in text_to_analyze or 'ENCRYPT' in text_to_analyze:
                matched_subcategories = ['PR.DS']
            else:
                matched_subcategories = ['PR.PT']  # Default to Protective Technology
        
        return matched_subcategories
    
    def generate_subcategory_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a comprehensive NIST CSF subcategory mapping report."""
        subcategory_findings = {}
        
        for finding in findings:
            subcategories = self.map_finding_to_subcategories(finding)
            
            for subcategory in subcategories:
                if subcategory not in subcategory_findings:
                    subcategory_findings[subcategory] = []
                subcategory_findings[subcategory].append(finding)
        
        # Calculate coverage
        total_subcategories = len(self.subcategory_mappings)
        covered_subcategories = len(subcategory_findings)
        coverage_percentage = (covered_subcategories / total_subcategories) * 100
        
        return {
            'subcategory_mappings': subcategory_findings,
            'coverage_summary': {
                'total_subcategories': total_subcategories,
                'covered_subcategories': covered_subcategories,
                'coverage_percentage': round(coverage_percentage, 2)
            },
            'recommendations': self._generate_coverage_recommendations(subcategory_findings)
        }
    
    def _generate_coverage_recommendations(self, subcategory_findings: Dict[str, List]) -> List[str]:
        """Generate recommendations based on NIST CSF coverage."""
        recommendations = []
        
        # Check for missing critical subcategories
        critical_subcategories = ['PR.AC', 'PR.DS', 'DE.CM', 'ID.RA']
        missing_critical = [sc for sc in critical_subcategories if sc not in subcategory_findings]
        
        if missing_critical:
            recommendations.append(
                f"Critical NIST CSF subcategories not covered: {', '.join(missing_critical)}"
            )
        
        # Check for high-coverage areas
        high_coverage = [sc for sc, findings in subcategory_findings.items() if len(findings) > 5]
        if high_coverage:
            recommendations.append(
                f"High attention areas: {', '.join(high_coverage)} - Consider prioritizing these"
            )
        
        return recommendations 
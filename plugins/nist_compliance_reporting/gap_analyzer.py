#!/usr/bin/env python3
"""
Compliance Gap Analyzer

Analyzes compliance gaps in NIST Cybersecurity Framework implementation.
"""

import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class ComplianceGapAnalyzer:
    """Analyzes gaps in NIST CSF compliance based on findings."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the gap analyzer."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
    
    def analyze_gaps(self, findings: List[Dict[str, Any]], 
                    subcategory_mappings: Dict[str, List]) -> Dict[str, Any]:
        """Analyze compliance gaps from findings and mappings."""
        
        # NIST CSF subcategories
        all_subcategories = [
            'ID.AM', 'ID.BE', 'ID.GV', 'ID.RA', 'ID.RM', 'ID.SC',
            'PR.AC', 'PR.AT', 'PR.DS', 'PR.IP', 'PR.MA', 'PR.PT',
            'DE.AE', 'DE.CM', 'DE.DP',
            'RS.RP', 'RS.CO', 'RS.AN', 'RS.MI', 'RS.IM',
            'RC.RP', 'RC.IM', 'RC.CO'
        ]
        
        covered_subcategories = set(subcategory_mappings.keys())
        missing_subcategories = set(all_subcategories) - covered_subcategories
        
        # Analyze gap severity
        gap_analysis = {}
        for subcategory in missing_subcategories:
            gap_analysis[subcategory] = {
                'status': 'NOT_COVERED',
                'severity': self._assess_gap_severity(subcategory),
                'recommendations': self._get_gap_recommendations(subcategory)
            }
        
        # Analyze partial coverage
        for subcategory, findings_list in subcategory_mappings.items():
            high_findings = [f for f in findings_list if f.get('severity') == 'HIGH']
            if high_findings:
                gap_analysis[subcategory] = {
                    'status': 'PARTIAL_COVERAGE',
                    'severity': 'HIGH',
                    'findings_count': len(high_findings),
                    'recommendations': [f"Address {len(high_findings)} high-severity findings in {subcategory}"]
                }
        
        return {
            'gap_summary': {
                'total_subcategories': len(all_subcategories),
                'covered_subcategories': len(covered_subcategories),
                'missing_subcategories': len(missing_subcategories),
                'coverage_percentage': (len(covered_subcategories) / len(all_subcategories)) * 100
            },
            'gap_details': gap_analysis,
            'priority_gaps': self._prioritize_gaps(gap_analysis)
        }
    
    def _assess_gap_severity(self, subcategory: str) -> str:
        """Assess the severity of a compliance gap."""
        critical_subcategories = ['PR.AC', 'PR.DS', 'DE.CM', 'ID.RA']
        high_priority = ['PR.PT', 'DE.AE', 'RS.RP']
        
        if subcategory in critical_subcategories:
            return 'CRITICAL'
        elif subcategory in high_priority:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _get_gap_recommendations(self, subcategory: str) -> List[str]:
        """Get recommendations for addressing a specific gap."""
        recommendations_map = {
            'PR.AC': ['Implement access control policies', 'Review user permissions'],
            'PR.DS': ['Enhance data protection measures', 'Implement encryption'],
            'DE.CM': ['Deploy monitoring solutions', 'Implement SIEM'],
            'ID.RA': ['Conduct risk assessments', 'Document risk management procedures']
        }
        
        return recommendations_map.get(subcategory, [f'Address {subcategory} requirements'])
    
    def _prioritize_gaps(self, gap_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize gaps based on severity and impact."""
        priority_list = []
        
        for subcategory, details in gap_analysis.items():
            severity = details.get('severity', 'MEDIUM')
            priority_score = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(severity, 1)
            
            priority_list.append({
                'subcategory': subcategory,
                'severity': severity,
                'priority_score': priority_score,
                'status': details.get('status'),
                'recommendations': details.get('recommendations', [])
            })
        
        return sorted(priority_list, key=lambda x: x['priority_score'], reverse=True)[:10] 
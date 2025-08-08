#!/usr/bin/env python3
"""
NIST Report Generator

Generates comprehensive NIST Cybersecurity Framework compliance reports.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class NISTReportGenerator:
    """Generates comprehensive NIST CSF compliance reports."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the report generator."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
    
    def generate_executive_summary(self, compliance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of NIST compliance status."""
        
        gap_summary = compliance_data.get('gap_analysis', {}).get('gap_summary', {})
        compliance_score = compliance_data.get('compliance_assessment', {}).get('score', 0)
        
        return {
            'report_metadata': {
                'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'report_type': 'NIST CSF Compliance Assessment',
                'scope': 'Mobile Application Security Analysis'
            },
            'executive_summary': {
                'overall_compliance_score': compliance_score,
                'compliance_level': self._determine_compliance_level(compliance_score),
                'coverage_percentage': gap_summary.get('coverage_percentage', 0),
                'total_findings': len(compliance_data.get('findings', [])),
                'critical_gaps': len([g for g in compliance_data.get('gap_analysis', {}).get('priority_gaps', []) 
                                    if g.get('severity') == 'CRITICAL']),
                'key_recommendations': self._generate_key_recommendations(compliance_data)
            }
        }
    
    def generate_detailed_report(self, compliance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed compliance report."""
        
        return {
            'compliance_overview': self._generate_compliance_overview(compliance_data),
            'gap_analysis_details': self._format_gap_analysis(compliance_data.get('gap_analysis', {})),
            'findings_summary': self._summarize_findings(compliance_data.get('findings', [])),
            'implementation_roadmap': self._format_roadmap(compliance_data.get('roadmap', {})),
            'recommendations': self._generate_detailed_recommendations(compliance_data)
        }
    
    def generate_comprehensive_report(self, compliance_report) -> Dict[str, Any]:
        """Generate comprehensive NIST compliance report combining executive and detailed reports."""
        
        # Convert compliance report to dict if needed
        if hasattr(compliance_report, 'to_dict'):
            compliance_data = compliance_report.to_dict()
        elif isinstance(compliance_report, dict):
            compliance_data = compliance_report
        else:
            # Fallback for other types
            compliance_data = {}
        
        # Generate executive summary
        executive_summary = self.generate_executive_summary(compliance_data)
        
        # Generate detailed report
        detailed_report = self.generate_detailed_report(compliance_data)
        
        # Combine into comprehensive report
        comprehensive_report = {
            'report_metadata': {
                'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'report_type': 'NIST CSF Comprehensive Compliance Assessment',
                'scope': 'Mobile Application Security Analysis'
            },
            'executive_summary': executive_summary.get('executive_summary', {}),
            'detailed_analysis': detailed_report,
            'compliance_data': compliance_data
        }
        
        return comprehensive_report
    
    def _determine_compliance_level(self, score: float) -> str:
        """Determine compliance level based on score."""
        if score >= 90:
            return 'EXCELLENT'
        elif score >= 75:
            return 'GOOD'
        elif score >= 60:
            return 'SATISFACTORY'
        elif score >= 40:
            return 'NEEDS_IMPROVEMENT'
        else:
            return 'CRITICAL'
    
    def _generate_key_recommendations(self, compliance_data: Dict[str, Any]) -> List[str]:
        """Generate key recommendations for executive summary."""
        recommendations = []
        
        compliance_score = compliance_data.get('compliance_assessment', {}).get('score', 0)
        critical_gaps = [g for g in compliance_data.get('gap_analysis', {}).get('priority_gaps', []) 
                        if g.get('severity') == 'CRITICAL']
        
        if compliance_score < 60:
            recommendations.append("Immediate action required to address critical security gaps")
        
        if critical_gaps:
            recommendations.append(f"Prioritize {len(critical_gaps)} critical NIST CSF subcategories")
        
        high_findings = [f for f in compliance_data.get('findings', []) if f.get('severity') == 'HIGH']
        if len(high_findings) > 5:
            recommendations.append(f"Address {len(high_findings)} high-severity security findings")
        
        if not recommendations:
            recommendations.append("Maintain current security posture and continue monitoring")
        
        return recommendations[:5]  # Top 5 recommendations
    
    def _generate_compliance_overview(self, compliance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance overview section."""
        
        gap_summary = compliance_data.get('gap_analysis', {}).get('gap_summary', {})
        
        return {
            'nist_csf_coverage': {
                'total_subcategories': gap_summary.get('total_subcategories', 23),
                'covered_subcategories': gap_summary.get('covered_subcategories', 0),
                'missing_subcategories': gap_summary.get('missing_subcategories', 0),
                'coverage_percentage': gap_summary.get('coverage_percentage', 0)
            },
            'maturity_assessment': self._assess_maturity(compliance_data),
            'risk_profile': self._generate_risk_profile(compliance_data)
        }
    
    def _assess_maturity(self, compliance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess NIST CSF implementation maturity."""
        compliance_score = compliance_data.get('compliance_assessment', {}).get('score', 0)
        
        if compliance_score >= 85:
            tier = 'Adaptive'
            description = 'Organization adapts its cybersecurity practices based on lessons learned and predictive indicators'
        elif compliance_score >= 70:
            tier = 'Repeatable'
            description = 'Organization has sufficient resources to manage cybersecurity risk and external participation'
        elif compliance_score >= 50:
            tier = 'Risk Informed'
            description = 'Organization has risk management practices approved by management'
        else:
            tier = 'Partial'
            description = 'Organization has limited cybersecurity risk management practices'
        
        return {
            'current_tier': tier,
            'description': description,
            'score': compliance_score,
            'next_tier_requirements': self._get_next_tier_requirements(tier)
        }
    
    def _generate_risk_profile(self, compliance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk profile based on findings."""
        findings = compliance_data.get('findings', [])
        
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM')
            if severity in risk_counts:
                risk_counts[severity] += 1
        
        total_risk_score = (risk_counts['CRITICAL'] * 4 + risk_counts['HIGH'] * 3 + 
                           risk_counts['MEDIUM'] * 2 + risk_counts['LOW'] * 1)
        
        if total_risk_score >= 20:
            risk_level = 'HIGH'
        elif total_risk_score >= 10:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'overall_risk_level': risk_level,
            'risk_score': total_risk_score,
            'risk_distribution': risk_counts,
            'risk_trends': 'Analysis based on current assessment'
        }
    
    def _format_gap_analysis(self, gap_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Format gap analysis for report."""
        return {
            'summary': gap_analysis.get('gap_summary', {}),
            'priority_gaps': gap_analysis.get('priority_gaps', [])[:10],  # Top 10
            'coverage_analysis': gap_analysis.get('gap_details', {})
        }
    
    def _summarize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize security findings."""
        by_category = {}
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for finding in findings:
            category = finding.get('category', 'UNKNOWN')
            severity = finding.get('severity', 'MEDIUM')
            
            if category not in by_category:
                by_category[category] = 0
            by_category[category] += 1
            
            if severity in by_severity:
                by_severity[severity] += 1
        
        return {
            'total_findings': len(findings),
            'by_category': by_category,
            'by_severity': by_severity,
            'top_categories': sorted(by_category.items(), key=lambda x: x[1], reverse=True)[:5]
        }
    
    def _format_roadmap(self, roadmap: Dict[str, Any]) -> Dict[str, Any]:
        """Format implementation roadmap for report."""
        return {
            'summary': roadmap.get('roadmap_summary', {}),
            'phases': roadmap.get('implementation_phases', []),
            'key_milestones': self._extract_milestones(roadmap),
            'success_metrics': roadmap.get('success_metrics', [])
        }
    
    def _extract_milestones(self, roadmap: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract key milestones from roadmap."""
        phases = roadmap.get('implementation_phases', [])
        milestones = []
        
        cumulative_months = 0
        for phase in phases:
            cumulative_months += phase.get('duration_months', 3)
            milestones.append({
                'phase': phase.get('name'),
                'target_month': cumulative_months,
                'objectives': phase.get('objectives', [])
            })
        
        return milestones
    
    def _generate_detailed_recommendations(self, compliance_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate detailed recommendations."""
        recommendations = []
        
        # Add roadmap action items as recommendations
        roadmap = compliance_data.get('roadmap', {})
        action_items = roadmap.get('action_items', [])
        
        for item in action_items[:10]:  # Top 10 actions
            recommendations.append({
                'id': item.get('id'),
                'title': item.get('title'),
                'priority': item.get('priority'),
                'description': item.get('description'),
                'estimated_effort': item.get('estimated_effort'),
                'success_criteria': item.get('success_criteria', [])
            })
        
        return recommendations
    
    def _get_next_tier_requirements(self, current_tier: str) -> List[str]:
        """Get requirements for next maturity tier."""
        tier_requirements = {
            'Partial': ['Establish formal cybersecurity policies', 'Implement basic risk management'],
            'Risk Informed': ['Enhance threat intelligence', 'Improve incident response capabilities'],
            'Repeatable': ['Implement continuous monitoring', 'Establish metrics and KPIs'],
            'Adaptive': ['Current tier - focus on optimization and innovation']
        }
        
        return tier_requirements.get(current_tier, ['Continue current practices']) 
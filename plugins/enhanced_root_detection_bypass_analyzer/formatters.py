"""
Enhanced Root Detection Bypass Analyzer Formatters

Formatting utilities for root detection analysis results and comprehensive reports.
"""

from typing import Dict, List, Any
import json
from datetime import datetime
from rich.text import Text
from rich.table import Table
from rich.console import Console

from .data_structures import (
    RootDetectionAnalysisResult, RootDetectionFinding,
    SecurityControlAssessment, ExecutionStatistics
)

class RootDetectionFormatter:
    """Formats root detection analysis results for output."""
    
    def __init__(self):
        """Initialize formatter."""
        self.timestamp = datetime.now().isoformat()
        self.console = Console()
    
    def format_analysis_result(self, result: RootDetectionAnalysisResult) -> Dict[str, Any]:
        """Format complete analysis result."""
        return {
            'timestamp': self.timestamp,
            'summary': self._format_summary(result),
            'detection_findings': self._format_detection_findings(result.detection_findings),
            'security_assessments': self._format_security_assessments(result.security_assessments),
            'bypass_analysis': result.bypass_analysis,
            'dynamic_analysis': result.dynamic_analysis_results,
            'overall_assessment': {
                'security_score': result.overall_security_score,
                'risk_level': result.risk_assessment,
                'risk_description': self._get_risk_description(result.risk_assessment)
            },
            'recommendations': result.recommendations,
            'masvs_compliance': result.masvs_compliance,
            'analysis_metadata': result.analysis_metadata
        }
    
    def _format_summary(self, result: RootDetectionAnalysisResult) -> Dict[str, Any]:
        """Format analysis summary."""
        total_findings = len(result.detection_findings)
        total_assessments = len(result.security_assessments)
        
        # Count findings by severity
        severity_counts = {}
        for finding in result.detection_findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count findings by detection type
        type_counts = {}
        for finding in result.detection_findings:
            detection_type = finding.detection_type
            type_counts[detection_type] = type_counts.get(detection_type, 0) + 1
        
        return {
            'total_detection_findings': total_findings,
            'total_security_assessments': total_assessments,
            'findings_by_severity': severity_counts,
            'findings_by_type': type_counts,
            'analysis_scope': 'Enhanced Root Detection and Bypass Analysis'
        }
    
    def _format_detection_findings(self, findings: List[RootDetectionFinding]) -> List[Dict[str, Any]]:
        """Format detection findings."""
        formatted = []
        
        for finding in findings:
            formatted_finding = {
                'finding_id': finding.detection_id,
                'detection_details': {
                    'type': finding.detection_type,
                    'severity': finding.severity,
                    'confidence': round(finding.confidence, 3),
                    'description': finding.description
                },
                'location_info': {
                    'file_path': finding.location,
                    'evidence': finding.evidence,
                    'pattern_category': finding.pattern_category
                },
                'security_analysis': {
                    'bypass_resistance_score': round(finding.bypass_resistance_score, 3),
                    'control_effectiveness': finding.security_control_effectiveness,
                    'attack_vectors': finding.attack_vectors,
                    'bypass_methods': finding.bypass_methods
                },
                'remediation': {
                    'recommendation': finding.remediation,
                    'priority': self._get_priority(finding.severity)
                },
                'compliance': {
                    'masvs_references': finding.masvs_refs,
                    'control_mappings': self._map_controls(finding.masvs_refs)
                },
                'metadata': finding.analysis_metadata
            }
            
            formatted.append(formatted_finding)
        
        return formatted
    
    def _format_security_assessments(self, assessments: List[SecurityControlAssessment]) -> List[Dict[str, Any]]:
        """Format security control assessments."""
        formatted = []
        
        for assessment in assessments:
            formatted_assessment = {
                'control_type': assessment.control_type,
                'strength_analysis': {
                    'implementation_strength': assessment.implementation_strength,
                    'effectiveness_score': round(assessment.effectiveness_score, 3),
                    'bypass_resistance': assessment.bypass_resistance,
                    'risk_level': assessment.risk_level
                },
                'gap_analysis': {
                    'coverage_gaps': assessment.coverage_gaps,
                    'weaknesses': assessment.weaknesses,
                    'improvement_areas': assessment.recommendations
                },
                'strengths': assessment.strengths,
                'recommendations': {
                    'immediate_actions': assessment.recommendations[:2],
                    'long_term_improvements': assessment.recommendations[2:],
                    'priority_level': self._get_control_priority(assessment.risk_level)
                }
            }
            
            formatted.append(formatted_assessment)
        
        return formatted
    
    def _get_priority(self, severity: str) -> str:
        """Get priority based on severity."""
        priority_map = {
            'critical': 'IMMEDIATE',
            'high': 'HIGH',
            'medium': 'MEDIUM',
            'low': 'LOW'
        }
        return priority_map.get(severity.lower(), 'MEDIUM')
    
    def _get_control_priority(self, risk_level: str) -> str:
        """Get control priority based on risk level."""
        priority_map = {
            'critical': 'IMMEDIATE',
            'high': 'HIGH',
            'medium': 'MEDIUM',
            'low': 'LOW'
        }
        return priority_map.get(risk_level.lower(), 'MEDIUM')
    
    def _map_controls(self, masvs_refs: List[str]) -> List[str]:
        """Map MASVS references to control descriptions."""
        control_mappings = {
            'MSTG-RESILIENCE-1': 'Anti-tampering and runtime application self-protection',
            'MSTG-RESILIENCE-2': 'Runtime application self-protection mechanisms',
            'MSTG-RESILIENCE-3': 'Device binding and hardware-backed attestation',
            'MSTG-PLATFORM-11': 'WebView configuration and security'
        }
        
        return [control_mappings.get(ref, ref) for ref in masvs_refs]
    
    def _get_risk_description(self, risk_level: str) -> str:
        """Get detailed risk description."""
        descriptions = {
            'critical': 'Critical security risk - immediate action required',
            'high': 'High security risk - prompt remediation needed',
            'medium': 'Moderate security risk - address in near term',
            'low': 'Low security risk - monitor and improve',
            'minimal': 'Minimal security risk - maintain current state'
        }
        return descriptions.get(risk_level.lower(), 'Risk level assessment required')
    
    def format_for_report(self, result: RootDetectionAnalysisResult) -> Dict[str, Any]:
        """Format for comprehensive security report."""
        formatted = self.format_analysis_result(result)
        
        # Add report-specific sections
        formatted['executive_summary'] = self._create_executive_summary(result)
        formatted['technical_details'] = self._create_technical_details(result)
        formatted['compliance_assessment'] = self._create_compliance_assessment(result)
        formatted['action_plan'] = self._create_action_plan(result)
        
        return formatted
    
    def _create_executive_summary(self, result: RootDetectionAnalysisResult) -> Dict[str, Any]:
        """Create executive summary for reports."""
        total_findings = len(result.detection_findings)
        critical_findings = len([f for f in result.detection_findings if f.severity == 'critical'])
        high_findings = len([f for f in result.detection_findings if f.severity == 'high'])
        
        return {
            'key_findings': [
                f"Identified {total_findings} root detection mechanisms",
                f"Found {critical_findings} critical security issues",
                f"Detected {high_findings} high-severity vulnerabilities",
                f"Overall security score: {result.overall_security_score:.1f}/10"
            ],
            'risk_summary': {
                'overall_risk': result.risk_assessment,
                'primary_concerns': self._get_primary_concerns(result),
                'immediate_actions_required': critical_findings > 0 or high_findings > 3
            },
            'security_posture': {
                'detection_coverage': self._assess_detection_coverage(result),
                'bypass_resistance': self._assess_bypass_resistance(result),
                'control_effectiveness': self._assess_control_effectiveness(result)
            }
        }
    
    def _create_technical_details(self, result: RootDetectionAnalysisResult) -> Dict[str, Any]:
        """Create technical details section."""
        return {
            'methodology': 'Enhanced static and dynamic root detection analysis',
            'analysis_scope': 'Root detection mechanisms, bypass techniques, and security controls',
            'detection_techniques': [
                'Native binary analysis',
                'File system permission analysis',
                'Process execution analysis',
                'System property analysis',
                'Package manager analysis',
                'Runtime detection analysis',
                'Device attestation analysis'
            ],
            'confidence_scoring': 'Evidence-based dynamic confidence calculation',
            'bypass_analysis': 'Comprehensive bypass technique and resistance assessment'
        }
    
    def _create_compliance_assessment(self, result: RootDetectionAnalysisResult) -> Dict[str, Any]:
        """Create compliance assessment section."""
        return {
            'masvs_compliance': {
                'controls_evaluated': result.masvs_compliance,
                'compliance_status': self._assess_masvs_compliance(result)
            },
            'security_standards': {
                'owasp_masvs': 'Mobile Application Security Verification Standard compliance',
                'resilience_controls': 'MSTG-RESILIENCE control assessment'
            }
        }
    
    def _create_action_plan(self, result: RootDetectionAnalysisResult) -> Dict[str, Any]:
        """Create action plan section."""
        immediate_actions = []
        short_term_actions = []
        long_term_actions = []
        
        # Categorize recommendations
        for finding in result.detection_findings:
            if finding.severity in ['critical', 'high']:
                immediate_actions.append(finding.remediation)
            elif finding.severity == 'medium':
                short_term_actions.append(finding.remediation)
            else:
                long_term_actions.append(finding.remediation)
        
        return {
            'immediate_actions': list(set(immediate_actions))[:5],
            'short_term_actions': list(set(short_term_actions))[:5],
            'long_term_actions': list(set(long_term_actions))[:5],
            'timeline': {
                'immediate': '1-2 weeks',
                'short_term': '1-3 months',
                'long_term': '3-6 months'
            }
        }
    
    def _get_primary_concerns(self, result: RootDetectionAnalysisResult) -> List[str]:
        """Get primary security concerns."""
        concerns = []
        
        # Check for critical findings
        critical_findings = [f for f in result.detection_findings if f.severity == 'critical']
        if critical_findings:
            concerns.append(f"{len(critical_findings)} critical root detection vulnerabilities")
        
        # Check for weak security controls
        weak_controls = [a for a in result.security_assessments 
                        if a.implementation_strength in ['weak', 'minimal']]
        if weak_controls:
            concerns.append(f"{len(weak_controls)} security controls with weak implementation")
        
        # Check for low bypass resistance
        low_resistance = [f for f in result.detection_findings 
                         if f.bypass_resistance_score < 0.5]
        if low_resistance:
            concerns.append(f"{len(low_resistance)} detection mechanisms with low bypass resistance")
        
        return concerns[:5]  # Top 5 concerns
    
    def _assess_detection_coverage(self, result: RootDetectionAnalysisResult) -> str:
        """Assess detection coverage level."""
        detection_types = set(f.detection_type for f in result.detection_findings)
        coverage_score = len(detection_types) / 7  # 7 detection types available
        
        if coverage_score >= 0.8:
            return "Comprehensive"
        elif coverage_score >= 0.6:
            return "Good"
        elif coverage_score >= 0.4:
            return "Moderate"
        else:
            return "Limited"
    
    def _assess_bypass_resistance(self, result: RootDetectionAnalysisResult) -> str:
        """Assess overall bypass resistance."""
        if not result.detection_findings:
            return "Unknown"
        
        avg_resistance = sum(f.bypass_resistance_score for f in result.detection_findings) / len(result.detection_findings)
        
        if avg_resistance >= 0.8:
            return "Strong"
        elif avg_resistance >= 0.6:
            return "Good"
        elif avg_resistance >= 0.4:
            return "Moderate"
        else:
            return "Weak"
    
    def _assess_control_effectiveness(self, result: RootDetectionAnalysisResult) -> str:
        """Assess security control effectiveness."""
        if not result.security_assessments:
            return "Unknown"
        
        avg_effectiveness = sum(a.effectiveness_score for a in result.security_assessments) / len(result.security_assessments)
        
        if avg_effectiveness >= 0.8:
            return "High"
        elif avg_effectiveness >= 0.6:
            return "Good"
        elif avg_effectiveness >= 0.4:
            return "Moderate"
        else:
            return "Low"
    
    def _assess_masvs_compliance(self, result: RootDetectionAnalysisResult) -> str:
        """Assess MASVS compliance status."""
        critical_issues = len([f for f in result.detection_findings if f.severity == 'critical'])
        high_issues = len([f for f in result.detection_findings if f.severity == 'high'])
        
        if critical_issues > 0:
            return 'NON_COMPLIANT'
        elif high_issues > 3:
            return 'PARTIALLY_COMPLIANT'
        else:
            return 'COMPLIANT'
    
    def create_rich_report(self, result: RootDetectionAnalysisResult) -> Text:
        """Create rich formatted report using Rich library."""
        report = Text()
        report.append("Enhanced Root Detection Bypass Analysis Report\n", style="bold blue")
        report.append("=" * 50 + "\n", style="blue")
        
        # Summary section
        report.append("\nSUMMARY\n", style="bold green")
        report.append(f"Total Findings: {len(result.detection_findings)}\n")
        report.append(f"Security Score: {result.overall_security_score:.1f}/10\n")
        report.append(f"Risk Level: {result.risk_assessment}\n")
        
        # Findings section
        if result.detection_findings:
            report.append("\nDETECTION FINDINGS\n", style="bold yellow")
            for finding in result.detection_findings[:5]:  # Show top 5
                severity_style = self._get_severity_style(finding.severity)
                report.append(f"• {finding.description} ", style=severity_style)
                report.append(f"(Confidence: {finding.confidence:.2f})\n")
        
        # Recommendations section
        if result.recommendations:
            report.append("\nRECOMMENDATIONS\n", style="bold magenta")
            for i, recommendation in enumerate(result.recommendations[:3], 1):
                report.append(f"{i}. {recommendation}\n")
        
        return report
    
    def _get_severity_style(self, severity: str) -> str:
        """Get Rich style for severity level."""
        style_map = {
            'critical': 'bold red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'green'
        }
        return style_map.get(severity.lower(), 'white')
    
    def format_analysis_results(self, result: RootDetectionAnalysisResult) -> Text:
        """
        Format complete analysis results for output.
        
        This method creates a comprehensive formatted report of the root detection
        analysis results using Rich Text formatting.
        
        Args:
            result: RootDetectionAnalysisResult object containing analysis data
            
        Returns:
            Text: Rich Text object with formatted analysis results
        """
        try:
            # Use the existing create_rich_report method if available
            if hasattr(self, 'create_rich_report'):
                return self.create_rich_report(result)
            
            # Fallback to basic formatting
            output = Text()
            output.append("🔍 Enhanced Root Detection Bypass Analysis Report\n", style="bold blue")
            output.append("=" * 60 + "\n\n", style="blue")
            
            # Summary
            output.append("📊 Analysis Summary\n", style="bold green")
            output.append(f"Detection Findings: {len(result.detection_findings)}\n")
            output.append(f"Security Assessments: {len(result.security_assessments)}\n")
            output.append(f"Overall Security Score: {result.overall_security_score:.2f}\n")
            output.append(f"Risk Level: {result.risk_assessment}\n\n")
            
            # Detection Findings
            if result.detection_findings:
                output.append("🔎 Detection Findings\n", style="bold yellow")
                for i, finding in enumerate(result.detection_findings[:5], 1):  # Limit to first 5
                    output.append(f"{i}. {finding.description}\n")
                    output.append(f"   Location: {finding.location}\n")
                    output.append(f"   Confidence: {finding.confidence:.2f}\n\n")
                
                if len(result.detection_findings) > 5:
                    output.append(f"... and {len(result.detection_findings) - 5} more findings\n\n")
            
            # Recommendations
            if result.recommendations:
                output.append("💡 Security Recommendations\n", style="bold green")
                for i, rec in enumerate(result.recommendations[:3], 1):  # Limit to first 3
                    output.append(f"{i}. {rec}\n")
                output.append("\n")
            
            # MASVS Compliance
            output.append("📋 MASVS Compliance\n", style="bold cyan")
            for category, status in result.masvs_compliance.items():
                output.append(f"{category}: {status}\n")
            
            return output
            
        except Exception as e:
            # Return basic error info if formatting fails
            error_text = Text()
            error_text.append("❌ Error formatting analysis results\n", style="bold red")
            error_text.append(f"Error: {str(e)}\n")
            return error_text
    
    def format_error_report(self, error_message: str) -> Text:
        """
        Format error report for failed analysis.
        
        Args:
            error_message: Error message string to format
            
        Returns:
            Text: Rich Text object with formatted error report
        """
        try:
            output = Text()
            output.append("❌ Enhanced Root Detection Analysis Failed\n", style="bold red")
            output.append("=" * 50 + "\n\n", style="red")
            
            output.append("📋 Error Details\n", style="bold yellow")
            output.append(f"Error Message: {error_message}\n\n")
            
            output.append("🔧 Troubleshooting Suggestions\n", style="bold blue")
            output.append("• Check APK file integrity and permissions\n")
            output.append("• Verify decompilation output is available\n")
            output.append("• Check for sufficient disk space and memory\n")
            output.append("• Review plugin configuration and dependencies\n\n")
            
            output.append("📞 Support Information\n", style="bold green")
            output.append("If the error persists, please check the logs for detailed error information.\n")
            
            return output
            
        except Exception as e:
            # Fallback to plain text if Rich formatting fails
            fallback_text = Text()
            fallback_text.append(f"Analysis failed: {error_message}\nFormatting error: {str(e)}\n")
            return fallback_text


def format_finding_summary(finding: RootDetectionFinding) -> str:
    """Create a brief summary of a root detection finding."""
    return (f"{finding.detection_type.upper()}: {finding.description} "
            f"(Severity: {finding.severity}, "
            f"Confidence: {finding.confidence:.2f}, "
            f"Bypass Resistance: {finding.bypass_resistance_score:.2f})")

def format_assessment_summary(assessment: SecurityControlAssessment) -> str:
    """Create a brief summary of a security control assessment."""
    return (f"{assessment.control_type.upper()}: {assessment.implementation_strength} implementation "
            f"(Effectiveness: {assessment.effectiveness_score:.2f}, "
            f"Risk: {assessment.risk_level})")

def format_execution_stats(stats: ExecutionStatistics) -> Dict[str, Any]:
    """Format execution statistics for reporting."""
    return {
        'performance_metrics': {
            'total_analysis_time': round(stats.total_analysis_time, 2),
            'parallel_execution_time': round(stats.parallel_execution_time, 2),
            'sequential_execution_time': round(stats.sequential_execution_time, 2)
        },
        'cache_metrics': {
            'cache_hits': stats.cache_hits,
            'cache_misses': stats.cache_misses,
            'cache_hit_rate': round(stats.cache_hits / max(stats.cache_hits + stats.cache_misses, 1) * 100, 1)
        },
        'analysis_metrics': {
            'successful_analyses': stats.successful_analyses,
            'failed_analyses': stats.failed_analyses,
            'success_rate': round(stats.successful_analyses / max(stats.successful_analyses + stats.failed_analyses, 1) * 100, 1)
        }
    }

def format_error_report(error_message: str) -> Text:
    """
    Format error report for failed analysis.
    
    Args:
        error_message: Error message string to format
        
    Returns:
        Text: Rich Text object with formatted error report
    """
    try:
            output = Text()
            output.append("❌ Enhanced Root Detection Analysis Failed\n", style="bold red")
            output.append("=" * 50 + "\n\n", style="red")
            
            output.append("📋 Error Details\n", style="bold yellow")
            output.append(f"Error Message: {error_message}\n\n")
            
            output.append("🔧 Troubleshooting Suggestions\n", style="bold blue")
            output.append("• Check APK file integrity and permissions\n")
            output.append("• Verify decompilation output is available\n")
            output.append("• Check for sufficient disk space and memory\n")
            output.append("• Review plugin configuration and dependencies\n\n")
            
            output.append("📞 Support Information\n", style="bold green")
            output.append("If the error persists, please check the logs for detailed error information.\n")
            
            return output
            
    except Exception as e:
        # Fallback to plain text if Rich formatting fails
        fallback_text = Text()
        fallback_text.append(f"Analysis failed: {error_message}\nFormatting error: {str(e)}\n")
        return fallback_text
#!/usr/bin/env python3
"""
SSL/TLS Analysis Formatters Module

This module provides comprehensive output formatting and reporting capabilities
for SSL/TLS security analysis results, including detailed technical reporting,
Rich text formatting, and structured output generation.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime

from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich.progress import Progress

from .data_structures import (
    SSLTLSAnalysisResult, CertificateAnalysis, TLSConfigurationAnalysis,
    NetworkSecurityConfigAnalysis, DynamicSSLTestingAnalysis,
    SSLTLSVulnerability, SSLTLSSeverity, PinningStrength, ValidationStatus
)

class SSLTLSAnalysisFormatter:
    """
    Professional SSL/TLS analysis results formatter.
    
    Provides comprehensive formatting capabilities for SSL/TLS security
    analysis results including executive summaries, detailed reports,
    and structured output generation.
    """
    
    def __init__(self):
        """Initialize SSL/TLS analysis formatter."""
        self.console = Console()
        self.logger = logging.getLogger(__name__)
        
        # Style mappings for different elements
        self.severity_styles = {
            SSLTLSSeverity.CRITICAL: "bold red",
            SSLTLSSeverity.HIGH: "red",
            SSLTLSSeverity.MEDIUM: "yellow",
            SSLTLSSeverity.LOW: "blue",
            SSLTLSSeverity.INFO: "dim"
        }
        
        self.status_styles = {
            ValidationStatus.ENABLED: "green",
            ValidationStatus.DISABLED: "red",
            ValidationStatus.BYPASSED: "red",
            ValidationStatus.UNKNOWN: "yellow"
        }
        
        self.pinning_styles = {
            PinningStrength.VERY_HIGH: "bold green",
            PinningStrength.HIGH: "green",
            PinningStrength.MEDIUM: "yellow",
            PinningStrength.WEAK: "red",
            PinningStrength.NONE: "dim red"
        }
    
    def generate_comprehensive_report(self, analysis_result: SSLTLSAnalysisResult) -> Tuple[str, Text]:
        """
        Generate comprehensive SSL/TLS security analysis report.
        
        Args:
            analysis_result: Complete SSL/TLS analysis results
            
        Returns:
            Tuple of (title, formatted_report_text)
        """
        title = "Advanced SSL/TLS Security Analysis"
        
        report = Text()
        report.append(f"🔒 {title}\n", style="bold blue")
        report.append("=" * 80 + "\n\n", style="blue")
        
        # Executive Summary
        self._add_executive_summary(report, analysis_result)
        
        # Analysis Overview
        self._add_analysis_overview(report, analysis_result)
        
        # Certificate Analysis Results
        self._add_certificate_analysis_section(report, analysis_result.certificate_analysis)
        
        # TLS Configuration Analysis Results
        self._add_tls_configuration_section(report, analysis_result.tls_configuration_analysis)
        
        # Network Security Configuration Results
        self._add_network_security_config_section(report, analysis_result.network_security_config_analysis)
        
        # Dynamic Testing Results
        self._add_dynamic_testing_section(report, analysis_result.dynamic_ssl_testing_analysis)
        
        # Vulnerability Details
        self._add_vulnerabilities_section(report, analysis_result.ssl_vulnerabilities)
        
        # Security Recommendations
        self._add_recommendations_section(report, analysis_result.recommendations)
        
        # Gap Resolution Summary
        self._add_gap_resolution_section(report, analysis_result.gap_resolution_results)
        
        # Analysis Statistics
        self._add_statistics_section(report, analysis_result.analysis_stats)
        
        return title, report
    
    def _add_executive_summary(self, report: Text, analysis: SSLTLSAnalysisResult) -> None:
        """Add executive summary section."""
        report.append("📊 EXECUTIVE SUMMARY\n", style="bold")
        report.append("-" * 40 + "\n\n")
        
        # Overall security score
        score_color = self._get_score_color(analysis.security_score)
        report.append(f"Overall Security Score: ", style="bold")
        report.append(f"{analysis.security_score}/100\n", style=score_color)
        
        # Risk assessment
        risk_level = self._calculate_risk_level(analysis)
        risk_color = self._get_risk_color(risk_level)
        report.append(f"Risk Level: ", style="bold")
        report.append(f"{risk_level}\n", style=risk_color)
        
        # Key findings summary
        critical_count = analysis.critical_issues_count
        high_count = analysis.high_issues_count
        
        report.append(f"Critical Issues: ", style="bold")
        report.append(f"{critical_count}\n", style="red" if critical_count > 0 else "green")
        
        report.append(f"High Severity Issues: ", style="bold")
        report.append(f"{high_count}\n", style="red" if high_count > 0 else "green")
        
        # Certificate pinning status
        pinning_detected = analysis.certificate_analysis.pinning_detected
        pinning_strength = analysis.certificate_analysis.pinning_strength
        
        report.append(f"Certificate Pinning: ", style="bold")
        if pinning_detected:
            report.append(f"Detected ({pinning_strength.value})\n", 
                         style=self.pinning_styles.get(pinning_strength, "yellow"))
        else:
            report.append("Not Detected\n", style="red")
        
        report.append("\n")
    
    def _add_analysis_overview(self, report: Text, analysis: SSLTLSAnalysisResult) -> None:
        """Add analysis overview section."""
        report.append("🔍 ANALYSIS OVERVIEW\n", style="bold")
        report.append("-" * 40 + "\n\n")
        
        # Analysis metadata
        report.append(f"Analysis Duration: {analysis.analysis_duration:.2f} seconds\n")
        report.append(f"Files Analyzed: {analysis.analyzed_files_count}\n")
        report.append(f"Classes Analyzed: {analysis.classes_analyzed}\n")
        report.append(f"Methods Analyzed: {analysis.methods_analyzed}\n")
        report.append(f"Security Patterns Matched: {analysis.patterns_matched}\n")
        
        # Analysis timestamp
        timestamp = analysis.analysis_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        report.append(f"Analysis Timestamp: {timestamp}\n")
        
        report.append("\n")
    
    def _add_certificate_analysis_section(self, report: Text, cert_analysis: CertificateAnalysis) -> None:
        """Add certificate analysis section."""
        report.append("📜 CERTIFICATE ANALYSIS\n", style="bold")
        report.append("-" * 40 + "\n\n")
        
        # Certificate validation status
        validation_status = cert_analysis.certificate_validation
        report.append(f"Certificate Validation: ", style="bold")
        report.append(f"{validation_status.value}\n", 
                     style=self.status_styles.get(validation_status, "yellow"))
        
        # Hostname verification status
        hostname_status = cert_analysis.hostname_verification
        report.append(f"Hostname Verification: ", style="bold")
        report.append(f"{hostname_status.value}\n",
                     style=self.status_styles.get(hostname_status, "yellow"))
        
        # Trust-all certificates detection
        trust_all = cert_analysis.trust_all_certificates
        report.append(f"Trust-All Certificates: ", style="bold")
        report.append(f"{'Detected' if trust_all else 'Not Detected'}\n",
                     style="red" if trust_all else "green")
        
        # Certificate pinning details
        if cert_analysis.pinning_detected:
            report.append(f"\nCertificate Pinning Details:\n", style="bold")
            for impl in cert_analysis.pinning_implementations:
                report.append(f"  • {impl.implementation_type} ({impl.strength.value})\n")
                report.append(f"    Location: {impl.location}\n", style="dim")
                report.append(f"    Detection Method: {impl.detection_method}\n", style="dim")
        
        # Trust manager issues
        if cert_analysis.insecure_trust_managers:
            report.append(f"\nInsecure Trust Managers:\n", style="bold red")
            for manager in cert_analysis.insecure_trust_managers:
                report.append(f"  • {manager}\n", style="red")
        
        report.append("\n")
    
    def _add_tls_configuration_section(self, report: Text, tls_analysis: TLSConfigurationAnalysis) -> None:
        """Add TLS configuration section."""
        report.append("🔐 TLS CONFIGURATION ANALYSIS\n", style="bold")
        report.append("-" * 40 + "\n\n")
        
        # Security scores
        report.append(f"Protocol Security Score: {tls_analysis.protocol_security_score}/100\n")
        report.append(f"Cipher Security Score: {tls_analysis.cipher_security_score}/100\n")
        report.append(f"Overall TLS Score: {tls_analysis.overall_tls_score}/100\n\n")
        
        # Protocol configurations
        if tls_analysis.protocol_configurations:
            report.append("Detected Protocols:\n", style="bold")
            for config in tls_analysis.protocol_configurations:
                for protocol in config.enabled_protocols:
                    color = "green" if protocol in ["TLSv1.2", "TLSv1.3"] else "red"
                    report.append(f"  • {protocol}\n", style=color)
        
        # Cipher configurations
        if tls_analysis.cipher_configurations:
            report.append("\nDetected Cipher Suites:\n", style="bold")
            for cipher in tls_analysis.cipher_configurations[:10]:  # Limit to first 10
                report.append(f"  • {cipher}\n")
            if len(tls_analysis.cipher_configurations) > 10:
                remaining = len(tls_analysis.cipher_configurations) - 10
                report.append(f"  ... and {remaining} more\n", style="dim")
        
        # Weak configurations
        if tls_analysis.weak_configurations:
            report.append("\nWeak Configurations:\n", style="bold red")
            for weak_config in tls_analysis.weak_configurations[:5]:  # Limit to first 5
                report.append(f"  • {weak_config.get('description', 'Unknown')}\n", style="red")
                report.append(f"    Location: {weak_config.get('location', 'Unknown')}\n", style="dim")
        
        report.append("\n")
    
    def _add_network_security_config_section(self, report: Text, nsc_analysis: NetworkSecurityConfigAnalysis) -> None:
        """Add Network Security Configuration section."""
        report.append("🌐 NETWORK SECURITY CONFIGURATION\n", style="bold")
        report.append("-" * 40 + "\n\n")
        
        # NSC file detection
        nsc_found = nsc_analysis.nsc_file_found
        report.append(f"NSC File Found: ", style="bold")
        report.append(f"{'Yes' if nsc_found else 'No'}\n", 
                     style="green" if nsc_found else "yellow")
        
        if nsc_found and nsc_analysis.file_path:
            report.append(f"File Path: {nsc_analysis.file_path}\n", style="dim")
        
        # Compliance status
        compliance = nsc_analysis.compliance_status
        report.append(f"Compliance Status: ", style="bold")
        report.append(f"{compliance.value}\n",
                     style="green" if compliance.value == "COMPLIANT" else "red")
        
        # Security score
        report.append(f"Security Score: {nsc_analysis.security_score}/100\n")
        
        # Domain configurations
        if nsc_analysis.domain_configs:
            report.append(f"\nDomain Configurations: {len(nsc_analysis.domain_configs)}\n", style="bold")
        
        # Trust anchors
        if nsc_analysis.trust_anchors:
            report.append(f"Trust Anchors: {len(nsc_analysis.trust_anchors)}\n", style="bold")
        
        # Compliance issues
        if nsc_analysis.compliance_issues:
            report.append(f"\nCompliance Issues:\n", style="bold red")
            for issue in nsc_analysis.compliance_issues[:3]:  # Limit to first 3
                report.append(f"  • {issue.get('description', 'Unknown issue')}\n", style="red")
        
        report.append("\n")
    
    def _add_dynamic_testing_section(self, report: Text, dynamic_analysis: DynamicSSLTestingAnalysis) -> None:
        """Add dynamic testing section."""
        report.append("🧪 DYNAMIC SSL/TLS TESTING\n", style="bold")
        report.append("-" * 40 + "\n\n")
        
        # Frida availability
        frida_available = dynamic_analysis.frida_available
        report.append(f"Frida Available: ", style="bold")
        report.append(f"{'Yes' if frida_available else 'No'}\n",
                     style="green" if frida_available else "yellow")
        
        if not frida_available:
            report.append("Dynamic testing requires Frida for runtime analysis\n", style="dim")
            report.append("\n")
            return
        
        # Overall bypass detection
        bypass_detected = dynamic_analysis.overall_bypass_detected
        report.append(f"SSL/TLS Bypass Detected: ", style="bold")
        report.append(f"{'Yes' if bypass_detected else 'No'}\n",
                     style="red" if bypass_detected else "green")
        
        # Test results summary
        total_tests = (len(dynamic_analysis.ssl_bypass_tests) + 
                      len(dynamic_analysis.runtime_analysis_tests) +
                      len(dynamic_analysis.pinning_bypass_tests) +
                      len(dynamic_analysis.kill_switch_tests))
        
        if total_tests > 0:
            report.append(f"\nDynamic Tests Executed: {total_tests}\n", style="bold")
            
            # Test categories
            if dynamic_analysis.ssl_bypass_tests:
                successful_bypasses = sum(1 for test in dynamic_analysis.ssl_bypass_tests if test.bypass_detected)
                report.append(f"  • SSL Bypass Tests: {len(dynamic_analysis.ssl_bypass_tests)}\n")
                if successful_bypasses > 0:
                    report.append(f"    - Bypasses Detected: {successful_bypasses}\n", style="red")
            
            if dynamic_analysis.pinning_bypass_tests:
                successful_pinning_bypasses = sum(1 for test in dynamic_analysis.pinning_bypass_tests if test.bypass_detected)
                report.append(f"  • Pinning Bypass Tests: {len(dynamic_analysis.pinning_bypass_tests)}\n")
                if successful_pinning_bypasses > 0:
                    report.append(f"    - Bypasses Detected: {successful_pinning_bypasses}\n", style="red")
        
        report.append("\n")
    
    def _add_vulnerabilities_section(self, report: Text, vulnerabilities: List[SSLTLSVulnerability]) -> None:
        """Add detailed vulnerabilities section."""
        if not vulnerabilities:
            return
        
        report.append("🚨 VULNERABILITY DETAILS\n", style="bold")
        report.append("-" * 40 + "\n\n")
        
        # Group vulnerabilities by severity
        critical_vulns = [v for v in vulnerabilities if v.severity == SSLTLSSeverity.CRITICAL]
        high_vulns = [v for v in vulnerabilities if v.severity == SSLTLSSeverity.HIGH]
        medium_vulns = [v for v in vulnerabilities if v.severity == SSLTLSSeverity.MEDIUM]
        low_vulns = [v for v in vulnerabilities if v.severity == SSLTLSSeverity.LOW]
        
        # Display critical vulnerabilities first
        if critical_vulns:
            report.append("CRITICAL SEVERITY:\n", style="bold red")
            for vuln in critical_vulns[:5]:  # Limit to first 5
                self._add_vulnerability_detail(report, vuln)
            if len(critical_vulns) > 5:
                report.append(f"... and {len(critical_vulns) - 5} more critical vulnerabilities\n\n", style="dim")
        
        # Display high severity vulnerabilities
        if high_vulns:
            report.append("HIGH SEVERITY:\n", style="bold red")
            for vuln in high_vulns[:3]:  # Limit to first 3
                self._add_vulnerability_detail(report, vuln)
            if len(high_vulns) > 3:
                report.append(f"... and {len(high_vulns) - 3} more high severity vulnerabilities\n\n", style="dim")
        
        # Display summary for medium and low
        if medium_vulns:
            report.append(f"MEDIUM SEVERITY: {len(medium_vulns)} issues found\n", style="yellow")
        if low_vulns:
            report.append(f"LOW SEVERITY: {len(low_vulns)} issues found\n", style="blue")
        
        report.append("\n")
    
    def _add_vulnerability_detail(self, report: Text, vuln: SSLTLSVulnerability) -> None:
        """Add detailed vulnerability information."""
        severity_style = self.severity_styles.get(vuln.severity, "white")
        
        report.append(f"• {vuln.title}\n", style="bold")
        report.append(f"  Severity: {vuln.severity.value} ", style=severity_style)
        report.append(f"| Confidence: {vuln.confidence:.2f}\n")
        report.append(f"  Location: {vuln.location}\n", style="dim")
        report.append(f"  Description: {vuln.description}\n")
        
        if vuln.cwe_id:
            report.append(f"  CWE: {vuln.cwe_id}\n", style="dim")
        
        if vuln.evidence and len(vuln.evidence) < 200:
            report.append(f"  Evidence: {vuln.evidence[:100]}...\n", style="dim")
        
        report.append("\n")
    
    def _add_recommendations_section(self, report: Text, recommendations: List[str]) -> None:
        """Add security recommendations section."""
        if not recommendations:
            return
        
        report.append("💡 SECURITY RECOMMENDATIONS\n", style="bold")
        report.append("-" * 40 + "\n\n")
        
        for i, recommendation in enumerate(recommendations[:10], 1):  # Limit to first 10
            report.append(f"{i}. {recommendation}\n")
        
        if len(recommendations) > 10:
            remaining = len(recommendations) - 10
            report.append(f"\n... and {remaining} more recommendations available in detailed report\n", style="dim")
        
        report.append("\n")
    
    def _add_gap_resolution_section(self, report: Text, gap_results: Dict[str, Any]) -> None:
        """Add gap resolution section."""
        if not gap_results:
            return
        
        report.append("🔧 GAP RESOLUTION ANALYSIS\n", style="bold")
        report.append("-" * 40 + "\n\n")
        
        resolved_gaps = gap_results.get('resolved_gaps', [])
        remaining_gaps = gap_results.get('remaining_gaps', [])
        
        if resolved_gaps:
            report.append(f"Resolved Security Gaps: {len(resolved_gaps)}\n", style="green")
        
        if remaining_gaps:
            report.append(f"Remaining Security Gaps: {len(remaining_gaps)}\n", style="red")
            report.append("Key Remaining Gaps:\n", style="bold")
            for gap in remaining_gaps[:3]:  # Show first 3
                report.append(f"  • {gap.get('description', 'Unknown gap')}\n", style="red")
        
        gap_score = gap_results.get('gap_resolution_score', 0)
        score_color = self._get_score_color(gap_score)
        report.append(f"Gap Resolution Score: {gap_score}/100\n", style=score_color)
        
        report.append("\n")
    
    def _add_statistics_section(self, report: Text, stats: Dict[str, Any]) -> None:
        """Add analysis statistics section."""
        if not stats:
            return
        
        report.append("📈 ANALYSIS STATISTICS\n", style="bold")
        report.append("-" * 40 + "\n\n")
        
        # Display key statistics
        key_stats = [
            ('Classes Analyzed', 'classes_analyzed'),
            ('Certificates Analyzed', 'certificates_analyzed'),
            ('Vulnerabilities Found', 'vulnerabilities_found'),
            ('Pinning Implementations Found', 'pinning_implementations_found'),
            ('Security Issues Found', 'security_issues_found')
        ]
        
        for label, key in key_stats:
            value = stats.get(key, 0)
            report.append(f"{label}: {value}\n")
        
        report.append("\n")
    
    # Utility methods
    def _get_score_color(self, score: int) -> str:
        """Get color style for security score."""
        if score >= 80:
            return "green"
        elif score >= 60:
            return "yellow"
        elif score >= 40:
            return "orange"
        else:
            return "red"
    
    def _calculate_risk_level(self, analysis: SSLTLSAnalysisResult) -> str:
        """Calculate overall risk level."""
        if analysis.critical_issues_count > 0:
            return "CRITICAL"
        elif analysis.high_issues_count > 2:
            return "HIGH"
        elif analysis.medium_issues_count > 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color style for risk level."""
        risk_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green"
        }
        return risk_colors.get(risk_level, "white")
    
    def generate_summary_table(self, analysis_result: SSLTLSAnalysisResult) -> Table:
        """Generate summary table for SSL/TLS analysis."""
        table = Table(title="SSL/TLS Security Analysis Summary")
        
        table.add_column("Security Area", style="bold")
        table.add_column("Status", justify="center")
        table.add_column("Score", justify="center")
        table.add_column("Issues", justify="center")
        
        # Certificate validation
        cert_status = "✅ Enabled" if analysis_result.certificate_analysis.certificate_validation == ValidationStatus.ENABLED else "❌ Issues"
        table.add_row(
            "Certificate Validation",
            cert_status,
            "N/A",
            str(len([v for v in analysis_result.ssl_vulnerabilities if 'certificate' in v.title.lower()]))
        )
        
        # TLS Configuration
        tls_score = analysis_result.tls_configuration_analysis.overall_tls_score
        tls_status = "✅ Good" if tls_score >= 70 else "❌ Issues"
        table.add_row(
            "TLS Configuration",
            tls_status,
            f"{tls_score}/100",
            str(len([v for v in analysis_result.ssl_vulnerabilities if 'tls' in v.title.lower() or 'ssl' in v.title.lower()]))
        )
        
        # Certificate Pinning
        pinning_status = "✅ Detected" if analysis_result.certificate_analysis.pinning_detected else "❌ Not Found"
        table.add_row(
            "Certificate Pinning",
            pinning_status,
            analysis_result.certificate_analysis.pinning_strength.value,
            str(len([v for v in analysis_result.ssl_vulnerabilities if 'pinning' in v.title.lower()]))
        )
        
        # Network Security Config
        nsc_status = "✅ Found" if analysis_result.network_security_config_analysis.nsc_file_found else "❌ Not Found"
        nsc_score = analysis_result.network_security_config_analysis.security_score
        table.add_row(
            "Network Security Config",
            nsc_status,
            f"{nsc_score}/100",
            str(len(analysis_result.network_security_config_analysis.compliance_issues))
        )
        
        return table
    
    def format_executive_summary(self, analysis_result: SSLTLSAnalysisResult) -> str:
        """Format executive summary as plain text."""
        summary = []
        summary.append("SSL/TLS Security Analysis Executive Summary")
        summary.append("=" * 45)
        summary.append("")
        
        # Overall assessment
        risk_level = self._calculate_risk_level(analysis_result)
        summary.append(f"Overall Risk Level: {risk_level}")
        summary.append(f"Security Score: {analysis_result.security_score}/100")
        summary.append("")
        
        # Key findings
        summary.append("Key Findings:")
        summary.append(f"- Critical Issues: {analysis_result.critical_issues_count}")
        summary.append(f"- High Severity Issues: {analysis_result.high_issues_count}")
        summary.append(f"- Total Vulnerabilities: {analysis_result.vulnerability_count}")
        summary.append("")
        
        # Certificate pinning status
        pinning_detected = analysis_result.certificate_analysis.pinning_detected
        summary.append(f"Certificate Pinning: {'Detected' if pinning_detected else 'Not Detected'}")
        if pinning_detected:
            strength = analysis_result.certificate_analysis.pinning_strength.value
            summary.append(f"Pinning Strength: {strength}")
        summary.append("")
        
        # Recommendations count
        rec_count = len(analysis_result.recommendations)
        summary.append(f"Security Recommendations: {rec_count}")
        
        return "\n".join(summary)
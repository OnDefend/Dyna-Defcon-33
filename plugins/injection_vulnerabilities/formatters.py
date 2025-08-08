"""
Injection Vulnerabilities - Formatters Component

This module provides comprehensive formatting capabilities for injection vulnerability
analysis results including Rich text formatting and report generation.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple

from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.console import Console

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

from plugins.injection_vulnerabilities.data_structures import (
    InjectionVulnerabilityResult, InjectionVulnerability, DynamicAnalysisResult,
    StaticAnalysisResult, ContentProviderAnalysis, RiskAssessment,
    SeverityLevel, RiskLevel, AnalysisMethod, ProviderSecurityLevel
)

class InjectionVulnerabilityFormatter:
    """Advanced formatter for injection vulnerability analysis results."""
    
    def __init__(self):
        """Initialize the formatter."""
        self.logger = logging.getLogger(__name__)
        self.console = Console()
    
    def format_report(self, result: InjectionVulnerabilityResult) -> Tuple[str, Text]:
        """Format comprehensive injection vulnerability report."""
        report = Text()
        
        # Header
        report.append("🔍 SQL Injection Vulnerability Analysis Report\n", style="bold blue")
        report.append("=" * 80 + "\n\n", style="blue")
        
        # Executive Summary
        self._add_executive_summary(report, result)
        
        # Analysis Results
        self._add_analysis_results(report, result)
        
        # Vulnerability Details
        self._add_vulnerability_details(report, result.vulnerabilities)
        
        # Content Provider Analysis
        if result.static_analysis and result.static_analysis.manifest_analysis:
            self._add_provider_analysis(report, result.static_analysis.manifest_analysis)
        
        # Risk Assessment
        if result.risk_assessment:
            self._add_risk_assessment(report, result.risk_assessment)
        
        # Recommendations
        self._add_recommendations(report, result)
        
        return ("SQL Injection Vulnerabilities", report)
    
    def _add_executive_summary(self, report: Text, result: InjectionVulnerabilityResult) -> None:
        """Add executive summary section."""
        report.append("📊 Executive Summary\n", style="bold green")
        
        # Overall status
        if result.vulnerabilities:
            total_vulns = len(result.vulnerabilities)
            critical_vulns = sum(1 for v in result.vulnerabilities if v.severity == SeverityLevel.CRITICAL)
            high_vulns = sum(1 for v in result.vulnerabilities if v.severity == SeverityLevel.HIGH)
            
            if critical_vulns > 0:
                report.append(f"🚨 CRITICAL: {total_vulns} SQL injection vulnerabilities detected\n", 
                            style="bold red")
            elif high_vulns > 0:
                report.append(f"⚠️ HIGH RISK: {total_vulns} SQL injection vulnerabilities detected\n", 
                            style="bold yellow")
            else:
                report.append(f"⚠️ {total_vulns} SQL injection vulnerabilities detected\n", 
                            style="yellow")
        else:
            report.append("✅ No SQL injection vulnerabilities detected\n", style="green")
        
        # Analysis method
        analysis_method = result.analysis_summary.get('analysis_method', 'unknown')
        method_display = {
            'dynamic': 'Dynamic analysis (Drozer)',
            'static': 'Static analysis only',
            'hybrid': 'Hybrid analysis (Dynamic + Static)',
            'none': 'No analysis performed'
        }.get(analysis_method, analysis_method)
        
        report.append(f"Analysis Method: {method_display}\n")
        
        # Drozer availability
        if result.context.drozer_available:
            report.append("Drozer Status: Available ✅\n", style="green")
        else:
            report.append("Drozer Status: Not available ❌\n", style="yellow")
        
        # Risk assessment
        if result.risk_assessment:
            risk_level = result.risk_assessment.overall_risk.value
            risk_score = result.risk_assessment.risk_score
            risk_color = self._get_risk_color(result.risk_assessment.overall_risk)
            
            report.append(f"Overall Risk: {risk_level} ({risk_score:.2f}/1.0)\n", 
                         style=f"bold {risk_color}")
        
        report.append("\n")
    
    def _add_analysis_results(self, report: Text, result: InjectionVulnerabilityResult) -> None:
        """Add analysis results section."""
        report.append("🔬 Analysis Results\n", style="bold cyan")
        
        # Dynamic analysis results
        if result.dynamic_analysis:
            self._add_dynamic_results(report, result.dynamic_analysis)
        
        # Static analysis results
        if result.static_analysis:
            self._add_static_results(report, result.static_analysis)
        
        # Analysis summary
        if result.analysis_summary:
            timing = result.analysis_summary.get('dynamic_analysis', {}).get('execution_time', 0)
            if timing > 0:
                report.append(f"Analysis completed in {timing:.1f} seconds\n")
        
        report.append("\n")
    
    def _add_dynamic_results(self, report: Text, dynamic_result: DynamicAnalysisResult) -> None:
        """Add dynamic analysis results."""
        report.append("Dynamic Analysis (Drozer):\n", style="cyan")
        
        # Execution status
        if dynamic_result.success:
            report.append("  ✅ Drozer scan completed successfully\n", style="green")
        else:
            report.append("  ❌ Drozer scan encountered issues\n", style="red")
        
        # Execution time
        report.append(f"  ⏱️ Execution time: {dynamic_result.execution_time:.1f}s\n")
        
        # Vulnerabilities found
        if dynamic_result.vulnerabilities_found:
            report.append(f"  🔍 Vulnerabilities detected: {len(dynamic_result.vulnerabilities_found)}\n", 
                         style="red")
        else:
            report.append("  ✅ No vulnerabilities detected\n", style="green")
        
        # Command executed
        report.append(f"  📝 Command: {dynamic_result.command_executed}\n", style="dim")
        
        # Error message if any
        if dynamic_result.error_message:
            report.append(f"  ⚠️ Error: {dynamic_result.error_message}\n", style="yellow")
    
    def _add_static_results(self, report: Text, static_result: StaticAnalysisResult) -> None:
        """Add static analysis results."""
        report.append("Static Analysis:\n", style="cyan")
        
        # Manifest analysis
        if static_result.manifest_analysis:
            providers = static_result.manifest_analysis
            exported_count = sum(1 for p in providers if p.exported)
            vulnerable_count = sum(1 for p in providers if p.vulnerabilities)
            
            report.append(f"  📱 Content providers analyzed: {len(providers)}\n")
            report.append(f"  📤 Exported providers: {exported_count}\n")
            
            if vulnerable_count > 0:
                report.append(f"  ⚠️ Vulnerable providers: {vulnerable_count}\n", style="yellow")
            else:
                report.append("  ✅ No vulnerable providers detected\n", style="green")
        
        # Code analysis
        if static_result.code_patterns:
            patterns = static_result.code_patterns
            high_risk_patterns = sum(1 for p in patterns if p.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL])
            
            report.append(f"  💻 Code patterns analyzed: {len(patterns)}\n")
            report.append(f"  📁 Files analyzed: {static_result.total_files_analyzed}\n")
            
            if high_risk_patterns > 0:
                report.append(f"  ⚠️ High-risk patterns: {high_risk_patterns}\n", style="yellow")
            else:
                report.append("  ✅ No high-risk patterns detected\n", style="green")
        
        # Analysis time
        if static_result.analysis_time > 0:
            report.append(f"  ⏱️ Analysis time: {static_result.analysis_time:.1f}s\n")
    
    def _add_vulnerability_details(self, report: Text, vulnerabilities: List[InjectionVulnerability]) -> None:
        """Add detailed vulnerability information."""
        if not vulnerabilities:
            return
        
        report.append("🚨 Vulnerability Details\n", style="bold red")
        
        # Group vulnerabilities by severity
        vulns_by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            if severity not in vulns_by_severity:
                vulns_by_severity[severity] = []
            vulns_by_severity[severity].append(vuln)
        
        # Display vulnerabilities by severity (most critical first)
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity in vulns_by_severity:
                severity_vulns = vulns_by_severity[severity]
                color = self._get_severity_color(SeverityLevel(severity))
                icon = self._get_severity_icon(SeverityLevel(severity))
                
                report.append(f"\n{icon} {severity} Severity ({len(severity_vulns)} vulnerabilities)\n", 
                            style=f"bold {color}")
                
                # Show top vulnerabilities
                for i, vuln in enumerate(severity_vulns[:3], 1):
                    report.append(f"  {i}. {vuln.title}\n", style=color)
                    report.append(f"     Description: {vuln.description}\n", style="dim")
                    report.append(f"     Location: {vuln.location}\n", style="dim")
                    report.append(f"     Method: {vuln.method.value}\n", style="dim")
                    report.append(f"     Confidence: {vuln.confidence:.1%}\n", style="dim")
                    
                    if vuln.evidence:
                        evidence = self._truncate_text(vuln.evidence, 100)
                        report.append(f"     Evidence: {evidence}\n", style="dim cyan")
                    
                    if vuln.code_snippet:
                        snippet = self._truncate_text(vuln.code_snippet, 80)
                        report.append(f"     Code: {snippet}\n", style="dim cyan")
                    
                    if vuln.recommendations:
                        report.append(f"     💡 {vuln.recommendations[0]}\n", style="yellow")
                    
                    if vuln.cwe_ids:
                        report.append(f"     📋 CWE: {', '.join(vuln.cwe_ids)}\n", style="dim")
                    
                    report.append("\n")
                
                # Show count of remaining vulnerabilities
                if len(severity_vulns) > 3:
                    remaining = len(severity_vulns) - 3
                    report.append(f"     ... and {remaining} more {severity.lower()} vulnerabilities\n\n", 
                                style=f"dim {color}")
    
    def _add_provider_analysis(self, report: Text, providers: List[ContentProviderAnalysis]) -> None:
        """Add content provider analysis section."""
        if not providers:
            return
        
        report.append("📱 Content Provider Analysis\n", style="bold magenta")
        
        # Summary statistics
        exported_providers = [p for p in providers if p.exported]
        vulnerable_providers = [p for p in providers if p.vulnerabilities]
        
        report.append(f"Total providers: {len(providers)}\n")
        report.append(f"Exported providers: {len(exported_providers)}\n")
        
        if vulnerable_providers:
            report.append(f"Vulnerable providers: {len(vulnerable_providers)}\n", style="red")
        else:
            report.append("No vulnerable providers detected\n", style="green")
        
        # Provider details
        if exported_providers:
            report.append("\nExported Providers:\n", style="magenta")
            
            for i, provider in enumerate(exported_providers[:5], 1):
                security_color = self._get_provider_security_color(provider.security_level)
                security_icon = self._get_provider_security_icon(provider.security_level)
                
                report.append(f"  {i}. {provider.authority}\n", style="magenta")
                report.append(f"     Security Level: {security_icon} {provider.security_level.value}\n", 
                            style=security_color)
                
                if provider.permissions:
                    report.append(f"     Permissions: {', '.join(provider.permissions)}\n", style="dim")
                else:
                    report.append("     Permissions: None ⚠️\n", style="yellow")
                
                if provider.vulnerabilities:
                    report.append(f"     Vulnerabilities: {len(provider.vulnerabilities)}\n", style="red")
                
                report.append("\n")
            
            if len(exported_providers) > 5:
                remaining = len(exported_providers) - 5
                report.append(f"     ... and {remaining} more exported providers\n\n", 
                            style="dim magenta")
    
    def _add_risk_assessment(self, report: Text, risk: RiskAssessment) -> None:
        """Add risk assessment section."""
        report.append("⚠️ Risk Assessment\n", style="bold yellow")
        
        # Overall risk
        risk_color = self._get_risk_color(risk.overall_risk)
        report.append(f"Overall Risk Level: {risk.overall_risk.value}\n", style=f"bold {risk_color}")
        report.append(f"Risk Score: {risk.risk_score:.2f}/1.0\n", style=risk_color)
        
        # Vulnerability breakdown
        if risk.total_vulnerabilities > 0:
            report.append(f"Total Vulnerabilities: {risk.total_vulnerabilities}\n")
            
            if risk.critical_vulnerabilities > 0:
                report.append(f"  🚨 Critical: {risk.critical_vulnerabilities}\n", style="bright_red")
            if risk.high_vulnerabilities > 0:
                report.append(f"  ❌ High: {risk.high_vulnerabilities}\n", style="red")
            if risk.medium_vulnerabilities > 0:
                report.append(f"  ⚠️ Medium: {risk.medium_vulnerabilities}\n", style="yellow")
            if risk.low_vulnerabilities > 0:
                report.append(f"  ℹ️ Low: {risk.low_vulnerabilities}\n", style="blue")
        
        # Provider statistics
        if risk.exported_providers > 0:
            report.append(f"Exported Providers: {risk.exported_providers}\n")
            if risk.vulnerable_providers > 0:
                report.append(f"Vulnerable Providers: {risk.vulnerable_providers}\n", style="red")
        
        # Risk factors
        if risk.risk_factors:
            report.append("\nKey Risk Factors:\n", style="yellow")
            for factor in risk.risk_factors[:5]:
                report.append(f"  • {factor}\n", style="yellow")
        
        report.append("\n")
    
    def _add_recommendations(self, report: Text, result: InjectionVulnerabilityResult) -> None:
        """Add security recommendations section."""
        report.append("💡 Security Recommendations\n", style="bold yellow")
        
        recommendations = []
        
        # Collect recommendations from vulnerabilities
        for vuln in result.vulnerabilities:
            if vuln.recommendations:
                recommendations.extend(vuln.recommendations)
        
        # Add risk-based recommendations
        if result.risk_assessment and result.risk_assessment.mitigations:
            recommendations.extend(result.risk_assessment.mitigations)
        
        # Add general recommendations
        if result.vulnerabilities:
            recommendations.extend([
                "Implement comprehensive input validation and sanitization",
                "Use parameterized queries or prepared statements exclusively",
                "Apply the principle of least privilege for database access",
                "Implement proper error handling to prevent information disclosure",
                "Conduct regular security code reviews and penetration testing"
            ])
        
        # Remove duplicates and display
        unique_recommendations = list(dict.fromkeys(recommendations))
        
        for i, rec in enumerate(unique_recommendations[:10], 1):
            report.append(f"  {i}. {rec}\n", style="yellow")
        
        if len(unique_recommendations) > 10:
            remaining = len(unique_recommendations) - 10
            report.append(f"  ... and {remaining} more recommendations\n", style="dim yellow")
    
    def _get_severity_color(self, severity: SeverityLevel) -> str:
        """Get color for severity level."""
        return {
            SeverityLevel.CRITICAL: "bright_red",
            SeverityLevel.HIGH: "red",
            SeverityLevel.MEDIUM: "yellow",
            SeverityLevel.LOW: "blue",
            SeverityLevel.INFO: "dim"
        }.get(severity, "dim")
    
    def _get_severity_icon(self, severity: SeverityLevel) -> str:
        """Get icon for severity level."""
        return {
            SeverityLevel.CRITICAL: "🚨",
            SeverityLevel.HIGH: "❌",
            SeverityLevel.MEDIUM: "⚠️",
            SeverityLevel.LOW: "ℹ️",
            SeverityLevel.INFO: "📝"
        }.get(severity, "•")
    
    def _get_risk_color(self, risk: RiskLevel) -> str:
        """Get color for risk level."""
        return {
            RiskLevel.CRITICAL: "bright_red",
            RiskLevel.HIGH: "red",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.LOW: "green",
            RiskLevel.UNKNOWN: "dim"
        }.get(risk, "dim")
    
    def _get_provider_security_color(self, security_level: ProviderSecurityLevel) -> str:
        """Get color for provider security level."""
        return {
            ProviderSecurityLevel.SECURE: "green",
            ProviderSecurityLevel.EXPORTED_PROTECTED: "yellow",
            ProviderSecurityLevel.EXPORTED_UNPROTECTED: "red",
            ProviderSecurityLevel.VULNERABLE: "bright_red"
        }.get(security_level, "dim")
    
    def _get_provider_security_icon(self, security_level: ProviderSecurityLevel) -> str:
        """Get icon for provider security level."""
        return {
            ProviderSecurityLevel.SECURE: "✅",
            ProviderSecurityLevel.EXPORTED_PROTECTED: "🔒",
            ProviderSecurityLevel.EXPORTED_UNPROTECTED: "⚠️",
            ProviderSecurityLevel.VULNERABLE: "🚨"
        }.get(security_level, "•")
    
    def _truncate_text(self, text: str, max_length: int) -> str:
        """Truncate text to maximum length."""
        if len(text) <= max_length:
            return text
        return text[:max_length - 3] + "..." 
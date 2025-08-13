"""
Enhanced Static Analysis - Formatters Module

This module provides comprehensive formatting capabilities for enhanced static analysis
results including Rich text formatting, summary generation, and report creation.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.console import Console

from .data_structures import (
    StaticAnalysisResult, SecurityFinding, SecretAnalysis, ManifestAnalysis,
    CodeQualityMetrics, RiskAssessment, SeverityLevel, RiskLevel, SecretType
)

class StaticAnalysisFormatter:
    """Advanced formatter for static analysis results."""
    
    def __init__(self):
        """Initialize the formatter."""
        self.logger = logging.getLogger(__name__)
        self.console = Console()
    
    def format_report(self, result: StaticAnalysisResult) -> Tuple[str, Text]:
        """Format comprehensive static analysis report."""
        report = Text()
        
        # Header
        report.append("🔍 Enhanced Static Analysis Report\n", style="bold blue")
        report.append("=" * 70 + "\n\n", style="blue")
        
        # Executive Summary
        self._add_executive_summary(report, result)
        
        # Security Findings
        self._add_security_findings(report, result.security_findings)
        
        # Secret Analysis
        self._add_secret_analysis(report, result.secret_analysis)
        
        # Manifest Analysis
        if result.manifest_analysis:
            self._add_manifest_analysis(report, result.manifest_analysis)
        
        # Code Quality Metrics
        if result.code_quality_metrics:
            self._add_code_quality_metrics(report, result.code_quality_metrics)
        
        # Risk Assessment
        if result.risk_assessment:
            self._add_risk_assessment(report, result.risk_assessment)
        
        # Recommendations
        self._add_recommendations(report, result)
        
        return ("Enhanced Static Analysis", report)
    
    def _add_executive_summary(self, report: Text, result: StaticAnalysisResult) -> None:
        """Add executive summary section."""
        report.append("📊 Executive Summary\n", style="bold green")
        
        # Overall risk assessment
        if result.risk_assessment:
            risk_level = result.risk_assessment.overall_risk.value
            risk_score = result.risk_assessment.risk_score
            
            risk_color = self._get_risk_color(result.risk_assessment.overall_risk)
            report.append(f"Overall Risk Level: {risk_level}\n", style=f"bold {risk_color}")
            report.append(f"Risk Score: {risk_score:.2f}/1.0\n", style=risk_color)
        
        # Security findings summary
        total_findings = len(result.security_findings)
        if total_findings > 0:
            report.append(f"Security Findings: {total_findings} total\n")
            
            severity_counts = self._count_by_severity(result.security_findings)
            for severity, count in severity_counts.items():
                if count > 0:
                    color = self._get_severity_color(SeverityLevel(severity))
                    icon = self._get_severity_icon(SeverityLevel(severity))
                    report.append(f"  {icon} {severity}: {count}\n", style=color)
        else:
            report.append("✅ No security vulnerabilities detected\n", style="green")
        
        # Secret detection summary
        total_secrets = len(result.secret_analysis)
        if total_secrets > 0:
            high_confidence_secrets = [s for s in result.secret_analysis if s.confidence >= 0.8]
            medium_confidence_secrets = [s for s in result.secret_analysis if 0.6 <= s.confidence < 0.8]
            
            report.append(f"Secret Detection: {total_secrets} analyzed\n")
            if high_confidence_secrets:
                report.append(f"  🔑 High Confidence: {len(high_confidence_secrets)}\n", style="bright_red")
            if medium_confidence_secrets:
                report.append(f"  🔐 Medium Confidence: {len(medium_confidence_secrets)}\n", style="yellow")
        else:
            report.append("✅ No high-confidence secrets detected\n", style="green")
        
        report.append("\n")
    
    def _add_security_findings(self, report: Text, findings: List[SecurityFinding]) -> None:
        """Add security findings section."""
        if not findings:
            return
        
        report.append("🚨 Security Findings\n", style="bold red")
        
        # Group findings by severity
        findings_by_severity = {}
        for finding in findings:
            severity = finding.severity.value
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)
        
        # Display findings by severity (most critical first)
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity in findings_by_severity:
                severity_findings = findings_by_severity[severity]
                color = self._get_severity_color(SeverityLevel(severity))
                icon = self._get_severity_icon(SeverityLevel(severity))
                
                report.append(f"\n{icon} {severity} Severity ({len(severity_findings)} issues)\n", 
                            style=f"bold {color}")
                
                # Show top 5 findings
                for i, finding in enumerate(severity_findings[:5], 1):
                    report.append(f"  {i}. {finding.title}\n", style=color)
                    report.append(f"     Category: {finding.category.value}\n", style="dim")
                    report.append(f"     File: {finding.file_path}\n", style="dim")
                    report.append(f"     Confidence: {finding.confidence:.1%}\n", style="dim")
                    
                    if finding.code_snippet:
                        snippet = self._truncate_text(finding.code_snippet, 100)
                        report.append(f"     Code: {snippet}\n", style="dim cyan")
                    
                    if finding.recommendations:
                        report.append(f"     💡 {finding.recommendations[0]}\n", style="yellow")
                    
                    if finding.masvs_control:
                        report.append(f"     📋 MASVS: {finding.masvs_control}\n", style="dim")
                    
                    report.append("\n")
                
                # Show count of remaining findings
                if len(severity_findings) > 5:
                    remaining = len(severity_findings) - 5
                    report.append(f"     ... and {remaining} more {severity.lower()} issues\n\n", 
                                style=f"dim {color}")
    
    def _add_secret_analysis(self, report: Text, secrets: List[SecretAnalysis]) -> None:
        """Add secret analysis section."""
        if not secrets:
            return
        
        report.append("🔍 Secret Analysis Results\n", style="bold magenta")
        
        # Group secrets by confidence level
        high_confidence = [s for s in secrets if s.confidence >= 0.8]
        medium_confidence = [s for s in secrets if 0.6 <= s.confidence < 0.8]
        low_confidence = [s for s in secrets if s.confidence < 0.6]
        
        # High confidence secrets
        if high_confidence:
            report.append(f"\n🔑 High Confidence Secrets ({len(high_confidence)})\n", 
                         style="bold bright_red")
            
            for i, secret in enumerate(high_confidence[:5], 1):
                report.append(f"  {i}. {secret.pattern_type.value.upper()}: {secret.masked_value}\n", 
                            style="bright_red")
                report.append(f"     Confidence: {secret.confidence:.1%}\n", style="dim")
                report.append(f"     Entropy: {secret.entropy:.2f}\n", style="dim")
                report.append(f"     File: {secret.file_path}\n", style="dim")
                report.append(f"     Risk: {secret.risk_level.value}\n", style="dim")
                
                if secret.context:
                    context = self._truncate_text(secret.context, 80)
                    report.append(f"     Context: {context}\n", style="dim cyan")
                
                report.append("\n")
            
            if len(high_confidence) > 5:
                remaining = len(high_confidence) - 5
                report.append(f"     ... and {remaining} more high confidence secrets\n\n", 
                            style="dim bright_red")
        
        # Medium confidence secrets
        if medium_confidence:
            report.append(f"🔐 Medium Confidence Secrets ({len(medium_confidence)})\n", 
                         style="bold yellow")
            
            for i, secret in enumerate(medium_confidence[:3], 1):
                report.append(f"  {i}. {secret.pattern_type.value.upper()}: {secret.masked_value}\n", 
                            style="yellow")
                report.append(f"     Confidence: {secret.confidence:.1%} | Entropy: {secret.entropy:.2f}\n", 
                            style="dim")
                report.append(f"     File: {secret.file_path}\n", style="dim")
                report.append("\n")
            
            if len(medium_confidence) > 3:
                remaining = len(medium_confidence) - 3
                report.append(f"     ... and {remaining} more medium confidence secrets\n\n", 
                            style="dim yellow")
    
    def _add_manifest_analysis(self, report: Text, manifest: ManifestAnalysis) -> None:
        """Add manifest analysis section."""
        report.append("📱 AndroidManifest.xml Analysis\n", style="bold cyan")
        
        # Security configuration
        if manifest.security_features:
            report.append("\nSecurity Configuration:\n", style="cyan")
            
            # Debug status
            debuggable = manifest.security_features.get('debuggable', False)
            if debuggable:
                report.append("  ❌ App is debuggable (security risk)\n", style="red")
            else:
                report.append("  ✅ App is not debuggable\n", style="green")
            
            # Backup configuration
            allow_backup = manifest.security_features.get('allow_backup', True)
            if allow_backup:
                report.append("  ⚠️ Backup is allowed (potential data exposure)\n", style="yellow")
            else:
                report.append("  ✅ Backup is disabled\n", style="green")
            
            # Cleartext traffic
            cleartext_traffic = manifest.security_features.get('uses_cleartext_traffic')
            if cleartext_traffic is True:
                report.append("  ❌ Cleartext traffic is explicitly allowed\n", style="red")
            elif cleartext_traffic is False:
                report.append("  ✅ Cleartext traffic is disabled\n", style="green")
            else:
                report.append("  ⚠️ Cleartext traffic setting not specified\n", style="yellow")
            
            # Target SDK
            target_sdk = manifest.target_sdk
            if target_sdk:
                if target_sdk >= 30:
                    report.append(f"  ✅ Target SDK: {target_sdk} (modern)\n", style="green")
                elif target_sdk >= 26:
                    report.append(f"  ⚠️ Target SDK: {target_sdk} (acceptable)\n", style="yellow")
                else:
                    report.append(f"  ❌ Target SDK: {target_sdk} (outdated)\n", style="red")
        
        # Dangerous permissions
        if manifest.dangerous_permissions:
            report.append(f"\n⚠️ Dangerous Permissions ({len(manifest.dangerous_permissions)}):\n", 
                         style="yellow")
            for perm in manifest.dangerous_permissions[:5]:
                perm_name = perm.get('name', 'Unknown')
                report.append(f"  • {perm_name}\n", style="yellow")
        
        # Exported components
        if manifest.exported_components:
            report.append(f"\n⚠️ Exported Components ({len(manifest.exported_components)}):\n", 
                         style="yellow")
            for comp in manifest.exported_components[:3]:
                comp_name = comp.get('name', 'Unknown')
                comp_type = comp.get('type', 'Unknown')
                report.append(f"  • {comp_type}: {comp_name}\n", style="yellow")
            
            if len(manifest.exported_components) > 3:
                remaining = len(manifest.exported_components) - 3
                report.append(f"  ... and {remaining} more\n", style="dim yellow")
        
        report.append("\n")
    
    def _add_code_quality_metrics(self, report: Text, metrics: CodeQualityMetrics) -> None:
        """Add code quality metrics section."""
        report.append("📈 Code Quality Metrics\n", style="bold blue")
        
        report.append(f"Total Files: {metrics.total_files}\n")
        report.append(f"Code Files: {metrics.code_files}\n")
        
        # Obfuscation level
        if metrics.obfuscation_level > 0.7:
            report.append(f"Obfuscation Level: {metrics.obfuscation_level:.1%} (High)\n", style="red")
        elif metrics.obfuscation_level > 0.3:
            report.append(f"Obfuscation Level: {metrics.obfuscation_level:.1%} (Medium)\n", style="yellow")
        else:
            report.append(f"Obfuscation Level: {metrics.obfuscation_level:.1%} (Low)\n", style="green")
        
        # Complexity metrics
        if metrics.complexity_score > 0:
            report.append(f"Complexity Score: {metrics.complexity_score:.2f}\n")
        
        if metrics.maintainability_index > 0:
            if metrics.maintainability_index > 70:
                report.append(f"Maintainability Index: {metrics.maintainability_index:.1f} (Good)\n", style="green")
            elif metrics.maintainability_index > 50:
                report.append(f"Maintainability Index: {metrics.maintainability_index:.1f} (Fair)\n", style="yellow")
            else:
                report.append(f"Maintainability Index: {metrics.maintainability_index:.1f} (Poor)\n", style="red")
        
        report.append("\n")
    
    def _add_risk_assessment(self, report: Text, risk: RiskAssessment) -> None:
        """Add risk assessment section."""
        report.append("⚠️ Risk Assessment\n", style="bold yellow")
        
        # Overall risk
        risk_color = self._get_risk_color(risk.overall_risk)
        report.append(f"Overall Risk: {risk.overall_risk.value}\n", style=f"bold {risk_color}")
        report.append(f"Risk Score: {risk.risk_score:.2f}/1.0\n", style=risk_color)
        
        # Issue breakdown
        if risk.total_issues > 0:
            report.append(f"Total Issues: {risk.total_issues}\n")
            if risk.critical_issues > 0:
                report.append(f"  🚨 Critical: {risk.critical_issues}\n", style="bright_red")
            if risk.high_issues > 0:
                report.append(f"  ❌ High: {risk.high_issues}\n", style="red")
            if risk.medium_issues > 0:
                report.append(f"  ⚠️ Medium: {risk.medium_issues}\n", style="yellow")
            if risk.low_issues > 0:
                report.append(f"  ℹ️ Low: {risk.low_issues}\n", style="blue")
        
        # Risk factors
        if risk.risk_factors:
            report.append("\nKey Risk Factors:\n", style="yellow")
            for factor in risk.risk_factors[:5]:
                report.append(f"  • {factor}\n", style="yellow")
        
        report.append("\n")
    
    def _add_recommendations(self, report: Text, result: StaticAnalysisResult) -> None:
        """Add security recommendations section."""
        report.append("💡 Security Recommendations\n", style="bold yellow")
        
        recommendations = []
        
        # Generate recommendations based on findings
        if result.risk_assessment:
            if result.risk_assessment.critical_issues > 0:
                recommendations.append("Immediately address critical security vulnerabilities")
            if result.risk_assessment.high_issues > 0:
                recommendations.append("Review and fix high-severity security issues")
        
        # Secret-based recommendations
        high_confidence_secrets = [s for s in result.secret_analysis if s.confidence >= 0.8]
        if high_confidence_secrets:
            recommendations.append("Remove or properly secure detected secrets and credentials")
        
        # Manifest-based recommendations
        if result.manifest_analysis:
            if result.manifest_analysis.security_features.get('debuggable', False):
                recommendations.append("Disable debug mode for production builds")
            if result.manifest_analysis.security_features.get('allow_backup', True):
                recommendations.append("Consider disabling backup for sensitive applications")
            if result.manifest_analysis.security_features.get('uses_cleartext_traffic', True):
                recommendations.append("Disable cleartext traffic and use HTTPS only")
        
        # General security recommendations
        recommendations.extend([
            "Implement proper input validation and sanitization",
            "Use strong cryptographic algorithms and proper key management",
            "Follow secure coding practices and OWASP guidelines",
            "Regularly update dependencies and security libraries",
            "Implement proper error handling and logging",
            "Use code obfuscation and anti-tampering measures for production"
        ])
        
        # Display recommendations
        for i, rec in enumerate(recommendations[:8], 1):
            report.append(f"  {i}. {rec}\n", style="yellow")
    
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
    
    def _count_by_severity(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {}
        for finding in findings:
            severity = finding.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _truncate_text(self, text: str, max_length: int) -> str:
        """Truncate text to maximum length."""
        if len(text) <= max_length:
            return text
        return text[:max_length - 3] + "..." 
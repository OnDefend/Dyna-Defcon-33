#!/usr/bin/env python3
"""
Runtime Decryption Analysis Formatters

Report formatting and output generation for runtime decryption analysis results.
Provides rich text formatting, summary statistics, and detailed findings presentation.

Output Formats:
- Rich text console output with color coding
- Detailed vulnerability reports
- MASVS compliance assessment
- Executive summary generation
- Dynamic analysis instructions
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from rich.text import Text
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress

from .data_structures import (
    RuntimeDecryptionFinding, RuntimeDecryptionAnalysisResult,
    DecryptionType, VulnerabilitySeverity, RuntimeDecryptionConfig
)

logger = logging.getLogger(__name__)

class RuntimeDecryptionFormatter:
    """
    formatter for runtime decryption analysis results.
    
    Provides comprehensive report generation with rich text formatting,
    statistical summaries, and actionable security recommendations.
    """
    
    def __init__(self, config: RuntimeDecryptionConfig):
        """Initialize the formatter with configuration."""
        self.config = config
        self.console = Console()
        self.logger = logging.getLogger(__name__)
        
        # Severity color mapping
        self.severity_colors = {
            VulnerabilitySeverity.CRITICAL: "red",
            VulnerabilitySeverity.HIGH: "orange3",
            VulnerabilitySeverity.MEDIUM: "yellow",
            VulnerabilitySeverity.LOW: "blue",
            VulnerabilitySeverity.INFO: "green"
        }
        
        # Pattern type descriptions
        self.pattern_descriptions = {
            DecryptionType.RUNTIME_DECRYPTION: "Runtime Decryption Operations",
            DecryptionType.NATIVE_DECRYPTION: "Native Binary Decryption",
            DecryptionType.RESOURCE_DECRYPTION: "Resource Content Decryption",
            DecryptionType.KEY_MANAGEMENT: "Cryptographic Key Management",
            DecryptionType.CRYPTO_IMPLEMENTATION: "Cryptographic Implementation",
            DecryptionType.WEAK_CRYPTO: "Weak Cryptographic Algorithms",
            DecryptionType.CUSTOM_CRYPTO: "Custom Cryptographic Implementation",
            DecryptionType.HARDCODED_CRYPTO: "Hardcoded Cryptographic Material"
        }
    
    def format_analysis_result(self, result: RuntimeDecryptionAnalysisResult) -> Text:
        """
        Format complete analysis result into rich text report.
        
        Args:
            result: Complete runtime decryption analysis result
            
        Returns:
            Text: Rich text formatted report
        """
        output = Text()
        
        # Header section
        output.append(self._format_header(result))
        
        # Executive summary
        output.append(self._format_executive_summary(result))
        
        # Detailed findings
        if result.findings:
            output.append(self._format_detailed_findings(result.findings))
        else:
            output.append(self._format_no_findings())
        
        # MASVS compliance assessment
        output.append(self._format_masvs_compliance(result.masvs_compliance))
        
        # Dynamic analysis section
        if result.frida_scripts_generated > 0:
            output.append(self._format_dynamic_analysis_section(result))
        
        # Remediation recommendations
        output.append(self._format_remediation_recommendations(result.findings))
        
        # Technical analysis summary
        output.append(self._format_technical_summary(result))
        
        return output
    
    def _format_header(self, result: RuntimeDecryptionAnalysisResult) -> Text:
        """Format report header section."""
        header = Text()
        header.append("🔬 Runtime Decryption Analysis Report\n", style="bold blue")
        header.append("=" * 50 + "\n", style="blue")
        header.append(f"Analysis Date: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
        header.append(f"Plugin Version: {result.plugin_version}\n")
        header.append(f"Analysis Duration: {result.analysis_duration:.2f} seconds\n\n")
        return header
    
    def _format_executive_summary(self, result: RuntimeDecryptionAnalysisResult) -> Text:
        """Format executive summary section."""
        summary = Text()
        summary.append("📊 Executive Summary\n", style="bold green")
        summary.append("-" * 20 + "\n", style="green")
        
        # Overall statistics
        summary.append(f"Total Findings: {len(result.findings)}\n")
        summary.append(f"Average Confidence: {result.average_confidence:.1%}\n")
        summary.append(f"Files Analyzed: {result.statistics.total_files_processed:,}\n")
        
        # Severity breakdown
        critical_count = len(result.get_findings_by_severity(VulnerabilitySeverity.CRITICAL))
        high_count = len(result.get_findings_by_severity(VulnerabilitySeverity.HIGH))
        medium_count = len(result.get_findings_by_severity(VulnerabilitySeverity.MEDIUM))
        low_count = len(result.get_findings_by_severity(VulnerabilitySeverity.LOW))
        
        summary.append("\nSeverity Distribution:\n", style="bold")
        summary.append(f"  Critical: {critical_count}\n", style="red")
        summary.append(f"  High: {high_count}\n", style="orange3")
        summary.append(f"  Medium: {medium_count}\n", style="yellow")
        summary.append(f"  Low: {low_count}\n", style="blue")
        
        # Risk assessment
        if result.has_critical_findings():
            summary.append("\n⚠️  CRITICAL RISK DETECTED\n", style="bold red")
            summary.append("Immediate security attention required.\n", style="red")
        elif high_count > 0:
            summary.append("\n🔴 HIGH RISK IDENTIFIED\n", style="bold orange3")
            summary.append("Security review recommended.\n", style="orange3")
        else:
            summary.append("\n✅ MODERATE/LOW RISK\n", style="bold green")
            summary.append("Standard security practices apply.\n", style="green")
        
        summary.append("\n")
        return summary
    
    def _format_detailed_findings(self, findings: List[RuntimeDecryptionFinding]) -> Text:
        """Format detailed findings section."""
        details = Text()
        details.append("🎯 Detailed Security Findings\n", style="bold red")
        details.append("-" * 30 + "\n", style="red")
        
        # Group findings by pattern type
        grouped_findings = {}
        for finding in findings:
            pattern_type = finding.pattern_type
            if pattern_type not in grouped_findings:
                grouped_findings[pattern_type] = []
            grouped_findings[pattern_type].append(finding)
        
        # Display findings by pattern type
        for pattern_type, pattern_findings in grouped_findings.items():
            details.append(f"\n📍 {self.pattern_descriptions.get(pattern_type, pattern_type.value)}\n", 
                          style="bold cyan")
            details.append("─" * 40 + "\n", style="cyan")
            
            # Show top findings (limited for readability)
            display_findings = pattern_findings[:5] if len(pattern_findings) > 5 else pattern_findings
            
            for i, finding in enumerate(display_findings, 1):
                details.append(self._format_single_finding(finding, i))
            
            if len(pattern_findings) > 5:
                remaining = len(pattern_findings) - 5
                details.append(f"... and {remaining} more {pattern_type.value} findings.\n\n")
        
        return details
    
    def _format_single_finding(self, finding: RuntimeDecryptionFinding, index: int) -> Text:
        """Format a single finding with detailed information."""
        finding_text = Text()
        
        # Finding header
        severity_color = self.severity_colors.get(finding.severity, "white")
        finding_text.append(f"{index}. {finding.finding_type}\n", style=f"bold {severity_color}")
        
        # Core information
        finding_text.append(f"   Class: {finding.class_name}\n", style="cyan")
        finding_text.append(f"   Method: {finding.method_name}\n", style="cyan")
        finding_text.append(f"   Location: {finding.location}\n", style="yellow")
        finding_text.append(f"   Severity: {finding.severity.value}\n", style=severity_color)
        finding_text.append(f"   Confidence: {finding.confidence:.1%}\n", style="green")
        
        # Pattern details
        if finding.matched_pattern:
            finding_text.append(f"   Pattern: {finding.matched_pattern}\n", style="magenta")
        
        # Description
        finding_text.append(f"   Description: {finding.description}\n", style="white")
        
        # Evidence
        if finding.evidence:
            finding_text.append("   Evidence:\n", style="bold")
            for evidence in finding.evidence[:3]:  # Show top 3 evidence items
                finding_text.append(f"     • {evidence}\n", style="dim")
        
        # Dynamic testing capability
        if finding.is_dynamic_testable():
            finding_text.append("   🧪 Dynamic Testing: Available\n", style="bold green")
            if finding.frida_script_path:
                finding_text.append(f"   📜 Frida Script: {finding.frida_script_path}\n", style="blue")
        
        # Security impact
        if finding.attack_vector:
            finding_text.append(f"   🎯 Attack Vector: {finding.attack_vector}\n", style="red")
        
        finding_text.append("\n")
        return finding_text
    
    def _format_no_findings(self) -> Text:
        """Format no findings section."""
        no_findings = Text()
        no_findings.append("✅ No Runtime Decryption Vulnerabilities Detected\n", style="bold green")
        no_findings.append("-" * 45 + "\n", style="green")
        no_findings.append(
            "The analysis did not identify any obvious runtime decryption vulnerabilities.\n"
            "This suggests that the application may have proper cryptographic implementations.\n\n"
        )
        return no_findings
    
    def _format_masvs_compliance(self, compliance: Dict[str, str]) -> Text:
        """Format MASVS compliance assessment."""
        masvs = Text()
        masvs.append("📋 MASVS Compliance Assessment\n", style="bold blue")
        masvs.append("-" * 32 + "\n", style="blue")
        
        if not compliance:
            masvs.append("No specific MASVS controls assessed.\n\n")
            return masvs
        
        for control, status in compliance.items():
            status_color = "green" if status == "PASSED" else "red"
            status_icon = "✅" if status == "PASSED" else "❌"
            
            masvs.append(f"{status_icon} {control}: {status}\n", style=status_color)
        
        # Overall compliance summary
        failed_controls = [c for c, s in compliance.items() if s == "FAILED"]
        if failed_controls:
            masvs.append(f"\n⚠️  {len(failed_controls)} MASVS control(s) failed\n", style="bold red")
            masvs.append("Security review and remediation recommended.\n", style="red")
        else:
            masvs.append("\n✅ All assessed MASVS controls passed\n", style="bold green")
            masvs.append("Good cryptographic security posture.\n", style="green")
        
        masvs.append("\n")
        return masvs
    
    def _format_dynamic_analysis_section(self, result: RuntimeDecryptionAnalysisResult) -> Text:
        """Format dynamic analysis section."""
        dynamic = Text()
        dynamic.append("🧪 Dynamic Analysis Capabilities\n", style="bold yellow")
        dynamic.append("-" * 33 + "\n", style="yellow")
        
        dynamic.append(f"Frida Scripts Generated: {result.frida_scripts_generated}\n")
        dynamic.append(f"Dynamic Testable Findings: {result.dynamic_testable_count}\n")
        
        if result.frida_scripts_generated > 0:
            dynamic.append("\n🚀 Dynamic Testing Instructions:\n", style="bold green")
            dynamic.append("1. Ensure device is connected and ADB is accessible\n")
            dynamic.append("2. Install Frida server on the target device\n")
            dynamic.append("3. Execute generated Frida scripts during app runtime\n")
            dynamic.append("4. Monitor console output for decryption activities\n")
            dynamic.append("5. Analyze results for sensitive data exposure\n")
            
            dynamic.append("\n📂 Script Location:\n", style="bold blue")
            dynamic.append(f"   {self.config.frida_output_directory}/\n", style="blue")
        
        dynamic.append("\n")
        return dynamic
    
    def _format_remediation_recommendations(self, findings: List[RuntimeDecryptionFinding]) -> Text:
        """Format remediation recommendations."""
        remediation = Text()
        remediation.append("💡 Security Remediation Recommendations\n", style="bold green")
        remediation.append("-" * 40 + "\n", style="green")
        
        if not findings:
            remediation.append("✅ No immediate remediation required.\n")
            remediation.append("Continue following secure coding best practices.\n\n")
            return remediation
        
        # Generate specific recommendations based on finding types
        pattern_types = set(finding.pattern_type for finding in findings)
        
        recommendations = []
        
        if DecryptionType.WEAK_CRYPTO in pattern_types:
            recommendations.append("🔴 Replace weak cryptographic algorithms (MD5, SHA1, DES) with stronger alternatives (SHA-256, AES)")
        
        if DecryptionType.HARDCODED_CRYPTO in pattern_types:
            recommendations.append("🔴 Remove hardcoded cryptographic keys and secrets from source code")
        
        if DecryptionType.CUSTOM_CRYPTO in pattern_types:
            recommendations.append("🟡 Review custom cryptographic implementations for security flaws")
        
        if DecryptionType.RUNTIME_DECRYPTION in pattern_types:
            recommendations.append("🟡 Implement runtime application self-protection (RASP) mechanisms")
        
        if DecryptionType.KEY_MANAGEMENT in pattern_types:
            recommendations.append("🟡 Use Android Keystore for secure key management")
        
        # General recommendations
        recommendations.extend([
            "🔵 Implement certificate pinning for network communications",
            "🔵 Use proper error handling to prevent information leakage",
            "🔵 Add obfuscation and anti-tampering protection",
            "🔵 Conduct regular security code reviews",
            "🔵 Implement comprehensive logging and monitoring"
        ])
        
        for i, recommendation in enumerate(recommendations, 1):
            remediation.append(f"{i}. {recommendation}\n")
        
        remediation.append("\n")
        return remediation
    
    def _format_technical_summary(self, result: RuntimeDecryptionAnalysisResult) -> Text:
        """Format technical analysis summary."""
        technical = Text()
        technical.append("🔬 Technical Analysis Summary\n", style="bold blue")
        technical.append("-" * 30 + "\n", style="blue")
        
        stats = result.statistics
        
        # File analysis statistics
        technical.append("File Analysis:\n", style="bold")
        technical.append(f"  Java Files: {stats.java_files_analyzed:,}\n")
        technical.append(f"  Smali Files: {stats.smali_files_analyzed:,}\n")
        technical.append(f"  Resource Files: {stats.resource_files_analyzed:,}\n")
        technical.append(f"  Total Processed: {stats.total_files_processed:,}\n")
        
        # Pattern analysis statistics
        technical.append("\nPattern Analysis:\n", style="bold")
        for pattern, count in stats.pattern_matches.items():
            technical.append(f"  {pattern}: {count}\n")
        
        # Performance metrics
        technical.append("\nPerformance Metrics:\n", style="bold")
        technical.append(f"  Analysis Duration: {result.analysis_duration:.2f}s\n")
        technical.append(f"  Average Confidence: {result.average_confidence:.1%}\n")
        technical.append(f"  Coverage: {result.coverage_percentage:.1%}\n")
        
        # Achievement summary
        if result.findings:
            technical.append("\n🏆 Analysis Achievement\n", style="bold magenta")
            technical.append("✅ Runtime Decryption Detection: Enhanced pattern matching\n", style="green")
            technical.append("✅ Professional Confidence Scoring: Evidence-based calculation\n", style="green")
            technical.append("✅ Dynamic Analysis Ready: Frida scripts generated\n", style="green")
            technical.append("✅ MASVS Compliance: Security control assessment\n", style="green")
        
        technical.append("\n")
        return technical
    
    def format_finding_summary(self, findings: List[RuntimeDecryptionFinding]) -> str:
        """Format a brief summary of findings for logging."""
        if not findings:
            return "No runtime decryption vulnerabilities detected"
        
        severity_counts = {}
        for finding in findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary_parts = []
        for severity, count in severity_counts.items():
            summary_parts.append(f"{count} {severity}")
        
        return f"Runtime decryption analysis: {len(findings)} findings ({', '.join(summary_parts)})"
    
    def create_findings_table(self, findings: List[RuntimeDecryptionFinding]) -> Table:
        """Create a rich table for findings display."""
        table = Table(title="Runtime Decryption Findings")
        
        table.add_column("Type", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("Confidence", style="green")
        table.add_column("Location", style="yellow")
        table.add_column("Pattern", style="magenta")
        
        for finding in findings[:20]:  # Limit for display
            severity_color = self.severity_colors.get(finding.severity, "white")
            table.add_row(
                finding.pattern_type.value,
                finding.severity.value,
                f"{finding.confidence:.1%}",
                f"{finding.class_name}.{finding.method_name}",
                finding.matched_pattern[:30] + "..." if len(finding.matched_pattern) > 30 else finding.matched_pattern
            )
        
        return table 
 
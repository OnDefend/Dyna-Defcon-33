#!/usr/bin/env python3
"""
Network Cleartext Traffic Analyzer - Rich Text Formatter

This module provides Rich text formatting for network cleartext traffic analysis results.

Features:
- Rich text output formatting with colors and styles
- Structured report generation
- Finding categorization and presentation
- Recommendation and verification command formatting
- Status and risk level color coding

Classes:
    NetworkCleartextFormatter: Main Rich text formatting engine
"""

import logging
from typing import Dict, List, Optional, Any
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.console import Console

from .data_structures import (
    CleartextTrafficAnalysisResult, NetworkSecurityFinding, SecurityRecommendation,
    VerificationCommand, RiskLevel, AnalysisStatus, HttpUrlDetection, HttpUrlType
)

class NetworkCleartextFormatter:
    """
    Rich text formatter for network cleartext traffic analysis results.
    
    Provides comprehensive formatting of analysis results with proper color coding,
    structured layout, and professional presentation suitable for security reports.
    """
    
    def __init__(self):
        """Initialize formatter"""
        self.logger = logging.getLogger(__name__)
        
        # Color scheme for different elements
        self.colors = {
            'header': 'bold blue',
            'subheader': 'bold cyan',
            'success': 'green',
            'warning': 'yellow',
            'error': 'red',
            'critical': 'bright_red',
            'info': 'blue',
            'dim': 'dim',
            'bold': 'bold'
        }
        
        # Status color mapping
        self.status_colors = {
            AnalysisStatus.PASS: 'green',
            AnalysisStatus.FAIL: 'red',
            AnalysisStatus.MANUAL: 'yellow',
            AnalysisStatus.ERROR: 'bright_red',
            AnalysisStatus.UNKNOWN: 'white'
        }
        
        # Risk level color mapping
        self.risk_colors = {
            RiskLevel.CRITICAL: 'bright_red',
            RiskLevel.HIGH: 'red',
            RiskLevel.MEDIUM: 'yellow',
            RiskLevel.LOW: 'green',
            RiskLevel.INFO: 'blue',
            RiskLevel.UNKNOWN: 'white'
        }
    
    def generate_rich_output(self, result: CleartextTrafficAnalysisResult) -> Text:
        """
        Generate comprehensive Rich text output for analysis results.
        
        Args:
            result: Complete cleartext traffic analysis result
            
        Returns:
            Rich Text object with formatted analysis report
        """
        try:
            output = Text()
            
            # Header section
            self._add_header(output, result)
            
            # Executive summary
            self._add_executive_summary(output, result)
            
            # Findings section
            if result.findings:
                self._add_findings_section(output, result.findings)
            
            # Analysis details
            self._add_analysis_details(output, result)
            
            # Recommendations
            if result.recommendations:
                self._add_recommendations_section(output, result.recommendations)
            
            # Verification commands
            if result.verification_commands:
                self._add_verification_section(output, result.verification_commands)
            
            # Risk assessment summary
            self._add_risk_summary(output, result)
            
            return output
            
        except Exception as e:
            self.logger.error(f"Error generating Rich output: {e}")
            return self._generate_error_output(str(e))
    
    def _add_header(self, output: Text, result: CleartextTrafficAnalysisResult):
        """Add header section with title and basic status"""
        output.append("🔒 Network Cleartext Traffic Analysis\n", style=self.colors['header'])
        output.append("=" * 50 + "\n", style=self.colors['info'])
        
        # Status and risk level
        status_color = self.status_colors.get(result.overall_status, 'white')
        risk_color = self.risk_colors.get(result.risk_level, 'white')
        
        output.append(f"Status: {result.overall_status.value}\n", style=status_color)
        output.append(f"Risk Level: {result.risk_level.value}\n", style=risk_color)
        
        if result.confidence_score > 0:
            confidence_color = self._get_confidence_color(result.confidence_score)
            output.append(f"Confidence: {result.confidence_score:.1%}\n", style=confidence_color)
        
        output.append("\n")
    
    def _add_executive_summary(self, output: Text, result: CleartextTrafficAnalysisResult):
        """Add executive summary section"""
        output.append("📊 Executive Summary\n", style=self.colors['subheader'])
        output.append("-" * 20 + "\n", style=self.colors['info'])
        
        # Key metrics
        total_findings = len(result.findings)
        critical_findings = len(result.get_critical_findings())
        
        output.append(f"• Total Security Findings: {total_findings}\n")
        
        if critical_findings > 0:
            output.append(f"• Critical/High Severity: {critical_findings}\n", style=self.risk_colors[RiskLevel.HIGH])
        
        # Analysis coverage
        analysis_areas = []
        if result.manifest_analysis.manifest_found:
            analysis_areas.append("AndroidManifest.xml")
        if result.nsc_analysis.config_found:
            analysis_areas.append("Network Security Configuration")
        if result.resource_analysis.http_urls_found:
            analysis_areas.append(f"{len(result.resource_analysis.http_urls_found)} HTTP URLs")
        
        if analysis_areas:
            output.append(f"• Analysis Coverage: {', '.join(analysis_areas)}\n")
        
        # Risk score if available
        risk_score = result.analysis_metadata.get('overall_risk_score')
        if risk_score is not None:
            risk_color = self._get_risk_score_color(risk_score)
            output.append(f"• Risk Score: {risk_score:.1f}/100\n", style=risk_color)
        
        output.append("\n")
    
    def _add_findings_section(self, output: Text, findings: List[NetworkSecurityFinding]):
        """Add detailed findings section"""
        output.append("🔍 Security Findings\n", style=self.colors['subheader'])
        output.append("-" * 18 + "\n", style=self.colors['info'])
        
        # Group findings by severity
        findings_by_severity = {}
        for finding in findings:
            severity = finding.severity
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)
        
        # Display findings by severity (critical first)
        severity_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]
        
        finding_number = 1
        for severity in severity_order:
            if severity not in findings_by_severity:
                continue
            
            severity_findings = findings_by_severity[severity]
            severity_color = self.risk_colors.get(severity, 'white')
            
            for finding in severity_findings:
                # Finding header
                output.append(f"{finding_number}. ", style=self.colors['bold'])
                output.append(f"[{finding.severity.value}] ", style=severity_color)
                output.append(f"{finding.title}\n", style=self.colors['bold'])
                
                # Description
                output.append(f"   {finding.description}\n")
                
                # Location
                if finding.location:
                    output.append(f"   Location: {finding.location}\n", style=self.colors['dim'])
                
                # Confidence
                if finding.confidence > 0:
                    confidence_color = self._get_confidence_color(finding.confidence)
                    output.append(f"   Confidence: {finding.confidence:.1%}\n", style=confidence_color)
                
                # Evidence (limited to first 3 items)
                if finding.evidence:
                    output.append("   Evidence:\n", style=self.colors['dim'])
                    for evidence in finding.evidence[:3]:
                        output.append(f"   • {evidence}\n", style=self.colors['dim'])
                    if len(finding.evidence) > 3:
                        output.append(f"   • ... and {len(finding.evidence) - 3} more\n", style=self.colors['dim'])
                
                # MASVS control
                if finding.masvs_control:
                    output.append(f"   MASVS: {finding.masvs_control}\n", style=self.colors['info'])
                
                output.append("\n")
                finding_number += 1
    
    def _add_analysis_details(self, output: Text, result: CleartextTrafficAnalysisResult):
        """Add detailed analysis results"""
        output.append("📱 Analysis Details\n", style=self.colors['subheader'])
        output.append("-" * 18 + "\n", style=self.colors['info'])
        
        # Manifest analysis
        if result.manifest_analysis.manifest_found:
            output.append("AndroidManifest.xml Analysis:\n", style=self.colors['bold'])
            
            if result.manifest_analysis.target_sdk:
                output.append(f"• Target SDK: {result.manifest_analysis.target_sdk}\n")
            
            cleartext_setting = result.manifest_analysis.uses_cleartext_traffic
            if cleartext_setting is not None:
                color = self.risk_colors[RiskLevel.HIGH] if cleartext_setting == "true" else self.colors['success']
                output.append(f"• usesCleartextTraffic: {cleartext_setting}\n", style=color)
            
            nsc_setting = result.manifest_analysis.network_security_config
            if nsc_setting:
                output.append(f"• Network Security Config: {nsc_setting}\n", style=self.colors['success'])
            
            output.append("\n")
        
        # NSC analysis
        if result.nsc_analysis.config_found:
            output.append("Network Security Configuration:\n", style=self.colors['bold'])
            
            config_count = len(result.nsc_analysis.config_files)
            output.append(f"• Config files found: {config_count}\n")
            
            cleartext_permitted = result.nsc_analysis.cleartext_permitted
            if cleartext_permitted is not None:
                status = "ENABLED" if cleartext_permitted else "DISABLED"
                color = self.risk_colors[RiskLevel.HIGH] if cleartext_permitted else self.colors['success']
                output.append(f"• Cleartext traffic: {status}\n", style=color)
            
            if result.nsc_analysis.certificate_pinning:
                output.append("• Certificate pinning: CONFIGURED\n", style=self.colors['success'])
            else:
                output.append("• Certificate pinning: NOT CONFIGURED\n", style=self.colors['warning'])
            
            output.append("\n")
        
        # Resource analysis
        http_urls = result.resource_analysis.http_urls_found
        if http_urls:
            output.append("Resource Analysis:\n", style=self.colors['bold'])
            output.append(f"• HTTP URLs found: {len(http_urls)}\n")
            
            # Group by URL type
            url_types = {}
            for detection in http_urls:
                url_type = detection.url_type
                url_types[url_type] = url_types.get(url_type, 0) + 1
            
            for url_type, count in url_types.items():
                type_name = url_type.value.replace('_', ' ').title()
                color = self._get_url_type_color(url_type)
                output.append(f"  - {type_name}: {count}\n", style=color)
            
            # Show high-risk URLs
            high_risk_urls = result.resource_analysis.get_high_risk_urls()
            if high_risk_urls:
                output.append(f"• High-risk URLs: {len(high_risk_urls)}\n", style=self.risk_colors[RiskLevel.HIGH])
            
            # Show sample URLs (first 3)
            if len(http_urls) > 0:
                output.append("• Sample URLs:\n", style=self.colors['dim'])
                for detection in http_urls[:3]:
                    file_name = detection.file_path.split('/')[-1] if '/' in detection.file_path else detection.file_path
                    output.append(f"  - {detection.url} (in {file_name})\n", style=self.colors['dim'])
                
                if len(http_urls) > 3:
                    output.append(f"  - ... and {len(http_urls) - 3} more URLs\n", style=self.colors['dim'])
            
            output.append("\n")
    
    def _add_recommendations_section(self, output: Text, recommendations: List[SecurityRecommendation]):
        """Add security recommendations section"""
        output.append("💡 Security Recommendations\n", style=self.colors['subheader'])
        output.append("-" * 26 + "\n", style=self.colors['info'])
        
        # Group by priority
        recs_by_priority = {}
        for rec in recommendations:
            priority = rec.priority
            if priority not in recs_by_priority:
                recs_by_priority[priority] = []
            recs_by_priority[priority].append(rec)
        
        # Display by priority (critical first)
        priority_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]
        
        rec_number = 1
        for priority in priority_order:
            if priority not in recs_by_priority:
                continue
            
            priority_recs = recs_by_priority[priority]
            priority_color = self.risk_colors.get(priority, 'white')
            
            for rec in priority_recs:
                # Recommendation header
                output.append(f"{rec_number}. ", style=self.colors['bold'])
                output.append(f"[{rec.priority.value}] ", style=priority_color)
                output.append(f"{rec.title}\n", style=self.colors['bold'])
                
                # Description
                output.append(f"   {rec.description}\n")
                
                # Implementation steps (first 3)
                if rec.implementation_steps:
                    output.append("   Implementation:\n", style=self.colors['dim'])
                    for step in rec.implementation_steps[:3]:
                        output.append(f"   • {step}\n", style=self.colors['dim'])
                    if len(rec.implementation_steps) > 3:
                        output.append(f"   • ... and {len(rec.implementation_steps) - 3} more steps\n", style=self.colors['dim'])
                
                # MASVS control
                if rec.masvs_control:
                    output.append(f"   MASVS: {rec.masvs_control}\n", style=self.colors['info'])
                
                output.append("\n")
                rec_number += 1
        
        # Limit to top 5 recommendations for readability
        if len(recommendations) > 5:
            output.append(f"... and {len(recommendations) - 5} more recommendations\n", style=self.colors['dim'])
            output.append("\n")
    
    def _add_verification_section(self, output: Text, commands: List[VerificationCommand]):
        """Add verification commands section"""
        output.append("🔧 Verification Commands\n", style=self.colors['subheader'])
        output.append("-" * 22 + "\n", style=self.colors['info'])
        
        # Group by category
        commands_by_category = {}
        for cmd in commands:
            category = cmd.category
            if category not in commands_by_category:
                commands_by_category[category] = []
            commands_by_category[category].append(cmd)
        
        for category, category_commands in commands_by_category.items():
            output.append(f"{category}:\n", style=self.colors['bold'])
            
            for cmd in category_commands[:3]:  # Limit to 3 per category
                output.append(f"• {cmd.title}\n", style=self.colors['bold'])
                output.append(f"  $ {cmd.command}\n", style=self.colors['info'])
                output.append(f"  {cmd.description}\n", style=self.colors['dim'])
                
                if cmd.requires_device:
                    output.append("  (Requires connected device)\n", style=self.colors['warning'])
                
                output.append("\n")
            
            if len(category_commands) > 3:
                output.append(f"  ... and {len(category_commands) - 3} more commands\n", style=self.colors['dim'])
                output.append("\n")
    
    def _add_risk_summary(self, output: Text, result: CleartextTrafficAnalysisResult):
        """Add risk assessment summary"""
        output.append("⚠️  Risk Assessment Summary\n", style=self.colors['subheader'])
        output.append("-" * 26 + "\n", style=self.colors['info'])
        
        # Overall assessment
        status_color = self.status_colors.get(result.overall_status, 'white')
        risk_color = self.risk_colors.get(result.risk_level, 'white')
        
        output.append(f"Overall Status: {result.overall_status.value}\n", style=status_color)
        output.append(f"Risk Level: {result.risk_level.value}\n", style=risk_color)
        
        # Risk factors
        risk_factors = result.analysis_metadata.get('risk_factors', [])
        if risk_factors:
            output.append("\nKey Risk Factors:\n", style=self.colors['bold'])
            for factor in risk_factors[:5]:  # Top 5 risk factors
                severity = factor.get('severity', 'MEDIUM')
                factor_color = self.risk_colors.get(RiskLevel(severity), 'white')
                output.append(f"• {factor.get('description', 'Unknown risk factor')}\n", style=factor_color)
        
        # Analysis duration
        if result.analysis_duration > 0:
            output.append(f"\nAnalysis completed in {result.analysis_duration:.1f} seconds\n", style=self.colors['dim'])
    
    def _get_confidence_color(self, confidence: float) -> str:
        """Get color for confidence level"""
        if confidence >= 0.9:
            return self.colors['success']
        elif confidence >= 0.7:
            return self.colors['info']
        elif confidence >= 0.5:
            return self.colors['warning']
        else:
            return self.colors['error']
    
    def _get_risk_score_color(self, score: float) -> str:
        """Get color for risk score"""
        if score >= 85:
            return self.risk_colors[RiskLevel.CRITICAL]
        elif score >= 70:
            return self.risk_colors[RiskLevel.HIGH]
        elif score >= 40:
            return self.risk_colors[RiskLevel.MEDIUM]
        else:
            return self.risk_colors[RiskLevel.LOW]
    
    def _get_url_type_color(self, url_type: HttpUrlType) -> str:
        """Get color for URL type"""
        type_colors = {
            HttpUrlType.HARDCODED_API: self.risk_colors[RiskLevel.HIGH],
            HttpUrlType.CONFIG_URL: self.risk_colors[RiskLevel.MEDIUM],
            HttpUrlType.EXTERNAL_SERVICE: self.risk_colors[RiskLevel.MEDIUM],
            HttpUrlType.TEST_URL: self.risk_colors[RiskLevel.LOW],
            HttpUrlType.ANALYTICS_URL: self.colors['info'],
            HttpUrlType.ADVERTISEMENT_URL: self.colors['info'],
            HttpUrlType.RESOURCE_URL: self.colors['dim'],
            HttpUrlType.UNKNOWN: self.colors['dim']
        }
        
        return type_colors.get(url_type, self.colors['dim'])
    
    def _generate_error_output(self, error_message: str) -> Text:
        """Generate error output for formatting failures"""
        output = Text()
        output.append("Network Cleartext Traffic Analysis - ERROR\n", style=self.colors['error'])
        output.append(f"Formatting failed: {error_message}\n", style=self.colors['error'])
        output.append("Manual analysis review required.\n", style=self.colors['warning'])
        return output
    
    def generate_summary_text(self, result: CleartextTrafficAnalysisResult) -> str:
        """
        Generate a brief text summary for integration with other tools.
        
        Args:
            result: Complete cleartext traffic analysis result
            
        Returns:
            Brief text summary string
        """
        try:
            summary_parts = []
            
            # Status and risk
            summary_parts.append(f"Status: {result.overall_status.value}")
            summary_parts.append(f"Risk: {result.risk_level.value}")
            
            # Finding count
            total_findings = len(result.findings)
            critical_findings = len(result.get_critical_findings())
            
            if total_findings > 0:
                if critical_findings > 0:
                    summary_parts.append(f"{total_findings} findings ({critical_findings} critical/high)")
                else:
                    summary_parts.append(f"{total_findings} findings")
            else:
                summary_parts.append("No security issues found")
            
            # Key issues
            key_issues = []
            
            # Check for cleartext enabled
            if result.manifest_analysis.get_cleartext_status() == "true":
                key_issues.append("cleartext traffic enabled")
            
            # Check for HTTP URLs
            http_count = len(result.resource_analysis.http_urls_found)
            if http_count > 0:
                key_issues.append(f"{http_count} HTTP URLs")
            
            # Check for NSC issues
            if result.nsc_analysis.config_found and result.nsc_analysis.cleartext_permitted:
                key_issues.append("NSC permits cleartext")
            
            if key_issues:
                summary_parts.append(f"Issues: {', '.join(key_issues)}")
            
            return " | ".join(summary_parts)
            
        except Exception as e:
            self.logger.error(f"Error generating summary text: {e}")
            return f"Network Cleartext Traffic Analysis - Error: {e}"

    def generate_comprehensive_report(self, result: CleartextTrafficAnalysisResult) -> Text:
        """
        Generate comprehensive network cleartext traffic report.
        
        Args:
            result: The analysis result to format
            
        Returns:
            Rich Text object with formatted report
        """
        try:
            # Use the existing generate_rich_output method which provides comprehensive formatting
            return self.generate_rich_output(result)
        except Exception as e:
            self.logger.error(f"Error generating comprehensive report: {e}")
            return self._generate_error_output(f"Report generation failed: {e}") 
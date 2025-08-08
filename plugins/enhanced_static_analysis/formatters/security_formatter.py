"""
Security Findings Formatter

This module handles the formatting of security findings for reports.
"""

import logging
from typing import List, Any

from rich.text import Text

logger = logging.getLogger(__name__)

class SecurityFindingsFormatter:
    """
    Formatter for security findings results.
    
    Provides rich formatting for security findings in reports.
    """
    
    def __init__(self):
        """Initialize the security findings formatter."""
        self.severity_colors = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "cyan"
        }
        
        self.severity_icons = {
            "CRITICAL": "🚨",
            "HIGH": "❌",
            "MEDIUM": "⚠️",
            "LOW": "ℹ️",
            "INFO": "💡"
        }
    
    def format_security_findings(self, findings: List[Any]) -> Text:
        """
        Format security findings for display.
        
        Args:
            findings: List of security findings
            
        Returns:
            Text: Formatted security findings
        """
        if not findings:
            return Text("✅ No security vulnerabilities detected\n", style="green")
        
        logger.info(f"Formatting {len(findings)} security findings")
        
        findings_text = Text()
        findings_text.append("🚨 Security Findings\n", style="bold red")
        
        # Group findings by severity
        findings_by_severity = self._group_findings_by_severity(findings)
        
        # Display findings by severity (most critical first)
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity in findings_by_severity:
                findings_text.append(self._format_severity_section(
                    severity, findings_by_severity[severity]
                ))
        
        findings_text.append("\n")
        return findings_text
    
    def _group_findings_by_severity(self, findings: List[Any]) -> dict:
        """
        Group findings by severity level.
        
        Args:
            findings: List of security findings
            
        Returns:
            dict: Findings grouped by severity
        """
        grouped = {}
        
        for finding in findings:
            severity = getattr(finding, 'severity', 'LOW')
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(finding)
        
        return grouped
    
    def _format_severity_section(self, severity: str, findings: List[Any]) -> Text:
        """
        Format a section for a specific severity level.
        
        Args:
            severity: Severity level
            findings: Findings for this severity
            
        Returns:
            Text: Formatted severity section
        """
        section = Text()
        
        severity_color = self.severity_colors.get(severity, "dim")
        severity_icon = self.severity_icons.get(severity, "•")
        
        section.append(
            f"\n{severity_icon} {severity} Severity ({len(findings)} issues)\n",
            style=f"bold {severity_color}",
        )
        
        # Show top 5 findings for this severity
        for i, finding in enumerate(findings[:5], 1):
            section.append(self._format_individual_finding(finding, i, severity_color))
        
        # Show count of remaining findings
        if len(findings) > 5:
            remaining = len(findings) - 5
            section.append(
                f"     ... and {remaining} more {severity.lower()} issues\n\n",
                style=f"dim {severity_color}",
            )
        
        return section
    
    def _format_individual_finding(self, finding: Any, index: int, color: str) -> Text:
        """
        Format an individual security finding.
        
        Args:
            finding: Individual finding
            index: Finding index
            color: Color for this severity
            
        Returns:
            Text: Formatted finding
        """
        finding_text = Text()
        
        # Title
        title = getattr(finding, 'title', 'Unknown Issue')
        finding_text.append(f"  {index}. {title}\n", style=color)
        
        # Category
        category = getattr(finding, 'category', 'Unknown')
        finding_text.append(f"     Category: {category}\n", style="dim")
        
        # File path
        file_path = getattr(finding, 'file_path', 'Unknown')
        finding_text.append(f"     File: {file_path}\n", style="dim")
        
        # Confidence
        confidence = getattr(finding, 'confidence', 0.0)
        finding_text.append(f"     Confidence: {confidence:.1%}\n", style="dim")
        
        # Risk score (if available)
        if hasattr(finding, 'risk_score'):
            risk_score = finding.risk_score
            finding_text.append(f"     Risk Score: {risk_score:.2f}\n", style="dim")
        
        # OWASP category (if available)
        if hasattr(finding, 'owasp_category'):
            owasp_category = finding.owasp_category
            finding_text.append(f"     OWASP: {owasp_category}\n", style="dim")
        
        # CWE ID (if available)
        if hasattr(finding, 'cwe_id'):
            cwe_id = finding.cwe_id
            finding_text.append(f"     CWE: {cwe_id}\n", style="dim")
        
        # Code snippet (if available)
        code_snippet = getattr(finding, 'code_snippet', '')
        if code_snippet:
            snippet = (
                code_snippet[:100] + "..."
                if len(code_snippet) > 100
                else code_snippet
            )
            finding_text.append(f"     Code: {snippet}\n", style="dim cyan")
        
        # Recommendations
        recommendations = getattr(finding, 'recommendations', [])
        if recommendations:
            finding_text.append(f"     💡 {recommendations[0]}\n", style="yellow")
        
        # Remediation steps (if available)
        if hasattr(finding, 'remediation_steps'):
            remediation_steps = finding.remediation_steps
            if remediation_steps:
                finding_text.append(f"     🔧 {remediation_steps[0]}\n", style="cyan")
        
        finding_text.append("\n")
        return finding_text
    
    def format_findings_summary(self, findings: List[Any]) -> Text:
        """
        Format a summary of security findings.
        
        Args:
            findings: List of security findings
            
        Returns:
            Text: Formatted summary
        """
        summary = Text()
        
        if not findings:
            summary.append("✅ No security vulnerabilities detected\n", style="green")
            return summary
        
        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = getattr(finding, 'severity', 'LOW')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary.append(f"🚨 Security Findings: {len(findings)} total\n", style="bold red")
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity in severity_counts:
                count = severity_counts[severity]
                icon = self.severity_icons.get(severity, "•")
                color = self.severity_colors.get(severity, "dim")
                summary.append(f"  {icon} {severity}: {count}\n", style=color)
        
        return summary
    
    def format_top_findings(self, findings: List[Any], limit: int = 3) -> Text:
        """
        Format top security findings.
        
        Args:
            findings: List of security findings
            limit: Maximum number of findings to show
            
        Returns:
            Text: Formatted top findings
        """
        if not findings:
            return Text()
        
        # Sort by severity and confidence
        severity_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                severity_weights.get(getattr(f, 'severity', 'LOW'), 0),
                getattr(f, 'confidence', 0.0)
            ),
            reverse=True
        )
        
        top_findings = Text()
        top_findings.append(f"🔥 Top {min(limit, len(findings))} Security Issues\n", style="bold red")
        
        for i, finding in enumerate(sorted_findings[:limit], 1):
            title = getattr(finding, 'title', 'Unknown Issue')
            severity = getattr(finding, 'severity', 'LOW')
            confidence = getattr(finding, 'confidence', 0.0)
            
            color = self.severity_colors.get(severity, "dim")
            icon = self.severity_icons.get(severity, "•")
            
            top_findings.append(
                f"  {i}. {icon} {title} ({severity}, {confidence:.1%})\n",
                style=color
            )
        
        return top_findings
    
    def format_category_breakdown(self, findings: List[Any]) -> Text:
        """
        Format findings breakdown by category.
        
        Args:
            findings: List of security findings
            
        Returns:
            Text: Formatted category breakdown
        """
        if not findings:
            return Text()
        
        # Group by category
        categories = {}
        for finding in findings:
            category = getattr(finding, 'category', 'Unknown')
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)
        
        breakdown = Text()
        breakdown.append("📊 Findings by Category\n", style="bold blue")
        
        # Sort categories by count
        sorted_categories = sorted(categories.items(), key=lambda x: len(x[1]), reverse=True)
        
        for category, category_findings in sorted_categories:
            count = len(category_findings)
            breakdown.append(f"  • {category}: {count} issues\n", style="cyan")
        
        return breakdown 
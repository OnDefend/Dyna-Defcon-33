"""
Enhanced Static Analysis Report Formatter

This module handles the formatting of comprehensive static analysis reports.
"""

import logging
from typing import Dict, List, Any, Tuple

from rich.text import Text

from .security_formatter import SecurityFindingsFormatter
from .secret_formatter import SecretAnalysisFormatter
from .manifest_formatter import ManifestAnalysisFormatter
from .quality_formatter import CodeQualityFormatter

logger = logging.getLogger(__name__)

class StaticAnalysisReportFormatter:
    """
    Main report formatter for enhanced static analysis.
    
    Coordinates all formatting components to generate comprehensive reports.
    """
    
    def __init__(self):
        """Initialize the report formatter with all sub-formatters."""
        self.security_formatter = SecurityFindingsFormatter()
        self.secret_formatter = SecretAnalysisFormatter()
        self.manifest_formatter = ManifestAnalysisFormatter()
        self.quality_formatter = CodeQualityFormatter()
    
    def format_comprehensive_report(self, analysis_results: Dict[str, Any]) -> Text:
        """
        Format comprehensive static analysis report.
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            Text: Formatted comprehensive report
        """
        logger.info("Formatting comprehensive static analysis report")
        
        report = Text()
        
        # Header
        report.append("🔍 Enhanced Static Analysis Report\n", style="bold blue")
        report.append("=" * 70 + "\n\n", style="blue")
        
        # Executive Summary
        report.append(self._format_executive_summary(analysis_results))
        
        # Security Findings
        security_findings = analysis_results.get("security_findings", [])
        if security_findings:
            report.append(self.security_formatter.format_security_findings(security_findings))
        
        # Secret Analysis
        secret_analysis = analysis_results.get("secret_analysis", [])
        if secret_analysis:
            report.append(self.secret_formatter.format_secret_analysis(secret_analysis))
        
        # Manifest Analysis
        manifest_analysis = analysis_results.get("manifest_analysis", {})
        if manifest_analysis and "error" not in manifest_analysis:
            report.append(self.manifest_formatter.format_manifest_analysis(manifest_analysis))
        
        # Code Quality Metrics
        code_quality = analysis_results.get("code_quality_metrics", {})
        if code_quality:
            report.append(self.quality_formatter.format_code_quality(code_quality))
        
        # Recommendations
        report.append(self._format_recommendations(analysis_results))
        
        logger.info("Report formatting completed successfully")
        return report
    
    def _format_executive_summary(self, analysis_results: Dict[str, Any]) -> Text:
        """
        Format executive summary section.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            Text: Formatted executive summary
        """
        summary = Text()
        
        # Executive Summary Header
        summary.append("📊 Executive Summary\n", style="bold green")
        
        # Risk Assessment
        risk_assessment = analysis_results.get("risk_assessment", {})
        
        # Handle both RiskAssessment objects and dictionaries
        if hasattr(risk_assessment, 'overall_risk'):
            # RiskAssessment dataclass object
            overall_risk = risk_assessment.overall_risk.value if hasattr(risk_assessment.overall_risk, 'value') else str(risk_assessment.overall_risk)
            risk_score = risk_assessment.risk_score
            critical_count = risk_assessment.critical_issues
            high_count = risk_assessment.high_issues
            medium_count = risk_assessment.medium_issues
            low_count = risk_assessment.low_issues
        else:
            # Dictionary format
            overall_risk = risk_assessment.get("overall_risk", "UNKNOWN")
            risk_score = risk_assessment.get("risk_score", 0.0)
            critical_count = risk_assessment.get("critical_issues", 0)
            high_count = risk_assessment.get("high_issues", 0)
            medium_count = risk_assessment.get("medium_issues", 0)
            low_count = risk_assessment.get("low_issues", 0)
        
        # Color code the risk level
        risk_color = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
            "MINIMAL": "green",
            "UNKNOWN": "dim",
        }.get(overall_risk, "dim")
        
        summary.append(f"Overall Risk Level: {overall_risk}\n", style=f"bold {risk_color}")
        summary.append(f"Risk Score: {risk_score:.2f}/1.0\n", style=risk_color)
        
        # Security findings summary
        security_findings = analysis_results.get("security_findings", [])
        
        summary.append(f"Security Findings: {len(security_findings)} total\n")
        if critical_count > 0:
            summary.append(f"  🚨 Critical: {critical_count}\n", style="bright_red")
        if high_count > 0:
            summary.append(f"  ❌ High: {high_count}\n", style="red")
        if medium_count > 0:
            summary.append(f"  ⚠️ Medium: {medium_count}\n", style="yellow")
        if low_count > 0:
            summary.append(f"  ℹ️ Low: {low_count}\n", style="blue")
        
        # Secret analysis summary
        secret_analyses = analysis_results.get("secret_analysis", [])
        high_confidence_secrets = [s for s in secret_analyses if getattr(s, 'confidence', 0) >= 0.7]
        medium_confidence_secrets = [s for s in secret_analyses if 0.4 <= getattr(s, 'confidence', 0) < 0.7]
        
        summary.append(f"Secret Detection: {len(secret_analyses)} analyzed\n")
        if high_confidence_secrets:
            summary.append(
                f"  🔑 High Confidence Secrets: {len(high_confidence_secrets)}\n",
                style="bright_red",
            )
        if medium_confidence_secrets:
            summary.append(
                f"  🔐 Medium Confidence Secrets: {len(medium_confidence_secrets)}\n",
                style="yellow",
            )
        
        # Manifest analysis summary
        manifest_analysis = analysis_results.get("manifest_analysis", {})
        if manifest_analysis and "error" not in manifest_analysis:
            manifest_risk = manifest_analysis.get("risk_assessment", {})
            manifest_issues = manifest_risk.get("total_issues", 0)
            if manifest_issues > 0:
                summary.append(f"Manifest Issues: {manifest_issues}\n", style="yellow")
        
        summary.append("\n")
        return summary
    
    def _format_recommendations(self, analysis_results: Dict[str, Any]) -> Text:
        """
        Format recommendations section.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            Text: Formatted recommendations
        """
        recommendations_text = Text()
        
        # Recommendations Header
        recommendations_text.append("💡 Security Recommendations\n", style="bold yellow")
        
        # Collect recommendations from all analyses
        all_recommendations = []
        
        # Risk assessment recommendations
        risk_assessment = analysis_results.get("risk_assessment", {})
        
        # Handle both RiskAssessment objects and dictionaries
        if hasattr(risk_assessment, 'critical_issues'):
            # RiskAssessment dataclass object
            critical_count = risk_assessment.critical_issues
            high_count = risk_assessment.high_issues
        else:
            # Dictionary format
            critical_count = risk_assessment.get("critical_issues", 0)
            high_count = risk_assessment.get("high_issues", 0)
        
        if critical_count > 0:
            all_recommendations.append("Immediately address critical security vulnerabilities")
        if high_count > 0:
            all_recommendations.append("Review and fix high-severity security issues")
        
        # Secret analysis recommendations
        secret_analyses = analysis_results.get("secret_analysis", [])
        high_confidence_secrets = [s for s in secret_analyses if getattr(s, 'confidence', 0) >= 0.7]
        if high_confidence_secrets:
            all_recommendations.append("Remove or properly secure detected secrets and credentials")
        
        # Manifest analysis recommendations
        manifest_analysis = analysis_results.get("manifest_analysis", {})
        if manifest_analysis and "error" not in manifest_analysis:
            manifest_recommendations = manifest_analysis.get("recommendations", [])
            all_recommendations.extend(manifest_recommendations[:3])  # Top 3
        
        # Code quality recommendations
        code_quality = analysis_results.get("code_quality_metrics", {})
        if code_quality:
            # Handle both CodeQualityMetrics objects and dictionaries
            if hasattr(code_quality, '__dict__'):
                # CodeQualityMetrics object - it doesn't have recommendations attribute by default
                quality_recommendations = []
            elif isinstance(code_quality, dict):
                # Dictionary format
                quality_recommendations = code_quality.get("recommendations", [])
            else:
                quality_recommendations = []
            all_recommendations.extend(quality_recommendations[:2])  # Top 2
        
        # General recommendations
        all_recommendations.extend([
            "Implement proper input validation and sanitization",
            "Use strong cryptographic algorithms and proper key management",
            "Follow secure coding practices and OWASP guidelines",
            "Regularly update dependencies and security libraries",
            "Implement proper error handling and logging",
            "Use code obfuscation and anti-tampering measures for production",
        ])
        
        # Format recommendations (limit to top 10)
        for i, rec in enumerate(all_recommendations[:10], 1):
            recommendations_text.append(f"  {i}. {rec}\n", style="yellow")
        
        recommendations_text.append("\n")
        return recommendations_text
    
    def generate_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate summary data for caching and integration.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            Dict[str, Any]: Summary data
        """
        logger.info("Generating analysis summary")
        
        risk_assessment = analysis_results.get("risk_assessment", {})
        security_findings = analysis_results.get("security_findings", [])
        secret_analyses = analysis_results.get("secret_analysis", [])
        manifest_analysis = analysis_results.get("manifest_analysis", {})
        
        # Handle both RiskAssessment objects and dictionaries for summary
        if hasattr(risk_assessment, 'overall_risk'):
            # RiskAssessment dataclass object
            overall_risk = risk_assessment.overall_risk.value if hasattr(risk_assessment.overall_risk, 'value') else str(risk_assessment.overall_risk)
            risk_score = risk_assessment.risk_score
            critical_issues = risk_assessment.critical_issues
            high_issues = risk_assessment.high_issues
            medium_issues = risk_assessment.medium_issues
            low_issues = risk_assessment.low_issues
        else:
            # Dictionary format
            overall_risk = risk_assessment.get("overall_risk", "UNKNOWN")
            risk_score = risk_assessment.get("risk_score", 0.0)
            critical_issues = risk_assessment.get("critical_issues", 0)
            high_issues = risk_assessment.get("high_issues", 0)
            medium_issues = risk_assessment.get("medium_issues", 0)
            low_issues = risk_assessment.get("low_issues", 0)
        
        # Count high-confidence secrets
        high_confidence_secrets = [s for s in secret_analyses if getattr(s, 'confidence', 0) >= 0.7]
        
        # Count manifest issues
        manifest_issues = 0
        if manifest_analysis and "error" not in manifest_analysis:
            manifest_risk = manifest_analysis.get("risk_assessment", {})
            manifest_issues = manifest_risk.get("total_issues", 0)
        
        summary = {
            "overall_risk": overall_risk,
            "risk_score": risk_score,
            "total_findings": len(security_findings),
            "critical_findings": critical_issues,
            "high_findings": high_issues,
            "medium_findings": medium_issues,
            "low_findings": low_issues,
            "secrets_detected": len(high_confidence_secrets),
            "total_secrets": len(secret_analyses),
            "manifest_issues": manifest_issues,
            "timestamp": self._get_current_timestamp(),
            "analysis_version": "2.0.0"
        }
        
        logger.info("Summary generation completed")
        return summary
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp for summary."""
        import datetime
        return datetime.datetime.now().isoformat()
    
    def format_brief_summary(self, analysis_results: Dict[str, Any]) -> str:
        """
        Format brief summary for quick overview.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            str: Brief summary text
        """
        summary = self.generate_summary(analysis_results)
        
        risk_level = summary["overall_risk"]
        total_findings = summary["total_findings"]
        secrets_detected = summary["secrets_detected"]
        
        brief = f"Risk: {risk_level} | Findings: {total_findings} | Secrets: {secrets_detected}"
        return brief
    
    def format_json_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format JSON summary for API responses.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            Dict[str, Any]: JSON-serializable summary
        """
        summary = self.generate_summary(analysis_results)
        
        # Add additional metadata
        summary["analysis_type"] = "enhanced_static_analysis"
        summary["components_analyzed"] = [
            "security_findings",
            "secret_analysis",
            "manifest_analysis",
            "code_quality_metrics"
        ]
        
        return summary 

    def format_report(self, analysis_results) -> Tuple[str, Text]:
        """
        Format static analysis report (compatibility method).
        
        Args:
            analysis_results: Analysis results object or dictionary
            
        Returns:
            Tuple[str, Text]: Plain text summary and formatted rich text report
        """
        # Convert analysis results to dictionary format if needed
        if hasattr(analysis_results, '__dict__'):
            results_dict = analysis_results.__dict__
        else:
            results_dict = analysis_results
        
        # Generate the comprehensive report
        formatted_report = self.format_comprehensive_report(results_dict)
        
        # Create a plain text summary
        summary = "Enhanced Static Analysis completed successfully"
        if isinstance(results_dict, dict):
            findings_count = len(results_dict.get('security_findings', []))
            secrets_count = len(results_dict.get('secret_analysis', []))
            summary = f"Enhanced Static Analysis: {findings_count} security findings, {secrets_count} secrets detected"
        
        return summary, formatted_report 
    def _get_current_timestamp(self) -> str:
        """Get current timestamp for summary."""
        import datetime
        return datetime.datetime.now().isoformat()
    
    def format_brief_summary(self, analysis_results: Dict[str, Any]) -> str:
        """
        Format brief summary for quick overview.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            str: Brief summary text
        """
        summary = self.generate_summary(analysis_results)
        
        risk_level = summary["overall_risk"]
        total_findings = summary["total_findings"]
        secrets_detected = summary["secrets_detected"]
        
        brief = f"Risk: {risk_level} | Findings: {total_findings} | Secrets: {secrets_detected}"
        return brief
    
    def format_json_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format JSON summary for API responses.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            Dict[str, Any]: JSON-serializable summary
        """
        summary = self.generate_summary(analysis_results)
        
        # Add additional metadata
        summary["analysis_type"] = "enhanced_static_analysis"
        summary["components_analyzed"] = [
            "security_findings",
            "secret_analysis",
            "manifest_analysis",
            "code_quality_metrics"
        ]
        
        return summary 

    def format_report(self, analysis_results) -> Tuple[str, Text]:
        """
        Format static analysis report (compatibility method).
        
        Args:
            analysis_results: Analysis results object or dictionary
            
        Returns:
            Tuple[str, Text]: Plain text summary and formatted rich text report
        """
        # Convert analysis results to dictionary format if needed
        if hasattr(analysis_results, '__dict__'):
            results_dict = analysis_results.__dict__
        else:
            results_dict = analysis_results
        
        # Generate the comprehensive report
        formatted_report = self.format_comprehensive_report(results_dict)
        
        # Create a plain text summary
        summary = "Enhanced Static Analysis completed successfully"
        if isinstance(results_dict, dict):
            findings_count = len(results_dict.get('security_findings', []))
            secrets_count = len(results_dict.get('secret_analysis', []))
            summary = f"Enhanced Static Analysis: {findings_count} security findings, {secrets_count} secrets detected"
        
        return summary, formatted_report 
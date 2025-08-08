"""
Injection Vulnerability Report Formatter

This module handles the formatting of injection vulnerability analysis reports.
"""

import logging
from typing import Dict, List, Any, Union

from rich.text import Text

logger = logging.getLogger(__name__)

class InjectionReportFormatter:
    """
    Formatter for injection vulnerability analysis reports.
    
    Provides rich formatting for injection vulnerability analysis results.
    """
    
    def __init__(self):
        """Initialize the report formatter."""
        self.severity_colors = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "cyan"
        }
        
        self.risk_colors = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
            "MINIMAL": "green"
        }
    
    def format_injection_analysis_report(self, analysis_results: Dict[str, Any]) -> Union[str, Text]:
        """
        Format injection vulnerability analysis report.
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            Union[str, Text]: Formatted report
        """
        logger.info("Formatting injection vulnerability analysis report")
        
        # Check for cancellation
        if analysis_results.get("analysis_metadata", {}).get("status") == "cancelled":
            return Text.from_markup("[yellow]Analysis cancelled: Shutdown requested.[/yellow]")
        
        # Check for failure
        if analysis_results.get("analysis_metadata", {}).get("status") == "failed":
            error = analysis_results.get("analysis_metadata", {}).get("error", "Unknown error")
            return Text.from_markup(f"[red]Analysis failed: {error}[/red]")
        
        # Get analysis strategy and results
        analysis_strategy = analysis_results.get("analysis_strategy", {})
        dynamic_results = analysis_results.get("dynamic_analysis", {})
        static_results = analysis_results.get("static_analysis", {})
        vulnerabilities = analysis_results.get("vulnerabilities", [])
        risk_assessment = analysis_results.get("risk_assessment", {})
        
        # Format based on available results
        if analysis_strategy.get("use_dynamic", False) and dynamic_results.get("status") == "completed":
            return self._format_dynamic_analysis_report(dynamic_results, vulnerabilities, risk_assessment)
        elif analysis_strategy.get("use_static", False) and static_results.get("status") == "completed":
            return self._format_static_analysis_report(static_results, vulnerabilities, risk_assessment)
        else:
            return self._format_fallback_report(analysis_results)
    
    def _format_dynamic_analysis_report(self, dynamic_results: Dict[str, Any], vulnerabilities: List[Dict[str, Any]], risk_assessment: Dict[str, Any]) -> Union[str, Text]:
        """
        Format dynamic analysis report.
        
        Args:
            dynamic_results: Dynamic analysis results
            vulnerabilities: List of vulnerabilities
            risk_assessment: Risk assessment
            
        Returns:
            Union[str, Text]: Formatted report
        """
        # Check if vulnerabilities were found
        if risk_assessment.get("has_critical", False) or risk_assessment.get("has_high", False):
            return self._format_vulnerability_detected_report(vulnerabilities, risk_assessment, "dynamic")
        else:
            return self._format_no_vulnerabilities_report(dynamic_results, risk_assessment, "dynamic")
    
    def _format_static_analysis_report(self, static_results: Dict[str, Any], vulnerabilities: List[Dict[str, Any]], risk_assessment: Dict[str, Any]) -> Union[str, Text]:
        """
        Format static analysis report.
        
        Args:
            static_results: Static analysis results
            vulnerabilities: List of vulnerabilities
            risk_assessment: Risk assessment
            
        Returns:
            Union[str, Text]: Formatted report
        """
        # Check if vulnerabilities were found
        if vulnerabilities:
            return self._format_vulnerability_detected_report(vulnerabilities, risk_assessment, "static")
        else:
            return self._format_no_vulnerabilities_report(static_results, risk_assessment, "static")
    
    def _format_vulnerability_detected_report(self, vulnerabilities: List[Dict[str, Any]], risk_assessment: Dict[str, Any], analysis_type: str) -> Union[str, Text]:
        """
        Format report when vulnerabilities are detected.
        
        Args:
            vulnerabilities: List of vulnerabilities
            risk_assessment: Risk assessment
            analysis_type: Type of analysis (dynamic/static)
            
        Returns:
            Union[str, Text]: Formatted report
        """
        report = Text()
        
        # Header
        report.append("[!] SQL injection vulnerability detected!\n", style="bright_red")
        
        # Risk assessment
        risk_level = risk_assessment.get("risk_level", "UNKNOWN")
        risk_score = risk_assessment.get("risk_score", 0.0)
        risk_color = self.risk_colors.get(risk_level, "dim")
        
        report.append(f"Risk Level: {risk_level} ({risk_score:.2f})\n", style=f"bold {risk_color}")
        report.append(f"Analysis Type: {analysis_type.title()}\n", style="dim")
        report.append(f"Vulnerabilities Found: {len(vulnerabilities)}\n", style="dim")
        
        # Severity breakdown
        severity_counts = risk_assessment.get("severity_breakdown", {})
        for severity, count in severity_counts.items():
            if count > 0:
                color = self.severity_colors.get(severity, "dim")
                report.append(f"  {severity}: {count}\n", style=color)
        
        # Top vulnerabilities
        report.append("\nTop Vulnerabilities:\n", style="bold")
        for i, vuln in enumerate(vulnerabilities[:3], 1):
            vuln_type = vuln.get("type", "unknown")
            severity = vuln.get("severity", "LOW")
            location = vuln.get("location", "unknown")
            
            color = self.severity_colors.get(severity, "dim")
            report.append(f"  {i}. {vuln_type} in {location} ({severity})\n", style=color)
        
        if len(vulnerabilities) > 3:
            report.append(f"  ... and {len(vulnerabilities) - 3} more\n", style="dim")
        
        # Recommendations
        report.append("\nImmediate Actions Required:\n", style="bold yellow")
        report.append("  1. Use parameterized queries\n", style="yellow")
        report.append("  2. Implement input validation\n", style="yellow")
        report.append("  3. Add proper access controls\n", style="yellow")
        report.append("  4. Review all content providers\n", style="yellow")
        
        return report
    
    def _format_no_vulnerabilities_report(self, analysis_results: Dict[str, Any], risk_assessment: Dict[str, Any], analysis_type: str) -> Union[str, Text]:
        """
        Format report when no vulnerabilities are detected.
        
        Args:
            analysis_results: Analysis results
            risk_assessment: Risk assessment
            analysis_type: Type of analysis (dynamic/static)
            
        Returns:
            Union[str, Text]: Formatted report
        """
        report = Text()
        
        # Header
        report.append("[+] No SQL injection vulnerabilities detected.\n", style="green")
        
        # Analysis details
        report.append(f"Analysis Type: {analysis_type.title()}\n", style="dim")
        report.append("Analysis completed successfully. All content providers tested are secure.\n", style="green")
        
        # Analysis confidence
        confidence = risk_assessment.get("analysis_confidence", 0.0)
        if confidence > 0:
            report.append(f"Analysis Confidence: {confidence:.1%}\n", style="dim")
        
        # Analysis time
        analysis_time = analysis_results.get("analysis_time", 0.0)
        if analysis_time > 0:
            report.append(f"Analysis Time: {analysis_time:.1f}s\n", style="dim")
        
        return report
    
    def _format_fallback_report(self, analysis_results: Dict[str, Any]) -> Union[str, Text]:
        """
        Format fallback report for error cases.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            Union[str, Text]: Formatted report
        """
        # Check specific error conditions
        analysis_strategy = analysis_results.get("analysis_strategy", {})
        rationale = analysis_strategy.get("rationale", [])
        
        if "Package name not available" in " ".join(rationale):
            return Text.from_markup("[yellow]Analysis skipped: Package name not available.[/yellow]")
        
        # Check for Drozer unavailability
        if "Drozer not available" in " ".join(rationale):
            static_results = analysis_results.get("static_analysis", {})
            if static_results.get("status") == "completed":
                vulnerabilities = analysis_results.get("vulnerabilities", [])
                risk_assessment = analysis_results.get("risk_assessment", {})
                
                if vulnerabilities:
                    report = Text()
                    report.append("[yellow]Dynamic analysis unavailable - Static analysis result:[/yellow]\n")
                    report.append(self._format_vulnerability_detected_report(vulnerabilities, risk_assessment, "static"))
                    return report
                else:
                    return Text.from_markup(
                        "[yellow]Dynamic analysis unavailable - Static analysis result:[/yellow]\n"
                        "[green]No SQL injection vulnerabilities detected in static analysis.[/green]"
                    )
        
        # Generic error fallback
        return Text.from_markup("[yellow]Analysis failed: Unable to complete injection vulnerability analysis.[/yellow]")
    
    def generate_analysis_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate analysis summary for caching and integration.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            Dict[str, Any]: Summary data
        """
        logger.info("Generating injection vulnerability analysis summary")
        
        vulnerabilities = analysis_results.get("vulnerabilities", [])
        risk_assessment = analysis_results.get("risk_assessment", {})
        analysis_strategy = analysis_results.get("analysis_strategy", {})
        
        summary = {
            "analysis_type": "injection_vulnerability",
            "analysis_mode": analysis_results.get("analysis_mode", "unknown"),
            "vulnerabilities_found": len(vulnerabilities),
            "risk_level": risk_assessment.get("risk_level", "UNKNOWN"),
            "risk_score": risk_assessment.get("risk_score", 0.0),
            "has_critical": risk_assessment.get("has_critical", False),
            "has_high": risk_assessment.get("has_high", False),
            "analysis_confidence": risk_assessment.get("analysis_confidence", 0.0),
            "primary_method": analysis_strategy.get("primary_method", "unknown"),
            "methods_used": [],
            "timestamp": self._get_current_timestamp(),
            "status": analysis_results.get("analysis_metadata", {}).get("status", "unknown")
        }
        
        # Determine methods used
        if analysis_results.get("dynamic_analysis", {}).get("status") == "completed":
            summary["methods_used"].append("dynamic")
        if analysis_results.get("static_analysis", {}).get("status") == "completed":
            summary["methods_used"].append("static")
        
        # Add vulnerability breakdown
        severity_counts = risk_assessment.get("severity_breakdown", {})
        summary["vulnerability_breakdown"] = {
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0)
        }
        
        logger.info("Summary generation completed")
        return summary
    
    def format_brief_summary(self, analysis_results: Dict[str, Any]) -> str:
        """
        Format brief summary for quick overview.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            str: Brief summary text
        """
        summary = self.generate_analysis_summary(analysis_results)
        
        risk_level = summary["risk_level"]
        vuln_count = summary["vulnerabilities_found"]
        method = summary["primary_method"]
        
        return f"Injection Analysis: {risk_level} risk | {vuln_count} vulnerabilities | Method: {method}"
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp for summary."""
        import datetime
        return datetime.datetime.now().isoformat()
    
    def format_legacy_report(self, analysis_results: Dict[str, Any]) -> str:
        """
        Format legacy-style report for backward compatibility.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            str: Legacy-formatted report
        """
        vulnerabilities = analysis_results.get("vulnerabilities", [])
        risk_assessment = analysis_results.get("risk_assessment", {})
        
        if risk_assessment.get("has_critical", False) or risk_assessment.get("has_high", False):
            # Format as vulnerability detected
            vuln_details = []
            for vuln in vulnerabilities[:3]:  # Top 3
                vuln_type = vuln.get("type", "unknown")
                location = vuln.get("location", "unknown")
                severity = vuln.get("severity", "UNKNOWN")
                vuln_details.append(f"  - {vuln_type} in {location} ({severity})")
            
            result = "❌ SQL injection vulnerabilities detected!\n"
            result += f"Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}\n"
            result += f"Vulnerabilities: {len(vulnerabilities)}\n"
            result += "Top Issues:\n"
            result += "\n".join(vuln_details)
            
            return result
        else:
            # Format as no vulnerabilities
            return "✅ No SQL injection vulnerabilities detected.\nAll content providers tested are secure." 
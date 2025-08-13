#!/usr/bin/env python3
"""
Output Manager for AODS - Enhanced with Enterprise Intelligence

This module provides centralized output management with enterprise intelligence
features including trend analysis, risk assessment, and comprehensive reporting.

Features:
- Standardized output formatting with consistent styling
- Configurable verbosity levels (QUIET, NORMAL, VERBOSE, DEBUG)
- Progress tracking with visual indicators
- Enterprise intelligence reporting
- Trend analysis visualization
- Risk assessment displays
- Executive summary generation

"""

import logging
import sys
from enum import IntEnum
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn,
                           TaskProgressColumn, TextColumn)
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich.align import Align

class OutputLevel(IntEnum):
    """Output verbosity levels."""

    QUIET = 0  # Only critical errors and final results
    NORMAL = 1  # Standard user-facing messages
    VERBOSE = 2  # Detailed progress and status information
    DEBUG = 3  # Debug information and technical details

class OutputManager:
    """
    Enhanced output management with enterprise intelligence features.

    Provides consistent formatting, verbosity control, progress tracking,
    and advanced enterprise intelligence reporting capabilities.
    """

    def __init__(self, level: OutputLevel = OutputLevel.NORMAL, quiet: bool = False):
        """
        Initialize the enhanced output manager.

        Args:
            level: Default output verbosity level
            quiet: If True, suppress all non-critical output
        """
        self.console = Console()
        self.level = OutputLevel.QUIET if quiet else level
        self.progress: Optional[Progress] = None
        self.current_task = None

        # Configure logging to use our output system
        self._configure_logging()

    def _configure_logging(self) -> None:
        """Configure logging to integrate with output manager."""
        # Enhanced logging configuration to show scan activities
        if self.level == OutputLevel.QUIET:
            logging.getLogger().setLevel(logging.ERROR)
        elif self.level == OutputLevel.NORMAL:
            # ENHANCED: Show INFO level in normal mode to display scan activities
            logging.getLogger().setLevel(logging.INFO)
        elif self.level == OutputLevel.VERBOSE:
            logging.getLogger().setLevel(logging.INFO)
        else:  # DEBUG
            logging.getLogger().setLevel(logging.DEBUG)
            
        # Configure specific loggers for better visibility
        logging.getLogger('plugin_manager').setLevel(logging.INFO)
        logging.getLogger('vulnerability_classifier').setLevel(logging.INFO)
        logging.getLogger('source_code_analyzer').setLevel(logging.INFO)
        logging.getLogger('report_generator').setLevel(logging.INFO)

    def banner(self, title: str, subtitle: str = "") -> None:
        """Display application banner."""
        if self.level == OutputLevel.QUIET:
            return

        banner_text = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🛡️  AUTOMATED OWASP DYNAMIC SCANNER                      ║
║                    Advanced Mobile Security Testing Suite                    ║
║                         Enterprise Intelligence Edition                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """

        self.console.print(
            Panel(
                Text(banner_text, style="bold blue"),
                title=f"[bold white]{title}[/bold white]",
                subtitle=f"[dim]{subtitle}[/dim]" if subtitle else "",
                border_style="blue",
            )
        )

    def enterprise_intelligence_summary(self, intelligence_report: Dict[str, Any]) -> None:
        """Display enterprise intelligence summary."""
        if self.level == OutputLevel.QUIET:
            return
        
        scan_intel = intelligence_report.get("scan_intelligence", {})
        vuln_intel = intelligence_report.get("vulnerability_intelligence", {})
        risk_assessment = intelligence_report.get("risk_assessment", {})
        
        # Main intelligence panel
        self.console.print("\n")
        self.console.print(Panel.fit(
            f"[bold blue]🏢 ENTERPRISE INTELLIGENCE REPORT[/bold blue]\n"
            f"[white]Scan ID:[/white] {scan_intel.get('scan_id', 'N/A')}\n"
            f"[white]Package:[/white] {scan_intel.get('package_name', 'N/A')}\n"
            f"[white]Timestamp:[/white] {scan_intel.get('timestamp', 'N/A')[:19]}",
            border_style="blue"
        ))
        
        # Risk Assessment
        risk_level = risk_assessment.get("risk_level", "UNKNOWN")
        risk_score = risk_assessment.get("risk_score", 0)
        
        risk_color = {
            "CRITICAL": "bright_red",
            "HIGH": "red", 
            "MEDIUM": "yellow",
            "LOW": "green",
            "MINIMAL": "bright_green"
        }.get(risk_level, "white")
        
        risk_panel = Panel(
            f"[{risk_color}]Risk Level: {risk_level}[/{risk_color}]\n"
            f"[white]Risk Score: {risk_score:.1f}/100[/white]\n"
            f"[white]Overall Confidence: {scan_intel.get('confidence_score', 0):.1%}[/white]",
            title="🎯 Risk Assessment",
            border_style=risk_color
        )
        
        # Vulnerability Intelligence  
        severity_dist = vuln_intel.get("severity_distribution", {})
        vuln_panel = Panel(
            f"[red]Critical: {severity_dist.get('critical', 0)}[/red]\n"
            f"[orange1]High: {severity_dist.get('high', 0)}[/orange1]\n"
            f"[yellow]Medium: {severity_dist.get('medium', 0)}[/yellow]\n"
            f"[blue]Low: {severity_dist.get('low', 0)}[/blue]\n"
            f"[white]Total: {vuln_intel.get('total_vulnerabilities', 0)}[/white]",
            title="🔍 Vulnerability Analysis",
            border_style="cyan"
        )
        
        # Create side-by-side layout
        from rich.columns import Columns
        self.console.print(Columns([risk_panel, vuln_panel], equal=True))
        
        # Additional metrics
        self.console.print(f"\n[bold]📊 Quality Metrics[/bold]")
        self.console.print(f"  • False Positive Rate: {vuln_intel.get('false_positive_ratio', 0):.1%}")
        self.console.print(f"  • MASTG Compliance: {vuln_intel.get('mastg_compliance', 0):.1%}")

    def trend_analysis_summary(self, trends: List[Dict[str, Any]]) -> None:
        """Display trend analysis summary."""
        if self.level == OutputLevel.QUIET or not trends:
            return
            
        self.console.print("\n[bold blue]📈 TREND ANALYSIS[/bold blue]")
        
        trend_table = Table(title="Security Trend Overview")
        trend_table.add_column("Metric", style="cyan", no_wrap=True)
        trend_table.add_column("Current", justify="right")
        trend_table.add_column("Previous", justify="right") 
        trend_table.add_column("Trend", justify="center")
        trend_table.add_column("Change", justify="right")
        
        for trend in trends:
            trend_direction = trend.get("trend_direction", "UNKNOWN")
            trend_icon = {
                "IMPROVING": "📈",
                "STABLE": "➡️", 
                "DEGRADING": "📉",
                "UNKNOWN": "❓"
            }.get(trend_direction, "❓")
            
            trend_color = {
                "IMPROVING": "green",
                "STABLE": "yellow",
                "DEGRADING": "red", 
                "UNKNOWN": "white"
            }.get(trend_direction, "white")
            
            current_val = trend.get("current_value", 0)
            previous_val = trend.get("previous_value", 0)
            change_pct = trend.get("change_percentage", 0)
            
            trend_table.add_row(
                trend.get("metric_name", "Unknown"),
                f"{current_val:.2f}",
                f"{previous_val:.2f}",
                f"[{trend_color}]{trend_icon}[/{trend_color}]",
                f"[{trend_color}]{change_pct:.1f}%[/{trend_color}]"
            )
        
        self.console.print(trend_table)

    def plugin_intelligence_summary(self, plugins: List[Dict[str, Any]]) -> None:
        """Display plugin intelligence summary."""
        if self.level == OutputLevel.QUIET or not plugins:
            return
            
        self.console.print("\n[bold blue]🔌 PLUGIN INTELLIGENCE[/bold blue]")
        
        plugin_table = Table(title="Plugin Performance Analysis")
        plugin_table.add_column("Plugin", style="cyan")
        plugin_table.add_column("Exec Time", justify="right")
        plugin_table.add_column("Vulns Found", justify="center")
        plugin_table.add_column("Confidence", justify="right")
        plugin_table.add_column("Accuracy", justify="right")
        plugin_table.add_column("Status", justify="center")
        
        for plugin in plugins:
            exec_time = plugin.get("execution_time", 0)
            vuln_count = plugin.get("vulnerability_count", 0)
            confidence = plugin.get("confidence_average", 0)
            accuracy = plugin.get("detection_accuracy", 0)
            
            # Determine status
            if exec_time > 30:
                status = "[red]SLOW[/red]"
            elif accuracy < 0.6:
                status = "[yellow]LOW ACC[/yellow]"  
            elif confidence < 0.6:
                status = "[yellow]LOW CONF[/yellow]"
            else:
                status = "[green]GOOD[/green]"
            
            plugin_table.add_row(
                plugin.get("plugin_name", "Unknown"),
                f"{exec_time:.1f}s",
                str(vuln_count),
                f"{confidence:.1%}",
                f"{accuracy:.1%}",
                status
            )
        
        self.console.print(plugin_table)

    def executive_summary(self, summary_text: str) -> None:
        """Display executive summary for leadership."""
        if self.level == OutputLevel.QUIET:
            return
            
        self.console.print("\n")
        self.console.print(Panel(
            summary_text,
            title="[bold white]👔 EXECUTIVE SUMMARY[/bold white]",
            border_style="gold1",
            padding=(1, 2)
        ))

    def enterprise_recommendations(self, recommendations: List[str]) -> None:
        """Display enterprise recommendations."""
        if self.level == OutputLevel.QUIET or not recommendations:
            return
            
        self.console.print("\n[bold blue]💡 ENTERPRISE RECOMMENDATIONS[/bold blue]")
        
        for i, rec in enumerate(recommendations, 1):
            # Parse recommendation priority from emoji/prefix
            if rec.startswith("🚨"):
                style = "bright_red"
            elif rec.startswith("⚠️"):
                style = "yellow"
            elif rec.startswith("📈"):
                style = "blue"
            elif rec.startswith("⚡"):
                style = "cyan"
            else:
                style = "white"
                
            self.console.print(f"  [{style}]{i}. {rec}[/{style}]")

    def risk_factors_analysis(self, risk_factors: List[str]) -> None:
        """Display risk factors analysis."""
        if self.level == OutputLevel.QUIET or not risk_factors:
            return
            
        self.console.print("\n[bold red]⚠️ IDENTIFIED RISK FACTORS[/bold red]")
        
        for factor in risk_factors:
            self.console.print(f"  [red]•[/red] {factor}")

    def compliance_status(self, mastg_score: float, compliance_details: Dict = None) -> None:
        """Display compliance status."""
        if self.level == OutputLevel.QUIET:
            return
            
        # Determine compliance level
        if mastg_score >= 0.8:
            compliance_level = "EXCELLENT"
            compliance_color = "bright_green"
        elif mastg_score >= 0.6:
            compliance_level = "GOOD" 
            compliance_color = "green"
        elif mastg_score >= 0.4:
            compliance_level = "MODERATE"
            compliance_color = "yellow"
        else:
            compliance_level = "POOR"
            compliance_color = "red"
            
        self.console.print(f"\n[bold blue]📋 COMPLIANCE STATUS[/bold blue]")
        self.console.print(f"  MASTG Compliance: [{compliance_color}]{compliance_level}[/{compliance_color}] ({mastg_score:.1%})")
        
        if compliance_details:
            self.console.print("  Detailed Breakdown:")
            for category, score in compliance_details.items():
                if isinstance(score, (int, float)):
                    self.console.print(f"    • {category}: {score:.1%}")

    def performance_metrics(self, scan_duration: float, plugin_stats: Dict = None) -> None:
        """Display performance metrics."""
        if self.level < OutputLevel.VERBOSE:
            return
            
        self.console.print(f"\n[bold blue]⚡ PERFORMANCE METRICS[/bold blue]")
        self.console.print(f"  Total Scan Duration: {scan_duration:.1f} seconds")
        
        if plugin_stats:
            self.console.print("  Plugin Performance:")
            for plugin_name, stats in plugin_stats.items():
                exec_time = stats.get("execution_time", 0)
                self.console.print(f"    • {plugin_name}: {exec_time:.1f}s")

    def enhanced_vulnerability_summary(self, vulnerabilities: List[Dict[str, Any]], 
                                     classification_stats: Dict = None) -> None:
        """Enhanced vulnerability summary with classification intelligence."""
        if not vulnerabilities:
            self.status("No vulnerabilities detected", "success")
            return

        # Vulnerability distribution
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        confidence_scores = []
        false_positive_count = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "INFO").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Track confidence if available
            confidence = vuln.get("confidence_score", vuln.get("confidence"))
            if confidence:
                confidence_scores.append(float(confidence))
            
            # Count false positives
            fp_indicators = vuln.get("false_positive_indicators", [])
            if len(fp_indicators) >= 2:
                false_positive_count += 1

        # Create vulnerability summary table
        vuln_table = Table(title="🔍 Vulnerability Analysis Summary")
        vuln_table.add_column("Severity", style="cyan", no_wrap=True)
        vuln_table.add_column("Count", justify="right")
        vuln_table.add_column("Percentage", justify="right")

        total_vulns = len(vulnerabilities)
        
        for severity, count in severity_counts.items():
            if count > 0:
                percentage = (count / total_vulns) * 100
                severity_color = {
                    "CRITICAL": "bright_red",
                    "HIGH": "red",
                    "MEDIUM": "yellow", 
                    "LOW": "blue",
                    "INFO": "dim"
                }.get(severity, "white")
                
                vuln_table.add_row(
                    f"[{severity_color}]{severity}[/{severity_color}]",
                    f"[{severity_color}]{count}[/{severity_color}]",
                    f"[{severity_color}]{percentage:.1f}%[/{severity_color}]"
                )

        self.console.print(vuln_table)
        
        # Quality metrics
        if confidence_scores:
            avg_confidence = sum(confidence_scores) / len(confidence_scores)
            self.console.print(f"\n[bold]Quality Metrics:[/bold]")
            self.console.print(f"  • Average Confidence: {avg_confidence:.1%}")
        
        if false_positive_count > 0:
            fp_rate = (false_positive_count / total_vulns) * 100
            self.console.print(f"  • Potential False Positives: {false_positive_count} ({fp_rate:.1f}%)")
        
        # Classification stats if available
        if classification_stats:
            self.console.print(f"\n[bold]Classification Intelligence:[/bold]")
            self.console.print(f"  • Enhanced Classification: {classification_stats.get('enhanced_classification_applied', 'No')}")
            self.console.print(f"  • Classifier Version: {classification_stats.get('classifier_version', 'Unknown')}")
            if "deduplication_reduction" in classification_stats:
                self.console.print(f"  • Deduplication Reduction: {classification_stats['deduplication_reduction']:.1f}%")

    def section_header(self, title: str, description: str = "") -> None:
        """Display a section header."""
        if self.level == OutputLevel.QUIET:
            return

        self.console.print(f"\n[bold blue]{'='*60}[/bold blue]")
        self.console.print(f"[bold white]📋 {title}[/bold white]")
        if description:
            self.console.print(f"[dim]{description}[/dim]")
        self.console.print(f"[bold blue]{'='*60}[/bold blue]")

    def status(self, message: str, status: str = "info") -> None:
        """Display a status message."""
        if self.level == OutputLevel.QUIET:
            return

        status_icons = {
            "info": "ℹ️",
            "success": "✅",
            "warning": "⚠️",
            "error": "❌",
            "progress": "🔄",
        }

        status_colors = {
            "info": "blue",
            "success": "green",
            "warning": "yellow",
            "error": "red",
            "progress": "cyan",
        }

        icon = status_icons.get(status, "ℹ️")
        color = status_colors.get(status, "white")

        self.console.print(f"[{color}]{icon} {message}[/{color}]")

    def force_enable_progress_bars(self) -> None:
        """Force enable progress bars by ensuring output level is not QUIET."""
        if self.level == OutputLevel.QUIET:
            self.level = OutputLevel.NORMAL
            self._configure_logging()
            self.info("🔄 Progress bars force-enabled - output level set to NORMAL")

    def ensure_progress_visibility(self) -> None:
        """Ensure progress bars will be visible by checking and adjusting output level."""
        if self.level == OutputLevel.QUIET:
            original_level = self.level
            self.level = OutputLevel.NORMAL
            self._configure_logging()
            self.debug(f"Progress visibility ensured - changed from {original_level.name} to {self.level.name}")

    def progress_start(self, description: str, total: Optional[int] = None) -> None:
        """Start a progress indicator."""
        # Ensure progress bars will be visible
        self.ensure_progress_visibility()
        
        if self.level == OutputLevel.QUIET:
            return

        if total:
            self.progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console,
            )
        else:
            self.progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            )

        self.progress.start()
        self.current_task = self.progress.add_task(description, total=total)

    def progress_update(self, advance: int = 1, description: str = None) -> None:
        """Update progress indicator."""
        if self.progress and self.current_task is not None:
            if description:
                self.progress.update(self.current_task, description=description)
            self.progress.advance(self.current_task, advance)

    def progress_stop(self) -> None:
        """Stop progress indicator."""
        if self.progress:
            self.progress.stop()
            self.progress = None
            self.current_task = None

    def test_result(self, test_name: str, status: str, details: str = "") -> None:
        """Display test result in standardized format."""
        if self.level == OutputLevel.QUIET and status not in ["FAIL", "ERROR"]:
            return

        status_styles = {
            "PASS": "green bold",
            "FAIL": "red bold",
            "SKIP": "yellow",
            "ERROR": "red bold",
            "INFO": "blue",
        }

        status_icons = {
            "PASS": "✅",
            "FAIL": "❌",
            "SKIP": "⏭️",
            "ERROR": "💥",
            "INFO": "ℹ️",
        }

        style = status_styles.get(status, "white")
        icon = status_icons.get(status, "•")

        self.console.print(
            f"  {icon} [bold]{test_name}[/bold]: [{style}]{status}[/{style}]"
        )

        if details and self.level >= OutputLevel.VERBOSE:
            # Indent details for readability
            indented_details = "\n".join(f"    {line}" for line in details.split("\n"))
            self.console.print(f"[dim]{indented_details}[/dim]")

    def vulnerability_summary(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """Display vulnerability summary (legacy method - enhanced version available)."""
        self.enhanced_vulnerability_summary(vulnerabilities)

    def scan_summary(self, metadata: Dict[str, Any]) -> None:
        """Display scan summary with enhanced metrics."""
        if self.level == OutputLevel.QUIET:
            return

        self.console.print("\n[bold blue]📊 SCAN SUMMARY[/bold blue]")
        
        # Basic scan info
        package_name = metadata.get("package_name", "Unknown")
        scan_duration = metadata.get("scan_duration", 0)
        
        self.console.print(f"  📱 Package: [cyan]{package_name}[/cyan]")
        self.console.print(f"  ⏱️  Duration: {scan_duration:.1f} seconds")
        
        # Enhanced metrics if available
        if "total_tests_run" in metadata:
            self.console.print(f"  🧪 Tests Run: {metadata['total_tests_run']}")
        
        if "vulnerabilities_found" in metadata:
            self.console.print(f"  🔍 Vulnerabilities: {metadata['vulnerabilities_found']}")

    def error(self, message: str, details: str = "") -> None:
        """Display error message."""
        self.console.print(f"[red bold]❌ ERROR: {message}[/red bold]")
        if details and self.level >= OutputLevel.VERBOSE:
            self.console.print(f"[red dim]{details}[/red dim]")

    def warning(self, message: str) -> None:
        """Display warning message."""
        if self.level >= OutputLevel.NORMAL:
            self.console.print(f"[yellow]⚠️  WARNING: {message}[/yellow]")

    def info(self, message: str, description: str = "") -> None:
        """Display informational message."""
        if self.level == OutputLevel.QUIET:
            return

        if description:
            self.console.print(f"[cyan]ℹ️[/cyan] {message}")
            self.console.print(f"   {description}")
        else:
            self.console.print(f"[cyan]ℹ️[/cyan] {message}")

    def success(self, message: str, description: str = "") -> None:
        """Display success message."""
        if self.level == OutputLevel.QUIET:
            return

        if description:
            self.console.print(f"[green]✅[/green] {message}")
            self.console.print(f"   {description}")
        else:
            self.console.print(f"[green]✅[/green] {message}")

    def debug(self, message: str) -> None:
        """Display debug message."""
        if self.level >= OutputLevel.DEBUG:
            self.console.print(f"[dim]🐛 DEBUG: {message}[/dim]")

    def verbose(self, message: str) -> None:
        """Display verbose message."""
        if self.level >= OutputLevel.VERBOSE:
            self.console.print(f"[cyan]📝 {message}[/cyan]")

    def report_generated(self, file_paths: Dict[str, str]) -> None:
        """Display report generation summary with enhanced format."""
        if self.level == OutputLevel.QUIET:
            return

        self.console.print("\n[bold green]📄 REPORTS GENERATED[/bold green]")

        for report_type, file_path in file_paths.items():
            # Get file size if possible
            try:
                from pathlib import Path
                file_size = Path(file_path).stat().st_size
                size_str = f" ({file_size:,} bytes)"
            except:
                size_str = ""
                
            self.console.print(f"  📋 {report_type}: [cyan]{file_path}[/cyan]{size_str}")

    def cleanup_debug_output(self, text: str) -> str:
        """Clean up debug output for production display."""
        if self.level >= OutputLevel.DEBUG:
            return text  # Keep all output in debug mode

        # Remove common debug patterns
        import re
        
        patterns_to_remove = [
            r"DEBUG:.*?\n",
            r"\[DEBUG\].*?\n",
            r"Traceback \(most recent call last\):.*?(?=\n[A-Z]|\n$)",
            r"^\s*at .*?\n",
            r"^\s*File \".*?\n",
            r"Exception in thread.*?\n",
        ]

        cleaned_text = text
        for pattern in patterns_to_remove:
            cleaned_text = re.sub(pattern, "", cleaned_text, flags=re.MULTILINE | re.DOTALL)

        # Remove excessive whitespace
        cleaned_text = re.sub(r"\n\s*\n\s*\n", "\n\n", cleaned_text)
        cleaned_text = cleaned_text.strip()

        return cleaned_text

# Global output manager instance
_output_manager: Optional[OutputManager] = None

def get_output_manager() -> OutputManager:
    """Get the global output manager instance."""
    global _output_manager
    if _output_manager is None:
        _output_manager = OutputManager()
    return _output_manager

def set_output_level(level: OutputLevel) -> None:
    """Set the global output verbosity level."""
    global _output_manager
    if _output_manager is None:
        _output_manager = OutputManager(level)
    else:
        _output_manager.level = level
        _output_manager._configure_logging()

def set_quiet_mode(quiet: bool = True) -> None:
    """Enable or disable quiet mode."""
    global _output_manager
    if _output_manager is None:
        _output_manager = OutputManager(quiet=quiet)
    else:
        _output_manager.level = OutputLevel.QUIET if quiet else OutputLevel.NORMAL
        _output_manager._configure_logging()

def status(message: str, status_type: str = "info") -> None:
    """Display a status message using the global output manager."""
    get_output_manager().status(message, status_type)

def error(message: str, details: str = "") -> None:
    """Display an error message using the global output manager."""
    get_output_manager().error(message, details)

def warning(message: str) -> None:
    """Display a warning message using the global output manager."""
    get_output_manager().warning(message)

def debug(message: str) -> None:
    """Display a debug message using the global output manager."""
    get_output_manager().debug(message)

def verbose(message: str) -> None:
    """Display a verbose message using the global output manager."""
    get_output_manager().verbose(message)

def force_enable_progress_bars() -> None:
    """Force enable progress bars globally."""
    global _output_manager
    if _output_manager is None:
        _output_manager = OutputManager(OutputLevel.NORMAL)
    else:
        _output_manager.force_enable_progress_bars()

def ensure_progress_visibility() -> None:
    """Ensure progress bars are visible globally."""
    global _output_manager
    if _output_manager is None:
        _output_manager = OutputManager(OutputLevel.NORMAL)
    else:
        _output_manager.ensure_progress_visibility()

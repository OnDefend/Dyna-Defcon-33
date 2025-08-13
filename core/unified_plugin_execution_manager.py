"""
Unified Plugin Execution Manager for AODS

This module provides a robust, production-ready plugin execution system that:
- Prevents premature scan termination through unified timeout management
- Integrates with graceful shutdown manager for coordinated cleanup
- Implements organic detection without hardcoding
- Provides comprehensive error handling and recovery
- Ensures all plugins run to completion according to AODS requirements
- Enhanced with comprehensive user notification and analysis transparency system
"""

import logging
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future, TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from rich.text import Text
from rich.panel import Panel
from rich.console import Console

try:
    from core.graceful_shutdown_manager import (
        get_shutdown_manager, 
        is_shutdown_requested,
        plugin_context,
        GracefulShutdownManager
    )
    GRACEFUL_SHUTDOWN_AVAILABLE = True
except ImportError:
    GRACEFUL_SHUTDOWN_AVAILABLE = False
    def is_shutdown_requested():
        return False
    def plugin_context(name):
        from contextlib import nullcontext
        return nullcontext()

logger = logging.getLogger(__name__)

class PluginExecutionState(Enum):
    """Plugin execution states for tracking progress."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"

@dataclass
class PluginExecutionConfig:
    """Configuration for plugin execution behavior."""
    default_timeout: int = 60  # Default plugin timeout in seconds
    max_timeout: int = 900     # Maximum allowed timeout (increased from 180 to 900 for JADX)
    retry_attempts: int = 2    # Number of retry attempts on failure
    retry_delay: float = 2.0   # Delay between retries
    enable_timeout_escalation: bool = True  # Escalate timeouts on retry
    check_shutdown_interval: float = 0.5   # How often to check for shutdown
    max_concurrent_plugins: int = 3         # Maximum concurrent plugin executions
    enable_recovery: bool = True            # Enable automatic recovery
    log_execution_details: bool = True      # Log detailed execution information

@dataclass
class PluginExecutionResult:
    """Result of plugin execution with comprehensive metadata."""
    plugin_name: str
    module_name: str
    state: PluginExecutionState
    title: Optional[str] = None
    content: Optional[Any] = None
    error_message: Optional[str] = None
    execution_time: float = 0.0
    timeout_used: int = 0
    retry_count: int = 0
    shutdown_requested: bool = False
    recovery_attempted: bool = False

@dataclass
class FileAccessFailure:
    """Represents a file access failure with comprehensive details."""
    file_path: str
    operation_type: str  # "read", "write", "parse", "analyze"
    error_type: str  # "FileNotFound", "PermissionDenied", "CorruptedFile", etc.
    error_message: str
    plugin_name: str
    impact_level: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    workaround_available: bool
    technical_details: Dict[str, Any]
    user_guidance: str
    timestamp: float = field(default_factory=time.time)

@dataclass
class AnalysisCoverageReport:
    """Comprehensive analysis coverage and limitation reporting."""
    plugin_name: str
    total_checks: int
    successful_checks: int
    failed_checks: int
    skipped_checks: int
    coverage_percentage: float
    analysis_depth: str  # "SURFACE", "STANDARD", "DEEP", "COMPREHENSIVE"
    limitations: List[str]
    security_controls_covered: List[str]
    security_controls_missed: List[str]
    confidence_level: float
    analysis_quality: str  # "EXCELLENT", "GOOD", "FAIR", "POOR"
    timestamp: float = field(default_factory=time.time)

@dataclass
class UserNotification:
    """Enhanced user notification with detailed context."""
    notification_id: str
    level: str  # "INFO", "WARNING", "ERROR", "CRITICAL"
    category: str  # "FILE_ACCESS", "ANALYSIS_LIMITATION", "SECURITY_FINDING", "SYSTEM_ERROR"
    title: str
    message: str
    technical_details: Dict[str, Any]
    user_guidance: str
    action_required: bool
    remediation_steps: List[str]
    impact_assessment: str
    visibility_level: str  # "PROMINENT", "STANDARD", "DEBUG"
    plugin_context: str
    timestamp: float = field(default_factory=time.time)

class UserNotificationSystem:
    """
    Comprehensive user notification system for analysis transparency.
    
    Provides:
    - File reading failure notifications with detailed context
    - Analysis coverage and limitation reporting
    - Prominent display of critical issues
    - User-friendly error explanations with remediation guidance
    - Technical detail preservation for expert users
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.UserNotificationSystem")
        self.console = Console()
        
        # Notification storage
        self.file_access_failures: List[FileAccessFailure] = []
        self.analysis_coverage_reports: List[AnalysisCoverageReport] = []
        self.user_notifications: List[UserNotification] = []
        
        # Notification counters
        self.notification_counter = 0
        self.critical_notifications = 0
        self.error_notifications = 0
        self.warning_notifications = 0
        
        # Display settings
        self.show_technical_details = True
        self.prominent_error_threshold = 3  # Show prominent display after 3 errors
        
        self.logger.info("🔔 User Notification System initialized")
    
    def report_file_access_failure(self, file_path: str, operation_type: str, 
                                 error: Exception, plugin_name: str, 
                                 impact_level: str = "MEDIUM") -> str:
        """
        Report comprehensive file access failure with user guidance.
        
        Args:
            file_path: Path to the file that failed
            operation_type: Type of operation that failed
            error: Exception that occurred
            plugin_name: Name of the plugin that encountered the failure
            impact_level: Impact level of the failure
            
        Returns:
            Notification ID for tracking
        """
        notification_id = f"file_access_{self.notification_counter}"
        self.notification_counter += 1
        
        # Determine error type and details
        error_type = type(error).__name__
        error_message = str(error)
        
        # Generate technical details
        technical_details = {
            "exception_type": error_type,
            "exception_message": error_message,
            "file_path": file_path,
            "operation_type": operation_type,
            "plugin_name": plugin_name,
            "error_context": self._analyze_error_context(error)
        }
        
        # Generate user guidance
        user_guidance = self._generate_file_access_guidance(
            file_path, operation_type, error_type, impact_level
        )
        
        # Check for workarounds
        workaround_available = self._check_workaround_availability(
            file_path, operation_type, error_type
        )
        
        # Create file access failure record
        failure = FileAccessFailure(
            file_path=file_path,
            operation_type=operation_type,
            error_type=error_type,
            error_message=error_message,
            plugin_name=plugin_name,
            impact_level=impact_level,
            workaround_available=workaround_available,
            technical_details=technical_details,
            user_guidance=user_guidance
        )
        
        self.file_access_failures.append(failure)
        
        # Create user notification
        self._create_file_access_notification(failure, notification_id)
        
        # Log the failure
        self.logger.error(f"📁 File access failure in {plugin_name}: {file_path} ({operation_type}) - {error_message}")
        
        return notification_id
    
    def report_analysis_coverage(self, plugin_name: str, total_checks: int, 
                               successful_checks: int, failed_checks: int, 
                               analysis_details: Dict[str, Any]) -> str:
        """
        Report comprehensive analysis coverage and limitations.
        
        Args:
            plugin_name: Name of the plugin reporting coverage
            total_checks: Total number of security checks attempted
            successful_checks: Number of successful checks
            failed_checks: Number of failed checks
            analysis_details: Additional analysis details
            
        Returns:
            Notification ID for tracking
        """
        notification_id = f"coverage_{self.notification_counter}"
        self.notification_counter += 1
        
        skipped_checks = total_checks - successful_checks - failed_checks
        coverage_percentage = (successful_checks / total_checks * 100) if total_checks > 0 else 0.0
        
        # Determine analysis depth and quality
        analysis_depth = self._determine_analysis_depth(analysis_details)
        analysis_quality = self._determine_analysis_quality(coverage_percentage, failed_checks, total_checks)
        
        # Extract security controls information
        security_controls_covered = analysis_details.get("security_controls_covered", [])
        security_controls_missed = analysis_details.get("security_controls_missed", [])
        limitations = analysis_details.get("limitations", [])
        
        # Calculate confidence level
        confidence_level = self._calculate_analysis_confidence(
            coverage_percentage, failed_checks, len(limitations)
        )
        
        # Create coverage report
        coverage_report = AnalysisCoverageReport(
            plugin_name=plugin_name,
            total_checks=total_checks,
            successful_checks=successful_checks,
            failed_checks=failed_checks,
            skipped_checks=skipped_checks,
            coverage_percentage=coverage_percentage,
            analysis_depth=analysis_depth,
            limitations=limitations,
            security_controls_covered=security_controls_covered,
            security_controls_missed=security_controls_missed,
            confidence_level=confidence_level,
            analysis_quality=analysis_quality
        )
        
        self.analysis_coverage_reports.append(coverage_report)
        
        # Create user notification
        self._create_coverage_notification(coverage_report, notification_id)
        
        # Log coverage information
        self.logger.info(f"📊 Analysis coverage for {plugin_name}: {coverage_percentage:.1f}% ({successful_checks}/{total_checks} checks)")
        
        return notification_id
    
    def create_prominent_error_display(self, errors: List[Dict[str, Any]]) -> Text:
        """
        Create prominent error display for critical issues.
        
        Args:
            errors: List of error information dictionaries
            
        Returns:
            Rich Text object with prominent error display
        """
        if not errors:
            return Text("No critical errors detected", style="green")
        
        # Create prominent error panel
        error_text = Text()
        error_text.append("🚨 CRITICAL ANALYSIS ISSUES DETECTED 🚨\n\n", style="bold red")
        
        for i, error in enumerate(errors, 1):
            error_text.append(f"{i}. ", style="bold red")
            error_text.append(f"{error.get('title', 'Unknown Error')}\n", style="red")
            error_text.append(f"   Plugin: {error.get('plugin', 'Unknown')}\n", style="yellow")
            error_text.append(f"   Impact: {error.get('impact', 'Unknown')}\n", style="orange")
            
            if error.get('guidance'):
                error_text.append(f"   Guidance: {error['guidance']}\n", style="cyan")
            
            if error.get('technical_details') and self.show_technical_details:
                error_text.append(f"   Technical: {error['technical_details']}\n", style="dim")
            
            error_text.append("\n")
        
        # Add remediation summary
        error_text.append("📋 RECOMMENDED ACTIONS:\n", style="bold cyan")
        error_text.append("• Review file permissions and APK integrity\n", style="cyan")
        error_text.append("• Check system resources and disk space\n", style="cyan")
        error_text.append("• Consider manual analysis for failed components\n", style="cyan")
        error_text.append("• Contact support if issues persist\n", style="cyan")
        
        return error_text
    
    def generate_analysis_transparency_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive analysis transparency report.
        
        Returns:
            Dictionary containing detailed transparency information
        """
        report = {
            "timestamp": time.time(),
            "summary": {
                "total_file_access_failures": len(self.file_access_failures),
                "total_coverage_reports": len(self.analysis_coverage_reports),
                "total_notifications": len(self.user_notifications),
                "critical_notifications": self.critical_notifications,
                "error_notifications": self.error_notifications,
                "warning_notifications": self.warning_notifications
            },
            "file_access_analysis": self._analyze_file_access_patterns(),
            "coverage_analysis": self._analyze_coverage_patterns(),
            "notification_breakdown": self._analyze_notification_patterns(),
            "system_health": self._assess_system_health(),
            "recommendations": self._generate_transparency_recommendations()
        }
        
        return report
    
    def _create_file_access_notification(self, failure: FileAccessFailure, notification_id: str):
        """Create user notification for file access failure."""
        # Determine notification level
        level = "CRITICAL" if failure.impact_level == "CRITICAL" else "ERROR"
        
        # Create notification
        notification = UserNotification(
            notification_id=notification_id,
            level=level,
            category="FILE_ACCESS",
            title=f"File Access Failure: {failure.operation_type.title()}",
            message=f"Failed to {failure.operation_type} file: {failure.file_path}",
            technical_details=failure.technical_details,
            user_guidance=failure.user_guidance,
            action_required=failure.impact_level in ["CRITICAL", "HIGH"],
            remediation_steps=self._generate_remediation_steps(failure),
            impact_assessment=self._assess_failure_impact(failure),
            visibility_level="PROMINENT" if failure.impact_level == "CRITICAL" else "STANDARD",
            plugin_context=failure.plugin_name
        )
        
        self.user_notifications.append(notification)
        
        # Update counters
        if level == "CRITICAL":
            self.critical_notifications += 1
        elif level == "ERROR":
            self.error_notifications += 1
    
    def _create_coverage_notification(self, coverage: AnalysisCoverageReport, notification_id: str):
        """Create user notification for coverage report."""
        # Determine notification level based on coverage quality
        if coverage.analysis_quality in ["POOR", "FAIR"] or coverage.coverage_percentage < 50:
            level = "WARNING"
        elif coverage.failed_checks > coverage.successful_checks:
            level = "ERROR"
        else:
            level = "INFO"
        
        # Create notification
        notification = UserNotification(
            notification_id=notification_id,
            level=level,
            category="ANALYSIS_LIMITATION",
            title=f"Analysis Coverage Report: {coverage.plugin_name}",
            message=f"Coverage: {coverage.coverage_percentage:.1f}% ({coverage.successful_checks}/{coverage.total_checks} checks)",
            technical_details={
                "coverage_percentage": coverage.coverage_percentage,
                "successful_checks": coverage.successful_checks,
                "failed_checks": coverage.failed_checks,
                "skipped_checks": coverage.skipped_checks,
                "analysis_depth": coverage.analysis_depth,
                "confidence_level": coverage.confidence_level
            },
            user_guidance=self._generate_coverage_guidance(coverage),
            action_required=coverage.analysis_quality == "POOR",
            remediation_steps=self._generate_coverage_remediation(coverage),
            impact_assessment=self._assess_coverage_impact(coverage),
            visibility_level="PROMINENT" if coverage.analysis_quality == "POOR" else "STANDARD",
            plugin_context=coverage.plugin_name
        )
        
        self.user_notifications.append(notification)
        
        # Update counters
        if level == "WARNING":
            self.warning_notifications += 1
        elif level == "ERROR":
            self.error_notifications += 1

    def _generate_file_access_guidance(self, file_path: str, operation_type: str, 
                                     error_type: str, impact_level: str) -> str:
        """Generate user-friendly guidance for file access failures."""
        guidance_map = {
            "FileNotFoundError": f"The file '{file_path}' could not be found. This may indicate:\n"
                               "• APK corruption or incomplete extraction\n"
                               "• File was removed during analysis\n"
                               "• Path specification error",
            "PermissionError": f"Permission denied accessing '{file_path}'. This may indicate:\n"
                             "• Insufficient file system permissions\n"
                             "• File is locked by another process\n"
                             "• Security restrictions on the file",
            "UnicodeDecodeError": f"Text encoding issues with '{file_path}'. This may indicate:\n"
                                "• Non-standard character encoding\n"
                                "• Binary file treated as text\n"
                                "• Corrupted file content",
            "ZipError": f"Archive corruption in '{file_path}'. This may indicate:\n"
                       "• APK file is corrupted\n"
                       "• Incomplete download\n"
                       "• Archive format issues"
        }
        
        base_guidance = guidance_map.get(error_type, 
            f"Unexpected error accessing '{file_path}' during {operation_type} operation.")
        
        if impact_level == "CRITICAL":
            base_guidance += "\n\n⚠️ CRITICAL: This failure significantly impacts analysis accuracy."
        elif impact_level == "HIGH":
            base_guidance += "\n\n⚠️ HIGH IMPACT: This failure may miss important security issues."
        
        return base_guidance

    def _check_workaround_availability(self, file_path: str, operation_type: str, 
                                     error_type: str) -> bool:
        """Check if workarounds are available for this type of failure."""
        # File not found - may have alternatives
        if error_type == "FileNotFoundError":
            return True
        # Permission errors - may be solvable
        if error_type == "PermissionError":
            return True
        # Encoding issues - may try different encodings
        if error_type == "UnicodeDecodeError":
            return True
        # Most other errors don't have simple workarounds
        return False

    def _analyze_error_context(self, error: Exception) -> Dict[str, Any]:
        """Analyze error context for additional technical details."""
        context = {
            "error_class": type(error).__name__,
            "error_message": str(error),
            "error_args": getattr(error, 'args', [])
        }
        
        # Add specific context based on error type
        if isinstance(error, FileNotFoundError):
            context["error_category"] = "file_system"
            context["suggested_checks"] = ["file_exists", "path_validity", "extraction_complete"]
        elif isinstance(error, PermissionError):
            context["error_category"] = "permissions"
            context["suggested_checks"] = ["file_permissions", "process_permissions", "file_lock_status"]
        elif isinstance(error, UnicodeDecodeError):
            context["error_category"] = "encoding"
            context["suggested_checks"] = ["file_encoding", "binary_content", "corruption_check"]
        else:
            context["error_category"] = "general"
            context["suggested_checks"] = ["file_integrity", "system_resources"]
        
        return context

    def _determine_analysis_depth(self, analysis_details: Dict[str, Any]) -> str:
        """Determine analysis depth based on details."""
        depth_indicators = analysis_details.get("depth_indicators", {})
        
        if depth_indicators.get("comprehensive_scan", False):
            return "COMPREHENSIVE"
        elif depth_indicators.get("deep_analysis", False):
            return "DEEP"
        elif depth_indicators.get("standard_checks", False):
            return "STANDARD"
        else:
            return "SURFACE"

    def _determine_analysis_quality(self, coverage_percentage: float, 
                                  failed_checks: int, total_checks: int) -> str:
        """Determine analysis quality based on metrics."""
        if coverage_percentage >= 95 and failed_checks == 0:
            return "EXCELLENT"
        elif coverage_percentage >= 80 and failed_checks <= total_checks * 0.1:
            return "GOOD"
        elif coverage_percentage >= 60 and failed_checks <= total_checks * 0.25:
            return "FAIR"
        else:
            return "POOR"

    def _calculate_analysis_confidence(self, coverage_percentage: float, 
                                     failed_checks: int, limitations_count: int) -> float:
        """Calculate confidence level for analysis results."""
        base_confidence = coverage_percentage / 100.0
        
        # Reduce confidence for failed checks
        failure_penalty = min(failed_checks * 0.05, 0.3)
        base_confidence -= failure_penalty
        
        # Reduce confidence for limitations
        limitation_penalty = min(limitations_count * 0.02, 0.2)
        base_confidence -= limitation_penalty
        
        return max(0.0, min(1.0, base_confidence))

    def _generate_remediation_steps(self, failure: FileAccessFailure) -> List[str]:
        """Generate specific remediation steps for file access failure."""
        steps = []
        
        if failure.error_type == "FileNotFoundError":
            steps.extend([
                "Verify APK file integrity",
                "Re-extract APK if extraction was incomplete",
                "Check for alternative file locations",
                "Ensure file wasn't deleted during analysis"
            ])
        elif failure.error_type == "PermissionError":
            steps.extend([
                "Check file system permissions",
                "Run analysis with appropriate privileges",
                "Ensure file is not locked by another process",
                "Verify storage device accessibility"
            ])
        elif failure.error_type == "UnicodeDecodeError":
            steps.extend([
                "Try alternative character encodings",
                "Verify file is not binary",
                "Check for file corruption",
                "Use binary mode for non-text analysis"
            ])
        else:
            steps.extend([
                "Check system resources and disk space",
                "Verify file and directory integrity",
                "Contact support with error details",
                "Consider manual analysis alternatives"
            ])
        
        return steps

    def _assess_failure_impact(self, failure: FileAccessFailure) -> str:
        """Assess the impact of a file access failure."""
        impact_descriptions = {
            "CRITICAL": "Analysis severely compromised. Major security vulnerabilities may be missed.",
            "HIGH": "Significant analysis gaps. Important security checks cannot be performed.",
            "MEDIUM": "Moderate impact on analysis completeness. Some security checks skipped.",
            "LOW": "Minimal impact. Analysis coverage slightly reduced but core functionality intact."
        }
        
        return impact_descriptions.get(failure.impact_level, "Impact level unknown")

    def _generate_coverage_guidance(self, coverage: AnalysisCoverageReport) -> str:
        """Generate user guidance for coverage reports."""
        if coverage.analysis_quality == "EXCELLENT":
            return "Analysis completed with excellent coverage. All security controls properly evaluated."
        elif coverage.analysis_quality == "GOOD":
            return "Analysis completed with good coverage. Minor gaps may exist but core security assessed."
        elif coverage.analysis_quality == "FAIR":
            return "Analysis completed with fair coverage. Some security controls may need manual review."
        else:
            return "Analysis completed with limited coverage. Significant security gaps require attention."

    def _generate_coverage_remediation(self, coverage: AnalysisCoverageReport) -> List[str]:
        """Generate remediation steps for coverage issues."""
        steps = []
        
        if coverage.coverage_percentage < 50:
            steps.extend([
                "Review APK structure and content",
                "Check for obfuscation or anti-analysis techniques",
                "Consider alternative analysis tools",
                "Perform manual security review"
            ])
        
        if coverage.failed_checks > coverage.successful_checks:
            steps.extend([
                "Investigate common failure patterns",
                "Check system resources and configuration",
                "Review plugin compatibility",
                "Update analysis tools if available"
            ])
        
        if len(coverage.limitations) > 5:
            steps.extend([
                "Address identified limitations systematically",
                "Prioritize high-impact limitations",
                "Seek additional analysis tools",
                "Document known analysis gaps"
            ])
        
        return steps

    def _assess_coverage_impact(self, coverage: AnalysisCoverageReport) -> str:
        """Assess the impact of coverage limitations."""
        if coverage.analysis_quality in ["EXCELLENT", "GOOD"]:
            return "Minimal impact. Analysis provides reliable security assessment."
        elif coverage.analysis_quality == "FAIR":
            return "Moderate impact. Additional manual review recommended for comprehensive security assessment."
        else:
            return "Significant impact. Analysis may miss critical security vulnerabilities. Manual review essential."

    def _analyze_file_access_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in file access failures."""
        if not self.file_access_failures:
            return {"status": "No file access failures detected"}
        
        # Group failures by type and plugin
        failure_by_type = {}
        failure_by_plugin = {}
        
        for failure in self.file_access_failures:
            failure_by_type[failure.error_type] = failure_by_type.get(failure.error_type, 0) + 1
            failure_by_plugin[failure.plugin_name] = failure_by_plugin.get(failure.plugin_name, 0) + 1
        
        return {
            "total_failures": len(self.file_access_failures),
            "failures_by_type": failure_by_type,
            "failures_by_plugin": failure_by_plugin,
            "most_problematic_plugin": max(failure_by_plugin.items(), key=lambda x: x[1])[0] if failure_by_plugin else None,
            "most_common_error": max(failure_by_type.items(), key=lambda x: x[1])[0] if failure_by_type else None
        }

    def _analyze_coverage_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in coverage reports."""
        if not self.analysis_coverage_reports:
            return {"status": "No coverage reports available"}
        
        total_coverage = sum(r.coverage_percentage for r in self.analysis_coverage_reports)
        avg_coverage = total_coverage / len(self.analysis_coverage_reports)
        
        quality_distribution = {}
        for report in self.analysis_coverage_reports:
            quality = report.analysis_quality
            quality_distribution[quality] = quality_distribution.get(quality, 0) + 1
        
        return {
            "total_reports": len(self.analysis_coverage_reports),
            "average_coverage": avg_coverage,
            "quality_distribution": quality_distribution,
            "plugins_analyzed": [r.plugin_name for r in self.analysis_coverage_reports]
        }

    def _analyze_notification_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in user notifications."""
        notifications_by_level = {}
        notifications_by_category = {}
        
        for notification in self.user_notifications:
            level = notification.level
            category = notification.category
            
            notifications_by_level[level] = notifications_by_level.get(level, 0) + 1
            notifications_by_category[category] = notifications_by_category.get(category, 0) + 1
        
        return {
            "total_notifications": len(self.user_notifications),
            "by_level": notifications_by_level,
            "by_category": notifications_by_category,
            "critical_count": self.critical_notifications,
            "error_count": self.error_notifications,
            "warning_count": self.warning_notifications
        }

    def _assess_system_health(self) -> Dict[str, Any]:
        """Assess overall system health based on notifications."""
        total_issues = len(self.file_access_failures) + len([n for n in self.user_notifications if n.level in ["ERROR", "CRITICAL"]])
        
        if total_issues == 0:
            health_status = "EXCELLENT"
        elif total_issues <= 3:
            health_status = "GOOD"
        elif total_issues <= 10:
            health_status = "FAIR"
        else:
            health_status = "POOR"
        
        return {
            "overall_health": health_status,
            "total_issues": total_issues,
            "critical_issues": self.critical_notifications,
            "system_recommendations": self._generate_system_recommendations(health_status, total_issues)
        }

    def _generate_system_recommendations(self, health_status: str, total_issues: int) -> List[str]:
        """Generate system-level recommendations."""
        recommendations = []
        
        if health_status == "POOR":
            recommendations.extend([
                "Review system configuration and resources",
                "Check APK file integrity",
                "Consider running analysis in isolated environment",
                "Update analysis tools and dependencies"
            ])
        elif health_status == "FAIR":
            recommendations.extend([
                "Monitor system resources during analysis",
                "Review file access patterns",
                "Consider incremental analysis approach"
            ])
        elif health_status == "GOOD":
            recommendations.append("System performing well. Monitor for any degradation.")
        else:
            recommendations.append("System performing excellently. Continue current practices.")
        
        return recommendations

    def _generate_transparency_recommendations(self) -> List[str]:
        """Generate recommendations for improving analysis transparency."""
        recommendations = []
        
        if len(self.file_access_failures) > 5:
            recommendations.append("High file access failure rate. Review APK extraction and file system permissions.")
        
        if self.critical_notifications > 2:
            recommendations.append("Multiple critical issues detected. Consider manual analysis review.")
        
        poor_coverage_reports = [r for r in self.analysis_coverage_reports if r.analysis_quality == "POOR"]
        if len(poor_coverage_reports) > 0:
            recommendations.append("Some plugins show poor coverage. Consider alternative analysis approaches.")
        
        if not recommendations:
            recommendations.append("Analysis transparency is good. Continue monitoring for improvements.")
        
        return recommendations

class UnifiedPluginExecutionManager:
    """
    Unified plugin execution manager that prevents premature termination.
    
    This manager provides:
    - Robust timeout management with escalation
    - Graceful shutdown integration
    - Coordinated plugin execution
    - Comprehensive error handling and recovery
    - Organic detection without hardcoding
    """
    
    def __init__(self, config: Optional[PluginExecutionConfig] = None):
        self.config = config or PluginExecutionConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Execution tracking
        self.active_plugins: Dict[str, Future] = {}
        self.execution_results: Dict[str, PluginExecutionResult] = {}
        self.execution_lock = threading.RLock()
        
        # Shutdown coordination
        self.shutdown_requested = False
        self.shutdown_event = threading.Event()
        
        # Statistics
        self.total_plugins = 0
        self.completed_plugins = 0
        self.failed_plugins = 0
        self.timeout_plugins = 0
        self.cancelled_plugins = 0
        
        # Thread pool for plugin execution
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.max_concurrent_plugins,
            thread_name_prefix="PluginExec"
        )
        
        self.logger.info(f"🔧 Unified Plugin Execution Manager initialized")
        self.logger.info(f"   Max concurrent plugins: {self.config.max_concurrent_plugins}")
        self.logger.info(f"   Default timeout: {self.config.default_timeout}s")
        self.logger.info(f"   Graceful shutdown: {'✅' if GRACEFUL_SHUTDOWN_AVAILABLE else '❌'}")

    def execute_plugin_safe(self, plugin_metadata, apk_ctx, 
                           timeout_override: Optional[int] = None) -> PluginExecutionResult:
        """
        Execute a single plugin with comprehensive safety measures.
        
        Args:
            plugin_metadata: Plugin metadata object
            apk_ctx: APK context object
            timeout_override: Optional timeout override
            
        Returns:
            PluginExecutionResult: Comprehensive execution result
        """
        plugin_name = plugin_metadata.name
        module_name = getattr(plugin_metadata, 'module_name', plugin_name)
        
        # Initialize result
        result = PluginExecutionResult(
            plugin_name=plugin_name,
            module_name=module_name,
            state=PluginExecutionState.PENDING
        )
        
        # Check for shutdown before starting
        if self._check_shutdown_request():
            result.state = PluginExecutionState.CANCELLED
            result.shutdown_requested = True
            self.logger.info(f"🛑 Plugin {plugin_name} cancelled due to shutdown request")
            return result
        
        # Determine timeout
        timeout = self._determine_timeout(plugin_metadata, timeout_override)
        result.timeout_used = timeout
        
        self.logger.info(f"🔍 Executing plugin: {plugin_name} (timeout: {timeout}s)")
        
        # Execute with retry logic
        for attempt in range(self.config.retry_attempts + 1):
            if self._check_shutdown_request():
                result.state = PluginExecutionState.CANCELLED
                result.shutdown_requested = True
                break
            
            result.retry_count = attempt
            
            # Adjust timeout for retries with conservative escalation
            current_timeout = timeout
            if attempt > 0 and self.config.enable_timeout_escalation:
                # Use conservative 1.2x factor instead of aggressive linear growth
                # This gives: 1.2x, 1.44x instead of 2x, 3x linear escalation
                escalation_factor = 1.2 ** attempt
                current_timeout = min(timeout * escalation_factor, self.config.max_timeout)
                self.logger.info(f"🔄 Retry {attempt} for {plugin_name} with conservative timeout escalation: {current_timeout:.1f}s (factor: {escalation_factor:.2f})")
            
            # Execute the plugin
            execution_result = self._execute_plugin_with_timeout(
                plugin_metadata, apk_ctx, current_timeout
            )
            
            # Update result
            result.state = execution_result.state
            result.title = execution_result.title
            result.content = execution_result.content
            result.error_message = execution_result.error_message
            result.execution_time = execution_result.execution_time
            
            # Check if execution was successful
            if result.state == PluginExecutionState.COMPLETED:
                self.logger.info(f"✅ Plugin {plugin_name} completed successfully in {result.execution_time:.1f}s")
                break
            elif result.state == PluginExecutionState.CANCELLED:
                self.logger.info(f"🛑 Plugin {plugin_name} cancelled")
                break
            elif attempt < self.config.retry_attempts:
                # Add intelligence: don't retry certain non-transient failures
                if self._should_skip_retry(result.error_message, plugin_name):
                    self.logger.warning(f"⚠️ Plugin {plugin_name} failed with non-transient error - skipping retries")
                    break
                
                self.logger.warning(f"⚠️ Plugin {plugin_name} failed (attempt {attempt + 1}), retrying...")
                if self.config.retry_delay > 0:
                    time.sleep(self.config.retry_delay)
            else:
                self.logger.error(f"❌ Plugin {plugin_name} failed after {self.config.retry_attempts + 1} attempts")
        
        # Update statistics
        with self.execution_lock:
            if result.state == PluginExecutionState.COMPLETED:
                self.completed_plugins += 1
            elif result.state == PluginExecutionState.FAILED:
                self.failed_plugins += 1
            elif result.state == PluginExecutionState.TIMEOUT:
                self.timeout_plugins += 1
            elif result.state == PluginExecutionState.CANCELLED:
                self.cancelled_plugins += 1
        
        return result

    def _should_skip_retry(self, error_message: str, plugin_name: str) -> bool:
        """
        Determine if a retry should be skipped based on error type.
        
        Args:
            error_message: The error message from the failed execution
            plugin_name: Name of the plugin that failed
            
        Returns:
            True if retry should be skipped (non-transient error), False otherwise
        """
        if not error_message:
            return False
        
        error_lower = error_message.lower()
        
        # Non-transient errors that won't be fixed by retrying with more time
        non_transient_patterns = [
            # Import/dependency errors
            'no module named', 'importerror', 'modulenotfounderror',
            'cannot import name', 'import failed',
            
            # Configuration errors
            'configuration error', 'config file not found', 'invalid configuration',
            'missing required parameter', 'invalid parameter',
            
            # File system errors that are persistent
            'permission denied', 'file not found', 'directory not found',
            'no such file or directory', 'access denied',
            
            # APK-specific non-transient issues
            'invalid apk', 'corrupted apk', 'apk parsing failed',
            'malformed apk', 'unsupported apk format',
            
            # Plugin-specific structural issues
            'plugin not compatible', 'unsupported plugin version',
            'plugin disabled', 'plugin initialization failed'
        ]
        
        # Check if error matches non-transient patterns
        for pattern in non_transient_patterns:
            if pattern in error_lower:
                self.logger.debug(f"Detected non-transient error for {plugin_name}: {pattern}")
                return True
        
        return False

    def _execute_plugin_with_timeout(self, plugin_metadata, apk_ctx, 
                                   timeout: int) -> PluginExecutionResult:
        """Execute plugin with timeout protection and shutdown monitoring."""
        plugin_name = plugin_metadata.name
        module_name = getattr(plugin_metadata, 'module_name', plugin_name)
        
        result = PluginExecutionResult(
            plugin_name=plugin_name,
            module_name=module_name,
            state=PluginExecutionState.RUNNING
        )
        
        start_time = time.time()
        
        try:
            # Use graceful shutdown context if available
            if GRACEFUL_SHUTDOWN_AVAILABLE:
                with plugin_context(plugin_name):
                    # Submit plugin execution to thread pool
                    future = self.executor.submit(
                        self._execute_plugin_core, plugin_metadata, apk_ctx
                    )
                    
                    # Monitor execution with shutdown checking
                    execution_result = self._monitor_plugin_execution(
                        future, plugin_name, timeout
                    )
            else:
                # Fallback execution without graceful shutdown
                future = self.executor.submit(
                    self._execute_plugin_core, plugin_metadata, apk_ctx
                )
                execution_result = self._monitor_plugin_execution(
                    future, plugin_name, timeout
                )
            
            result.title = execution_result.get('title')
            result.content = execution_result.get('content')
            result.state = execution_result.get('state', PluginExecutionState.COMPLETED)
            result.error_message = execution_result.get('error_message')
            
        except Exception as e:
            result.state = PluginExecutionState.FAILED
            result.error_message = f"Plugin execution error: {str(e)}"
            self.logger.error(f"❌ Plugin {plugin_name} execution error: {e}")
        
        result.execution_time = time.time() - start_time
        return result

    def _execute_plugin_core(self, plugin_metadata, apk_ctx) -> Dict[str, Any]:
        """Core plugin execution logic with shutdown checking."""
        try:
            # Check for shutdown before execution
            if self._check_shutdown_request():
                return {
                    'state': PluginExecutionState.CANCELLED,
                    'error_message': 'Execution cancelled due to shutdown request'
                }
            
            # Get the plugin module with defensive programming
            module = getattr(plugin_metadata, 'module', None)
            if not module:
                raise AttributeError(f"Plugin {plugin_metadata.name} module not available - plugin may not be properly loaded")
            
            # Look for run_plugin function first (our standard), then fall back to run
            plugin_function = None
            if hasattr(module, 'run_plugin'):
                plugin_function = module.run_plugin
            elif hasattr(module, 'run'):
                plugin_function = module.run
            else:
                raise AttributeError(f"Plugin {plugin_metadata.name} does not have a 'run_plugin' or 'run' method")
            
            # Determine function signature and call appropriately
            import inspect
            
            sig = inspect.signature(plugin_function)
            params = list(sig.parameters.keys())
            
            # Execute plugin with appropriate parameters
            if len(params) >= 2 and "deep_mode" in params:
                result = plugin_function(apk_ctx, deep_mode=True)
            else:
                result = plugin_function(apk_ctx)
            
            # Validate result format
            if isinstance(result, tuple) and len(result) == 2:
                title, content = result
                return {
                    'state': PluginExecutionState.COMPLETED,
                    'title': title,
                    'content': content
                }
            else:
                return {
                    'state': PluginExecutionState.COMPLETED,
                    'title': plugin_metadata.name,
                    'content': result
                }
                
        except Exception as e:
            return {
                'state': PluginExecutionState.FAILED,
                'error_message': f"Plugin execution failed: {str(e)}"
            }

    def _monitor_plugin_execution(self, future: Future, plugin_name: str, 
                                timeout: int) -> Dict[str, Any]:
        """Monitor plugin execution with shutdown checking and timeout handling."""
        start_time = time.time()
        check_interval = self.config.check_shutdown_interval
        
        while True:
            # Check for shutdown request
            if self._check_shutdown_request():
                self.logger.info(f"🛑 Cancelling plugin {plugin_name} due to shutdown request")
                future.cancel()
                return {
                    'state': PluginExecutionState.CANCELLED,
                    'error_message': 'Cancelled due to shutdown request'
                }
            
            # Check if future is done
            if future.done():
                try:
                    return future.result()
                except Exception as e:
                    return {
                        'state': PluginExecutionState.FAILED,
                        'error_message': f"Plugin execution exception: {str(e)}"
                    }
            
            # Check for timeout
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                self.logger.warning(f"⏱️ Plugin {plugin_name} timed out after {timeout}s")
                future.cancel()
                return {
                    'state': PluginExecutionState.TIMEOUT,
                    'error_message': f'Plugin timed out after {timeout}s'
                }
            
            # Wait before next check
            time.sleep(check_interval)

    def _determine_timeout(self, plugin_metadata, timeout_override: Optional[int]) -> int:
        """Determine appropriate timeout for plugin execution."""
        if timeout_override:
            return min(timeout_override, self.config.max_timeout)
        
        # Check plugin metadata for timeout hint
        if hasattr(plugin_metadata, 'execution_time_estimate'):
            estimated_time = plugin_metadata.execution_time_estimate
            # Add 50% buffer to estimated time
            timeout = int(estimated_time * 1.5)
            return min(max(timeout, self.config.default_timeout), self.config.max_timeout)
        
        return self.config.default_timeout

    def _check_shutdown_request(self) -> bool:
        """Check if shutdown has been requested."""
        if self.shutdown_requested:
            return True
        
        if GRACEFUL_SHUTDOWN_AVAILABLE:
            return is_shutdown_requested()
        
        return False

    def execute_all_plugins(self, plugins: List, apk_ctx) -> Dict[str, Tuple[str, Any]]:
        """
        Execute all plugins with unified management and graceful shutdown support.
        
        Args:
            plugins: List of plugin metadata objects
            apk_ctx: APK context object
            
        Returns:
            Dict[str, Tuple[str, Any]]: Plugin results in expected format
        """
        self.total_plugins = len(plugins)
        results = {}
        
        if not plugins:
            self.logger.warning("No plugins to execute")
            return results
        
        self.logger.info(f"🚀 Starting execution of {len(plugins)} plugins")
        
        # Execute plugins with progress tracking
        for i, plugin in enumerate(plugins, 1):
            # Check for shutdown before each plugin
            if self._check_shutdown_request():
                self.logger.warning(f"🛑 Shutdown requested - stopping plugin execution at {i-1}/{len(plugins)}")
                break
            
            plugin_name = plugin.name
            self.logger.info(f"🔍 [{i}/{len(plugins)}] Executing: {plugin_name}")
            
            # Execute plugin safely
            execution_result = self.execute_plugin_safe(plugin, apk_ctx)
            
            # Store result in expected format
            if execution_result.state == PluginExecutionState.COMPLETED:
                results[execution_result.module_name] = (
                    execution_result.title or plugin_name,
                    execution_result.content
                )
            else:
                # Store error result in expected format
                error_title = f"❌ {plugin_name}"
                error_content = execution_result.error_message or "Plugin execution failed"
                results[execution_result.module_name] = (error_title, error_content)
            
            # Store detailed result
            self.execution_results[execution_result.module_name] = execution_result
        
        # Log execution summary
        self._log_execution_summary()
        
        return results

    def _log_execution_summary(self):
        """Log comprehensive execution summary."""
        total = self.total_plugins
        completed = self.completed_plugins
        failed = self.failed_plugins
        timeout = self.timeout_plugins
        cancelled = self.cancelled_plugins
        
        self.logger.info(f"📊 Plugin Execution Summary:")
        self.logger.info(f"   Total: {total}")
        self.logger.info(f"   ✅ Completed: {completed}")
        self.logger.info(f"   ❌ Failed: {failed}")
        self.logger.info(f"   ⏱️ Timeout: {timeout}")
        self.logger.info(f"   🛑 Cancelled: {cancelled}")
        
        if total > 0:
            success_rate = (completed / total) * 100
            self.logger.info(f"   📈 Success Rate: {success_rate:.1f}%")

    def shutdown(self):
        """Shutdown the plugin execution manager gracefully."""
        self.logger.info("🛑 Shutting down plugin execution manager...")
        
        self.shutdown_requested = True
        self.shutdown_event.set()
        
        # Cancel active plugins
        with self.execution_lock:
            for plugin_name, future in self.active_plugins.items():
                if not future.done():
                    self.logger.info(f"🛑 Cancelling active plugin: {plugin_name}")
                    future.cancel()
        
        # Shutdown executor (remove timeout parameter for compatibility)
        self.executor.shutdown(wait=True)
        
        self.logger.info("✅ Plugin execution manager shutdown complete")

    def get_execution_statistics(self) -> Dict[str, Any]:
        """Get comprehensive execution statistics."""
        return {
            'total_plugins': self.total_plugins,
            'completed_plugins': self.completed_plugins,
            'failed_plugins': self.failed_plugins,
            'timeout_plugins': self.timeout_plugins,
            'cancelled_plugins': self.cancelled_plugins,
            'success_rate': (self.completed_plugins / max(self.total_plugins, 1)) * 100,
            'active_plugins': len(self.active_plugins),
            'execution_results': self.execution_results
        }

    @contextmanager
    def execution_context(self):
        """Context manager for plugin execution with automatic cleanup."""
        try:
            yield self
        finally:
            if not self.shutdown_requested:
                self.shutdown()

# Factory function for creating unified plugin execution manager
def create_unified_plugin_execution_manager(
    config: Optional[PluginExecutionConfig] = None
) -> UnifiedPluginExecutionManager:
    """
    Create a unified plugin execution manager with optimal configuration.
    
    Args:
        config: Optional configuration override
        
    Returns:
        UnifiedPluginExecutionManager: Configured execution manager
    """
    if config is None:
        config = PluginExecutionConfig(
            default_timeout=60,
            max_timeout=900,  # Updated from 180 to match new max_timeout
            retry_attempts=2,
            retry_delay=2.0,
            enable_timeout_escalation=True,
            check_shutdown_interval=0.5,
            max_concurrent_plugins=3,
            enable_recovery=True,
            log_execution_details=True
        )
    
    return UnifiedPluginExecutionManager(config)

# Integration helper for existing plugin managers
def integrate_with_existing_plugin_manager(plugin_manager):
    """
    Integrate unified execution manager with existing plugin manager.
    
    Args:
        plugin_manager: Existing plugin manager instance
    """
    # Create unified execution manager
    unified_manager = create_unified_plugin_execution_manager()
    
    # Replace execute_all_plugins method
    original_execute_all_plugins = plugin_manager.execute_all_plugins
    
    def enhanced_execute_all_plugins(apk_ctx):
        """Enhanced plugin execution with unified management."""
        plugins = plugin_manager.get_executable_plugins()
        return unified_manager.execute_all_plugins(plugins, apk_ctx)
    
    plugin_manager.execute_all_plugins = enhanced_execute_all_plugins
    plugin_manager._unified_execution_manager = unified_manager
    
    return plugin_manager

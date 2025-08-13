#!/usr/bin/env python3
"""
Enhanced Scan Status Reporter

Provides accurate, real-time scan status reporting with improved completion
status accuracy, comprehensive progress tracking, and detailed error reporting.

Features:
- Real-time progress tracking with stage-by-stage updates
- Accurate completion status with validation
- Comprehensive error reporting and recovery suggestions
- Resource usage monitoring during scans
- Plugin-level status tracking
- Performance metrics and optimization recommendations
"""

import time
import logging
import threading
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import json
from pathlib import Path

logger = logging.getLogger(__name__)

class ScanStage(Enum):
    """Comprehensive scan stages for accurate progress tracking"""
    INITIALIZING = "initializing"
    PREPROCESSING = "preprocessing"
    PLUGIN_LOADING = "plugin_loading"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    FRAMEWORK_FILTERING = "framework_filtering"
    ML_ENHANCEMENT = "ml_enhancement"
    VULNERABILITY_CLASSIFICATION = "vulnerability_classification"
    REPORT_GENERATION = "report_generation"
    POST_PROCESSING = "post_processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanStatus(Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETING = "completing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

class ResourceStatus(Enum):
    """Resource utilization status"""
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"
    OPTIMIZED = "optimized"

@dataclass
class PluginStatus:
    """Individual plugin execution status"""
    plugin_name: str
    status: ScanStatus
    progress: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    execution_time: Optional[float] = None
    error_message: Optional[str] = None
    findings_count: int = 0
    confidence_score: Optional[float] = None
    resource_usage: Dict[str, float] = field(default_factory=dict)

@dataclass
class StageProgress:
    """Progress tracking for scan stages"""
    stage: ScanStage
    status: ScanStatus
    progress: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    estimated_duration: Optional[float] = None
    actual_duration: Optional[float] = None
    plugins_completed: int = 0
    plugins_total: int = 0
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

@dataclass
class ResourceMetrics:
    """Resource utilization metrics"""
    cpu_usage: float = 0.0
    memory_usage_mb: float = 0.0
    disk_io_mb: float = 0.0
    network_usage_mb: float = 0.0
    temperature: Optional[float] = None
    battery_level: Optional[float] = None
    status: ResourceStatus = ResourceStatus.NORMAL

@dataclass
class ScanReport:
    """Comprehensive scan status report"""
    scan_id: str
    package_name: str
    scan_type: str
    status: ScanStatus
    current_stage: ScanStage
    overall_progress: float
    start_time: datetime
    estimated_completion: Optional[datetime]
    actual_completion: Optional[datetime]
    total_duration: Optional[float]
    
    # Stage tracking
    stages: Dict[ScanStage, StageProgress] = field(default_factory=dict)
    
    # Plugin tracking
    plugins: Dict[str, PluginStatus] = field(default_factory=dict)
    
    # Resource tracking
    resource_metrics: ResourceMetrics = field(default_factory=ResourceMetrics)
    resource_history: List[ResourceMetrics] = field(default_factory=list)
    
    # Results tracking
    total_findings: int = 0
    vulnerability_count: int = 0
    false_positive_count: int = 0
    accuracy_score: Optional[float] = None
    
    # Error tracking
    errors: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Performance metrics
    performance_score: Optional[float] = None
    optimization_recommendations: List[str] = field(default_factory=list)

class EnhancedScanStatusReporter:
    """
    Enhanced scan status reporter with comprehensive tracking capabilities.
    
    Provides real-time status updates, accurate progress tracking, and detailed
    completion status reporting for AODS scans.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the enhanced scan status reporter."""
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Configuration
        self.update_interval = self.config.get("update_interval", 1.0)  # seconds
        self.enable_resource_monitoring = self.config.get("enable_resource_monitoring", True)
        self.enable_performance_tracking = self.config.get("enable_performance_tracking", True)
        self.auto_save_reports = self.config.get("auto_save_reports", True)
        self.report_directory = Path(self.config.get("report_directory", "scan_reports"))
        
        # State management
        self._lock = threading.RLock()
        self._active_scans: Dict[str, ScanReport] = {}
        self._completed_scans: Dict[str, ScanReport] = {}
        self._monitoring_threads: Dict[str, threading.Thread] = {}
        self._stop_monitoring: Dict[str, threading.Event] = {}
        
        # Callbacks
        self._progress_callbacks: List[Callable[[str, ScanReport], None]] = []
        self._completion_callbacks: List[Callable[[str, ScanReport], None]] = []
        self._error_callbacks: List[Callable[[str, Dict[str, Any]], None]] = []
        
        # Performance baseline for optimization recommendations
        self._performance_baselines = {
            ScanStage.STATIC_ANALYSIS: 120.0,  # seconds
            ScanStage.DYNAMIC_ANALYSIS: 180.0,  # seconds
            ScanStage.FRAMEWORK_FILTERING: 30.0,  # seconds
            ScanStage.ML_ENHANCEMENT: 45.0,  # seconds
        }
        
        # Create report directory
        if self.auto_save_reports:
            self.report_directory.mkdir(exist_ok=True)
        
        logger.info("Enhanced Scan Status Reporter initialized")
    
    def start_scan_tracking(self, scan_id: str, package_name: str, 
                          scan_type: str, estimated_stages: List[ScanStage]) -> ScanReport:
        """Start tracking a new scan."""
        
        with self._lock:
            # Create scan report
            scan_report = ScanReport(
                scan_id=scan_id,
                package_name=package_name,
                scan_type=scan_type,
                status=ScanStatus.PENDING,
                current_stage=ScanStage.INITIALIZING,
                overall_progress=0.0,
                start_time=datetime.now()
            )
            
            # Initialize stage tracking
            for stage in estimated_stages:
                scan_report.stages[stage] = StageProgress(
                    stage=stage,
                    status=ScanStatus.PENDING
                )
            
            # Store scan report
            self._active_scans[scan_id] = scan_report
            
            # Start monitoring thread
            self._start_monitoring_thread(scan_id)
            
            logger.info(f"Started tracking scan {scan_id} for package {package_name}")
            return scan_report
    
    def update_stage_progress(self, scan_id: str, stage: ScanStage, 
                            progress: float, status: ScanStatus = ScanStatus.RUNNING) -> None:
        """Update progress for a specific stage."""
        
        with self._lock:
            if scan_id not in self._active_scans:
                logger.warning(f"Scan {scan_id} not found for stage update")
                return
            
            scan_report = self._active_scans[scan_id]
            
            # Update current stage
            scan_report.current_stage = stage
            
            # Update stage progress
            if stage in scan_report.stages:
                stage_progress = scan_report.stages[stage]
                stage_progress.progress = progress
                stage_progress.status = status
                
                if status == ScanStatus.RUNNING and stage_progress.start_time is None:
                    stage_progress.start_time = datetime.now()
                elif status in [ScanStatus.COMPLETED, ScanStatus.FAILED] and stage_progress.end_time is None:
                    stage_progress.end_time = datetime.now()
                    if stage_progress.start_time:
                        stage_progress.actual_duration = (
                            stage_progress.end_time - stage_progress.start_time
                        ).total_seconds()
            
            # Update overall progress
            scan_report.overall_progress = self._calculate_overall_progress(scan_report)
            
            # Update scan status
            if status == ScanStatus.FAILED:
                scan_report.status = ScanStatus.FAILED
            elif progress >= 100.0 and stage == list(scan_report.stages.keys())[-1]:
                scan_report.status = ScanStatus.COMPLETED
            else:
                scan_report.status = ScanStatus.RUNNING
            
            # Trigger callbacks
            self._trigger_progress_callbacks(scan_id, scan_report)
    
    def update_plugin_status(self, scan_id: str, plugin_name: str, 
                           status: ScanStatus, progress: float = 0.0,
                           findings_count: int = 0, error_message: Optional[str] = None) -> None:
        """Update status for a specific plugin."""
        
        with self._lock:
            if scan_id not in self._active_scans:
                logger.warning(f"Scan {scan_id} not found for plugin update")
                return
            
            scan_report = self._active_scans[scan_id]
            
            # Get or create plugin status
            if plugin_name not in scan_report.plugins:
                scan_report.plugins[plugin_name] = PluginStatus(
                    plugin_name=plugin_name,
                    status=status,
                    progress=progress
                )
            
            plugin_status = scan_report.plugins[plugin_name]
            plugin_status.status = status
            plugin_status.progress = progress
            plugin_status.findings_count = findings_count
            plugin_status.error_message = error_message
            
            # Update timing
            if status == ScanStatus.RUNNING and plugin_status.start_time is None:
                plugin_status.start_time = datetime.now()
            elif status in [ScanStatus.COMPLETED, ScanStatus.FAILED] and plugin_status.end_time is None:
                plugin_status.end_time = datetime.now()
                if plugin_status.start_time:
                    plugin_status.execution_time = (
                        plugin_status.end_time - plugin_status.start_time
                    ).total_seconds()
            
            # Update current stage plugin counts
            current_stage = scan_report.current_stage
            if current_stage in scan_report.stages:
                stage_progress = scan_report.stages[current_stage]
                stage_progress.plugins_completed = sum(
                    1 for p in scan_report.plugins.values() 
                    if p.status == ScanStatus.COMPLETED
                )
                stage_progress.plugins_total = len(scan_report.plugins)
    
    def add_scan_error(self, scan_id: str, error_message: str, 
                      error_type: str = "general", stage: Optional[ScanStage] = None) -> None:
        """Add an error to the scan report."""
        
        with self._lock:
            if scan_id not in self._active_scans:
                logger.warning(f"Scan {scan_id} not found for error update")
                return
            
            scan_report = self._active_scans[scan_id]
            
            error_entry = {
                "timestamp": datetime.now().isoformat(),
                "error_type": error_type,
                "error_message": error_message,
                "stage": stage.value if stage else None
            }
            
            scan_report.errors.append(error_entry)
            
            # Update stage error if applicable
            if stage and stage in scan_report.stages:
                scan_report.stages[stage].error_message = error_message
            
            # Trigger error callbacks
            self._trigger_error_callbacks(scan_id, error_entry)
    
    def add_scan_warning(self, scan_id: str, warning_message: str) -> None:
        """Add a warning to the scan report."""
        
        with self._lock:
            if scan_id not in self._active_scans:
                return
            
            scan_report = self._active_scans[scan_id]
            scan_report.warnings.append(warning_message)
    
    def complete_scan(self, scan_id: str, final_status: ScanStatus = ScanStatus.COMPLETED,
                     total_findings: int = 0, vulnerability_count: int = 0,
                     false_positive_count: int = 0, accuracy_score: Optional[float] = None) -> ScanReport:
        """Mark a scan as completed and finalize the report."""
        
        with self._lock:
            if scan_id not in self._active_scans:
                logger.warning(f"Scan {scan_id} not found for completion")
                return None
            
            scan_report = self._active_scans[scan_id]
            
            # Update final status
            scan_report.status = final_status
            scan_report.actual_completion = datetime.now()
            scan_report.total_duration = (
                scan_report.actual_completion - scan_report.start_time
            ).total_seconds()
            
            # Update results
            scan_report.total_findings = total_findings
            scan_report.vulnerability_count = vulnerability_count
            scan_report.false_positive_count = false_positive_count
            scan_report.accuracy_score = accuracy_score
            
            # Set final stage
            if final_status == ScanStatus.COMPLETED:
                scan_report.current_stage = ScanStage.COMPLETED
                scan_report.overall_progress = 100.0
            elif final_status == ScanStatus.FAILED:
                scan_report.current_stage = ScanStage.FAILED
            
            # Generate performance recommendations
            scan_report.optimization_recommendations = self._generate_optimization_recommendations(scan_report)
            scan_report.performance_score = self._calculate_performance_score(scan_report)
            
            # Stop monitoring
            self._stop_monitoring_thread(scan_id)
            
            # Move to completed scans
            self._completed_scans[scan_id] = scan_report
            del self._active_scans[scan_id]
            
            # Save report if enabled
            if self.auto_save_reports:
                self._save_scan_report(scan_report)
            
            # Trigger completion callbacks
            self._trigger_completion_callbacks(scan_id, scan_report)
            
            logger.info(f"Completed scan {scan_id} with status {final_status.value}")
            return scan_report
    
    def get_scan_status(self, scan_id: str) -> Optional[ScanReport]:
        """Get current status of a scan."""
        
        with self._lock:
            if scan_id in self._active_scans:
                return self._active_scans[scan_id]
            elif scan_id in self._completed_scans:
                return self._completed_scans[scan_id]
            return None
    
    def get_all_active_scans(self) -> Dict[str, ScanReport]:
        """Get all currently active scans."""
        
        with self._lock:
            return self._active_scans.copy()
    
    def get_scan_summary(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a concise summary of scan status."""
        
        scan_report = self.get_scan_status(scan_id)
        if not scan_report:
            return None
        
        # Calculate stage completion percentage
        completed_stages = sum(
            1 for stage_progress in scan_report.stages.values()
            if stage_progress.status == ScanStatus.COMPLETED
        )
        total_stages = len(scan_report.stages)
        stage_completion = (completed_stages / total_stages * 100) if total_stages > 0 else 0
        
        # Calculate plugin completion
        completed_plugins = sum(
            1 for plugin_status in scan_report.plugins.values()
            if plugin_status.status == ScanStatus.COMPLETED
        )
        total_plugins = len(scan_report.plugins)
        plugin_completion = (completed_plugins / total_plugins * 100) if total_plugins > 0 else 0
        
        # Estimate time remaining
        time_remaining = self._estimate_time_remaining(scan_report)
        
        return {
            "scan_id": scan_id,
            "package_name": scan_report.package_name,
            "status": scan_report.status.value,
            "current_stage": scan_report.current_stage.value,
            "overall_progress": scan_report.overall_progress,
            "stage_completion": stage_completion,
            "plugin_completion": plugin_completion,
            "runtime_seconds": (
                datetime.now() - scan_report.start_time
            ).total_seconds() if scan_report.status in [ScanStatus.RUNNING, ScanStatus.COMPLETING] else (
                scan_report.total_duration or 0
            ),
            "estimated_time_remaining": time_remaining,
            "findings_count": scan_report.total_findings,
            "error_count": len(scan_report.errors),
            "warning_count": len(scan_report.warnings),
            "resource_status": scan_report.resource_metrics.status.value,
            "performance_score": scan_report.performance_score
        }
    
    def _calculate_overall_progress(self, scan_report: ScanReport) -> float:
        """Calculate overall scan progress based on stage completion."""
        
        if not scan_report.stages:
            return 0.0
        
        # Weight stages by typical execution time
        stage_weights = {
            ScanStage.INITIALIZING: 0.05,
            ScanStage.PREPROCESSING: 0.10,
            ScanStage.PLUGIN_LOADING: 0.05,
            ScanStage.STATIC_ANALYSIS: 0.30,
            ScanStage.DYNAMIC_ANALYSIS: 0.25,
            ScanStage.FRAMEWORK_FILTERING: 0.10,
            ScanStage.ML_ENHANCEMENT: 0.08,
            ScanStage.VULNERABILITY_CLASSIFICATION: 0.05,
            ScanStage.REPORT_GENERATION: 0.02
        }
        
        total_weight = 0.0
        weighted_progress = 0.0
        
        for stage, stage_progress in scan_report.stages.items():
            weight = stage_weights.get(stage, 0.05)  # Default weight
            total_weight += weight
            weighted_progress += (stage_progress.progress / 100.0) * weight
        
        return (weighted_progress / total_weight * 100.0) if total_weight > 0 else 0.0
    
    def _estimate_time_remaining(self, scan_report: ScanReport) -> Optional[float]:
        """Estimate time remaining for scan completion."""
        
        if scan_report.status != ScanStatus.RUNNING:
            return None
        
        elapsed_time = (datetime.now() - scan_report.start_time).total_seconds()
        progress = scan_report.overall_progress
        
        if progress <= 0:
            return None
        
        # Simple linear extrapolation
        estimated_total_time = elapsed_time / (progress / 100.0)
        time_remaining = estimated_total_time - elapsed_time
        
        return max(0, time_remaining)
    
    def _generate_optimization_recommendations(self, scan_report: ScanReport) -> List[str]:
        """Generate performance optimization recommendations."""
        
        recommendations = []
        
        # Check stage durations against baselines
        for stage, stage_progress in scan_report.stages.items():
            if stage_progress.actual_duration and stage in self._performance_baselines:
                baseline = self._performance_baselines[stage]
                if stage_progress.actual_duration > baseline * 1.5:
                    recommendations.append(
                        f"Consider optimizing {stage.value} stage (took {stage_progress.actual_duration:.1f}s, baseline: {baseline:.1f}s)"
                    )
        
        # Check plugin performance
        slow_plugins = [
            plugin.plugin_name for plugin in scan_report.plugins.values()
            if plugin.execution_time and plugin.execution_time > 60.0
        ]
        if slow_plugins:
            recommendations.append(f"Consider reviewing slow plugins: {', '.join(slow_plugins)}")
        
        # Check error rate
        error_rate = len(scan_report.errors) / len(scan_report.plugins) if scan_report.plugins else 0
        if error_rate > 0.1:
            recommendations.append("High plugin error rate detected - consider reviewing plugin configuration")
        
        # Resource usage recommendations
        if scan_report.resource_metrics.memory_usage_mb > 2048:
            recommendations.append("High memory usage detected - consider batch processing for large APKs")
        
        if scan_report.resource_metrics.cpu_usage > 90:
            recommendations.append("High CPU usage detected - consider reducing parallel plugin execution")
        
        return recommendations
    
    def _calculate_performance_score(self, scan_report: ScanReport) -> float:
        """Calculate overall performance score (0-100)."""
        
        score = 100.0
        
        # Deduct points for excessive duration
        if scan_report.total_duration:
            expected_duration = 300.0  # 5 minutes baseline
            if scan_report.total_duration > expected_duration:
                time_penalty = min(30, (scan_report.total_duration - expected_duration) / 60 * 5)
                score -= time_penalty
        
        # Deduct points for errors
        error_penalty = min(20, len(scan_report.errors) * 5)
        score -= error_penalty
        
        # Deduct points for resource issues
        if scan_report.resource_metrics.status == ResourceStatus.CRITICAL:
            score -= 15
        elif scan_report.resource_metrics.status == ResourceStatus.HIGH:
            score -= 10
        
        # Bonus for high accuracy
        if scan_report.accuracy_score and scan_report.accuracy_score > 0.9:
            score += 5
        
        return max(0, score)
    
    def _start_monitoring_thread(self, scan_id: str) -> None:
        """Start resource monitoring thread for a scan."""
        
        if not self.enable_resource_monitoring:
            return
        
        stop_event = threading.Event()
        self._stop_monitoring[scan_id] = stop_event
        
        def monitor_resources():
            while not stop_event.is_set():
                try:
                    # Update resource metrics
                    self._update_resource_metrics(scan_id)
                    time.sleep(self.update_interval)
                except Exception as e:
                    logger.debug(f"Resource monitoring error for {scan_id}: {e}")
        
        thread = threading.Thread(target=monitor_resources, daemon=True)
        thread.start()
        self._monitoring_threads[scan_id] = thread
    
    def _stop_monitoring_thread(self, scan_id: str) -> None:
        """Stop resource monitoring thread for a scan."""
        
        if scan_id in self._stop_monitoring:
            self._stop_monitoring[scan_id].set()
            del self._stop_monitoring[scan_id]
        
        if scan_id in self._monitoring_threads:
            del self._monitoring_threads[scan_id]
    
    def _update_resource_metrics(self, scan_id: str) -> None:
        """Update resource metrics for a scan."""
        
        try:
            import psutil
            
            with self._lock:
                if scan_id not in self._active_scans:
                    return
                
                scan_report = self._active_scans[scan_id]
                
                # Get current system metrics
                cpu_percent = psutil.cpu_percent(interval=None)
                memory = psutil.virtual_memory()
                disk_io = psutil.disk_io_counters()
                
                # Update resource metrics
                metrics = ResourceMetrics(
                    cpu_usage=cpu_percent,
                    memory_usage_mb=memory.used / (1024 * 1024),
                    disk_io_mb=disk_io.read_bytes / (1024 * 1024) if disk_io else 0,
                    status=self._determine_resource_status(cpu_percent, memory.percent)
                )
                
                scan_report.resource_metrics = metrics
                scan_report.resource_history.append(metrics)
                
                # Limit history size
                if len(scan_report.resource_history) > 100:
                    scan_report.resource_history = scan_report.resource_history[-50:]
        
        except ImportError:
            # psutil not available - skip resource monitoring
            pass
        except Exception as e:
            logger.debug(f"Error updating resource metrics: {e}")
    
    def _determine_resource_status(self, cpu_percent: float, memory_percent: float) -> ResourceStatus:
        """Determine resource status based on usage levels."""
        
        if cpu_percent > 95 or memory_percent > 90:
            return ResourceStatus.CRITICAL
        elif cpu_percent > 80 or memory_percent > 75:
            return ResourceStatus.HIGH
        elif cpu_percent < 30 and memory_percent < 50:
            return ResourceStatus.OPTIMIZED
        else:
            return ResourceStatus.NORMAL
    
    def _save_scan_report(self, scan_report: ScanReport) -> None:
        """Save scan report to file."""
        
        try:
            report_file = self.report_directory / f"scan_report_{scan_report.scan_id}.json"
            
            # Convert to JSON-serializable format
            report_dict = {
                "scan_id": scan_report.scan_id,
                "package_name": scan_report.package_name,
                "scan_type": scan_report.scan_type,
                "status": scan_report.status.value,
                "current_stage": scan_report.current_stage.value,
                "overall_progress": scan_report.overall_progress,
                "start_time": scan_report.start_time.isoformat(),
                "actual_completion": scan_report.actual_completion.isoformat() if scan_report.actual_completion else None,
                "total_duration": scan_report.total_duration,
                "total_findings": scan_report.total_findings,
                "vulnerability_count": scan_report.vulnerability_count,
                "false_positive_count": scan_report.false_positive_count,
                "accuracy_score": scan_report.accuracy_score,
                "performance_score": scan_report.performance_score,
                "errors": scan_report.errors,
                "warnings": scan_report.warnings,
                "optimization_recommendations": scan_report.optimization_recommendations
            }
            
            with open(report_file, 'w') as f:
                json.dump(report_dict, f, indent=2)
                
            logger.debug(f"Saved scan report to {report_file}")
        
        except Exception as e:
            logger.error(f"Failed to save scan report: {e}")
    
    def _trigger_progress_callbacks(self, scan_id: str, scan_report: ScanReport) -> None:
        """Trigger progress update callbacks."""
        
        for callback in self._progress_callbacks:
            try:
                callback(scan_id, scan_report)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")
    
    def _trigger_completion_callbacks(self, scan_id: str, scan_report: ScanReport) -> None:
        """Trigger completion callbacks."""
        
        for callback in self._completion_callbacks:
            try:
                callback(scan_id, scan_report)
            except Exception as e:
                logger.error(f"Completion callback error: {e}")
    
    def _trigger_error_callbacks(self, scan_id: str, error_entry: Dict[str, Any]) -> None:
        """Trigger error callbacks."""
        
        for callback in self._error_callbacks:
            try:
                callback(scan_id, error_entry)
            except Exception as e:
                logger.error(f"Error callback error: {e}")
    
    def add_progress_callback(self, callback: Callable[[str, ScanReport], None]) -> None:
        """Add a progress update callback."""
        self._progress_callbacks.append(callback)
    
    def add_completion_callback(self, callback: Callable[[str, ScanReport], None]) -> None:
        """Add a completion callback."""
        self._completion_callbacks.append(callback)
    
    def add_error_callback(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """Add an error callback."""
        self._error_callbacks.append(callback)
    
    def cleanup(self) -> None:
        """Cleanup resources and stop all monitoring."""
        
        with self._lock:
            # Stop all monitoring threads
            for scan_id in list(self._stop_monitoring.keys()):
                self._stop_monitoring_thread(scan_id)
            
            # Clear all state
            self._active_scans.clear()
            self._monitoring_threads.clear()
            self._stop_monitoring.clear()
        
        logger.info("Enhanced scan status reporter cleanup complete")

# Global instance for module-level access
_global_reporter = None

def get_scan_status_reporter(config: Optional[Dict[str, Any]] = None) -> EnhancedScanStatusReporter:
    """Get the global scan status reporter instance."""
    global _global_reporter
    if _global_reporter is None:
        _global_reporter = EnhancedScanStatusReporter(config)
    return _global_reporter

def create_scan_status_context(scan_id: str, package_name: str, scan_type: str, 
                             estimated_stages: List[ScanStage]) -> ScanReport:
    """Convenience function to create scan status tracking context."""
    reporter = get_scan_status_reporter()
    return reporter.start_scan_tracking(scan_id, package_name, scan_type, estimated_stages) 
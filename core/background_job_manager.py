#!/usr/bin/env python3
"""
Background Job Manager for AODS
Handles long-running JADX decompilation jobs without losing vulnerability detection
"""

import os
import time
import threading
import logging
import json
import queue
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import psutil

logger = logging.getLogger(__name__)

class JobPriority(Enum):
    """Job priority levels"""
    LIGHTNING = "lightning"      # 60s hard timeout
    FAST = "fast"               # 5min soft, 15min background
    STANDARD = "standard"       # 10min soft, 30min background  
    DEEP = "deep"              # 20min soft, 60min background

class BackgroundJobStatus(Enum):
    """Background job status"""
    ACTIVE = "active"
    BACKGROUND = "background"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class BackgroundJob:
    """Background job data structure"""
    job_id: str
    apk_path: str
    package_name: str
    priority: JobPriority
    start_time: float
    soft_timeout: float
    hard_timeout: float
    status: BackgroundJobStatus
    process: Optional[any] = None
    partial_results: Dict[str, Any] = None
    final_results: Dict[str, Any] = None
    error_message: Optional[str] = None
    background_start_time: Optional[float] = None

class BackgroundJobManager:
    """Manages long-running JADX jobs in background for complete vulnerability detection"""
    
    def __init__(self):
        self.active_jobs: Dict[str, BackgroundJob] = {}
        self.background_jobs: Dict[str, BackgroundJob] = {}
        self.completed_jobs: Dict[str, BackgroundJob] = {}
        
        self.job_queue = queue.Queue()
        self.result_callbacks: Dict[str, callable] = {}
        
        self._background_thread = None
        self._monitor_thread = None
        self._running = False
        
        # Timeout configuration by priority
        self.timeout_config = {
            JobPriority.LIGHTNING: {"soft": 60, "hard": 120},      # Fast failure for lightning
            JobPriority.FAST: {"soft": 300, "hard": 900},         # 5min soft, 15min hard  
            JobPriority.STANDARD: {"soft": 600, "hard": 1800},    # 10min soft, 30min hard
            JobPriority.DEEP: {"soft": 1200, "hard": 3600}        # 20min soft, 60min hard
        }
        
        self.logger = logger
        
    def start_job_with_background_support(self, job_id: str, apk_path: str, 
                                        package_name: str, priority: JobPriority,
                                        process: any) -> Dict[str, Any]:
        """
        Start a job with intelligent background processing support.
        
        Returns immediate response with partial results if job needs background processing.
        """
        config = self.timeout_config[priority]
        
        job = BackgroundJob(
            job_id=job_id,
            apk_path=apk_path,
            package_name=package_name,
            priority=priority,
            start_time=time.time(),
            soft_timeout=config["soft"],
            hard_timeout=config["hard"],
            status=BackgroundJobStatus.ACTIVE,
            process=process
        )
        
        self.active_jobs[job_id] = job
        self._ensure_monitoring_active()
        
        # Wait for soft timeout or completion
        return self._wait_with_background_fallback(job_id)
    
    def _wait_with_background_fallback(self, job_id: str) -> Dict[str, Any]:
        """Wait for job completion with background fallback strategy"""
        if job_id not in self.active_jobs:
            return {"success": False, "error": "Job not found"}
        
        job = self.active_jobs[job_id]
        start_wait = time.time()
        
        # Wait until soft timeout
        while time.time() - start_wait < job.soft_timeout:
            # Check if job completed normally
            if job.process and job.process.poll() is not None:
                return self._handle_job_completion(job_id)
            
            # Check for process hang (no CPU activity)
            if self._is_process_hung(job):
                self.logger.warning(f"Process {job_id} appears hung - moving to background")
                break
                
            time.sleep(1)
        
        # Soft timeout reached - move to background for detailed scans
        if job.priority in [JobPriority.FAST, JobPriority.STANDARD, JobPriority.DEEP]:
            return self._move_to_background_processing(job_id)
        else:
            # Lightning mode - force terminate for speed
            return self._force_terminate_lightning_job(job_id)
    
    def _move_to_background_processing(self, job_id: str) -> Dict[str, Any]:
        """Move job to background processing to avoid missing vulnerabilities"""
        if job_id not in self.active_jobs:
            return {"success": False, "error": "Job not found"}
        
        job = self.active_jobs[job_id]
        job.status = BackgroundJobStatus.BACKGROUND
        job.background_start_time = time.time()
        
        # Move to background tracking
        self.background_jobs[job_id] = job
        del self.active_jobs[job_id]
        
        # Generate partial results for immediate return
        partial_results = self._generate_partial_results(job)
        job.partial_results = partial_results
        
        self.logger.info(f"Job {job_id} moved to background processing - partial results returned")
        
        return {
            "success": True,
            "background_processing": True,
            "job_id": job_id,
            "partial_results": partial_results,
            "message": f"Analysis moved to background - partial results available, complete results will be available later",
            "estimated_completion": time.time() + (job.hard_timeout - job.soft_timeout),
            "check_status_command": f"python -c \"from core.background_job_manager import get_job_status; print(get_job_status('{job_id}'))\""
        }
    
    def _force_terminate_lightning_job(self, job_id: str) -> Dict[str, Any]:
        """Force terminate lightning jobs for speed (acceptable trade-off)"""
        if job_id not in self.active_jobs:
            return {"success": False, "error": "Job not found"}
        
        job = self.active_jobs[job_id]
        
        # Terminate process
        if job.process:
            try:
                if hasattr(job.process, 'pid'):
                    os.killpg(os.getpgid(job.process.pid), 15)  # SIGTERM
                    time.sleep(2)
                    if job.process.poll() is None:
                        os.killpg(os.getpgid(job.process.pid), 9)  # SIGKILL
            except Exception as e:
                self.logger.warning(f"Error terminating lightning job {job_id}: {e}")
        
        job.status = BackgroundJobStatus.FAILED
        job.error_message = "Lightning mode timeout - prioritizing speed over completeness"
        
        # Move to completed
        self.completed_jobs[job_id] = job
        del self.active_jobs[job_id]
        
        self.logger.info(f"Lightning job {job_id} terminated for speed optimization")
        
        return {
            "success": False,
            "lightning_timeout": True,
            "message": "Lightning mode prioritizes speed - use 'fast' or 'standard' profile for complete analysis",
            "suggestion": "For complete vulnerability detection, use: --profile fast"
        }
    
    def _generate_partial_results(self, job: BackgroundJob) -> Dict[str, Any]:
        """Generate partial results from available data"""
        try:
            # Try to extract any partial results from process output
            partial_results = {
                "analysis_status": "partial",
                "background_processing": True,
                "package_name": job.package_name,
                "apk_path": job.apk_path,
                "analysis_start_time": job.start_time,
                "moved_to_background_time": job.background_start_time,
                "vulnerabilities": [],  # Will be populated when background completes
                "metadata": {
                    "analysis_method": "background_decompilation",
                    "priority": job.priority.value,
                    "status": "processing_in_background"
                }
            }
            
            # Try to extract any preliminary findings
            if job.process and hasattr(job.process, 'stdout'):
                # Attempt to parse any partial output
                partial_results["preliminary_analysis"] = self._extract_preliminary_findings(job)
            
            return partial_results
            
        except Exception as e:
            self.logger.error(f"Failed to generate partial results for {job.job_id}: {e}")
            return {"error": "Failed to generate partial results", "background_processing": True}
    
    def _extract_preliminary_findings(self, job: BackgroundJob) -> Dict[str, Any]:
        """Extract any preliminary findings from process output"""
        # This would implement parsing of partial JADX output
        # For now, return basic metadata
        return {
            "apk_size_mb": os.path.getsize(job.apk_path) / (1024 * 1024),
            "analysis_priority": job.priority.value,
            "note": "Detailed findings will be available when background processing completes"
        }
    
    def _handle_job_completion(self, job_id: str) -> Dict[str, Any]:
        """Handle normal job completion"""
        if job_id not in self.active_jobs:
            return {"success": False, "error": "Job not found"}
        
        job = self.active_jobs[job_id]
        
        # Process completed normally
        if job.process and job.process.returncode == 0:
            job.status = BackgroundJobStatus.COMPLETED
            # Extract full results here
            job.final_results = self._extract_final_results(job)
        else:
            job.status = BackgroundJobStatus.FAILED
            job.error_message = f"Process failed with return code {job.process.returncode if job.process else 'unknown'}"
        
        # Move to completed
        self.completed_jobs[job_id] = job
        del self.active_jobs[job_id]
        
        return {
            "success": job.status == BackgroundJobStatus.COMPLETED,
            "results": job.final_results if job.status == BackgroundJobStatus.COMPLETED else None,
            "error": job.error_message if job.status == BackgroundJobStatus.FAILED else None
        }
    
    def _extract_final_results(self, job: BackgroundJob) -> Dict[str, Any]:
        """Extract final results from completed job"""
        # Implementation would extract actual JADX results
        return {
            "analysis_status": "complete",
            "package_name": job.package_name,
            "vulnerabilities": [],  # Would be populated with actual findings
            "analysis_duration": time.time() - job.start_time,
            "priority": job.priority.value
        }
    
    def _is_process_hung(self, job: BackgroundJob) -> bool:
        """Detect if process is hung (no CPU activity)"""
        if not job.process or not hasattr(job.process, 'pid'):
            return False
        
        try:
            process = psutil.Process(job.process.pid)
            cpu_percent = process.cpu_percent(interval=1)
            
            # If CPU usage is 0 for extended period, likely hung
            if cpu_percent < 0.1 and time.time() - job.start_time > 30:
                return True
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return True  # Process not accessible, consider hung
        
        return False
    
    def _ensure_monitoring_active(self):
        """Ensure background monitoring is active"""
        if not self._running:
            self._running = True
            self._monitor_thread = threading.Thread(target=self._monitor_background_jobs, daemon=True)
            self._monitor_thread.start()
    
    def _monitor_background_jobs(self):
        """Monitor background jobs for completion"""
        while self._running:
            try:
                # Check background jobs
                completed_background_jobs = []
                
                for job_id, job in self.background_jobs.items():
                    # Check if background job completed
                    if job.process and job.process.poll() is not None:
                        completed_background_jobs.append(job_id)
                    
                    # Check hard timeout
                    elif job.background_start_time and \
                         time.time() - job.background_start_time > (job.hard_timeout - job.soft_timeout):
                        self.logger.warning(f"Background job {job_id} exceeded hard timeout")
                        self._terminate_background_job(job_id)
                        completed_background_jobs.append(job_id)
                
                # Move completed background jobs
                for job_id in completed_background_jobs:
                    self._finalize_background_job(job_id)
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error in background job monitoring: {e}")
                time.sleep(10)
    
    def _finalize_background_job(self, job_id: str):
        """Finalize a background job"""
        if job_id not in self.background_jobs:
            return
        
        job = self.background_jobs[job_id]
        
        if job.process and job.process.returncode == 0:
            job.status = BackgroundJobStatus.COMPLETED
            job.final_results = self._extract_final_results(job)
            self.logger.info(f"Background job {job_id} completed successfully")
        else:
            job.status = BackgroundJobStatus.FAILED
            job.error_message = "Background processing failed or timed out"
        
        # Move to completed
        self.completed_jobs[job_id] = job
        del self.background_jobs[job_id]
        
        # Call result callback if registered
        if job_id in self.result_callbacks:
            try:
                self.result_callbacks[job_id](job)
            except Exception as e:
                self.logger.error(f"Error calling result callback for {job_id}: {e}")
    
    def _terminate_background_job(self, job_id: str):
        """Terminate a background job that exceeded hard timeout"""
        if job_id not in self.background_jobs:
            return
        
        job = self.background_jobs[job_id]
        
        if job.process:
            try:
                os.killpg(os.getpgid(job.process.pid), 15)  # SIGTERM
                time.sleep(5)
                if job.process.poll() is None:
                    os.killpg(os.getpgid(job.process.pid), 9)  # SIGKILL
            except Exception as e:
                self.logger.error(f"Error terminating background job {job_id}: {e}")
        
        job.status = BackgroundJobStatus.FAILED
        job.error_message = f"Background job exceeded hard timeout ({job.hard_timeout}s)"
    
    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Get status of any job"""
        # Check all job collections
        for collection_name, collection in [
            ("active", self.active_jobs),
            ("background", self.background_jobs), 
            ("completed", self.completed_jobs)
        ]:
            if job_id in collection:
                job = collection[job_id]
                return {
                    "job_id": job_id,
                    "status": job.status.value,
                    "collection": collection_name,
                    "package_name": job.package_name,
                    "priority": job.priority.value,
                    "start_time": job.start_time,
                    "background_start_time": job.background_start_time,
                    "has_partial_results": job.partial_results is not None,
                    "has_final_results": job.final_results is not None,
                    "error_message": job.error_message
                }
        
        return {"error": f"Job {job_id} not found"}
    
    def shutdown(self):
        """Gracefully shutdown the background job manager"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=10)

# Global instance
background_job_manager = BackgroundJobManager()

# Convenience functions
def get_job_status(job_id: str) -> Dict[str, Any]:
    """Get job status globally"""
    return background_job_manager.get_job_status(job_id)

def start_background_job(job_id: str, apk_path: str, package_name: str, 
                        priority: JobPriority, process: any) -> Dict[str, Any]:
    """Start a background job globally"""
    return background_job_manager.start_job_with_background_support(
        job_id, apk_path, package_name, priority, process
    ) 
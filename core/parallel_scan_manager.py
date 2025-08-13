#!/usr/bin/env python3
"""
Parallel Scan Manager for AODS
==============================

This module manages parallel execution of static and dynamic scans in separate
subprocesses, with proper coordination and consolidation of results.

Features:
- Separate subprocess execution for static and dynamic scans
- Cross-platform window management (tmux, screen, xterm, etc.)
- Real-time progress monitoring
- Result consolidation and deduplication
- Timeout management and graceful shutdown
- Edge case handling for different environments
"""

import asyncio
import json
import logging
import os
import platform
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from concurrent.futures import ProcessPoolExecutor, as_completed
import threading
import queue
import importlib
from core.framework_filtering_system import filter_vulnerability_results, FrameworkFilterManager
from core.vulnerability_classification import VulnerabilitySourceClassifier
from core.vulnerability_origin_tracker import VulnerabilityOriginTracker
from core.runtime_evidence_validator import RuntimeEvidenceValidator

@dataclass
class ScanConfiguration:
    """Configuration for a scan execution."""
    scan_type: str  # "static" or "dynamic"
    apk_path: str
    package_name: str
    mode: str = "deep"
    vulnerable_app_mode: bool = False
    timeout: int = 1800  # 30 minutes default
    output_file: Optional[str] = None
    window_title: Optional[str] = None
    additional_args: List[str] = field(default_factory=list)

@dataclass
class ScanResult:
    """Result from a scan execution."""
    scan_type: str
    success: bool
    duration: float
    output_file: Optional[str] = None
    findings_count: int = 0
    error_message: Optional[str] = None
    process_id: Optional[int] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert ScanResult to dictionary for JSON serialization."""
        return {
            'scan_type': self.scan_type,
            'success': self.success,
            'duration': self.duration,
            'output_file': self.output_file,
            'findings_count': self.findings_count,
            'error_message': self.error_message,
            'process_id': self.process_id,
            'findings': self.findings
        }

class ParallelScanManager:
    """
    Manages parallel execution of AODS scans with cross-platform support.
    """
    
    def __init__(self, work_dir: Optional[str] = None):
        """Initialize the parallel scan manager."""
        self.logger = logging.getLogger(__name__)
        self.work_dir = Path(work_dir) if work_dir else Path.cwd()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="aods_parallel_"))
        self.running_processes: Dict[str, subprocess.Popen] = {}
        self.scan_results: Dict[str, ScanResult] = {}
        self.terminal_type = self._detect_terminal_environment()
        self.consolidation_config = self._load_consolidation_config()
        
        # **APK CONTEXT FIX**: Store target package for filtering
        self.target_package = None
        
        # Initialize unified execution framework
        self._initialize_unified_execution()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _detect_terminal_environment(self) -> str:
        """Detect the available terminal multiplexer or window manager."""
        # Check for terminal multiplexers
        if shutil.which('tmux'):
            return 'tmux'
        elif shutil.which('screen'):
            return 'screen'
        elif platform.system() == 'Linux' and os.environ.get('DISPLAY'):
            # Check for GUI terminal emulators
            if shutil.which('gnome-terminal'):
                return 'gnome-terminal'
            elif shutil.which('xterm'):
                return 'xterm'
            elif shutil.which('konsole'):
                return 'konsole'
            elif shutil.which('terminator'):
                return 'terminator'
        elif platform.system() == 'Darwin':  # macOS
            return 'terminal-app'
        elif platform.system() == 'Windows':
            return 'cmd'
        
        return 'subprocess'  # Fallback to subprocess without separate windows
    
    def _load_consolidation_config(self) -> Dict[str, Any]:
        """Load configuration for result consolidation."""
        return {
            'deduplication': {
                'enabled': True,
                'similarity_threshold': 0.85,
                'merge_similar_findings': True
            },
            'prioritization': {
                'static_weight': 0.6,
                'dynamic_weight': 0.4,
                'confidence_threshold': 0.3
            },
            'filtering': {
                'framework_noise_filter': True,
                'min_severity': 'INFO',
                'exclude_test_files': True
            }
        }
    
    def create_scan_command(self, config: ScanConfiguration) -> List[str]:
        """Create the command line for a scan execution."""
        # Use virtual environment python if available
        python_cmd = 'venv/bin/python' if Path('venv/bin/python').exists() else 'python3'
        
        base_cmd = [
            python_cmd, 'dyna.py',
            '--apk', config.apk_path,
            '--pkg', config.package_name,
            '--mode', config.mode,
            '--formats', 'json',
            '--verbose'
        ]
        
        if config.vulnerable_app_mode:
            base_cmd.append('--vulnerable-app-mode')
        
        # Add scan-type specific arguments
        if config.scan_type == 'static':
            base_cmd.extend([
                '--static-only'
            ])
        elif config.scan_type == 'dynamic':
            base_cmd.extend([
                '--dynamic-only'
            ])
        
        # Add output file
        if config.output_file:
            base_cmd.extend(['--output', config.output_file])
        
        # Add any additional arguments
        base_cmd.extend(config.additional_args)
        
        return base_cmd
    
    def run_scan_in_window(self, config: ScanConfiguration) -> subprocess.Popen:
        """Run a scan in a separate window/terminal."""
        # Create output file path first
        if not config.output_file:
            config.output_file = str(self.temp_dir / f"{config.scan_type}_results.json")
        
        # Create command with output file included
        cmd = self.create_scan_command(config)
        
        log_file = str(self.temp_dir / f"{config.scan_type}_scan.log")
        
        if self.terminal_type == 'tmux':
            return self._run_with_tmux(cmd, config, log_file)
        elif self.terminal_type == 'screen':
            return self._run_with_screen(cmd, config, log_file)
        elif self.terminal_type == 'gnome-terminal':
            return self._run_with_gnome_terminal(cmd, config, log_file)
        elif self.terminal_type == 'xterm':
            return self._run_with_xterm(cmd, config, log_file)
        elif self.terminal_type == 'terminal-app':
            return self._run_with_terminal_app(cmd, config, log_file)
        elif self.terminal_type == 'cmd':
            return self._run_with_cmd(cmd, config, log_file)
        else:
            return self._run_with_subprocess(cmd, config, log_file)
    
    def _run_with_tmux(self, cmd: List[str], config: ScanConfiguration, log_file: str) -> subprocess.Popen:
        """Run scan in a new tmux window."""
        session_name = f"aods_{config.scan_type}_{int(time.time())}"
        window_title = config.window_title or f"AODS {config.scan_type.title()} Scan"
        
        # Create tmux session and run command
        tmux_cmd = [
            'tmux', 'new-session', '-d', '-s', session_name,
            '-c', str(self.work_dir),
            f"echo 'Starting {config.scan_type} scan...'; {' '.join(cmd)} 2>&1 | tee {log_file}; echo 'Scan completed. Press any key to close.'; read"
        ]
        
        # Set window title
        subprocess.run(['tmux', 'rename-window', '-t', session_name, window_title], 
                      capture_output=True)
        
        return subprocess.Popen(tmux_cmd, cwd=self.work_dir)
    
    def _run_with_screen(self, cmd: List[str], config: ScanConfiguration, log_file: str) -> subprocess.Popen:
        """Run scan in a new screen session."""
        session_name = f"aods_{config.scan_type}_{int(time.time())}"
        
        screen_cmd = [
            'screen', '-dmS', session_name,
            'bash', '-c',
            f"cd {self.work_dir}; echo 'Starting {config.scan_type} scan...'; {' '.join(cmd)} 2>&1 | tee {log_file}; echo 'Scan completed. Press any key to close.'; read"
        ]
        
        return subprocess.Popen(screen_cmd, cwd=self.work_dir)
    
    def _run_with_gnome_terminal(self, cmd: List[str], config: ScanConfiguration, log_file: str) -> subprocess.Popen:
        """Run scan in a new gnome-terminal window."""
        window_title = config.window_title or f"AODS {config.scan_type.title()} Scan"
        
        terminal_cmd = [
            'gnome-terminal',
            '--title', window_title,
            '--working-directory', str(self.work_dir),
            '--',
            'bash', '-c',
            f"echo 'Starting {config.scan_type} scan...'; {' '.join(cmd)} 2>&1 | tee {log_file}; echo 'Scan completed. Press any key to close.'; read"
        ]
        
        return subprocess.Popen(terminal_cmd, cwd=self.work_dir)
    
    def _run_with_xterm(self, cmd: List[str], config: ScanConfiguration, log_file: str) -> subprocess.Popen:
        """Run scan in a new xterm window."""
        window_title = config.window_title or f"AODS {config.scan_type.title()} Scan"
        
        xterm_cmd = [
            'xterm',
            '-title', window_title,
            '-e',
            'bash', '-c',
            f"cd {self.work_dir}; echo 'Starting {config.scan_type} scan...'; {' '.join(cmd)} 2>&1 | tee {log_file}; echo 'Scan completed. Press any key to close.'; read"
        ]
        
        return subprocess.Popen(xterm_cmd, cwd=self.work_dir)
    
    def _run_with_terminal_app(self, cmd: List[str], config: ScanConfiguration, log_file: str) -> subprocess.Popen:
        """Run scan in a new macOS Terminal window."""
        window_title = config.window_title or f"AODS {config.scan_type.title()} Scan"
        
        script = f'''
        tell application "Terminal"
            do script "cd {self.work_dir}; echo 'Starting {config.scan_type} scan...'; {' '.join(cmd)} 2>&1 | tee {log_file}; echo 'Scan completed. Press any key to close.'; read"
            set custom title of front window to "{window_title}"
        end tell
        '''
        
        return subprocess.Popen(['osascript', '-e', script])
    
    def _run_with_cmd(self, cmd: List[str], config: ScanConfiguration, log_file: str) -> subprocess.Popen:
        """Run scan in a new Windows command prompt."""
        window_title = config.window_title or f"AODS {config.scan_type.title()} Scan"
        
        cmd_script = f'''
        cd /d {self.work_dir}
        echo Starting {config.scan_type} scan...
        {' '.join(cmd)} 2>&1 | tee {log_file}
        echo Scan completed. Press any key to close.
        pause
        '''
        
        return subprocess.Popen(['cmd', '/c', 'start', '/wait', window_title, 'cmd', '/c', cmd_script])
    
    def _run_with_subprocess(self, cmd: List[str], config: ScanConfiguration, log_file: str) -> subprocess.Popen:
        """Run scan as a background subprocess (fallback method)."""
        self.logger.info(f"Running {config.scan_type} scan with command: {' '.join(cmd)}")
        
        # Ensure the command exists
        if not shutil.which('python3'):
            self.logger.error("python3 not found in PATH")
            raise FileNotFoundError("python3 not found in PATH")
        
        # Create log file directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(log_file, 'w') as log:
                process = subprocess.Popen(
                    cmd,
                    cwd=self.work_dir,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    bufsize=1,  # Line buffered
                    env=dict(os.environ, PYTHONPATH=str(self.work_dir))  # Ensure Python path is set
                )
                
                # Log the process start
                self.logger.info(f"Started {config.scan_type} scan process (PID: {process.pid})")
                
                return process
                
        except Exception as e:
            self.logger.error(f"Failed to start {config.scan_type} scan: {e}")
            raise
    
    def monitor_scan_progress(self, config: ScanConfiguration) -> None:
        """Monitor scan progress by reading log files."""
        log_file = self.temp_dir / f"{config.scan_type}_scan.log"
        
        if not log_file.exists():
            return
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Move to end of file
                f.seek(0, 2)
                
                while config.scan_type in self.running_processes:
                    line = f.readline()
                    if line:
                        # Extract progress information
                        if 'progress:' in line.lower() or 'analyzed' in line.lower():
                            self.logger.info(f"[{config.scan_type.upper()}] {line.strip()}")
                        elif 'error' in line.lower() or 'failed' in line.lower():
                            self.logger.warning(f"[{config.scan_type.upper()}] {line.strip()}")
                    else:
                        time.sleep(0.1)  # Optimized pause - 10x faster polling
                        
        except Exception as e:
            self.logger.debug(f"Error monitoring {config.scan_type} progress: {e}")
    
    def run_parallel_scans(self, apk_path: str, package_name: str, 
                          mode: str = "deep", vulnerable_app_mode: bool = False,
                          timeout: int = 1800, objection_context: Dict = None) -> Dict[str, ScanResult]:
        """
        Run static and dynamic scans in parallel.
        
        Args:
            apk_path: Path to the APK file
            package_name: Package name of the app
            mode: Scan mode (safe/deep)
            vulnerable_app_mode: Enable vulnerable app mode
            timeout: Timeout in seconds for each scan
            
        Returns:
            Dictionary of scan results
        """
        # Try unified execution framework first
        print(f"🔧 DEBUG: unified_execution_available: {hasattr(self, 'unified_execution_available') and getattr(self, 'unified_execution_available', False)}")
        if hasattr(self, 'unified_execution_available') and self.unified_execution_available:
            try:
                # CRITICAL FIX: Store unified results in self.scan_results for consolidate_results() access
                unified_results = self.run_parallel_scans_unified(apk_path, package_name, mode, vulnerable_app_mode, timeout, objection_context=objection_context)
                print(f"🔧 DEBUG: unified_results keys: {list(unified_results.keys()) if unified_results else 'None'}")
                print(f"🔧 DEBUG: Before update - self.scan_results: {self.scan_results}")
                self.scan_results.update(unified_results)
                print(f"🔧 DEBUG: After update - self.scan_results: {self.scan_results}")
                return unified_results
            except Exception as e:
                self.logger.warning(f"⚠️  Unified execution failed: {e}")
                self.logger.info("🔄 Falling back to legacy parallel execution...")
                print(f"🔧 DEBUG: Unified execution FAILED, falling back to legacy: {e}")
        
        # Legacy parallel execution implementation
        self.logger.info("🚀 Starting parallel AODS scans...")
        
        # Create scan configurations
        static_config = ScanConfiguration(
            scan_type="static",
            apk_path=apk_path,
            package_name=package_name,
            mode=mode,
            vulnerable_app_mode=vulnerable_app_mode,
            timeout=timeout,
            window_title="AODS Static Analysis"
        )
        
        dynamic_config = ScanConfiguration(
            scan_type="dynamic",
            apk_path=apk_path,
            package_name=package_name,
            mode=mode,
            vulnerable_app_mode=vulnerable_app_mode,
            timeout=timeout,
            window_title="AODS Dynamic Analysis"
        )
        
        # Start both scans
        start_time = time.time()
        
        try:
            # Launch static scan
            self.logger.info("📊 Launching static analysis in separate window...")
            static_process = self.run_scan_in_window(static_config)
            self.running_processes['static'] = static_process
            
            # Launch dynamic scan
            self.logger.info("🔧 Launching dynamic analysis in separate window...")
            dynamic_process = self.run_scan_in_window(dynamic_config)
            self.running_processes['dynamic'] = dynamic_process
            
            # Start progress monitoring in separate threads
            static_monitor = threading.Thread(
                target=self.monitor_scan_progress, 
                args=(static_config,), 
                daemon=True
            )
            dynamic_monitor = threading.Thread(
                target=self.monitor_scan_progress, 
                args=(dynamic_config,), 
                daemon=True
            )
            
            static_monitor.start()
            dynamic_monitor.start()
            
            # Wait for both scans to complete
            self._wait_for_scans(static_config, dynamic_config, timeout)
            
        except Exception as e:
            self.logger.error(f"Error during parallel scan execution: {e}")
            self._cleanup_processes()
            
        finally:
            # Process results
            total_time = time.time() - start_time
            self.logger.info(f"⏱️ Total parallel scan time: {total_time:.2f} seconds")
            
            # Collect and consolidate results
            self._collect_scan_results(static_config, dynamic_config)
            
        return self.scan_results
    
    def _wait_for_scans(self, static_config: ScanConfiguration, 
                       dynamic_config: ScanConfiguration, timeout: int) -> None:
        """Wait for both scans to complete with timeout handling."""
        configs = [static_config, dynamic_config]
        start_time = time.time()
        
        while configs and (time.time() - start_time) < timeout:
            for config in configs[:]:  # Copy list to modify during iteration
                process = self.running_processes.get(config.scan_type)
                
                if process and process.poll() is not None:
                    # Process completed
                    self.logger.info(f"✅ {config.scan_type.title()} scan completed")
                    configs.remove(config)
                    del self.running_processes[config.scan_type]
                
            if configs:
                time.sleep(2)  # Optimized check interval - 2.5x faster monitoring
        
        # Handle timeouts
        for config in configs:
            self.logger.warning(f"⏰ {config.scan_type.title()} scan timed out after {timeout}s")
            self._terminate_scan(config.scan_type)
    
    def _terminate_scan(self, scan_type: str) -> None:
        """Gracefully terminate a scan process."""
        process = self.running_processes.get(scan_type)
        if process:
            try:
                process.terminate()
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            finally:
                del self.running_processes[scan_type]
    
    def _collect_scan_results(self, static_config: ScanConfiguration, 
                             dynamic_config: ScanConfiguration) -> None:
        """Collect and process results from completed scans."""
        for config in [static_config, dynamic_config]:
            # CRITICAL FIX: Check if we already have a scan result with enhanced_report
            existing_result = self.scan_results.get(config.scan_type)
            if existing_result and hasattr(existing_result, 'enhanced_report'):
                # Preserve the existing result with enhanced_report
                result = existing_result
                self.logger.info(f"🔧 PRESERVED: Existing {config.scan_type} result with enhanced_report")
            else:
                # Create new result if none exists
                result = ScanResult(
                    scan_type=config.scan_type,
                    success=False,
                    duration=0.0
                )
            
            # Check if scan completed successfully
            log_file = self.temp_dir / f"{config.scan_type}_scan.log"
            output_file = self.temp_dir / f"{config.scan_type}_results.json"
            
            # Check process status
            process = self.running_processes.get(config.scan_type)
            if process:
                return_code = process.poll()
                if return_code is not None:
                    result.process_id = process.pid
                    if return_code != 0:
                        result.error_message = f"Process exited with code {return_code}"
            
            # Check for output file
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        findings = json.load(f)
                        result.success = True
                        result.findings = findings
                        result.findings_count = len(findings.get('vulnerabilities', []))
                        result.output_file = str(output_file)
                        self.logger.info(f"✅ {config.scan_type.title()} scan completed successfully with {result.findings_count} findings")
                except Exception as e:
                    result.error_message = f"Failed to parse results: {e}"
                    self.logger.error(f"❌ Failed to parse {config.scan_type} results: {e}")
            else:
                result.error_message = f"No output file generated: {output_file}"
                self.logger.warning(f"⚠️ No output file found for {config.scan_type} scan: {output_file}")
            
            # Extract duration and additional info from log
            if log_file.exists():
                try:
                    with open(log_file, 'r') as f:
                        log_content = f.read()
                        # Look for duration information
                        import re
                        duration_match = re.search(r'completed.*?(\d+\.\d+).*?seconds', log_content, re.IGNORECASE)
                        if duration_match:
                            result.duration = float(duration_match.group(1))
                        
                        # Look for error messages
                        if not result.success and not result.error_message:
                            error_match = re.search(r'error.*?(\w+.*?)(?:\n|$)', log_content, re.IGNORECASE)
                            if error_match:
                                result.error_message = error_match.group(1).strip()
                        
                        # Log key information from log file
                        if 'error' in log_content.lower() or 'failed' in log_content.lower():
                            self.logger.warning(f"⚠️ {config.scan_type.title()} scan log contains errors")
                        elif 'completed' in log_content.lower() or 'success' in log_content.lower():
                            self.logger.info(f"✅ {config.scan_type.title()} scan log indicates completion")
                            
                except Exception as e:
                    self.logger.debug(f"Error reading {config.scan_type} log file: {e}")
            
            # If still no success and no error message, provide default error
            if not result.success and not result.error_message:
                result.error_message = f"{config.scan_type.title()} scan failed - no output generated"
            
            self.scan_results[config.scan_type] = result
    
    def consolidate_results(self) -> Dict[str, Any]:
        """
        Consolidate results from static and dynamic scans with infrastructure vs runtime separation.
        
        Returns:
            Consolidated findings with deduplication, prioritization, and clear categorization
        """
        self.logger.info("🔄 Consolidating scan results with infrastructure/runtime separation...")
        
        # Get scan results safely
        self.logger.info(f"🔧 DEBUG: scan_results keys: {list(self.scan_results.keys()) if self.scan_results else 'None'}")
        self.logger.info(f"🔧 DEBUG: scan_results: {self.scan_results}")
        static_result = self.scan_results.get('static')
        dynamic_result = self.scan_results.get('dynamic')
        self.logger.info(f"🔧 DEBUG: static_result exists: {static_result is not None}")
        self.logger.info(f"🔧 DEBUG: static_result success: {getattr(static_result, 'success', 'No success attr') if static_result else 'None'}")
        
        # Infrastructure plugins (provide app structure and configuration analysis)
        infrastructure_plugins = [
            'jadx_static_analysis',
            'enhanced_manifest_analysis', 
            'enhanced_data_storage_analyzer',
            'apk_signing_certificate_analyzer',
            'improper_platform_usage',
            'enhanced_static_analysis'
        ]
        
        # Runtime analysis plugins (provide dynamic behavior analysis)
        runtime_plugins = [
            'frida_dynamic_analysis',
            'runtime_decryption_analysis',
            'anti_tampering_analysis',
            'mitmproxy_network_analysis',
            'advanced_dynamic_analysis'
        ]
        
        consolidated = {
            'metadata': {
                'consolidation_timestamp': time.time(),
                'static_scan': static_result.to_dict() if static_result else None,
                'dynamic_scan': dynamic_result.to_dict() if dynamic_result else None,
                'consolidation_config': self.consolidation_config,
                'infrastructure_plugins': infrastructure_plugins,
                'runtime_plugins': runtime_plugins
            },
            'vulnerabilities': [],
            'infrastructure_findings': [],  # NEW: Separate infrastructure findings
            'runtime_findings': [],         # NEW: Separate runtime findings
            'statistics': {
                'total_findings': 0,
                'static_findings': 0,
                'dynamic_findings': 0,
                'infrastructure_findings': 0,  # NEW: Infrastructure findings count
                'runtime_findings': 0,         # NEW: Runtime findings count
                'deduplicated_findings': 0,
                'high_confidence_findings': 0
            }
        }
        
        all_findings = []
        
        # Collect findings from both scans with source categorization
        if static_result and static_result.success:
            # CRITICAL DEBUG: Log static_result attributes and enhanced_report details
            self.logger.info(f"🔧 DEBUG: static_result attributes: {[attr for attr in dir(static_result) if not attr.startswith('_')]}")
            self.logger.info(f"🔧 DEBUG: hasattr(static_result, 'enhanced_report'): {hasattr(static_result, 'enhanced_report')}")
            if hasattr(static_result, 'enhanced_report'):
                enhanced_report = static_result.enhanced_report
                self.logger.info(f"🔧 DEBUG: enhanced_report type: {type(enhanced_report)}")
                self.logger.info(f"🔧 DEBUG: enhanced_report truthy: {bool(enhanced_report)}")
                if enhanced_report:
                    if isinstance(enhanced_report, dict):
                        self.logger.info(f"🔧 DEBUG: enhanced_report keys: {list(enhanced_report.keys())}")
                        vulnerabilities = enhanced_report.get('vulnerabilities', [])
                        self.logger.info(f"🔧 DEBUG: vulnerabilities in enhanced_report: {len(vulnerabilities)}")
                    else:
                        self.logger.info(f"🔧 DEBUG: enhanced_report is not a dict: {enhanced_report}")
            
            # CRITICAL FIX: Use enhanced_report if available, otherwise fall back to regular findings
            if hasattr(static_result, 'enhanced_report') and static_result.enhanced_report:
                static_findings = static_result.enhanced_report.get('vulnerabilities', [])
                self.logger.info(f"🔧 INTEGRATION SUCCESS: Using {len(static_findings)} enhanced vulnerabilities from static scan")
            else:
                static_findings = static_result.findings.get('vulnerabilities', [])
                self.logger.info(f"🔧 FALLBACK: Using {len(static_findings)} raw static findings")
            
            # CRITICAL DEBUG: Log first finding structure
            if static_findings:
                first_finding = static_findings[0]
                self.logger.info(f"🔧 DEBUG: First finding sample: {str(first_finding)[:500]}...")
            
            for finding in static_findings:
                # Skip non-vulnerability findings (like status messages)
                if isinstance(finding, str):
                    continue
                    
                if isinstance(finding, dict):
                    finding['source_scan'] = 'static'
                    
                    # Categorize by plugin source for infrastructure vs runtime separation
                    plugin_name = finding.get('plugin', finding.get('plugin_name', '')).lower()
                    finding_source = self._categorize_finding_source(plugin_name, infrastructure_plugins, runtime_plugins)
                    finding['finding_category'] = finding_source
                    
                    all_findings.append(finding)
                    
                    # Add to appropriate category
                    if finding_source == 'infrastructure':
                        consolidated['infrastructure_findings'].append(finding)
                    elif finding_source == 'runtime':
                        consolidated['runtime_findings'].append(finding)
                    
            consolidated['statistics']['static_findings'] = len([f for f in static_findings if not isinstance(f, str)])
        
        if dynamic_result and dynamic_result.success:
            # **DEBUG**: Log dynamic_result structure to understand where enhanced_report is stored
            self.logger.info(f"🔧 DEBUG: dynamic_result type: {type(dynamic_result)}")
            self.logger.info(f"🔧 DEBUG: dynamic_result attributes: {[attr for attr in dir(dynamic_result) if not attr.startswith('_')]}")
            self.logger.info(f"🔧 DEBUG: hasattr(dynamic_result, 'enhanced_report'): {hasattr(dynamic_result, 'enhanced_report')}")
            
            # **CRITICAL FIX**: Access enhanced_report from the correct location in the findings data structure
            dynamic_findings = []
            
            if hasattr(dynamic_result, 'findings') and isinstance(dynamic_result.findings, tuple) and len(dynamic_result.findings) >= 2:
                # Handle the tuple structure: ('dynamic_scan_completed', dynamic_results_dict)
                findings_tuple = dynamic_result.findings
                if len(findings_tuple) >= 2 and isinstance(findings_tuple[1], dict):
                    dynamic_results_dict = findings_tuple[1]
                    
                    # Look for enhanced_report in the dynamic_results_dict
                    if 'enhanced_report' in dynamic_results_dict:
                        enhanced_report = dynamic_results_dict['enhanced_report']
                        self.logger.info(f"🔧 FOUND IT! Enhanced report in findings tuple with {len(enhanced_report.get('vulnerabilities', []))} vulnerabilities")
                        dynamic_findings = enhanced_report.get('vulnerabilities', [])
                        self.logger.info(f"🔧 INTEGRATION SUCCESS: Using {len(dynamic_findings)} enhanced vulnerabilities from dynamic scan")
                    else:
                        self.logger.info(f"🔧 DEBUG: No enhanced_report in dynamic_results_dict. Keys: {list(dynamic_results_dict.keys())}")
            elif hasattr(dynamic_result, 'findings') and isinstance(dynamic_result.findings, dict):
                # Handle direct dict structure
                if 'enhanced_report' in dynamic_result.findings:
                    enhanced_report = dynamic_result.findings['enhanced_report']
                    self.logger.info(f"🔧 DEBUG: Found enhanced_report in findings dict with {len(enhanced_report.get('vulnerabilities', []))} vulnerabilities")
                    dynamic_findings = enhanced_report.get('vulnerabilities', [])
                    self.logger.info(f"🔧 INTEGRATION SUCCESS: Using {len(dynamic_findings)} enhanced vulnerabilities from dynamic scan")
                else:
                    dynamic_findings = dynamic_result.findings.get('vulnerabilities', [])
                    self.logger.info(f"🔧 FALLBACK: Using {len(dynamic_findings)} raw dynamic findings")
            else:
                # Final fallback to ScanResult.enhanced_report attribute
                if hasattr(dynamic_result, 'enhanced_report') and dynamic_result.enhanced_report:
                    enhanced_report = dynamic_result.enhanced_report
                    dynamic_findings = enhanced_report.get('vulnerabilities', []) if isinstance(enhanced_report, dict) else []
                    self.logger.info(f"🔧 FALLBACK TO ATTRIBUTE: Using {len(dynamic_findings)} enhanced vulnerabilities from dynamic scan")
                else:
                    self.logger.info(f"🔧 NO ENHANCED REPORT FOUND: Unable to access enhanced vulnerabilities")
            
            for finding in dynamic_findings:
                finding['source_scan'] = 'dynamic'
                
                # Categorize by plugin source for infrastructure vs runtime separation  
                plugin_name = finding.get('plugin', '').lower()
                finding_source = self._categorize_finding_source(plugin_name, infrastructure_plugins, runtime_plugins)
                finding['finding_category'] = finding_source
                
                all_findings.append(finding)
                
                # Add to appropriate category (dynamic findings are typically runtime)
                if finding_source == 'infrastructure':
                    consolidated['infrastructure_findings'].append(finding)
                elif finding_source == 'runtime':
                    consolidated['runtime_findings'].append(finding)
                    
            consolidated['statistics']['dynamic_findings'] = len(dynamic_findings)
        
        # Update category statistics
        consolidated['statistics']['infrastructure_findings'] = len(consolidated['infrastructure_findings'])
        consolidated['statistics']['runtime_findings'] = len(consolidated['runtime_findings'])
        
                        # Apply deduplication if configured (to all findings and separately to categories)
        if self.consolidation_config.get('enable_deduplication', True):
            try:
                # ENHANCED PRECISION DEDUPLICATION: Use precision fix for enhanced vulnerabilities
                from core.enhanced_deduplication_precision_fix import apply_enhanced_deduplication_precision
                
                # CRITICAL FIX: Convert objects to dictionaries for deduplication compatibility
                def convert_to_dict_format(findings_list):
                    """Convert various finding formats to dictionary format for deduplication."""
                    converted_findings = []
                    for finding in findings_list:
                        if isinstance(finding, dict):
                            # Handle nested structures in dict findings
                            if 'vulnerabilities' in finding and isinstance(finding['vulnerabilities'], list):
                                # This is a nested finding with sub-vulnerabilities
                                for sub_vuln in finding['vulnerabilities']:
                                    if isinstance(sub_vuln, dict):
                                        converted_findings.append(sub_vuln)
                                    else:
                                        # Convert object to dict
                                        vuln_dict = {}
                                        for attr in ['title', 'description', 'severity', 'file_path', 'vulnerable_code', 'cwe_id', 'masvs_control', 'confidence', 'vulnerability_type']:
                                            if hasattr(sub_vuln, attr):
                                                vuln_dict[attr] = str(getattr(sub_vuln, attr))
                                        if vuln_dict.get('title'):  # Only add if has a title
                                            converted_findings.append(vuln_dict)
                            else:
                                # Regular dict finding
                                converted_findings.append(finding)
                        elif hasattr(finding, '__dict__'):
                            converted_findings.append(finding.__dict__)
                        elif hasattr(finding, '_asdict'):
                            converted_findings.append(finding._asdict())
                        else:
                            # Try to extract attributes manually
                            finding_dict = {}
                            for attr in ['title', 'description', 'severity', 'file_path', 'vulnerable_code', 'cwe_id', 'masvs', 'confidence']:
                                if hasattr(finding, attr):
                                    finding_dict[attr] = getattr(finding, attr)
                            if finding_dict:  # Only add if we extracted some data
                                converted_findings.append(finding_dict)
                            else:
                                self.logger.warning(f"⚠️ Could not convert finding to dict format: {type(finding)}")
                    
                    self.logger.info(f"🔧 Converted {len(findings_list)} raw findings → {len(converted_findings)} valid vulnerabilities")
                    return converted_findings
                
                # Convert findings to dictionary format before deduplication
                all_findings_dict = convert_to_dict_format(all_findings)
                infrastructure_findings_dict = convert_to_dict_format(consolidated['infrastructure_findings'])
                runtime_findings_dict = convert_to_dict_format(consolidated['runtime_findings'])
                
                self.logger.info(f"🔧 Converting findings for enhanced precision deduplication: {len(all_findings)} → {len(all_findings_dict)} valid dict entries")
                
                # Apply enhanced precision deduplication instead of aggressive deduplication
                self.logger.info("🎯 PRECISION DEDUPLICATION: Applying enhanced deduplication precision fix")
                all_findings = apply_enhanced_deduplication_precision(all_findings_dict)
                
                # Apply precision deduplication within categories for cleaner separated reporting
                consolidated['infrastructure_findings'] = apply_enhanced_deduplication_precision(infrastructure_findings_dict)
                consolidated['runtime_findings'] = apply_enhanced_deduplication_precision(runtime_findings_dict)
                
                consolidated['statistics']['deduplicated_findings'] = len(all_findings)
                consolidated['statistics']['infrastructure_findings'] = len(consolidated['infrastructure_findings'])
                consolidated['statistics']['runtime_findings'] = len(consolidated['runtime_findings'])
                
                self.logger.info(f"✅ Applied deduplication: {consolidated['statistics']['deduplicated_findings']} unique findings")
                self.logger.info(f"   - Infrastructure: {consolidated['statistics']['infrastructure_findings']} findings")
                self.logger.info(f"   - Runtime: {consolidated['statistics']['runtime_findings']} findings")
            except Exception as e:
                self.logger.warning(f"⚠️ Deduplication failed: {e}")
                consolidated['statistics']['deduplicated_findings'] = len(all_findings)
        
        # Apply confidence filtering if configured  
        confidence_threshold = self.consolidation_config.get('confidence_threshold', 0.0)
        if confidence_threshold > 0.0:
            high_confidence_findings = [
                f for f in all_findings 
                if f.get('confidence', 0.0) >= confidence_threshold
            ]
            consolidated['statistics']['high_confidence_findings'] = len(high_confidence_findings)
            if self.consolidation_config.get('filter_by_confidence', False):
                all_findings = high_confidence_findings
                # Also filter categories
                consolidated['infrastructure_findings'] = [
                    f for f in consolidated['infrastructure_findings'] 
                    if f.get('confidence', 0.0) >= confidence_threshold
                ]
                consolidated['runtime_findings'] = [
                    f for f in consolidated['runtime_findings'] 
                    if f.get('confidence', 0.0) >= confidence_threshold
                ]
                self.logger.info(f"✅ Applied confidence filtering (>= {confidence_threshold}): {len(all_findings)} findings")
        
        # CRITICAL FIX: Check if we already have enhanced vulnerabilities to avoid double processing
        has_enhanced_static = (static_result and hasattr(static_result, 'enhanced_report') and 
                              static_result.enhanced_report and 
                              static_result.enhanced_report.get('vulnerabilities'))
        has_enhanced_dynamic = (dynamic_result and hasattr(dynamic_result, 'enhanced_report') and 
                               dynamic_result.enhanced_report and 
                               dynamic_result.enhanced_report.get('vulnerabilities'))
        
        if has_enhanced_static or has_enhanced_dynamic:
            # Use already enhanced vulnerabilities directly - no need for double processing
            self.logger.info(f"🔧 INTEGRATION SUCCESS: Using pre-enhanced vulnerabilities from scan results")
            self.logger.info(f"   - Enhanced static: {has_enhanced_static}")
            self.logger.info(f"   - Enhanced dynamic: {has_enhanced_dynamic}")
            
            # Use the enhanced findings we already collected
            consolidated['vulnerabilities'] = all_findings
            consolidated['statistics']['total_findings'] = len(all_findings)
            
            self.logger.info(f"✅ Using {len(all_findings)} pre-enhanced vulnerabilities directly")
            self.logger.info(f"   - Infrastructure: {len(consolidated['infrastructure_findings'])} findings")
            self.logger.info(f"   - Runtime: {len(consolidated['runtime_findings'])} findings")
            
        else:
            # Apply enhanced vulnerability reporting only if not already enhanced
            try:
                from core.enhanced_vulnerability_reporting_engine import EnhancedVulnerabilityReportingEngine
                
                # Get APK context for enhanced reporting
                apk_path = getattr(self, 'apk_path', '')
                package_name = getattr(self, 'package_name', '')
                
                # **ENHANCED REPORTING FIX**: Pass required arguments to constructor
                enhanced_engine = EnhancedVulnerabilityReportingEngine(apk_path=apk_path, target_package=package_name)
                
                app_context = {
                    'package_name': package_name,
                    'apk_path': apk_path,
                    'decompiled_path': getattr(self, 'decompiled_path', ''),
                    'scan_mode': getattr(self, 'scan_mode', 'standard')
                }
                
                self.logger.info(f"🔧 Applying enhanced reporting to {len(all_findings)} raw findings...")
                enhanced_results = enhanced_engine.enhance_vulnerability_report(all_findings, app_context)
                
                if enhanced_results and enhanced_results.get('vulnerabilities'):
                    enhanced_vulnerabilities = enhanced_results.get('vulnerabilities', [])
                    consolidated['vulnerabilities'] = enhanced_vulnerabilities
                    consolidated['statistics']['total_findings'] = len(enhanced_vulnerabilities)
                    
                    # Update infrastructure/runtime categories with enhanced findings
                    consolidated['infrastructure_findings'].clear()
                    consolidated['runtime_findings'].clear()
                    
                    for vuln in enhanced_vulnerabilities:
                        plugin_name = vuln.get('plugin', vuln.get('source', '')).lower()
                        finding_source = self._categorize_finding_source(plugin_name, 
                                                                       consolidated['metadata']['infrastructure_plugins'], 
                                                                       consolidated['metadata']['runtime_plugins'])
                        vuln['finding_category'] = finding_source
                        
                        if finding_source == 'infrastructure':
                            consolidated['infrastructure_findings'].append(vuln)
                        elif finding_source == 'runtime':
                            consolidated['runtime_findings'].append(vuln)
                    
                    # Update category statistics
                    consolidated['statistics']['infrastructure_findings'] = len(consolidated['infrastructure_findings'])
                    consolidated['statistics']['runtime_findings'] = len(consolidated['runtime_findings'])
                    
                    self.logger.info(f"✅ Enhanced reporting success: {len(enhanced_vulnerabilities)} vulnerabilities")
                    self.logger.info(f"   - Infrastructure: {consolidated['statistics']['infrastructure_findings']} findings")
                    self.logger.info(f"   - Runtime: {consolidated['statistics']['runtime_findings']} findings")
                else:
                    # Fallback to raw findings
                    consolidated['vulnerabilities'] = all_findings
                    consolidated['statistics']['total_findings'] = len(all_findings)
                    self.logger.warning(f"⚠️ Enhanced reporting failed - using {len(all_findings)} raw findings")
                    
            except Exception as e:
                self.logger.warning(f"⚠️ Enhanced reporting failed: {e}")
                consolidated['vulnerabilities'] = all_findings
                consolidated['statistics']['total_findings'] = len(all_findings)
        
        # Save consolidated results with separated categories
        output_file = self.temp_dir / 'consolidated_results.json'
        with open(output_file, 'w') as f:
            json.dump(consolidated, f, indent=2, default=self._json_serializable_converter)
        
        self.logger.info(f"✅ Consolidation complete with infrastructure/runtime separation:")
        self.logger.info(f"   - Total findings: {consolidated['statistics']['total_findings']}")
        self.logger.info(f"   - Infrastructure findings: {len(consolidated['infrastructure_findings'])}")
        self.logger.info(f"   - Runtime findings: {len(consolidated['runtime_findings'])}")
        self.logger.info(f"📁 Results saved to: {output_file}")
        
        return consolidated
    
    def _categorize_finding_source(self, plugin_name: str, infrastructure_plugins: List[str], runtime_plugins: List[str]) -> str:
        """
        Categorize a finding as 'infrastructure' or 'runtime' based on its plugin source.
        
        Args:
            plugin_name: Name of the plugin that generated the finding
            infrastructure_plugins: List of infrastructure plugin names
            runtime_plugins: List of runtime plugin names
            
        Returns:
            'infrastructure', 'runtime', or 'unknown'
        """
        # Check for exact matches
        if plugin_name in infrastructure_plugins:
            return 'infrastructure'
        if plugin_name in runtime_plugins:
            return 'runtime'
            
        # Check for partial matches (plugin names often have variations)
        for infra_plugin in infrastructure_plugins:
            if infra_plugin.lower() in plugin_name or plugin_name in infra_plugin.lower():
                return 'infrastructure'
                
        for runtime_plugin in runtime_plugins:
            if runtime_plugin.lower() in plugin_name or plugin_name in runtime_plugin.lower():
                return 'runtime'
        
        # Categorize by content keywords if no plugin match
        if any(keyword in plugin_name for keyword in ['manifest', 'static', 'certificate', 'structure', 'storage']):
            return 'infrastructure'
        elif any(keyword in plugin_name for keyword in ['dynamic', 'frida', 'runtime', 'behavioral', 'network']):
            return 'runtime'
        
        # Default to infrastructure for unknown static analysis plugins
        return 'infrastructure'
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings using the unified deduplication framework."""
        if not findings:
            return findings
        
        # **UNIFIED DEDUPLICATION**: Use the authoritative unified framework
        try:
            from core.unified_deduplication_framework import (
                deduplicate_findings, 
                DeduplicationStrategy
            )
            from core.deduplication_config_manager import get_strategy_for_component
            
            self.logger.info(f"🔧 **PARALLEL SCAN MANAGER**: Applying unified deduplication to {len(findings)} findings")
            
            # Use configured strategy for parallel scan manager (CLI controllable)
            configured_strategy = get_strategy_for_component('parallel_scan_manager')
            dedup_result = deduplicate_findings(findings, configured_strategy)
            
            self.logger.info(f"🔧 **PARALLEL SCAN MANAGER**: Using {configured_strategy.value} strategy")
            deduplicated = dedup_result.unique_findings
            
            removed_count = len(findings) - len(deduplicated)
            self.logger.info(f"🔧 **PARALLEL DEDUPLICATION COMPLETE**: Removed {removed_count} duplicates")
            
            return deduplicated
            
        except Exception as e:
            self.logger.error(f"🚨 **UNIFIED DEDUPLICATION FAILED in parallel manager**: {e}")
            self.logger.warning("   - Falling back to simple deduplication")
            
            # Fallback: Simple deduplication based on title and location
            seen = set()
            deduplicated = []
            
            for finding in findings:
                key = (
                    finding.get('title', ''),
                    finding.get('location', ''),
                    finding.get('category', '')
                )
                
                if key not in seen:
                    seen.add(key)
                    deduplicated.append(finding)
                else:
                    # Merge information from duplicate finding
                    for existing in deduplicated:
                        if (existing.get('title') == finding.get('title') and
                            existing.get('location') == finding.get('location')):
                            
                            # Add source scan info
                            if 'source_scans' not in existing:
                                existing['source_scans'] = [existing.get('source_scan', 'unknown')]
                            existing['source_scans'].append(finding.get('source_scan', 'unknown'))
                            
                            # Take higher confidence
                            existing['confidence'] = max(
                                existing.get('confidence', 0),
                                finding.get('confidence', 0)
                            )
                            break
            
            self.logger.info(f"**FALLBACK DEDUPLICATION**: Removed {len(findings) - len(deduplicated)} duplicates")
            return deduplicated
    
    def _filter_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply filtering rules to remove noise."""
        filtered = []
        
        for finding in findings:
            # Filter by severity
            severity = finding.get('severity', 'INFO').upper()
            min_severity = self.consolidation_config['filtering']['min_severity'].upper()
            
            if self._severity_level(severity) < self._severity_level(min_severity):
                continue
            
            # Filter framework noise
            if self.consolidation_config['filtering']['framework_noise_filter']:
                location = finding.get('location', '').lower()
                if any(noise in location for noise in ['kotlin/', 'android/support', 'androidx/', 'com/google']):
                    continue
            
            # Filter test files
            if self.consolidation_config['filtering']['exclude_test_files']:
                location = finding.get('location', '').lower()
                if any(test in location for test in ['/test/', '/androidtest/', 'test.java']):
                    continue
            
            filtered.append(finding)
        
        return filtered
    
    def _prioritize_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply prioritization based on scan type and confidence."""
        for finding in findings:
            source_scan = finding.get('source_scan', 'unknown')
            base_confidence = finding.get('confidence', 0.5)
            
            # Adjust confidence based on scan type
            if source_scan == 'static':
                weight = self.consolidation_config['prioritization']['static_weight']
            else:
                weight = self.consolidation_config['prioritization']['dynamic_weight']
            
            finding['adjusted_confidence'] = base_confidence * weight
        
        # Sort by adjusted confidence (highest first)
        findings.sort(key=lambda x: x.get('adjusted_confidence', 0), reverse=True)
        
        return findings
    
    def _severity_level(self, severity: str) -> int:
        """Convert severity string to numeric level."""
        levels = {'INFO': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 4, 'CRITICAL': 5}
        return levels.get(severity.upper(), 1)
    
    def _signal_handler(self, signum: int, frame) -> None:
        """Handle shutdown signals gracefully."""
        self.logger.info("🛑 Shutdown signal received, cleaning up...")
        self._cleanup_processes()
        exit(0)
    
    def _cleanup_processes(self) -> None:
        """Clean up all running processes."""
        for scan_type, process in self.running_processes.items():
            try:
                self.logger.info(f"🧹 Terminating {scan_type} scan...")
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            except Exception as e:
                self.logger.debug(f"Error cleaning up {scan_type} process: {e}")
        
        self.running_processes.clear()
    
    def __del__(self):
        """Cleanup on object destruction."""
        self._cleanup_processes()
        
        # Clean up temporary directory
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass

    def _initialize_unified_execution(self):
        """Initialize unified execution framework integration."""
        self.unified_execution_available = False
        self.unified_manager = None
        
        try:
            from core.execution import (
                UnifiedExecutionManager,
                ExecutionConfig,
                ExecutionMode
            )
            
            # Create configuration optimized for parallel scanning
            config = ExecutionConfig(
                execution_mode=ExecutionMode.PROCESS_SEPARATED,
                max_workers=2,  # Static and dynamic processes
                timeout_seconds=1800,  # 30 minutes
                enable_parallel_execution=True,
                enable_process_separation=True,
                enable_resource_monitoring=True
            )
            
            self.unified_manager = UnifiedExecutionManager(config)
            self.unified_execution_available = True
            self.logger.info("✅ Unified execution framework integrated with ParallelScanManager")
            
        except ImportError:
            self.logger.info("ℹ️  Unified execution framework not available - using legacy parallel execution")
        except Exception as e:
            self.logger.warning(f"⚠️  Failed to initialize unified execution: {e} - using legacy implementation")

    def run_parallel_scans_unified(self, apk_path: str, package_name: str, 
                                  mode: str = "deep", vulnerable_app_mode: bool = False,
                                  timeout: int = 1800, scan_types: List[str] = None,
                                  disable_static_analysis: bool = False, 
                                  disable_dynamic_analysis: bool = False,
                                  objection_context: Dict = None) -> Dict[str, ScanResult]:
        """
        Run parallel scans using unified execution framework with Lightning optimization.
        
        This method provides enhanced parallel execution with:
        - Zero code duplication through shared components
        - Intelligent strategy selection
        - Better resource management
        - Consistent error handling
        - Lightning mode speed optimization
        - Scan type filtering for dynamic-only/static-only execution
        
        Args:
            scan_types: List of scan types to run ('static', 'dynamic'). If None, runs both.
            disable_static_analysis: If True, skips static analysis entirely
            disable_dynamic_analysis: If True, skips dynamic analysis entirely
        """
        # **APK CONTEXT FIX**: Store target package for filtering
        self.target_package = package_name
        
        # **DYNAMIC ANALYSIS FIX**: Store disable flags as instance variables
        self._disable_static_analysis = disable_static_analysis
        self._disable_dynamic_analysis = disable_dynamic_analysis
        
        # CRITICAL FIX: Process scan type constraints
        if scan_types is None:
            scan_types = []
            if not disable_static_analysis:
                scan_types.append('static')
            if not disable_dynamic_analysis:
                scan_types.append('dynamic')
        
        self.logger.info(f"🎯 Parallel scan types requested: {scan_types}")
        
        # LIGHTNING MODE DETECTION: Check if we're in Lightning mode
        is_lightning_mode = mode == "lightning" or "lightning" in mode.lower()
        
        if is_lightning_mode:
            self.logger.info("⚡ Lightning mode detected - applying speed optimizations")
            # Lightning optimizations: aggressive timeout reduction
            # Exception for JADX decompilation which may need more time for complex APKs
            jadx_timeout = self._calculate_jadx_timeout(apk_path) if timeout > 120 else timeout
            timeout = min(timeout, 120)  # 2-minute max for Lightning (most plugins)
            self.logger.info(f"⚡ Lightning: Reduced timeout to {timeout}s for fast execution")
            if jadx_timeout > timeout:
                self.logger.info(f"⚡ Lightning: JADX exception - allowing up to {jadx_timeout}s for decompilation")
        
        if not self.unified_execution_available:
            # Fallback to legacy implementation
            return self.run_parallel_scans(apk_path, package_name, mode, vulnerable_app_mode, timeout, objection_context)
        
        if is_lightning_mode:
            self.logger.info("⚡ Lightning: Starting speed-optimized unified parallel scans")
        else:
            self.logger.info("🚀 Starting unified parallel AODS scans...")
        
        # Import here to avoid circular imports
        from core.execution import ExecutionMode
        
        # REMOVED: Fake ExecutionTask creation - now using real plugin execution
        # Instead of creating fake tasks, execute real plugins directly
        
        # Create APK context and plugin manager for real plugin execution
        from core.apk_ctx import APKContext
        from core.plugin_manager import create_plugin_manager
        
        # Create APK context for analysis
        apk_ctx = APKContext(apk_path_str=apk_path, package_name=package_name)
        apk_ctx.set_scan_mode(mode)
        apk_ctx.vulnerable_app_mode = vulnerable_app_mode
        
        # Create plugin manager with real plugins
        plugin_manager = create_plugin_manager(
            scan_mode=mode,
            vulnerable_app_mode=vulnerable_app_mode
        )
        
        # Execute plugins directly using plugin manager (bypass unified execution framework)
        try:
            start_time = time.time()
            
            # Get optimized plugins for Lightning mode
            if is_lightning_mode:
                optimized_plugins = plugin_manager.get_optimized_plugins()
                plugin_count = len(optimized_plugins)
                self.logger.info(f"⚡ Lightning: Executing {plugin_count} optimized plugins for speed")
            else:
                plugin_count = len(plugin_manager.plugins)
                self.logger.info(f"🚀 Executing {plugin_count} plugins...")
            
            # CRITICAL FIX: Execute plugins based on scan type filtering with infrastructure support
            if 'dynamic' in scan_types and 'static' not in scan_types:
                self.logger.info("🎯 DYNAMIC-ONLY: Running Frida-first analysis with essential plugins only")
                self.logger.info("🔧 Executing JADX + Frida for optimized dynamic analysis...")
                
                # FRIDA-FIRST ESSENTIAL PLUGINS: Minimal required plugins for dynamic analysis
                infrastructure_plugins = [
                    'jadx_static_analysis',  # REQUIRED: Provides app structure for Frida hooks
                    'frida_dynamic_analysis',  # REQUIRED: Frida runtime instrumentation (Frida-first approach)
                ]
                
                # Filter plugin manager to only run infrastructure plugins
                original_plugins = plugin_manager.plugins.copy()
                filtered_plugins = {}
                
                for plugin_name, plugin_instance in original_plugins.items():
                    if plugin_name in infrastructure_plugins:
                        filtered_plugins[plugin_name] = plugin_instance
                        self.logger.info(f"✅ Including essential plugin: {plugin_name}")
                    else:
                        self.logger.info(f"⏭️  Skipping non-essential plugin: {plugin_name}")
                
                # Temporarily replace plugins with filtered set
                plugin_manager.plugins = filtered_plugins
                
                # Execute infrastructure plugins to provide structure for dynamic analysis
                plugin_results = plugin_manager.execute_all_plugins(apk_ctx)
                
                # Restore original plugins
                plugin_manager.plugins = original_plugins
                
                self.logger.info(f"🔧 Frida-first execution complete: {len(plugin_results)} essential plugins executed")
                
                # Execute additional dynamic analysis plugins that can leverage infrastructure results
                self.logger.info("🔍 Executing enhanced dynamic analysis plugins with infrastructure context...")
                
                # Enhanced dynamic analysis plugins that benefit from app structure knowledge
                enhanced_dynamic_plugins = [
                    'advanced_dynamic_analysis_modules',  # Comprehensive dynamic security testing
                    'intent_fuzzing_analysis',  # Intent fuzzing with app structure context
                    'injection_vulnerabilities',  # SQL injection dynamic testing
                    'advanced_ssl_tls_analyzer',  # Dynamic SSL/TLS security testing
                    'runtime_decryption_analysis',  # Runtime decryption analysis
                    'enhanced_root_detection_bypass_analyzer',  # Root detection bypass testing
                    'dynamic_code_analyzer',  # Dynamic code analysis
                    'privacy_leak_detection',  # Privacy leak detection with dynamic analysis
                ]
                
                # Filter and execute enhanced dynamic plugins
                enhanced_plugins = {}
                for plugin_name, plugin_instance in original_plugins.items():
                    if plugin_name in enhanced_dynamic_plugins:
                        enhanced_plugins[plugin_name] = plugin_instance
                        self.logger.info(f"✅ Including enhanced dynamic plugin: {plugin_name}")
                
                if enhanced_plugins:
                    # Temporarily replace plugins with enhanced dynamic set
                    plugin_manager.plugins = enhanced_plugins
                    
                    # Enhance APK context with infrastructure results for better dynamic analysis
                    if hasattr(apk_ctx, 'set_infrastructure_results'):
                        apk_ctx.set_infrastructure_results(plugin_results)
                    
                    # Enable dynamic analysis features in APK context
                    apk_ctx.dynamic_analysis_enabled = True
                    if hasattr(apk_ctx, 'frida_available'):
                        apk_ctx.frida_available = True
                    
                    # Execute enhanced dynamic analysis plugins
                    enhanced_results = plugin_manager.execute_all_plugins(apk_ctx)
                    
                    # Merge infrastructure and enhanced results
                    for plugin_name, result in enhanced_results.items():
                        plugin_results[plugin_name] = result
                    
                    self.logger.info(f"🚀 Enhanced dynamic analysis complete: {len(enhanced_results)} additional plugins executed")
                else:
                    self.logger.warning("⚠️  No enhanced dynamic analysis plugins available")
                
                # Restore original plugins for any remaining processing
                plugin_manager.plugins = original_plugins
                
            elif 'static' in scan_types and 'dynamic' not in scan_types:
                self.logger.info("🎯 STATIC-ONLY: Running static analysis plugins only")
                plugin_results = plugin_manager.execute_all_plugins(apk_ctx)
                
            else:
                self.logger.info("🎯 FULL SCAN: Running all plugins (static + dynamic)")
                plugin_results = plugin_manager.execute_all_plugins(apk_ctx)
            
            # ENHANCED REPORTING INTEGRATION - Apply detailed vulnerability reporting
            enhanced_findings = self._apply_enhanced_reporting(plugin_results, apk_path, package_name, mode)
            
            # Convert plugin results to ParallelScanManager format
            scan_results = {}
            
            # CRITICAL FIX: Apply scan type filtering
            
            # CRITICAL FIX: Create static scan result only if requested
            if 'static' in scan_types:
                static_results = ScanResult(
                    scan_type="static",
                    success=True,
                    duration=time.time() - start_time,
                    findings=enhanced_findings.get('enhanced_vulnerabilities', plugin_results),
                    findings_count=len(enhanced_findings.get('enhanced_vulnerabilities', plugin_results)),
                    process_id=None
                )
                # ENHANCED VULNERABILITY INTEGRATION: Store complete enhanced report for dyna.py access
                static_results.enhanced_report = enhanced_findings
                print(f"🔧 DEBUG: Set enhanced_report on static_results with {len(enhanced_findings.get('vulnerabilities', []))} vulnerabilities")
                print(f"🔧 DEBUG: Set enhanced_report with {len(enhanced_findings.get('vulnerabilities', []))} vulnerabilities")
                print(f"🔧 DEBUG: Enhanced report keys: {list(enhanced_findings.keys())}")
                scan_results["static"] = static_results
                self.logger.info(f"✅ Static analysis completed: {len(enhanced_findings.get('enhanced_vulnerabilities', plugin_results))} findings")
            else:
                self.logger.info("⏭️  Static analysis SKIPPED (not in requested scan types)")
            
            # CRITICAL FIX: Execute actual dynamic analysis instead of duplicating static results
            if mode == "deep" and not getattr(self, '_disable_dynamic_analysis', False):
                self.logger.info("🔧 Starting dynamic analysis execution...")
                try:
                    # Execute actual dynamic analysis
                    dynamic_start_time = time.time()
                    dynamic_findings = self._execute_dynamic_scan(apk_path, package_name, mode, vulnerable_app_mode, timeout)
                    dynamic_duration = time.time() - dynamic_start_time
                    
                    # Create real dynamic scan result
                    dynamic_results = ScanResult(
                        scan_type="dynamic",
                        success=True,
                        duration=dynamic_duration,
                        findings=dynamic_findings if dynamic_findings else [],
                        findings_count=len(dynamic_findings) if dynamic_findings else 0,
                        process_id=None
                    )
                    # **FINAL FIX**: Use the actual dynamic scan results instead of empty enhanced_findings
                    if isinstance(dynamic_findings, dict) and 'enhanced_report' in dynamic_findings:
                        # Use the enhanced_report from the successful dynamic scan
                        actual_enhanced_report = dynamic_findings['enhanced_report']
                        dynamic_results.enhanced_report = actual_enhanced_report
                        print(f"🔧 FINAL FIX: Set enhanced_report with ACTUAL {len(actual_enhanced_report.get('vulnerabilities', []))} vulnerabilities from dynamic scan")
                    else:
                        # Fallback: Create enhanced_report structure from dynamic_findings tuple results
                        if hasattr(dynamic_results, 'findings') and isinstance(dynamic_results.findings, tuple) and len(dynamic_results.findings) >= 2:
                            findings_data = dynamic_results.findings[1]
                            if isinstance(findings_data, dict) and 'enhanced_report' in findings_data:
                                dynamic_results.enhanced_report = findings_data['enhanced_report']
                                print(f"🔧 FINAL FIX: Set enhanced_report from findings tuple with {len(findings_data['enhanced_report'].get('vulnerabilities', []))} vulnerabilities")
                            else:
                                dynamic_results.enhanced_report = enhanced_findings
                                print(f"🔧 DEBUG: Fallback to empty enhanced_findings")
                        else:
                            dynamic_results.enhanced_report = enhanced_findings
                            print(f"🔧 DEBUG: Set enhanced_report on dynamic_results with {len(enhanced_findings.get('vulnerabilities', []))} vulnerabilities")
                    self.logger.info(f"✅ Dynamic analysis completed: {len(dynamic_findings) if dynamic_findings else 0} findings")
                    
                except Exception as e:
                    self.logger.warning(f"⚠️  Dynamic analysis failed: {e} - continuing with static-only results")
                    # Create empty dynamic result on failure
                    dynamic_results = ScanResult(
                        scan_type="dynamic",
                        success=False,
                        duration=0.0,
                        findings=[],
                        findings_count=0,
                        process_id=None,
                        error_message=str(e)
                    )
                    # **FINAL FIX**: Set enhanced_report with actual data even on failure
                    if hasattr(dynamic_results, 'findings') and isinstance(dynamic_results.findings, tuple) and len(dynamic_results.findings) >= 2:
                        findings_data = dynamic_results.findings[1]
                        if isinstance(findings_data, dict) and 'enhanced_report' in findings_data:
                            dynamic_results.enhanced_report = findings_data['enhanced_report']
                            print(f"🔧 FINAL FIX: Set enhanced_report from failed scan with {len(findings_data['enhanced_report'].get('vulnerabilities', []))} vulnerabilities")
                        else:
                            dynamic_results.enhanced_report = enhanced_findings
                            print(f"🔧 DEBUG: Set enhanced_report on failed dynamic_results with {len(enhanced_findings.get('vulnerabilities', []))} vulnerabilities")
                    else:
                        dynamic_results.enhanced_report = enhanced_findings
                        print(f"🔧 DEBUG: Set enhanced_report on failed dynamic_results with {len(enhanced_findings.get('vulnerabilities', []))} vulnerabilities")
            else:
                # Create empty dynamic result when dynamic analysis is disabled
                self.logger.info(f"ℹ️  Dynamic analysis skipped (mode={mode}, disabled={getattr(self, '_disable_dynamic_analysis', False)})")
                dynamic_results = ScanResult(
                    scan_type="dynamic",
                    success=False,
                    duration=0.0,
                    findings=[],
                    findings_count=0,
                    process_id=None,
                    error_message="Dynamic analysis not enabled for this mode"
                )
                # **FINAL FIX**: Don't override with empty enhanced_findings when dynamic is skipped
                # When dynamic is skipped, enhanced_report should remain empty to avoid confusion
                dynamic_results.enhanced_report = {
                    'enhanced_vulnerabilities': [],
                    'vulnerabilities': [],
                    'executive_summary': {'total_vulnerabilities': 0, 'severity_breakdown': {}},
                    'metadata': {'scan_type': 'skipped'},
                    'coordination_metrics': {}
                }
                print(f"🔧 DEBUG: Set empty enhanced_report on skipped dynamic_results")
            
            scan_results["dynamic"] = dynamic_results
            
            # Display enhanced vulnerability reporting instead of basic summary
            if enhanced_findings and enhanced_findings.get('enhanced_vulnerabilities'):
                self._display_enhanced_vulnerability_report(enhanced_findings)
            else:
                self.logger.warning("⚠️  Enhanced reporting not available - showing basic summary")
            
            total_time = time.time() - start_time
            self.logger.info(f"⏱️ Plugin execution time: {total_time:.2f} seconds")
            self.logger.info(f"📊 Plugins executed: {len(plugin_results)}")
            self.logger.info(f"✅ Success rate: {len(plugin_results)}/{plugin_count} plugins")
            
            # Process Objection integration post-scan
            if objection_context and objection_context.get('recon_results'):
                try:
                    from plugins.objection_integration import ObjectionVerificationAssistant
                    
                    self.logger.info("🔍 Processing Objection verification for AODS findings")
                    verification_assistant = ObjectionVerificationAssistant()
                    
                    # Extract vulnerabilities from scan results for verification
                    all_vulnerabilities = []
                    for scan_type, scan_result in scan_results.items():
                        if hasattr(scan_result, 'findings') and scan_result.findings:
                            if isinstance(scan_result.findings, tuple) and len(scan_result.findings) >= 2:
                                findings_data = scan_result.findings[1]
                                if isinstance(findings_data, dict) and 'vulnerabilities' in findings_data:
                                    all_vulnerabilities.extend(findings_data['vulnerabilities'])
                    
                    # Generate verification commands for findings
                    verification_commands = verification_assistant.generate_verification_commands(
                        all_vulnerabilities
                    )
                    objection_context['verification_commands'] = verification_commands
                    
                    # Add Objection results to scan results
                    objection_result = ScanResult(
                        success=True,
                        scan_type="objection_integration",
                        process_id=0,
                        findings=({}, {
                            'recon_results': objection_context.get('recon_results'),
                            'verification_commands': verification_commands,
                            'integration_mode': 'post_scan_verification'
                        })
                    )
                    scan_results["objection"] = objection_result
                    
                    self.logger.info(f"✅ Objection integration complete: {len(verification_commands)} verification commands generated")
                    
                except ImportError as e:
                    self.logger.warning(f"⚠️ Objection integration not available: {e}")
                except Exception as e:
                    self.logger.warning(f"⚠️ Objection post-processing failed: {e}")
            
            return scan_results
            
        except Exception as e:
            self.logger.error(f"❌ Plugin execution failed: {e}")
            import traceback
            self.logger.debug(f"Full traceback: {traceback.format_exc()}")
            
            # Return empty results instead of infinite retry loop
            self.logger.warning("⚠️  Plugin execution failed - returning empty results to prevent infinite retry")
            
            # Create empty scan results 
            empty_results = {}
            empty_results["static"] = ScanResult(
                scan_type="static",
                success=False,
                duration=0.0,
                findings=[],
                findings_count=0,
                process_id=None,
                error_message=str(e)
            )
            empty_results["dynamic"] = ScanResult(
                scan_type="dynamic", 
                success=False,
                duration=0.0,
                findings=[],
                findings_count=0,
                process_id=None,
                error_message=str(e)
            )
            
            return empty_results
    
    def _update_main_process_plugin_statuses(self, execution_result):
        """Update plugin statuses in the main process based on parallel execution results."""
        try:
            # Import here to avoid circular imports
            import traceback
            from core.plugin_manager import PluginStatus
            
            self.logger.info("🔄 Updating main process plugin statuses from parallel execution results")
            
            # Try to get access to the main plugin manager
            # This is a bit of a hack, but necessary for cross-process status updates
            main_plugin_manager = None
            
            # Try to import dyna and get the plugin manager from there
            try:
                import dyna
                if hasattr(dyna, '_current_plugin_manager'):
                    main_plugin_manager = dyna._current_plugin_manager
                elif hasattr(dyna, 'plugin_manager'):
                    main_plugin_manager = dyna.plugin_manager
            except (ImportError, AttributeError):
                pass
            
            if not main_plugin_manager:
                self.logger.debug("No main plugin manager found for status updates")
                return
            
            # Update statuses based on execution success
            if execution_result.successful_plugins > 0:
                # Mark some plugins as completed based on successful execution
                for plugin_name, plugin_metadata in main_plugin_manager.plugins.items():
                    if plugin_metadata.status == PluginStatus.PENDING:
                        # For now, mark all pending plugins as completed if we had successful execution
                        # This is a simplified approach since we don't have per-plugin status from parallel execution
                        plugin_metadata.status = PluginStatus.COMPLETED
                        plugin_metadata.execution_time = execution_result.execution_time / execution_result.total_plugins
                        self.logger.debug(f"Updated {plugin_name} status to COMPLETED")
            
            # Update failed plugins if execution failed
            if execution_result.failed_plugins > 0:
                # Mark some plugins as failed
                failed_count = 0
                for plugin_name, plugin_metadata in main_plugin_manager.plugins.items():
                    if plugin_metadata.status == PluginStatus.PENDING and failed_count < execution_result.failed_plugins:
                        plugin_metadata.status = PluginStatus.FAILED
                        plugin_metadata.error_message = "Failed during parallel execution"
                        failed_count += 1
                        self.logger.debug(f"Updated {plugin_name} status to FAILED")
            
            self.logger.info(f"✅ Updated plugin statuses: {execution_result.successful_plugins} completed, {execution_result.failed_plugins} failed")
            
        except Exception as e:
            self.logger.warning(f"Failed to update main process plugin statuses: {e}")
            self.logger.debug(f"Status update error details: {traceback.format_exc()}")
    
    def _json_serializable_converter(self, obj):
        """Convert objects to JSON-serializable format."""
        # **COMPREHENSIVE RICH TEXT FIX**: Handle all Rich library objects
        if hasattr(obj, '__rich_console__') or hasattr(obj, '__rich__'):
            # This is any Rich object - convert to string representation
            if hasattr(obj, 'plain'):
                return str(obj.plain)
            elif hasattr(obj, '__rich_console__'):
                # Use Rich's own rendering if plain not available
                try:
                    from rich.console import Console
                    console = Console(file=None, width=80)
                    with console.capture() as capture:
                        console.print(obj)
                    return capture.get().strip()
                except:
                    return str(obj)
            else:
                return str(obj)
        # Handle Rich Text objects specifically (common in plugin outputs)
        elif hasattr(obj, 'plain') and str(type(obj)).find('rich') != -1:
            return str(obj.plain)
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        elif hasattr(obj, '_asdict'):
            return obj._asdict()
        elif isinstance(obj, (list, tuple)):
            return [self._json_serializable_converter(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: self._json_serializable_converter(value) for key, value in obj.items()}
        else:
            return str(obj)

    def _execute_static_scan(self, apk_path: str, package_name: str, mode: str, vulnerable_app_mode: bool, timeout: int = 1800):
        """Execute static analysis scan."""
        try:
            self.logger.info(f"🔍 Executing static analysis for {package_name}")
            
            # Import and run standard AODS static analysis
            from dyna import OWASPTestSuiteDrozer
            
            # Get scan profile from context - critical fix for deep mode
            scan_profile = getattr(self, 'scan_profile', 'deep' if mode == 'deep' else 'standard')
            
            # Create temporary test suite for static analysis with proper scan profile
            test_suite = OWASPTestSuiteDrozer(
                apk_path=apk_path,
                package_name=package_name,
                scan_profile=scan_profile  # CRITICAL FIX: Pass scan profile for deep mode
            )
            
            # Set scan mode and vulnerability mode
            test_suite.scan_mode = mode
            test_suite.vulnerable_app_mode = vulnerable_app_mode
            
            # Run static-only plugins
            static_results = test_suite.run_static_analysis_only(timeout=timeout)
            
            self.logger.info(f"✅ Static analysis completed for {package_name}")
            return ('static_scan_completed', static_results)
            
        except Exception as e:
            self.logger.error(f"❌ Static analysis failed: {e}")
            return ('static_scan_failed', {'error': str(e)})
    
    def _execute_dynamic_scan(self, apk_path: str, package_name: str, mode: str, vulnerable_app_mode: bool, timeout: int = 1800):
        """Execute dynamic analysis scan."""
        try:
            self.logger.info(f"🔧 Executing dynamic analysis for {package_name}")
            
            # Import and run standard AODS dynamic analysis
            from dyna import OWASPTestSuiteDrozer
            
            # Get scan profile from context - critical fix for deep mode
            scan_profile = getattr(self, 'scan_profile', 'deep' if mode == 'deep' else 'standard')
            
            # Create temporary test suite for dynamic analysis with proper scan profile
            test_suite = OWASPTestSuiteDrozer(
                apk_path=apk_path,
                package_name=package_name,
                scan_profile=scan_profile  # CRITICAL FIX: Pass scan profile for deep mode
            )
            
            # Set scan mode and vulnerability mode
            test_suite.scan_mode = mode
            test_suite.vulnerable_app_mode = vulnerable_app_mode
            
            # Run dynamic-only analysis
            dynamic_results = test_suite.run_dynamic_analysis_only(timeout=timeout)
            
            # **VULNERABILITY EXTRACTION FIX**: Extract vulnerabilities from complex plugin results
            self.logger.info(f"🔧 Extracting vulnerabilities from dynamic scan results...")
            extracted_vulnerabilities = self._extract_vulnerabilities_from_dynamic_results(dynamic_results)
            
            # Create enhanced_report structure that consolidation expects
            if isinstance(dynamic_results, dict):
                dynamic_results['enhanced_report'] = {
                    'vulnerabilities': extracted_vulnerabilities,
                    'metadata': {
                        'scan_type': 'dynamic',
                        'extraction_method': 'plugin_results_extraction',
                        'total_vulnerabilities': len(extracted_vulnerabilities)
                    }
                }
                self.logger.info(f"✅ Enhanced report created with {len(extracted_vulnerabilities)} vulnerabilities")
            
            self.logger.info(f"✅ Dynamic analysis completed for {package_name}")
            return ('dynamic_scan_completed', dynamic_results)
            
        except Exception as e:
            self.logger.error(f"❌ Dynamic analysis failed: {e}")
            return ('dynamic_scan_failed', {'error': str(e)})

    def _extract_vulnerabilities_from_dynamic_results(self, dynamic_results: dict) -> list:
        """
        Extract vulnerabilities from complex dynamic scan plugin results.
        
        Handles multiple plugin result formats and converts them to standardized vulnerability format.
        NOW WITH ACCURATE SOURCE CLASSIFICATION (Task 4.1).
        """
        extracted_vulnerabilities = []
        
        try:
            # Initialize classification components (imports now at module level)
            classifier = VulnerabilitySourceClassifier()
            origin_tracker = VulnerabilityOriginTracker()
            evidence_validator = RuntimeEvidenceValidator()
            
            # Navigate to plugin results in the complex nested structure
            if isinstance(dynamic_results, dict):
                results_data = dynamic_results.get('results', {})
                
                # Process each plugin's results
                for plugin_name, plugin_data in results_data.items():
                    if not isinstance(plugin_data, dict):
                        continue
                        
                    plugin_result = plugin_data.get('result', {})
                    plugin_title = plugin_data.get('title', plugin_name)
                    
                    # **METHOD 1**: Direct vulnerabilities array (standard format)
                    if isinstance(plugin_result, dict) and 'vulnerabilities' in plugin_result:
                        vulnerabilities = plugin_result['vulnerabilities']
                        if isinstance(vulnerabilities, list):
                            for vuln in vulnerabilities:
                                if isinstance(vuln, dict):
                                    vuln['plugin_name'] = plugin_name  # Ensure plugin_name for classification
                                    vuln['plugin'] = plugin_name
                                    vuln['plugin_title'] = plugin_title
                                    
                                    # Apply accurate source classification (Task 4.1)
                                    classification = classifier.classify_vulnerability_source(vuln)
                                    vuln['source'] = classification.source.value
                                    vuln['detection_method'] = classification.detection_method.value
                                    vuln['analysis_phase'] = classification.analysis_phase.value
                                    vuln['evidence_type'] = classification.evidence_type.value
                                    vuln['classification_confidence'] = classification.confidence_score
                                    
                                    # Add origin tracking
                                    origin_metadata = origin_tracker.track_vulnerability_origin(vuln, {
                                        'plugin_name': plugin_name,
                                        'plugin_title': plugin_title
                                    })
                                    vuln['origin_id'] = origin_metadata.origin_id
                                    vuln['origin_validation'] = origin_metadata.validation_status
                                    
                                    extracted_vulnerabilities.append(vuln)
                    
                    # **METHOD 2**: Analysis result with vulnerabilities (JADX format)
                    elif isinstance(plugin_result, dict) and 'analysis_result' in plugin_result:
                        analysis_result = plugin_result['analysis_result']
                        if hasattr(analysis_result, 'vulnerabilities'):
                            for vuln in analysis_result.vulnerabilities:
                                vuln_dict = {
                                    'title': getattr(vuln, 'title', 'Unknown'),
                                    'description': getattr(vuln, 'description', ''),
                                    'severity': getattr(vuln, 'severity', 'info').upper(),
                                    'vulnerability_type': getattr(vuln, 'vulnerability_type', 'unknown'),
                                    'confidence': getattr(vuln, 'confidence', 0.5),
                                    'plugin_name': plugin_name,  # Ensure plugin_name for classification
                                    'plugin': plugin_name,
                                    'plugin_title': plugin_title
                                }
                                
                                # Apply accurate source classification (Task 4.1)
                                classification = classifier.classify_vulnerability_source(vuln_dict)
                                vuln_dict['source'] = classification.source.value
                                vuln_dict['detection_method'] = classification.detection_method.value
                                vuln_dict['analysis_phase'] = classification.analysis_phase.value
                                vuln_dict['evidence_type'] = classification.evidence_type.value
                                vuln_dict['classification_confidence'] = classification.confidence_score
                                
                                # Add origin tracking
                                origin_metadata = origin_tracker.track_vulnerability_origin(vuln_dict, {
                                    'plugin_name': plugin_name,
                                    'plugin_title': plugin_title
                                })
                                vuln_dict['origin_id'] = origin_metadata.origin_id
                                vuln_dict['origin_validation'] = origin_metadata.validation_status
                                
                                extracted_vulnerabilities.append(vuln_dict)
                    
                    # **METHOD 3**: Rich text results that contain vulnerability information
                    elif hasattr(plugin_result, '__rich_console__') or hasattr(plugin_result, 'plain'):
                        # Extract vulnerabilities from Rich text content
                        text_content = str(plugin_result.plain if hasattr(plugin_result, 'plain') else plugin_result)
                        vulns_from_text = self._extract_vulnerabilities_from_text_with_classification(text_content, plugin_name, plugin_title, classifier, origin_tracker)
                        extracted_vulnerabilities.extend(vulns_from_text)
                    
                    # **METHOD 4**: Complex nested results (various plugin formats)
                    elif isinstance(plugin_result, dict):
                        vulns_from_complex = self._extract_vulnerabilities_from_complex_result_with_classification(plugin_result, plugin_name, plugin_title, classifier, origin_tracker)
                        extracted_vulnerabilities.extend(vulns_from_complex)
                    
                    # **METHOD 5**: String results indicating completion/findings
                    elif isinstance(plugin_result, str) and any(keyword in plugin_result.lower() for keyword in ['vulnerability', 'finding', 'issue', 'critical', 'high']):
                        # Create informational finding from string result
                        vuln_dict = {
                            'title': f'{plugin_title} Finding',
                            'description': plugin_result,
                            'severity': 'INFO',
                            'vulnerability_type': 'analysis_result',
                            'confidence': 0.7,
                            'plugin_name': plugin_name,  # Ensure plugin_name for classification
                            'plugin': plugin_name,
                            'plugin_title': plugin_title
                        }
                        
                        # Apply accurate source classification (Task 4.1)
                        classification = classifier.classify_vulnerability_source(vuln_dict)
                        vuln_dict['source'] = classification.source.value
                        vuln_dict['detection_method'] = classification.detection_method.value
                        vuln_dict['analysis_phase'] = classification.analysis_phase.value
                        vuln_dict['evidence_type'] = classification.evidence_type.value
                        vuln_dict['classification_confidence'] = classification.confidence_score
                        
                        # Add origin tracking
                        origin_metadata = origin_tracker.track_vulnerability_origin(vuln_dict, {
                            'plugin_name': plugin_name,
                            'plugin_title': plugin_title
                        })
                        vuln_dict['origin_id'] = origin_metadata.origin_id
                        vuln_dict['origin_validation'] = origin_metadata.validation_status
                        
                        extracted_vulnerabilities.append(vuln_dict)
            
            # Generate classification summary
            classification_summary = classifier.get_classification_summary(extracted_vulnerabilities)
            validation_summary = evidence_validator.get_validation_summary(extracted_vulnerabilities)
            tracking_summary = origin_tracker.get_tracking_summary()
            
            self.logger.info(f"🔧 EXTRACTION SUCCESS: Found {len(extracted_vulnerabilities)} vulnerabilities from dynamic scan")
            self.logger.info(f"📊 SOURCE CLASSIFICATION SUMMARY:")
            self.logger.info(f"   🔍 Runtime dynamic: {classification_summary.get('runtime_count', 0)}")
            self.logger.info(f"   📋 Static analysis: {classification_summary.get('static_count', 0)}")
            self.logger.info(f"   ⚙️ Configuration: {classification_summary.get('config_count', 0)}")
            self.logger.info(f"   ❓ Unknown source: {classification_summary.get('unknown_count', 0)}")
            self.logger.info(f"   🎯 Classification confidence: {classification_summary.get('average_confidence', 0):.2f}")
            self.logger.info(f"   ✅ Valid runtime evidence: {validation_summary.get('valid_runtime_count', 0)}")
            
            return extracted_vulnerabilities
            
        except ImportError as e:
            self.logger.warning(f"⚠️ Classification system not available, using fallback: {e}")
            # Fallback to original method without classification
            return self._extract_vulnerabilities_from_dynamic_results_fallback(dynamic_results)
            
        except Exception as e:
            self.logger.error(f"❌ Vulnerability extraction failed: {e}")
            return []

    def _extract_vulnerabilities_from_text(self, text_content: str, plugin_name: str, plugin_title: str) -> list:
        """Extract vulnerability information from Rich text content."""
        vulnerabilities = []
        
        # Look for common vulnerability indicators in text
        high_risk_keywords = ['critical', 'high', 'vulnerability', 'exploit', 'insecure', 'weak']
        medium_risk_keywords = ['medium', 'warning', 'issue', 'concern', 'deprecated']
        
        if any(keyword in text_content.lower() for keyword in high_risk_keywords):
            severity = 'HIGH' if any(kw in text_content.lower() for kw in ['critical', 'high', 'exploit']) else 'MEDIUM'
            
            vuln_dict = {
                'title': f'{plugin_title} Security Analysis',
                'description': text_content[:500] + '...' if len(text_content) > 500 else text_content,
                'severity': severity,
                'vulnerability_type': 'security_analysis',
                'confidence': 0.8,
                'plugin': plugin_name,
                'plugin_title': plugin_title,
                'source': 'dynamic_analysis'
            }
            vulnerabilities.append(vuln_dict)
            
        return vulnerabilities

    def _extract_vulnerabilities_from_complex_result(self, result_dict: dict, plugin_name: str, plugin_title: str) -> list:
        """Extract vulnerabilities from complex nested result dictionaries."""
        vulnerabilities = []
        
        # Look for vulnerability-related keys in the result
        vulnerability_keys = ['vulnerabilities', 'findings', 'issues', 'security_findings', 'risks']
        
        for key in vulnerability_keys:
            if key in result_dict:
                items = result_dict[key]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            vuln_dict = {
                                'title': item.get('title', f'{plugin_title} Finding'),
                                'description': item.get('description', item.get('summary', str(item))),
                                'severity': item.get('severity', 'MEDIUM').upper(),
                                'vulnerability_type': item.get('type', item.get('category', 'security_finding')),
                                'confidence': item.get('confidence', 0.7),
                                'plugin': plugin_name,
                                'plugin_title': plugin_title,
                                'source': 'dynamic_analysis'
                            }
                            vulnerabilities.append(vuln_dict)
        
        # Check for numeric vulnerability counts that indicate findings
        if 'total_vulnerabilities' in result_dict and result_dict['total_vulnerabilities'] > 0:
            vuln_dict = {
                'title': f'{plugin_title} Security Analysis',
                'description': f'Found {result_dict["total_vulnerabilities"]} security issues',
                'severity': 'MEDIUM',
                'vulnerability_type': 'security_analysis',
                'confidence': 0.8,
                'plugin': plugin_name,
                'plugin_title': plugin_title,
                'source': 'dynamic_analysis'
            }
            vulnerabilities.append(vuln_dict)
            
        return vulnerabilities
    
    def _extract_vulnerabilities_from_text_with_classification(self, text_content: str, plugin_name: str, plugin_title: str, classifier, origin_tracker) -> list:
        """Extract vulnerability information from Rich text content with accurate classification."""
        vulnerabilities = []
        
        # Look for common vulnerability indicators in text
        high_risk_keywords = ['critical', 'high', 'vulnerability', 'exploit', 'insecure', 'weak']
        medium_risk_keywords = ['medium', 'warning', 'issue', 'concern', 'deprecated']
        
        if any(keyword in text_content.lower() for keyword in high_risk_keywords):
            severity = 'HIGH' if any(kw in text_content.lower() for kw in ['critical', 'high', 'exploit']) else 'MEDIUM'
            
            vuln_dict = {
                'title': f'{plugin_title} Security Analysis',
                'description': text_content[:500] + '...' if len(text_content) > 500 else text_content,
                'severity': severity,
                'vulnerability_type': 'security_analysis',
                'confidence': 0.8,
                'plugin_name': plugin_name,  # Ensure plugin_name for classification
                'plugin': plugin_name,
                'plugin_title': plugin_title
            }
            
            # Apply accurate source classification (Task 4.1)
            classification = classifier.classify_vulnerability_source(vuln_dict)
            vuln_dict['source'] = classification.source.value
            vuln_dict['detection_method'] = classification.detection_method.value
            vuln_dict['analysis_phase'] = classification.analysis_phase.value
            vuln_dict['evidence_type'] = classification.evidence_type.value
            vuln_dict['classification_confidence'] = classification.confidence_score
            
            # Add origin tracking
            origin_metadata = origin_tracker.track_vulnerability_origin(vuln_dict, {
                'plugin_name': plugin_name,
                'plugin_title': plugin_title
            })
            vuln_dict['origin_id'] = origin_metadata.origin_id
            vuln_dict['origin_validation'] = origin_metadata.validation_status
            
            vulnerabilities.append(vuln_dict)
            
        return vulnerabilities

    def _extract_vulnerabilities_from_complex_result_with_classification(self, result_dict: dict, plugin_name: str, plugin_title: str, classifier, origin_tracker) -> list:
        """Extract vulnerabilities from complex nested result dictionaries with accurate classification."""
        vulnerabilities = []
        
        # Look for vulnerability-related keys in the result
        vulnerability_keys = ['vulnerabilities', 'findings', 'issues', 'security_findings', 'risks']
        
        for key in vulnerability_keys:
            if key in result_dict:
                items = result_dict[key]
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            vuln_dict = {
                                'title': item.get('title', f'{plugin_title} Finding'),
                                'description': item.get('description', item.get('summary', str(item))),
                                'severity': item.get('severity', 'MEDIUM').upper(),
                                'vulnerability_type': item.get('type', item.get('category', 'security_finding')),
                                'confidence': item.get('confidence', 0.7),
                                'plugin_name': plugin_name,  # Ensure plugin_name for classification
                                'plugin': plugin_name,
                                'plugin_title': plugin_title
                            }
                            
                            # Apply accurate source classification (Task 4.1)
                            classification = classifier.classify_vulnerability_source(vuln_dict)
                            vuln_dict['source'] = classification.source.value
                            vuln_dict['detection_method'] = classification.detection_method.value
                            vuln_dict['analysis_phase'] = classification.analysis_phase.value
                            vuln_dict['evidence_type'] = classification.evidence_type.value
                            vuln_dict['classification_confidence'] = classification.confidence_score
                            
                            # Add origin tracking
                            origin_metadata = origin_tracker.track_vulnerability_origin(vuln_dict, {
                                'plugin_name': plugin_name,
                                'plugin_title': plugin_title
                            })
                            vuln_dict['origin_id'] = origin_metadata.origin_id
                            vuln_dict['origin_validation'] = origin_metadata.validation_status
                            
                            vulnerabilities.append(vuln_dict)
        
        # Check for numeric vulnerability counts that indicate findings
        if 'total_vulnerabilities' in result_dict and result_dict['total_vulnerabilities'] > 0:
            vuln_dict = {
                'title': f'{plugin_title} Security Analysis',
                'description': f'Found {result_dict["total_vulnerabilities"]} security issues',
                'severity': 'MEDIUM',
                'vulnerability_type': 'security_analysis',
                'confidence': 0.8,
                'plugin_name': plugin_name,  # Ensure plugin_name for classification
                'plugin': plugin_name,
                'plugin_title': plugin_title
            }
            
            # Apply accurate source classification (Task 4.1)
            classification = classifier.classify_vulnerability_source(vuln_dict)
            vuln_dict['source'] = classification.source.value
            vuln_dict['detection_method'] = classification.detection_method.value
            vuln_dict['analysis_phase'] = classification.analysis_phase.value
            vuln_dict['evidence_type'] = classification.evidence_type.value
            vuln_dict['classification_confidence'] = classification.confidence_score
            
            # Add origin tracking
            origin_metadata = origin_tracker.track_vulnerability_origin(vuln_dict, {
                'plugin_name': plugin_name,
                'plugin_title': plugin_title
            })
            vuln_dict['origin_id'] = origin_metadata.origin_id
            vuln_dict['origin_validation'] = origin_metadata.validation_status
            
            vulnerabilities.append(vuln_dict)
            
        return vulnerabilities
    
    def _extract_vulnerabilities_from_dynamic_results_fallback(self, dynamic_results: dict) -> list:
        """
        Fallback method for vulnerability extraction without classification system.
        
        This is used when the new classification system is not available.
        """
        extracted_vulnerabilities = []
        
        try:
            # Navigate to plugin results in the complex nested structure
            if isinstance(dynamic_results, dict):
                results_data = dynamic_results.get('results', {})
                
                # Process each plugin's results
                for plugin_name, plugin_data in results_data.items():
                    if not isinstance(plugin_data, dict):
                        continue
                        
                    plugin_result = plugin_data.get('result', {})
                    plugin_title = plugin_data.get('title', plugin_name)
                    
                    # **METHOD 1**: Direct vulnerabilities array (standard format)
                    if isinstance(plugin_result, dict) and 'vulnerabilities' in plugin_result:
                        vulnerabilities = plugin_result['vulnerabilities']
                        if isinstance(vulnerabilities, list):
                            for vuln in vulnerabilities:
                                if isinstance(vuln, dict):
                                    vuln['plugin'] = plugin_name
                                    vuln['plugin_title'] = plugin_title
                                    # Default fallback labeling (original behavior)
                                    if 'source' not in vuln:
                                        vuln['source'] = 'dynamic_analysis'
                                    extracted_vulnerabilities.append(vuln)
                    
                    # **METHOD 2**: Analysis result with vulnerabilities (JADX format)
                    elif isinstance(plugin_result, dict) and 'analysis_result' in plugin_result:
                        analysis_result = plugin_result['analysis_result']
                        if hasattr(analysis_result, 'vulnerabilities'):
                            for vuln in analysis_result.vulnerabilities:
                                vuln_dict = {
                                    'title': getattr(vuln, 'title', 'Unknown'),
                                    'description': getattr(vuln, 'description', ''),
                                    'severity': getattr(vuln, 'severity', 'info').upper(),
                                    'vulnerability_type': getattr(vuln, 'vulnerability_type', 'unknown'),
                                    'confidence': getattr(vuln, 'confidence', 0.5),
                                    'plugin': plugin_name,
                                    'plugin_title': plugin_title,
                                    'source': 'dynamic_analysis'  # Fallback labeling
                                }
                                extracted_vulnerabilities.append(vuln_dict)
                    
                    # **METHOD 3**: Rich text results that contain vulnerability information
                    elif hasattr(plugin_result, '__rich_console__') or hasattr(plugin_result, 'plain'):
                        # Extract vulnerabilities from Rich text content
                        text_content = str(plugin_result.plain if hasattr(plugin_result, 'plain') else plugin_result)
                        vulns_from_text = self._extract_vulnerabilities_from_text(text_content, plugin_name, plugin_title)
                        extracted_vulnerabilities.extend(vulns_from_text)
                    
                    # **METHOD 4**: Complex nested results (various plugin formats)
                    elif isinstance(plugin_result, dict):
                        vulns_from_complex = self._extract_vulnerabilities_from_complex_result(plugin_result, plugin_name, plugin_title)
                        extracted_vulnerabilities.extend(vulns_from_complex)
                    
                    # **METHOD 5**: String results indicating completion/findings
                    elif isinstance(plugin_result, str) and any(keyword in plugin_result.lower() for keyword in ['vulnerability', 'finding', 'issue', 'critical', 'high']):
                        # Create informational finding from string result
                        vuln_dict = {
                            'title': f'{plugin_title} Finding',
                            'description': plugin_result,
                            'severity': 'INFO',
                            'vulnerability_type': 'analysis_result',
                            'confidence': 0.7,
                            'plugin': plugin_name,
                            'plugin_title': plugin_title,
                            'source': 'dynamic_analysis'  # Fallback labeling
                        }
                        extracted_vulnerabilities.append(vuln_dict)
                        
            self.logger.info(f"🔧 FALLBACK EXTRACTION: Found {len(extracted_vulnerabilities)} vulnerabilities from dynamic scan")
            return extracted_vulnerabilities
            
        except Exception as e:
            self.logger.error(f"❌ Fallback vulnerability extraction failed: {e}")
            return []

    def _json_serializable_converter(self, obj):
        """Convert objects to JSON-serializable format."""
        # **COMPREHENSIVE RICH TEXT FIX**: Handle all Rich library objects
        if hasattr(obj, '__rich_console__') or hasattr(obj, '__rich__'):
            # This is any Rich object - convert to string representation
            if hasattr(obj, 'plain'):
                return str(obj.plain)
            elif hasattr(obj, '__rich_console__'):
                # Use Rich's own rendering if plain not available
                try:
                    from rich.console import Console
                    console = Console(file=None, width=80)
                    with console.capture() as capture:
                        console.print(obj)
                    return capture.get().strip()
                except:
                    return str(obj)
            else:
                return str(obj)
        # Handle Rich Text objects specifically (common in plugin outputs)
        elif hasattr(obj, 'plain') and str(type(obj)).find('rich') != -1:
            return str(obj.plain)
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        elif hasattr(obj, '_asdict'):
            return obj._asdict()
        elif isinstance(obj, (list, tuple)):
            return [self._json_serializable_converter(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: self._json_serializable_converter(value) for key, value in obj.items()}
        else:
            return str(obj)

    def _convert_unified_results(self, execution_result, apk_path: str, package_name: str) -> Dict[str, ScanResult]:
        """Convert unified execution results to ParallelScanManager format."""
        scan_results = {}
        
        self.logger.info(f"🔍 Converting {len(execution_result.results)} execution results...")
        
        # DIAGNOSTIC: Log the structure of execution_result
        self.logger.info(f"🔬 DIAGNOSTIC: execution_result type: {type(execution_result)}")
        self.logger.info(f"🔬 DIAGNOSTIC: execution_result.results keys: {list(execution_result.results.keys())}")
        
        for task_name, result in execution_result.results.items():
            self.logger.info(f"🔬 DIAGNOSTIC: Processing task '{task_name}' with result type: {type(result)}")
            
            # Check if this is an aggregated scan result that contains individual plugin results
            if isinstance(result, tuple) and len(result) >= 2 and isinstance(result[1], dict):
                result_data = result[1]
                
                # If this is an aggregated scan result, extract individual plugin results
                if 'results' in result_data and isinstance(result_data['results'], dict):
                    self.logger.info(f"🔍 Extracting individual plugin results from {task_name}")
                    inner_results = result_data['results']
                    
                    # Process each individual plugin result
                    for plugin_name, plugin_result in inner_results.items():
                        self.logger.info(f"📋 Processing individual plugin: {plugin_name}")
                        
                        # Determine scan type from plugin name
                        plugin_scan_type = "static" if any(keyword in plugin_name.lower() for keyword in 
                                                         ["static", "manifest", "certificate", "enhanced_static_analysis", "jadx"]) else "dynamic"
                        
                        # Process the individual plugin result using the existing logic
                        individual_vulnerabilities = self._process_individual_plugin_result(plugin_name, plugin_result, plugin_scan_type)
                        
                        # Add to the appropriate scan results
                        if plugin_scan_type not in scan_results:
                            scan_results[plugin_scan_type] = ScanResult(
                                scan_type=plugin_scan_type,
                                success=True,
                                vulnerabilities=[],
                                execution_time=0
                            )
                        
                        scan_results[plugin_scan_type].vulnerabilities.extend(individual_vulnerabilities)
                        self.logger.info(f"✅ Added {len(individual_vulnerabilities)} vulnerabilities from {plugin_name}")
                    
                    continue  # Skip the old aggregated processing
            
            # Original logic for non-aggregated results (fallback)
            # Determine scan type from task name or result title
            scan_type = "dynamic"  # default
            if "static" in task_name.lower():
                scan_type = "static"
            elif isinstance(result, tuple) and len(result) >= 2:
                result_title = result[0]
                if result_title == 'static_scan_completed':
                    scan_type = "static"
                elif result_title == 'dynamic_scan_completed':
                    scan_type = "dynamic"
            
            # Extract vulnerabilities from result 
            vulnerabilities = []
            findings_count = 0
            
            self.logger.debug(f"Processing {task_name}: type={type(result)}")
            
            # Handle tuple format from PluginExecutionResult (title, content)
            if isinstance(result, tuple) and len(result) >= 2:
                result_title, result_data = result[0], result[1]
                
                self.logger.debug(f"Tuple result - title: {result_title}, data type: {type(result_data)}")
                
                # ENHANCED: Check for scan completion results (from standalone analysis functions)
                if result_title in ['static_scan_completed', 'dynamic_scan_completed']:
                    self.logger.info(f"🎯 Processing completed scan result: {result_title}")
                    
                    # Extract vulnerabilities from the report data
                    vulnerabilities = []
                    if isinstance(result_data, dict):
                        # Check for vulnerabilities in various report formats
                        if 'vulnerabilities' in result_data:
                            vulnerabilities = result_data['vulnerabilities']
                        elif 'findings' in result_data:
                            vulnerabilities = result_data['findings']
                        elif 'external_vulnerabilities' in result_data:
                            vulnerabilities = result_data['external_vulnerabilities']
                        else:
                            # Extract from nested report structure
                            for key in ['report', 'results', 'data']:
                                if key in result_data and isinstance(result_data[key], dict):
                                    nested_data = result_data[key]
                                    if 'vulnerabilities' in nested_data:
                                        vulnerabilities = nested_data['vulnerabilities']
                                        break
                                    elif 'findings' in nested_data:
                                        vulnerabilities = nested_data['findings']
                                        break
                    
                    self.logger.info(f"✅ Extracted {len(vulnerabilities)} vulnerabilities from {result_title}")
                
                # ENHANCED: Check for generic ExecutionTask results (fallback for when task names are lost)
                elif task_name == 'ExecutionTask' and isinstance(result_data, dict):
                    self.logger.info(f"🎯 Processing generic ExecutionTask result with {len(result_data)} keys")
                    
                    # Look for vulnerabilities in the result data structure
                    vulnerabilities = []
                    if 'external_vulnerabilities' in result_data:
                        vulnerabilities = result_data['external_vulnerabilities']
                        self.logger.info(f"✅ Found {len(vulnerabilities)} external_vulnerabilities in ExecutionTask")
                    elif 'vulnerabilities' in result_data:
                        vulnerabilities = result_data['vulnerabilities']
                        self.logger.info(f"✅ Found {len(vulnerabilities)} vulnerabilities in ExecutionTask")
                    elif 'findings' in result_data:
                        vulnerabilities = result_data['findings']
                        self.logger.info(f"✅ Found {len(vulnerabilities)} findings in ExecutionTask")
                    else:
                        # Log the keys for debugging
                        self.logger.info(f"🔍 ExecutionTask result keys: {list(result_data.keys())}")
                        
                        # Look for vulnerability data in nested structures
                        for key, value in result_data.items():
                            if isinstance(value, list) and len(value) > 0:
                                if isinstance(value[0], dict) and any(vuln_key in value[0] for vuln_key in ['title', 'severity', 'description']):
                                    vulnerabilities = value
                                    self.logger.info(f"✅ Found {len(vulnerabilities)} vulnerabilities in ExecutionTask.{key}")
                                    break
                
                # Handle dict format (enhanced static analysis format)
                elif isinstance(result_data, dict):
                    self.logger.debug(f"Dict data keys: {list(result_data.keys())}")
                    
                    # Check for direct vulnerabilities key (our mapped format)
                    if 'vulnerabilities' in result_data:
                        vulnerabilities = result_data['vulnerabilities']
                        self.logger.info(f"✅ Found {len(vulnerabilities)} vulnerabilities in {task_name}")
                        
                        # Add detailed debugging for the found vulnerabilities
                        if len(vulnerabilities) > 0:
                            self.logger.debug(f"First vulnerability type: {type(vulnerabilities[0])}")
                            self.logger.debug(f"First vulnerability keys: {list(vulnerabilities[0].keys()) if isinstance(vulnerabilities[0], dict) else 'Not a dict'}")
                    
                    # Check for metadata with total_findings
                    elif 'metadata' in result_data:
                        self.logger.debug(f"Checking metadata path - metadata: {result_data.get('metadata', {})}")
                        total_findings = result_data.get('metadata', {}).get('total_findings', 0)
                        self.logger.debug(f"Total findings from metadata: {total_findings}")
                        if total_findings > 0:
                            # Enhanced static analysis includes both security_findings and secret_analysis
                            security_findings = result_data.get('security_findings', [])
                            secret_analysis = result_data.get('secret_analysis', [])
                            
                            # Convert security findings to vulnerability format
                            for finding in security_findings:
                                vuln = {
                                    "title": getattr(finding, 'title', 'Security Finding'),
                                    "description": getattr(finding, 'description', ''),
                                    "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                                    "category": finding.category.value if hasattr(finding.category, 'value') else str(finding.category),
                                    "file_path": getattr(finding, 'file_path', ''),
                                    "line_number": getattr(finding, 'line_number', 0),
                                    "source_type": "security_finding",
                                    "plugin": task_name
                                }
                                vulnerabilities.append(vuln)
                            
                            # Convert secret analysis to vulnerability format  
                            for secret in secret_analysis:
                                vuln = {
                                    "title": f"Potential {secret.pattern_type.value.upper()} Secret Detected",
                                    "description": f"Secret detected: {getattr(secret, 'masked_value', 'hidden')}",
                                    "severity": self._determine_secret_severity_from_object(secret),
                                    "category": "INSECURE_STORAGE",
                                    "confidence": getattr(secret, 'confidence', 0.0),
                                    "file_path": getattr(secret, 'file_path', ''),
                                    "line_number": getattr(secret, 'line_number', 0),
                                    "secret_type": secret.pattern_type.value if hasattr(secret.pattern_type, 'value') else str(secret.pattern_type),
                                    "source_type": "secret_analysis",
                                    "plugin": task_name
                                }
                                vulnerabilities.append(vuln)
                            
                            self.logger.info(f"✅ Extracted {len(security_findings)} security findings + {len(secret_analysis)} secrets from {task_name}")
                        else:
                            # Create a generic vulnerability entry for non-zero data
                            vulnerabilities = [{"title": f"{scan_type.title()} Analysis", "description": str(result_data), "plugin": task_name}]
                    
                    # Check for direct vulnerabilities in dict without wrapper
                    elif any(key in result_data for key in ['security_findings', 'secret_analysis', 'findings']):
                        # This is raw plugin data, convert it
                        vulnerabilities = [{"title": f"{scan_type.title()} Analysis Result", "data": result_data, "plugin": task_name}]
                        self.logger.info(f"✅ Found raw plugin data in {task_name}")
                    
                    else:
                        # Last resort: treat entire dict as a finding
                        vulnerabilities = [{"title": f"{scan_type.title()} Analysis", "data": result_data, "plugin": task_name}]
                
                # Handle list format
                elif isinstance(result_data, list):
                    vulnerabilities = result_data
                    self.logger.info(f"✅ Found {len(vulnerabilities)} vulnerabilities (list format) in {task_name}")
                
                # Handle string/text format (create basic vulnerability entry)
                elif result_data and result_data != "No results found" and not vulnerabilities:
                    # Only create generic vulnerability if we haven't already extracted vulnerabilities above
                    # Check if this is a JADX static analysis report
                    result_str = str(result_data)
                    if "JADX Static Analysis" in result_str and ("secrets found" in result_str or "patterns found" in result_str):
                        # Parse JADX report to extract actual vulnerabilities
                        vulnerabilities = self._parse_jadx_report(result_str, task_name)
                        self.logger.info(f"✅ Parsed {len(vulnerabilities)} vulnerabilities from JADX report in {task_name}")
                    else:
                        # Regular text result
                        vulnerabilities = [{"title": f"{scan_type.title()} Analysis", "description": str(result_data), "plugin": task_name}]
                        self.logger.info(f"✅ Created vulnerability from text result in {task_name}")
            
            # Handle non-tuple results (direct data)
            elif isinstance(result, dict) and not vulnerabilities:
                # Only process if we haven't already extracted vulnerabilities above
                if 'vulnerabilities' in result:
                    vulnerabilities = result['vulnerabilities']
                else:
                    vulnerabilities = [{"title": f"{scan_type.title()} Analysis", "data": result, "plugin": task_name}]
                self.logger.info(f"✅ Found {len(vulnerabilities)} vulnerabilities (direct dict) in {task_name}")
            
            findings_count = len(vulnerabilities)
            
            # Create output file path
            output_file_path = self.temp_dir / f"{scan_type}_results.json"
            
            # Write results to expected JSON file format
            try:
                output_data = {
                    "vulnerabilities": vulnerabilities,
                    "metadata": {
                        "scan_type": scan_type,
                        "total_findings": findings_count,
                        "execution_time": execution_result.execution_time / 2 if hasattr(execution_result, 'execution_time') else 0.0
                    }
                }
                
                with open(output_file_path, 'w') as f:
                    json.dump(output_data, f, indent=2, default=self._json_serializable_converter)
                
                self.logger.info(f"✅ Written {findings_count} findings to {output_file_path}")
                
            except Exception as e:
                self.logger.error(f"❌ Failed to write {scan_type} results file: {e}")
                output_file_path = None
            
            # Create ScanResult object
            scan_result = ScanResult(
                scan_type=scan_type,
                success=execution_result.successful_plugins > 0 if hasattr(execution_result, 'successful_plugins') else len(vulnerabilities) > 0,
                duration=execution_result.execution_time / 2 if hasattr(execution_result, 'execution_time') else 0.0,
                findings_count=findings_count,
                output_file=str(output_file_path) if output_file_path else None,
                findings=vulnerabilities
            )
                
            scan_results[scan_type] = scan_result
        
        # Store results for consolidation
        self.scan_results = scan_results
        
        return scan_results
    
    def _calculate_jadx_timeout(self, apk_path: str) -> int:
        """Calculate appropriate timeout for JADX decompilation based on APK size and complexity"""
        try:
            import os
            from pathlib import Path
            
            apk_size_mb = Path(apk_path).stat().st_size / (1024 * 1024)
            
            # Base timeout calculation based on APK size
            if apk_size_mb < 5:
                base_timeout = 180  # 3 minutes for small APKs
            elif apk_size_mb < 20:
                base_timeout = 300  # 5 minutes for medium APKs  
            elif apk_size_mb < 50:
                base_timeout = 450  # 7.5 minutes for large APKs
            else:
                base_timeout = 600  # 10 minutes for very large APKs
                
            self.logger.debug(f"JADX timeout calculated: {base_timeout}s for {apk_size_mb:.1f}MB APK")
            return base_timeout
            
        except Exception as e:
            self.logger.warning(f"Failed to calculate JADX timeout: {e}, using default 300s")
            return 300  # 5 minute default

    def _apply_enhanced_reporting(self, plugin_results: Dict, apk_path: str, package_name: str, mode: str) -> Dict:
        """Apply Enhanced Vulnerability Reporting Engine to plugin results with Task 4.2 Integration."""
        try:
            # Import Enhanced Vulnerability Reporting Engine and new formatter
            from core.enhanced_vulnerability_reporting_engine import EnhancedVulnerabilityReportingEngine
            from core.runtime_evidence_formatter import RuntimeEvidenceFormatter
            
            self.logger.info("🔧 Applying Enhanced Vulnerability Reporting with Runtime Evidence Formatting...")
            
            # Initialize enhanced reporting engine and runtime formatter
            enhanced_engine = EnhancedVulnerabilityReportingEngine(apk_path=apk_path, target_package=getattr(self, 'target_package', None))
            runtime_formatter = RuntimeEvidenceFormatter()
            
            # Create app context for enhanced analysis with better decompiled path detection
            decompiled_path = ''
            
            # Try to find the actual decompiled path
            import glob
            jadx_dirs = glob.glob("/tmp/jadx_decompiled/jadx_*")
            if jadx_dirs:
                # Use the most recent JADX directory
                jadx_dirs.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                for jadx_dir in jadx_dirs:
                    sources_path = os.path.join(jadx_dir, "sources")
                    if os.path.exists(sources_path):
                        decompiled_path = sources_path
                        break
                    elif any(f.endswith('.java') for f in os.listdir(jadx_dir) if os.path.isfile(os.path.join(jadx_dir, f))):
                        decompiled_path = jadx_dir
                        break
            
            app_context = {
                'package_name': package_name,
                'apk_path': apk_path,
                'decompiled_path': decompiled_path or getattr(self, 'decompiled_path', ''),
                'scan_mode': mode
            }
            
            # Convert plugin results to findings format - extract actual vulnerabilities organically
            raw_findings = []
            self._multiple_findings_buffer = []  # Initialize buffer for plugins with multiple findings
            
            for plugin_name, result in plugin_results.items():

                
                if isinstance(result, tuple) and len(result) >= 2:
                    title, content = result[0], result[1]
                    
                    # Organically extract structured vulnerability data if available
                    finding = self._extract_vulnerability_data(plugin_name, title, content)
                    if finding:
                        raw_findings.append(finding)
                    
                    # Check for multiple findings from plugins like JADX and enhanced_manifest_analysis
                    if hasattr(self, '_multiple_findings_buffer') and self._multiple_findings_buffer:
                        # Add all additional findings from buffer

                        raw_findings.extend(self._multiple_findings_buffer)
                        self._multiple_findings_buffer = []  # Clear buffer after processing
            
            # CRITICAL: Apply comprehensive framework filtering before enhancement
            self.logger.info(f"📊 Collected {len(raw_findings)} raw findings, applying framework filtering...")
            print(f"🔧 DEBUG: _apply_enhanced_reporting - raw_findings count: {len(raw_findings)}")
            if raw_findings:
                print(f"🔧 DEBUG: First raw finding sample: {raw_findings[0] if raw_findings else 'None'}")
            else:
                print("🔧 DEBUG: No raw findings collected from plugins!")
            
            try:
                # Use the new modular framework filtering system  
                # Create a minimal APK context for filtering
                class FilterAPKContext:
                    def __init__(self, package_name, decompiled_path):
                        self.package_name = package_name
                        self.decompiled_path = decompiled_path
                        self.manifest_path = os.path.join(decompiled_path, "AndroidManifest.xml") if decompiled_path else None
                        self.decompiled_apk_dir = Path(decompiled_path) if decompiled_path else None

                filter_apk_ctx = FilterAPKContext(package_name, app_context.get('decompiled_path', ''))
                
                pre_filter_count = len(raw_findings)
                # Use new modular filtering system
                filtering_result = filter_vulnerability_results(raw_findings, filter_apk_ctx)
                framework_filtered = filtering_result.get('filtered_vulnerabilities', raw_findings)
                post_framework_count = len(framework_filtered)
                
                # **INTEGRATE**: Use existing false positive filtering system
                # This keeps real vulnerabilities (even in dependencies) but filters noise
                try:
                    from core.false_positive_filter import FalsePositiveFilter
                    fp_filter = FalsePositiveFilter()
                    filter_result = fp_filter.filter_report(framework_filtered)
                    raw_findings = filter_result['vulnerabilities']
                    post_filter_count = len(raw_findings)
                    fp_stats = filter_result['statistics']
                    
                    self.logger.info(f"🎯 Enhanced filtering results:")
                    self.logger.info(f"   Original findings: {pre_filter_count}")
                    self.logger.info(f"   After framework filtering: {post_framework_count}")
                    self.logger.info(f"   After false positive filtering: {post_filter_count}")
                    self.logger.info(f"   Framework findings filtered: {pre_filter_count - post_framework_count}")
                    self.logger.info(f"   False positives filtered: {fp_stats.get('total_filtered', 0)}")
                    
                except ImportError as ie:
                    self.logger.warning(f"False positive filter not available: {ie}")
                    raw_findings = framework_filtered
                    post_filter_count = len(raw_findings)
                    
                    self.logger.info(f"🎯 Framework filtering results:")
                    self.logger.info(f"   Original findings: {pre_filter_count}")
                    self.logger.info(f"   App-only findings: {post_filter_count}")  
                    self.logger.info(f"   Framework findings filtered: {pre_filter_count - post_filter_count}")
                
            except Exception as e:
                self.logger.error(f"❌ Framework filtering failed: {e}")
                # Continue with unfiltered results if filtering fails
            
            # ENHANCEMENT: Firebase Integration Analysis
            try:
                from plugins.enhanced_firebase_integration_analyzer import EnhancedFirebaseIntegrationAnalyzer
                from core.framework_filtering_system import FrameworkFilterManager
                
                # Detect Firebase integration using the framework filter manager
                filter_manager = FrameworkFilterManager(package_name, filter_apk_ctx)
                firebase_detected = filter_manager.detect_firebase_integration(filter_apk_ctx)
                
                if firebase_detected:
                    self.logger.info("🔥 Firebase integration detected - running specialized analysis...")
                    firebase_analyzer = EnhancedFirebaseIntegrationAnalyzer(filter_apk_ctx)
                    firebase_results = firebase_analyzer.analyze_firebase_integration_security()
                    
                    if firebase_results and firebase_results.get('firebase_vulnerabilities'):
                        firebase_findings = firebase_results['firebase_vulnerabilities']
                        raw_findings.extend(firebase_findings)
                        self.logger.info(f"🔥 Added {len(firebase_findings)} Firebase-specific findings")
                    else:
                        self.logger.info("🔥 Firebase analysis completed - no vulnerabilities found")
                else:
                    self.logger.debug("🔥 No Firebase integration detected")
                    
            except Exception as e:
                self.logger.warning(f"⚠️ Firebase integration analysis failed: {e}")
                # Continue without Firebase analysis if it fails
            
            self.logger.info(f"🔧 Enhancing {len(raw_findings)} vulnerability findings...")
            
            # Report ML enhancement stage progress
            self.logger.info(f"🤖 Starting ML-enhanced vulnerability classification...")
            self.logger.info(f"🤖 Processing {len(raw_findings)} findings through ML pipeline...")
            
            # Apply enhanced reporting
            print(f"🔧 DEBUG: Calling enhance_vulnerability_report with {len(raw_findings)} findings")
            enhanced_results = enhanced_engine.enhance_vulnerability_report(raw_findings, app_context)
            print(f"🔧 DEBUG: enhance_vulnerability_report returned: {type(enhanced_results)}")
            if enhanced_results:
                print(f"🔧 DEBUG: enhanced_results keys: {list(enhanced_results.keys()) if isinstance(enhanced_results, dict) else 'Not a dict'}")
            else:
                print("🔧 DEBUG: enhanced_results is None or empty!")
            
            if enhanced_results:
                self.logger.info(f"🤖 ML enhancement completed successfully!")
                self.logger.info(f"✅ Enhanced reporting generated:")
                self.logger.info(f"   Enhanced vulnerabilities: {enhanced_results['executive_summary']['total_vulnerabilities']}")
                self.logger.info(f"   Severity breakdown: {enhanced_results['executive_summary']['severity_breakdown']}")
                self.logger.info(f"🤖 ML-enhanced confidence scoring applied")
                
                # **TASK 4.2 INTEGRATION**: Apply Runtime Evidence Formatting
                try:
                    vulnerabilities = enhanced_results.get('vulnerabilities', [])
                    if vulnerabilities:
                        self.logger.info(f"🎯 Applying runtime evidence formatting to {len(vulnerabilities)} vulnerabilities...")
                        
                        # Categorize vulnerabilities by detection method
                        categorized_vulnerabilities = runtime_formatter.categorize_by_detection_method(vulnerabilities)
                        
                        # Generate detailed report with enhanced categorization
                        formatted_report = runtime_formatter.generate_detailed_report(categorized_vulnerabilities)
                        
                        # Extract formatted vulnerabilities for integration
                        all_formatted_vulns = []
                        for category_vulns in categorized_vulnerabilities.values():
                            for formatted_vuln in category_vulns:
                                # Convert FormattedVulnerability back to dict format for compatibility
                                vuln_dict = {
                                    'vulnerability_id': formatted_vuln.vulnerability_id,
                                    'title': formatted_vuln.title,
                                    'description': formatted_vuln.description,
                                    'severity': formatted_vuln.severity,
                                    'confidence': formatted_vuln.confidence,
                                    'detection_category': formatted_vuln.detection_category.value,
                                    'source_classification': formatted_vuln.source_classification,
                                    'detection_method': formatted_vuln.detection_method,
                                    'analysis_phase': formatted_vuln.analysis_phase,
                                    'evidence_type': formatted_vuln.evidence_type,
                                    'actionable_information': formatted_vuln.actionable_information,
                                    'formatting_metadata': formatted_vuln.formatting_metadata
                                }
                                
                                # Add runtime evidence if available
                                if formatted_vuln.runtime_evidence:
                                    vuln_dict['runtime_evidence_package'] = {
                                        'hook_timestamp': formatted_vuln.runtime_evidence.hook_timestamp,
                                        'formatted_timestamp': formatted_vuln.runtime_evidence.formatted_timestamp,
                                        'call_stack': formatted_vuln.runtime_evidence.call_stack,
                                        'execution_context': formatted_vuln.runtime_evidence.execution_context,
                                        'runtime_parameters': formatted_vuln.runtime_evidence.runtime_parameters,
                                        'evidence_quality': formatted_vuln.runtime_evidence.evidence_quality.value,
                                        'evidence_hash': formatted_vuln.runtime_evidence.evidence_hash,
                                        'frida_session_info': formatted_vuln.runtime_evidence.frida_session_info
                                    }
                                
                                # Add static/config evidence
                                if formatted_vuln.static_evidence:
                                    vuln_dict['static_evidence'] = formatted_vuln.static_evidence
                                if formatted_vuln.configuration_evidence:
                                    vuln_dict['configuration_evidence'] = formatted_vuln.configuration_evidence
                                
                                # **CRITICAL**: Add code evidence for security professionals
                                if formatted_vuln.code_snippet:
                                    vuln_dict['code_snippet'] = formatted_vuln.code_snippet
                                if formatted_vuln.file_path:
                                    vuln_dict['file_path'] = formatted_vuln.file_path
                                if formatted_vuln.line_number:
                                    vuln_dict['line_number'] = formatted_vuln.line_number
                                if formatted_vuln.surrounding_context:
                                    vuln_dict['surrounding_context'] = formatted_vuln.surrounding_context
                                
                                all_formatted_vulns.append(vuln_dict)
                        
                        # Log categorization results
                        self.logger.info(f"📊 TASK 4.2 CATEGORIZATION RESULTS:")
                        for category, vulns in categorized_vulnerabilities.items():
                            if vulns:
                                self.logger.info(f"   🔍 {category}: {len(vulns)} vulnerabilities")
                        
                        # Update enhanced_results with formatted vulnerabilities and report
                        enhanced_results['vulnerabilities'] = all_formatted_vulns
                        enhanced_results['runtime_evidence_report'] = formatted_report
                        enhanced_results['categorized_vulnerabilities'] = {
                            category: len(vulns) for category, vulns in categorized_vulnerabilities.items()
                        }
                        
                        self.logger.info(f"✅ Task 4.2 Runtime Evidence Formatting applied successfully!")
                        
                except ImportError as fmt_import_error:
                    self.logger.warning(f"⚠️ Runtime Evidence Formatter not available: {fmt_import_error}")
                except Exception as fmt_error:
                    self.logger.error(f"❌ Runtime evidence formatting failed: {fmt_error}")
                    # Continue with original results if formatting fails
                
                # CRITICAL FIX: Return enhanced results in the format expected by caller
                # The calling code expects 'enhanced_vulnerabilities' and 'vulnerabilities' keys
                return {
                    'enhanced_vulnerabilities': enhanced_results.get('vulnerabilities', []),
                    'vulnerabilities': enhanced_results.get('vulnerabilities', []),
                    'executive_summary': enhanced_results.get('executive_summary', {}),
                    'metadata': enhanced_results.get('metadata', {}),
                    'coordination_metrics': enhanced_results.get('coordination_metrics', {}),
                    'runtime_evidence_report': enhanced_results.get('runtime_evidence_report', {}),
                    'categorized_vulnerabilities': enhanced_results.get('categorized_vulnerabilities', {})
                }
            else:
                self.logger.warning("⚠️ Enhanced reporting returned empty results")
                return {
                    'enhanced_vulnerabilities': [],
                    'vulnerabilities': [],
                    'executive_summary': {},
                    'metadata': {},
                    'coordination_metrics': {}
                }
                
        except ImportError:
            self.logger.warning("⚠️ Enhanced Vulnerability Reporting Engine not available")
            return {
                'enhanced_vulnerabilities': [],
                'vulnerabilities': [],
                'executive_summary': {},
                'metadata': {},
                'coordination_metrics': {}
            }
        except Exception as e:
            self.logger.error(f"❌ Enhanced reporting failed: {e}")
            return {
                'enhanced_vulnerabilities': [],
                'vulnerabilities': [],
                'executive_summary': {},
                'metadata': {},
                'coordination_metrics': {}
            }
    
    def _extract_vulnerability_data(self, plugin_name: str, title: Any, content: Any) -> Optional[Dict]:
        """Extract structured vulnerability data from plugin results."""
        try:
            # **MANIFEST ANALYSIS FIX**: Handle enhanced_manifest_analysis plugin format FIRST (before general tuple check)
            if plugin_name == 'enhanced_manifest_analysis':
                # Handle nested tuple format: (title, (result_title, ManifestAnalysisResult))
                actual_content = content
                if isinstance(content, tuple) and len(content) >= 2:
                    # Handle double-nested tuple structure
                    if isinstance(content[1], tuple) and len(content[1]) >= 2:
                        actual_content = content[1][1]  # The actual ManifestAnalysisResult
                    else:
                        actual_content = content[1]
                
                if hasattr(actual_content, 'security_findings'):
                    # Extract individual security findings from ManifestAnalysisResult
                    if actual_content.security_findings:
                        all_findings = []
                        for security_finding in actual_content.security_findings:
                            finding = {
                                'title': getattr(security_finding, 'title', str(security_finding)),
                                'description': getattr(security_finding, 'description', str(security_finding)),
                                'plugin_name': plugin_name,
                                'severity': getattr(security_finding, 'severity', 'MEDIUM'),
                                'confidence': getattr(security_finding, 'confidence', 0.8),
                                'evidence': getattr(security_finding, 'evidence', ''),
                                'file_path': 'AndroidManifest.xml',
                                'line_number': getattr(security_finding, 'line_number', 0),
                                'cwe_id': getattr(security_finding, 'cwe_id', ''),
                                'masvs_control': getattr(security_finding, 'masvs_control', ''),
                                'vulnerability_type': getattr(security_finding, 'vulnerability_type', ''),
                                'source': plugin_name,
                                'recommendations': getattr(security_finding, 'recommendations', [])
                            }
                            all_findings.append(finding)
                        

                    
                        # Store multiple findings for this plugin
                        if hasattr(self, '_multiple_findings_buffer'):
                            self._multiple_findings_buffer.extend(all_findings)
                        else:
                            self._multiple_findings_buffer = all_findings
                        
                        # Return the first finding (others will be processed separately)
                        return all_findings[0] if all_findings else None
            
            # Handle dictionary format vulnerabilities
            elif isinstance(content, dict):
                # Handle new JADX structured format with multiple vulnerabilities
                if 'vulnerabilities' in content and isinstance(content['vulnerabilities'], list):
                    vulns = content['vulnerabilities']
                    if vulns:
                        # Return ALL vulnerabilities from JADX structured format
                        all_findings = []
                        for vuln in vulns:
                            if isinstance(vuln, dict):
                                finding = {
                                    'title': vuln.get('title', str(title)),
                                    'description': vuln.get('description', str(vuln)),
                                    'plugin_name': plugin_name,
                                    'severity': vuln.get('severity', 'Medium'),
                                    'confidence': vuln.get('confidence', 0.0),
                                    'evidence': vuln.get('evidence', vuln.get('code_snippet', '')),
                                    'file_path': vuln.get('file_path', ''),
                                    'line_number': vuln.get('line_number', 0),
                                    'cwe_id': vuln.get('cwe_id', ''),
                                    'masvs_control': vuln.get('masvs_control', ''),
                                    'vulnerability_type': vuln.get('vulnerability_type', ''),
                                    'source': vuln.get('source', plugin_name),
                                    'recommendations': vuln.get('recommendations', [])
                                }
                                all_findings.append(finding)
                        
                        # Store multiple findings for this plugin
                        if hasattr(self, '_multiple_findings_buffer'):
                            self._multiple_findings_buffer.extend(all_findings)
                        else:
                            self._multiple_findings_buffer = all_findings
                        
                        # Return the first finding (others will be processed separately)
                        return all_findings[0] if all_findings else None
                
                # Handle legacy single vulnerability format
                elif any(key in content for key in ['vulnerability', 'finding']):
                    vuln = content.get('vulnerability') or content.get('finding')
                    if isinstance(vuln, dict) and vuln.get('file_path'):
                        finding = {
                            'title': vuln.get('title', str(title)),
                            'description': vuln.get('description', str(content)),
                            'plugin_name': plugin_name,
                            'severity': vuln.get('severity', 'Medium'),
                            'confidence': vuln.get('confidence', 0.0),
                            'evidence': vuln.get('evidence', ''),
                            'file_path': vuln.get('file_path', ''),
                            'line_number': vuln.get('line_number', 0),
                            'cwe_id': vuln.get('cwe_id', ''),
                            'recommendations': vuln.get('recommendations', [])
                        }
                        return finding
                
                # Direct vulnerability dictionary
                elif content.get('file_path') or content.get('location'):
                    finding = {
                        'title': content.get('title', str(title)),
                        'description': content.get('description', str(content)),
                        'plugin_name': plugin_name,
                        'severity': content.get('severity', 'Medium'),
                        'confidence': content.get('confidence', 0.0),
                        'evidence': content.get('evidence', ''),
                        'file_path': content.get('file_path', ''),
                        'line_number': content.get('line_number', 0),
                        'cwe_id': content.get('cwe_id', ''),
                        'recommendations': content.get('recommendations', [])
                    }
                    return finding
            
            # Organic detection: Only consider content with vulnerability-like characteristics
            if self._has_vulnerability_characteristics(title, content):
                # Create basic finding structure for unstructured but valid content
                finding = {
                    'title': str(title),
                    'description': str(content),
                    'plugin_name': plugin_name,
                    'severity': 'Medium',  # Default severity for unstructured findings
                    'confidence': 0.0,
                    'evidence': '',
                    'file_path': '',
                    'line_number': 0,
                    'cwe_id': '',
                    'recommendations': []
                }
                return finding
            
            # If no vulnerability characteristics detected, skip silently
            return None
            
        except Exception as e:
            self.logger.error(f"Error extracting vulnerability data from {plugin_name}: {e}")
            return None
    
    def _extract_file_path(self, content: Any) -> str:
        """Extract file path from various content formats."""
        try:
            if hasattr(content, 'location'):
                location = content.location
                if isinstance(location, str) and ':' in location:
                    return location.split(':')[0]
                elif hasattr(location, 'file_path'):
                    return location.file_path
            elif hasattr(content, 'file_path'):
                return content.file_path
            return ''
        except:
            return ''
    
    def _extract_line_number(self, content: Any) -> int:
        """Extract line number from various content formats."""
        try:
            if hasattr(content, 'location'):
                location = content.location
                if isinstance(location, str) and ':' in location:
                    parts = location.split(':')
                    if len(parts) > 1:
                        return int(parts[1])
                elif hasattr(location, 'line_number'):
                    return location.line_number
            elif hasattr(content, 'line_number'):
                return content.line_number
            return 0
        except:
            return 0

    def _has_vulnerability_characteristics(self, title: Any, content: Any) -> bool:
        """Organically detect if content represents a vulnerability based on structure and characteristics."""
        try:
            # Explicit exclusion: Skip INFO status entries (informational, not vulnerabilities)
            if isinstance(content, dict) and content.get('Status') == 'INFO':
                return False
            if isinstance(content, dict) and content.get('status') == 'INFO':
                return False
            
            # Skip pure informational entries based on title patterns
            title_str = str(title).lower()
            if any(info_pattern in title_str for info_pattern in [
                'information extraction', 'apk information', 'metadata extraction',
                'certificate details', 'basic information'
            ]):
                return False
            
            # Check for structured vulnerability objects with typical attributes
            if hasattr(content, '__dict__'):
                vulnerability_attributes = ['severity', 'confidence', 'evidence', 'location', 
                                          'file_path', 'line_number', 'cwe_mapping', 'recommendations']
                if any(hasattr(content, attr) for attr in vulnerability_attributes):
                    return True
            
            # Check for dictionary format with vulnerability-like keys
            if isinstance(content, dict):
                vulnerability_keys = ['severity', 'confidence', 'evidence', 'file_path', 
                                    'line_number', 'cwe_id', 'recommendations', 'location']
                if any(key in content for key in vulnerability_keys):
                    return True
                
                # Check for nested vulnerabilities structure
                if 'vulnerabilities' in content and isinstance(content['vulnerabilities'], list):
                    return len(content['vulnerabilities']) > 0
            
            # Check for list of vulnerability objects
            if isinstance(content, (list, tuple)) and content:
                first_item = content[0]
                if isinstance(first_item, dict) and any(key in first_item for key in ['severity', 'file_path', 'evidence']):
                    return True
                if hasattr(first_item, '__dict__') and any(hasattr(first_item, attr) for attr in ['severity', 'location']):
                    return True
            
            # Content-based organic detection for security-related findings
            content_str = str(content)
            title_str = str(title)
            
            # Look for security-related technical indicators (organic patterns)
            security_indicators = [
                # File extensions and paths that indicate code analysis
                '.java' in content_str or '.smali' in content_str or '.xml' in content_str,
                # Security-related technical terms (not UI text)
                any(term in content_str for term in ['CWE-', 'CVE-', 'vulnerability', 'insecure', 'weak']),
                # Code-like patterns (method calls, file paths)
                any(pattern in content_str for pattern in ['.', '/', '()', 'line:', 'method:']),
                # Security severity indicators
                any(sev in title_str for sev in ['HIGH', 'MEDIUM', 'LOW', 'CRITICAL']),
                # Length suggests detailed analysis rather than simple status
                len(content_str) > 50 and len(content_str) < 5000
            ]
            
            # Require at least 2 security indicators for organic detection
            return sum(security_indicators) >= 2
            
        except Exception as e:
            # If we can't analyze it, be conservative and include it
            return len(str(content)) > 20  # Basic length check as fallback
    
    def _display_enhanced_vulnerability_report(self, enhanced_findings: Dict):
        """Display detailed vulnerability report with context."""
        try:
            self.logger.info("\n" + "="*80)
            self.logger.info("📊 ENHANCED VULNERABILITY REPORT")
            self.logger.info("="*80)
            
            # Executive Summary
            exec_summary = enhanced_findings.get('executive_summary', {})
            if exec_summary:
                self.logger.info("\n🎯 EXECUTIVE SUMMARY:")
                self.logger.info(f"   Total Vulnerabilities: {exec_summary.get('total_vulnerabilities', 0)}")
                
                severity_breakdown = exec_summary.get('severity_breakdown', {})
                if severity_breakdown:
                    self.logger.info("   Severity Breakdown:")
                    for severity, count in severity_breakdown.items():
                        if count > 0:
                            self.logger.info(f"     {severity}: {count}")
            
            # Enhanced Vulnerabilities Details
            enhanced_vulns = enhanced_findings.get('enhanced_vulnerabilities', [])
            if enhanced_vulns:
                self.logger.info(f"\n🔍 DETAILED VULNERABILITY ANALYSIS ({len(enhanced_vulns)} findings):")
                
                for i, vuln in enumerate(enhanced_vulns[:5], 1):  # Show first 5 for brevity
                    self.logger.info(f"\n   {i}. {vuln.get('title', 'Unknown')}")
                    self.logger.info(f"      Severity: {vuln.get('severity', 'Unknown')}")
                    self.logger.info(f"      File: {vuln.get('file_path', 'N/A')}")
                    self.logger.info(f"      MASVS: {vuln.get('masvs_control', 'N/A')}")
                    self.logger.info(f"      CWE: {vuln.get('cwe_id', 'N/A')}")
                    
                    remediation = vuln.get('specific_remediation', '')
                    if remediation and len(remediation) < 200:
                        self.logger.info(f"      Remediation: {remediation}")
                
                if len(enhanced_vulns) > 5:
                    self.logger.info(f"   ... and {len(enhanced_vulns) - 5} more detailed vulnerabilities")
            
            # Actionable Recommendations
            recommendations = enhanced_findings.get('actionable_recommendations', [])
            if recommendations:
                self.logger.info(f"\n💡 ACTIONABLE RECOMMENDATIONS:")
                for i, rec in enumerate(recommendations[:3], 1):  # Show first 3
                    self.logger.info(f"   {i}. {rec}")
            
            self.logger.info("\n" + "="*80)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to display enhanced vulnerability report: {e}")


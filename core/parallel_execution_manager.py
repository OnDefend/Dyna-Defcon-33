#!/usr/bin/env python3
"""
Parallel Execution Manager for AODS Framework

This module enables running static and dynamic analysis in separate processes/windows
while maintaining coordination and real-time communication between them.

Features:
- Process separation for static and dynamic analysis
- Inter-process communication via shared memory and queues
- Real-time progress synchronization
- Independent window management
- Graceful shutdown coordination
- Results aggregation from both processes
"""

import json
import logging
import multiprocessing as mp
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)

class ProcessType(Enum):
    """Types of analysis processes."""
    STATIC = "static"
    DYNAMIC = "dynamic"
    COORDINATOR = "coordinator"

class ProcessStatus(Enum):
    """Status of analysis processes."""
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"

@dataclass
class ProcessInfo:
    """Information about an analysis process."""
    process_id: int
    process_type: ProcessType
    status: ProcessStatus
    start_time: float
    end_time: Optional[float] = None
    progress: float = 0.0
    current_task: str = ""
    window_id: Optional[str] = None
    error_message: Optional[str] = None

@dataclass
class AnalysisResults:
    """Results from analysis processes."""
    static_results: Optional[Dict[str, Any]] = None
    dynamic_results: Optional[Dict[str, Any]] = None
    combined_vulnerabilities: List[Dict[str, Any]] = None
    execution_stats: Optional[Dict[str, Any]] = None

class InterProcessCommunicator:
    """Manages communication between analysis processes."""
    
    def __init__(self):
        self.static_queue = mp.Queue()
        self.dynamic_queue = mp.Queue()
        self.coordinator_queue = mp.Queue()
        self.shared_state = mp.Manager().dict()
        self.results_dict = mp.Manager().dict()
        self.shutdown_event = mp.Event()
        
        # Initialize shared state
        self.shared_state.update({
            'static_progress': 0.0,
            'dynamic_progress': 0.0,
            'static_status': ProcessStatus.INITIALIZING.value,
            'dynamic_status': ProcessStatus.INITIALIZING.value,
            'static_task': '',
            'dynamic_task': '',
            'start_time': time.time()
        })
    
    def update_progress(self, process_type: ProcessType, progress: float, task: str = ""):
        """Update progress for a specific process."""
        if process_type == ProcessType.STATIC:
            self.shared_state['static_progress'] = progress
            self.shared_state['static_task'] = task
        elif process_type == ProcessType.DYNAMIC:
            self.shared_state['dynamic_progress'] = progress
            self.shared_state['dynamic_task'] = task
    
    def update_status(self, process_type: ProcessType, status: ProcessStatus):
        """Update status for a specific process."""
        if process_type == ProcessType.STATIC:
            self.shared_state['static_status'] = status.value
        elif process_type == ProcessType.DYNAMIC:
            self.shared_state['dynamic_status'] = status.value
    
    def get_shared_state(self) -> Dict:
        """Get current shared state."""
        return dict(self.shared_state)
    
    def store_results(self, process_type: ProcessType, results: Dict[str, Any]):
        """Store results from a process."""
        self.results_dict[process_type.value] = results
    
    def get_results(self) -> AnalysisResults:
        """Get combined results from all processes."""
        return AnalysisResults(
            static_results=self.results_dict.get('static'),
            dynamic_results=self.results_dict.get('dynamic'),
            execution_stats=self.results_dict.get('stats')
        )
    
    def signal_shutdown(self):
        """Signal all processes to shutdown."""
        self.shutdown_event.set()
    
    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested."""
        return self.shutdown_event.is_set()

class WindowManager:
    """Manages separate windows for different analysis processes."""
    
    def __init__(self):
        self.windows: Dict[str, subprocess.Popen] = {}
        self.terminal_type = self._detect_terminal()
    
    def _detect_terminal(self) -> str:
        """Detect the available terminal emulator."""
        terminals = [
            ('gnome-terminal', ['--', 'bash', '-c']),
            ('xterm', ['-e', 'bash', '-c']),
            ('konsole', ['-e', 'bash', '-c']),
            ('terminator', ['-e', 'bash', '-c']),
            ('lxterminal', ['-e', 'bash', '-c']),
        ]
        
        for terminal, _ in terminals:
            try:
                subprocess.run(['which', terminal], capture_output=True, check=True)
                return terminal
            except subprocess.CalledProcessError:
                continue
        
        # Fallback to basic terminal detection
        if 'DISPLAY' in os.environ:
            return 'xterm'
        else:
            return 'tmux'  # For console environments
    
    def open_window(self, window_id: str, title: str, command: List[str]) -> bool:
        """Open a new window for a process."""
        try:
            if self.terminal_type == 'gnome-terminal':
                cmd = [
                    'gnome-terminal',
                    '--title', title,
                    '--geometry', '120x40',
                    '--',
                    'bash', '-c',
                    ' '.join(command) + '; read -p "Press Enter to close..."'
                ]
            elif self.terminal_type == 'xterm':
                cmd = [
                    'xterm',
                    '-title', title,
                    '-geometry', '120x40',
                    '-e', 'bash', '-c',
                    ' '.join(command) + '; read -p "Press Enter to close..."'
                ]
            elif self.terminal_type == 'tmux':
                # For tmux, create new session/window
                session_name = f"aods_{window_id}"
                cmd = [
                    'tmux', 'new-session', '-d',
                    '-s', session_name,
                    '-x', '120', '-y', '40',
                    ' '.join(command)
                ]
            else:
                # Fallback - run in background
                cmd = command
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            self.windows[window_id] = process
            logger.info(f"Opened window '{title}' with ID: {window_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to open window '{title}': {e}")
            return False
    
    def close_window(self, window_id: str):
        """Close a specific window."""
        if window_id in self.windows:
            try:
                process = self.windows[window_id]
                if process.poll() is None:  # Process still running
                    if os.name != 'nt':
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    else:
                        process.terminate()
                    process.wait(timeout=5)
                del self.windows[window_id]
                logger.info(f"Closed window: {window_id}")
            except Exception as e:
                logger.error(f"Error closing window {window_id}: {e}")
    
    def close_all_windows(self):
        """Close all managed windows."""
        for window_id in list(self.windows.keys()):
            self.close_window(window_id)

class StaticAnalysisProcess:
    """Handles static analysis in a separate process."""
    
    def __init__(self, communicator: InterProcessCommunicator, apk_path: str, package_name: str):
        self.communicator = communicator
        self.apk_path = apk_path
        self.package_name = package_name
        self.console = Console()
    
    def run(self):
        """Execute static analysis."""
        try:
            self.communicator.update_status(ProcessType.STATIC, ProcessStatus.RUNNING)
            self.console.print("[bold green]🔍 AODS Static Analysis Process[/bold green]")
            self.console.print(f"Analyzing APK: {self.apk_path}")
            self.console.print(f"Package: {self.package_name}")
            self.console.print("-" * 60)
            
            # Import AODS components
            from core.analyzer import APKAnalyzer
            from core.apk_ctx import APKContext
            from core.plugin_manager import create_plugin_manager
            from core.report_generator import ReportGenerator
            
            # Initialize APK context
            self.communicator.update_progress(ProcessType.STATIC, 10, "Initializing APK context")
            apk_ctx = APKContext(self.apk_path, self.package_name)
            
            # CRITICAL FIX: Use centralized scan mode tracker instead of hardcoding
            try:
                from core.scan_mode_tracker import get_effective_scan_mode
                effective_scan_mode = get_effective_scan_mode(self.package_name)
                if effective_scan_mode:
                    apk_ctx.set_scan_mode(effective_scan_mode)
                else:
                    apk_ctx.set_scan_mode("safe")  # Default fallback
            except ImportError:
                apk_ctx.set_scan_mode("safe")  # Fallback if tracker not available
            
            # Initialize plugin manager
            self.communicator.update_progress(ProcessType.STATIC, 20, "Loading plugins")
            plugin_mgr = create_plugin_manager()
            
            # Get static analysis plugins
            static_plugins = [p for p in plugin_mgr.get_available_plugins() 
                            if 'static' in p.name.lower() or 'manifest' in p.name.lower()]
            
            self.console.print(f"Loaded {len(static_plugins)} static analysis plugins")
            
            # Execute static analysis plugins
            results = {}
            for i, plugin in enumerate(static_plugins):
                if self.communicator.is_shutdown_requested():
                    break
                
                progress = 30 + (i / len(static_plugins)) * 60
                self.communicator.update_progress(
                    ProcessType.STATIC, progress, f"Running {plugin.name}"
                )
                
                try:
                    self.console.print(f"🔄 Executing: {plugin.name}")
                    result = plugin_mgr.execute_plugin(plugin.name, apk_ctx)
                    results[plugin.name] = result
                    self.console.print(f"✅ Completed: {plugin.name}")
                except Exception as e:
                    self.console.print(f"❌ Failed: {plugin.name} - {e}")
                    results[plugin.name] = {"error": str(e)}
            
            # Generate static analysis report
            self.communicator.update_progress(ProcessType.STATIC, 95, "Generating report")
            
            # Store results
            self.communicator.store_results(ProcessType.STATIC, {
                'plugin_results': results,
                'apk_info': {
                    'path': self.apk_path,
                    'package': self.package_name,
                    'analysis_time': time.time() - self.communicator.shared_state['start_time']
                }
            })
            
            self.communicator.update_progress(ProcessType.STATIC, 100, "Static analysis completed")
            self.communicator.update_status(ProcessType.STATIC, ProcessStatus.COMPLETED)
            
            self.console.print("[bold green]✅ Static Analysis Completed Successfully[/bold green]")
            
        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            self.communicator.update_status(ProcessType.STATIC, ProcessStatus.FAILED)
            self.console.print(f"[bold red]❌ Static analysis failed: {e}[/bold red]")

class DynamicAnalysisProcess:
    """Handles dynamic analysis in a separate process."""
    
    def __init__(self, communicator: InterProcessCommunicator, apk_path: str, package_name: str):
        self.communicator = communicator
        self.apk_path = apk_path
        self.package_name = package_name
        self.console = Console()
    
    def run(self):
        """Execute dynamic analysis."""
        try:
            self.communicator.update_status(ProcessType.DYNAMIC, ProcessStatus.RUNNING)
            self.console.print("[bold blue]📱 AODS Dynamic Analysis Process[/bold blue]")
            self.console.print(f"Analyzing APK: {self.apk_path}")
            self.console.print(f"Package: {self.package_name}")
            self.console.print("-" * 60)
            
            # Check device availability
            self.communicator.update_progress(ProcessType.DYNAMIC, 10, "Checking device connectivity")
            
            device_available = self._check_device_availability()
            if not device_available:
                self.console.print("[yellow]⚠️ No Android device detected - skipping dynamic analysis[/yellow]")
                self.communicator.update_status(ProcessType.DYNAMIC, ProcessStatus.COMPLETED)
                return
            
            # Import dynamic analysis components
            from core.enhanced_drozer_manager import DrozerHelper
            from dyna import run_dynamic_log_analysis
            
            # Initialize Drozer
            self.communicator.update_progress(ProcessType.DYNAMIC, 20, "Initializing Drozer")
            drozer_helper = DrozerHelper(self.package_name)
            
            if not drozer_helper.start_drozer():
                self.console.print("[yellow]⚠️ Could not start Drozer - limited dynamic analysis[/yellow]")
            
            # Run dynamic log analysis
            self.communicator.update_progress(ProcessType.DYNAMIC, 40, "Starting dynamic log analysis")
            
            self.console.print("🚀 Starting dynamic security analysis...")
            dynamic_results = run_dynamic_log_analysis(
                package_name=self.package_name,
                duration_seconds=180,
                enterprise_mode=True
            )
            
            # Monitor progress during dynamic analysis
            for i in range(18):  # 180 seconds / 10 second intervals
                if self.communicator.is_shutdown_requested():
                    break
                
                progress = 40 + (i / 18) * 50
                elapsed_time = i * 10
                self.communicator.update_progress(
                    ProcessType.DYNAMIC, progress, 
                    f"Dynamic analysis running... ({elapsed_time}s)"
                )
                time.sleep(10)
            
            # Store results
            self.communicator.store_results(ProcessType.DYNAMIC, {
                'dynamic_results': dynamic_results,
                'drozer_available': drozer_helper is not None,
                'analysis_time': time.time() - self.communicator.shared_state['start_time']
            })
            
            self.communicator.update_progress(ProcessType.DYNAMIC, 100, "Dynamic analysis completed")
            self.communicator.update_status(ProcessType.DYNAMIC, ProcessStatus.COMPLETED)
            
            self.console.print("[bold blue]✅ Dynamic Analysis Completed Successfully[/bold blue]")
            
        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}")
            self.communicator.update_status(ProcessType.DYNAMIC, ProcessStatus.FAILED)
            self.console.print(f"[bold red]❌ Dynamic analysis failed: {e}[/bold red]")
    
    def _check_device_availability(self) -> bool:
        """Check if Android device is available for dynamic analysis."""
        try:
            result = subprocess.run(
                ['adb', 'devices'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                devices = [line for line in result.stdout.split('\n') 
                          if 'device' in line and line.strip()]
                return len(devices) > 0
            return False
            
        except Exception:
            return False

class ParallelExecutionManager:
    """Main manager for parallel static and dynamic analysis execution."""
    
    def __init__(self, apk_path: str, package_name: str):
        self.apk_path = apk_path
        self.package_name = package_name
        self.communicator = InterProcessCommunicator()
        self.window_manager = WindowManager()
        self.console = Console()
        
        self.processes: Dict[ProcessType, mp.Process] = {}
        self.process_info: Dict[ProcessType, ProcessInfo] = {}
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.console.print("\n[yellow]⚠️ Shutdown signal received - cleaning up...[/yellow]")
        self.shutdown()
    
    def start_parallel_analysis(self, open_windows: bool = True) -> AnalysisResults:
        """Start parallel static and dynamic analysis."""
        self.console.print("[bold]🚀 Starting Parallel AODS Analysis[/bold]")
        self.console.print(f"APK: {self.apk_path}")
        self.console.print(f"Package: {self.package_name}")
        self.console.print("-" * 60)
        
        try:
            # Start static analysis process
            static_process = mp.Process(
                target=self._run_static_analysis,
                name="AODS-Static"
            )
            static_process.start()
            self.processes[ProcessType.STATIC] = static_process
            
            # Start dynamic analysis process
            dynamic_process = mp.Process(
                target=self._run_dynamic_analysis,
                name="AODS-Dynamic"
            )
            dynamic_process.start()
            self.processes[ProcessType.DYNAMIC] = dynamic_process
            
            # Open separate windows if requested
            if open_windows:
                self._open_analysis_windows()
            
            # Monitor progress
            self._monitor_progress()
            
            # Wait for completion
            self._wait_for_completion()
            
            # Get combined results
            results = self.communicator.get_results()
            
            self.console.print("[bold green]✅ Parallel Analysis Completed[/bold green]")
            return results
            
        except Exception as e:
            self.console.print(f"[bold red]❌ Parallel analysis failed: {e}[/bold red]")
            raise
        finally:
            self.cleanup()
    
    def _run_static_analysis(self):
        """Run static analysis in separate process."""
        static_analyzer = StaticAnalysisProcess(
            self.communicator, self.apk_path, self.package_name
        )
        static_analyzer.run()
    
    def _run_dynamic_analysis(self):
        """Run dynamic analysis in separate process."""
        dynamic_analyzer = DynamicAnalysisProcess(
            self.communicator, self.apk_path, self.package_name
        )
        dynamic_analyzer.run()
    
    def _open_analysis_windows(self):
        """Open separate windows for each analysis process."""
        python_exe = sys.executable
        script_path = __file__
        
        # Static analysis window
        static_cmd = [
            python_exe, '-c',
            f"""
import sys
sys.path.append('{os.path.dirname(os.path.abspath(__file__))}')
from {__name__} import StaticAnalysisProcess, InterProcessCommunicator
communicator = InterProcessCommunicator()
analyzer = StaticAnalysisProcess(communicator, '{self.apk_path}', '{self.package_name}')
analyzer.run()
"""
        ]
        
        # Dynamic analysis window
        dynamic_cmd = [
            python_exe, '-c',
            f"""
import sys
sys.path.append('{os.path.dirname(os.path.abspath(__file__))}')
from {__name__} import DynamicAnalysisProcess, InterProcessCommunicator
communicator = InterProcessCommunicator()
analyzer = DynamicAnalysisProcess(communicator, '{self.apk_path}', '{self.package_name}')
analyzer.run()
"""
        ]
        
        self.window_manager.open_window(
            "static", "AODS Static Analysis", static_cmd
        )
        self.window_manager.open_window(
            "dynamic", "AODS Dynamic Analysis", dynamic_cmd
        )
    
    def _monitor_progress(self):
        """Monitor progress of both analysis processes."""
        def progress_monitor():
            # Check for active Rich Live displays to prevent conflicts
            try:
                # Attempt to create live display with conflict detection
                with Live(self._generate_progress_display(), refresh_per_second=2) as live:
                    while not self._all_processes_completed():
                        if self.communicator.is_shutdown_requested():
                            break
                        live.update(self._generate_progress_display())
                        time.sleep(0.5)
            except RuntimeError as e:
                if "Only one live display may be active at once" in str(e):
                    # Fallback execution without live display when conflict detected
                    self.logger.warning("Rich Live display conflict detected - using fallback execution without live display")
                    self._monitor_progress_fallback()
                else:
                    # Re-raise other RuntimeErrors
                    raise
            except Exception as e:
                # Handle any other display-related errors gracefully
                self.logger.warning(f"Display error occurred, falling back to non-live progress monitoring: {e}")
                self._monitor_progress_fallback()
        
        monitor_thread = threading.Thread(target=progress_monitor, daemon=True)
        monitor_thread.start()
    
    def _monitor_progress_fallback(self):
        """Fallback progress monitoring without Rich Live display."""
        self.logger.info("Starting fallback progress monitoring (no live display)")
        while not self._all_processes_completed():
            if self.communicator.is_shutdown_requested():
                break
            # Log progress periodically instead of live display
            progress_status = self._get_progress_summary()
            if progress_status:
                self.logger.info(f"Progress: {progress_status}")
            time.sleep(2)  # Less frequent updates for fallback mode
    
    def _get_progress_summary(self) -> str:
        """Get a text summary of current progress for fallback logging."""
        try:
            static_progress = self.communicator.get_static_progress()
            dynamic_progress = self.communicator.get_dynamic_progress()
            return f"Static: {static_progress:.1f}%, Dynamic: {dynamic_progress:.1f}%"
        except Exception:
            return "Progress monitoring active"
    
    def _generate_progress_display(self) -> Panel:
        """Generate real-time progress display."""
        state = self.communicator.get_shared_state()
        
        table = Table.grid(padding=1)
        table.add_column(style="bold")
        table.add_column()
        table.add_column()
        
        # Static analysis progress
        static_progress = state.get('static_progress', 0)
        static_status = state.get('static_status', 'initializing')
        static_task = state.get('static_task', '')
        
        static_bar = "█" * int(static_progress / 5) + "░" * (20 - int(static_progress / 5))
        table.add_row(
            "🔍 Static:",
            f"[green]{static_bar}[/green] {static_progress:.1f}%",
            f"[dim]{static_task}[/dim]"
        )
        
        # Dynamic analysis progress
        dynamic_progress = state.get('dynamic_progress', 0)
        dynamic_status = state.get('dynamic_status', 'initializing')
        dynamic_task = state.get('dynamic_task', '')
        
        dynamic_bar = "█" * int(dynamic_progress / 5) + "░" * (20 - int(dynamic_progress / 5))
        table.add_row(
            "📱 Dynamic:",
            f"[blue]{dynamic_bar}[/blue] {dynamic_progress:.1f}%",
            f"[dim]{dynamic_task}[/dim]"
        )
        
        elapsed_time = time.time() - state.get('start_time', time.time())
        
        return Panel(
            table,
            title="[bold]AODS Parallel Analysis Progress[/bold]",
            subtitle=f"Elapsed: {elapsed_time:.1f}s",
            border_style="bright_blue"
        )
    
    def _all_processes_completed(self) -> bool:
        """Check if all processes have completed."""
        state = self.communicator.get_shared_state()
        static_done = state.get('static_status') in ['completed', 'failed']
        dynamic_done = state.get('dynamic_status') in ['completed', 'failed']
        return static_done and dynamic_done
    
    def _wait_for_completion(self):
        """Wait for all processes to complete."""
        for process_type, process in self.processes.items():
            try:
                process.join(timeout=600)  # 10 minute timeout
                if process.is_alive():
                    self.console.print(f"[yellow]⚠️ {process_type.value} process timeout - terminating[/yellow]")
                    process.terminate()
                    process.join(timeout=5)
                    if process.is_alive():
                        process.kill()
            except Exception as e:
                self.console.print(f"[red]Error waiting for {process_type.value} process: {e}[/red]")
    
    def shutdown(self):
        """Shutdown all processes and cleanup."""
        self.communicator.signal_shutdown()
        
        # Terminate processes
        for process_type, process in self.processes.items():
            if process.is_alive():
                try:
                    process.terminate()
                    process.join(timeout=5)
                    if process.is_alive():
                        process.kill()
                except Exception as e:
                    logger.error(f"Error terminating {process_type.value} process: {e}")
        
        self.cleanup()
    
    def cleanup(self):
        """Cleanup resources."""
        self.window_manager.close_all_windows()
        
        # Clean up processes
        for process in self.processes.values():
            if process.is_alive():
                try:
                    process.terminate()
                    process.join(timeout=2)
                except Exception:
                    pass

def run_parallel_analysis(apk_path: str, package_name: str, open_windows: bool = True):
    """
    Interface function for legacy compatibility with dyna.py
    This provides the expected run_parallel_analysis function.
    """
    try:
        manager = ParallelExecutionManager(
            apk_path=apk_path,
            package_name=package_name
        )
        return manager.start_parallel_analysis(open_windows=open_windows)
    except Exception as e:
        logger.error(f"Parallel analysis failed: {e}")
        return None

def main():
    """Main entry point for testing parallel execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description="AODS Parallel Analysis Manager")
    parser.add_argument("--apk", required=True, help="Path to APK file")
    parser.add_argument("--pkg", required=True, help="Package name")
    parser.add_argument("--no-windows", action="store_true", 
                       help="Don't open separate windows")
    
    args = parser.parse_args()
    
    try:
        results = run_parallel_analysis(
            args.apk, args.pkg, open_windows=not args.no_windows
        )
        
        console = Console()
        console.print("[bold green]Analysis completed successfully![/bold green]")
        
        if results.static_results:
            console.print("✅ Static analysis completed")
        if results.dynamic_results:
            console.print("✅ Dynamic analysis completed")
            
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
    except Exception as e:
        print(f"Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
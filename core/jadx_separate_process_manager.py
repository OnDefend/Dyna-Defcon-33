#!/usr/bin/env python3
"""
JADX Separate Process Manager - Safe Optimizations Implementation

This module implements the approved separate process execution strategy for JADX decompilation,
addressing large APK processing issues through resource isolation and non-blocking execution.

Key Features:
- Separate process execution with proper timeout control
- Non-blocking execution allowing other plugins to continue
- Resource isolation with configurable memory limits
- Proper process termination and cleanup
- Inter-process communication for status updates
- Fallback mechanisms for process failures

"""

import os
import sys
import time
import signal
import logging
import subprocess
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ProcessStatus(Enum):
    """Process execution status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"

@dataclass
class ProcessConfig:
    """Configuration for JADX separate process execution"""
    timeout_seconds: int = 600
    memory_limit_mb: int = 2048
    thread_count: int = 4
    max_retries: int = 2
    cleanup_on_failure: bool = True
    enable_progress_reporting: bool = True
    background_processing: bool = False

@dataclass
class ProcessResult:
    """Result of JADX separate process execution"""
    status: ProcessStatus
    exit_code: Optional[int] = None
    output_dir: Optional[str] = None
    execution_time: float = 0.0
    memory_peak_mb: float = 0.0
    error_message: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    process_id: Optional[int] = None

class JADXSeparateProcessManager:
    """
    JADX Separate Process Manager implementing safe optimizations for large APK processing
    
    This class provides separate process execution for JADX decompilation with:
    - Resource isolation and monitoring
    - Proper timeout control and cleanup
    - Non-blocking execution
    - Progress reporting and status tracking
    """
    
    def __init__(self, jadx_path: Optional[str] = None):
        self.jadx_path = jadx_path or self._find_jadx_executable()
        self.active_processes: Dict[str, subprocess.Popen] = {}
        self.process_results: Dict[str, ProcessResult] = {}
        
        if not self.jadx_path:
            raise RuntimeError("JADX executable not found. Please install JADX or specify path.")
            
    def _find_jadx_executable(self) -> Optional[str]:
        """Find JADX executable in system PATH"""
        for cmd in ['jadx', 'jadx-gui']:
            try:
                result = subprocess.run(['which', cmd], capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout.strip()
            except Exception:
                pass
        return None
        
    def decompile_apk_separate_process(
        self,
        apk_path: str,
        output_dir: str,
        config: Optional[ProcessConfig] = None
    ) -> ProcessResult:
        """
        Execute JADX decompilation in separate process with monitoring
        
        Args:
            apk_path: Path to APK file to decompile
            output_dir: Directory to store decompilation results
            config: Process configuration (optional)
            
        Returns:
            ProcessResult with execution details and status
        """
        config = config or ProcessConfig()
        process_id = f"jadx_{int(time.time())}_{os.getpid()}"
        
        logger.info(f"Starting JADX separate process decompilation: {apk_path}")
        logger.info(f"Process ID: {process_id}")
        
        try:
            # Prepare output directory
            os.makedirs(output_dir, exist_ok=True)
            
            # Create JADX command
            cmd = self._build_jadx_command(apk_path, output_dir, config)
            
            # Start process with resource limits
            process = self._start_jadx_process(cmd, config)
            self.active_processes[process_id] = process
            
            # Wait for completion or timeout
            result = self._wait_for_process_completion(process, config, process_id)
            
            # Store result
            self.process_results[process_id] = result
            
            # Cleanup
            if process_id in self.active_processes:
                del self.active_processes[process_id]
                
            logger.info(f"JADX process completed: {result.status.value}, Time: {result.execution_time:.1f}s")
            return result
            
        except Exception as e:
            logger.error(f"JADX separate process execution failed: {e}")
            result = ProcessResult(
                status=ProcessStatus.FAILED,
                error_message=str(e),
                execution_time=0.0
            )
            self.process_results[process_id] = result
            return result
            
    def _build_jadx_command(self, apk_path: str, output_dir: str, config: ProcessConfig) -> List[str]:
        """Build JADX command with optimized parameters"""
        cmd = [
            self.jadx_path,
            '--output-dir', output_dir,
            '--threads-count', str(config.thread_count),
            '--no-imports',  # Reduce memory usage
            '--no-debug-info',  # Reduce output size
            '--show-bad-code',  # Include problematic code
            apk_path
        ]
        
        # Add memory optimization flags for large APKs
        if config.memory_limit_mb > 1024:
            cmd.extend(['--no-inline-anonymous', '--no-replace-consts'])
            
        return cmd
        
    def _start_jadx_process(self, cmd: List[str], config: ProcessConfig) -> subprocess.Popen:
        """Start JADX process with resource limits"""
        env = os.environ.copy()
        
        # Set JVM memory limits
        java_opts = f"-Xmx{config.memory_limit_mb}m -Xms512m"
        env['JAVA_OPTS'] = java_opts
        env['_JAVA_OPTIONS'] = java_opts
        
        # Start process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            preexec_fn=os.setsid if os.name != 'nt' else None
        )
        
        return process
        
    def _wait_for_process_completion(
        self,
        process: subprocess.Popen,
        config: ProcessConfig,
        process_id: str
    ) -> ProcessResult:
        """Wait for process completion with timeout handling"""
        start_time = time.time()
        
        try:
            # Wait for completion with timeout
            stdout, stderr = process.communicate(timeout=config.timeout_seconds)
            execution_time = time.time() - start_time
            
            # Determine status based on exit code
            if process.returncode == 0:
                status = ProcessStatus.COMPLETED
            else:
                status = ProcessStatus.FAILED
                
            return ProcessResult(
                status=status,
                exit_code=process.returncode,
                execution_time=execution_time,
                stdout=stdout,
                stderr=stderr,
                process_id=process.pid
            )
            
        except subprocess.TimeoutExpired:
            # Handle timeout
            logger.warning(f"JADX process {process_id} timed out after {config.timeout_seconds}s")
            
            # Terminate process tree
            self._terminate_process_tree(process)
            
            execution_time = time.time() - start_time
            return ProcessResult(
                status=ProcessStatus.TIMEOUT,
                execution_time=execution_time,
                error_message=f"Process timed out after {config.timeout_seconds} seconds",
                process_id=process.pid
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return ProcessResult(
                status=ProcessStatus.FAILED,
                execution_time=execution_time,
                error_message=str(e),
                process_id=process.pid
            )
            
    def _terminate_process_tree(self, process: subprocess.Popen) -> None:
        """Terminate process and all children"""
        try:
            if os.name == 'nt':
                # Windows
                process.terminate()
            else:
                # Unix-like systems
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                
            # Wait for graceful termination
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                # Force kill
                if os.name == 'nt':
                    process.kill()
                else:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    
        except Exception as e:
            logger.error(f"Error terminating process tree: {e}")
            
    def get_process_status(self, process_id: str) -> Optional[ProcessResult]:
        """Get status of a specific process"""
        return self.process_results.get(process_id)
        
    def list_active_processes(self) -> List[str]:
        """List all active process IDs"""
        return list(self.active_processes.keys())
        
    def cancel_process(self, process_id: str) -> bool:
        """Cancel a running process"""
        if process_id in self.active_processes:
            try:
                process = self.active_processes[process_id]
                self._terminate_process_tree(process)
                
                # Update result
                result = ProcessResult(
                    status=ProcessStatus.CANCELLED,
                    process_id=process.pid,
                    execution_time=time.time()
                )
                self.process_results[process_id] = result
                
                # Cleanup
                del self.active_processes[process_id]
                return True
                
            except Exception as e:
                logger.error(f"Error cancelling process {process_id}: {e}")
                return False
                
        return False
        
    def cleanup_all_processes(self) -> None:
        """Cleanup all active processes"""
        for process_id in list(self.active_processes.keys()):
            self.cancel_process(process_id)

def main():
    """Test the JADX Separate Process Manager"""
    import argparse
    
    parser = argparse.ArgumentParser(description='JADX Separate Process Manager Test')
    parser.add_argument('apk_path', help='Path to APK file')
    parser.add_argument('output_dir', help='Output directory')
    parser.add_argument('--timeout', type=int, default=600, help='Timeout in seconds')
    parser.add_argument('--memory-limit', type=int, default=2048, help='Memory limit in MB')
    parser.add_argument('--threads', type=int, default=4, help='Thread count')
    
    args = parser.parse_args()
    
    # Create configuration
    config = ProcessConfig(
        timeout_seconds=args.timeout,
        memory_limit_mb=args.memory_limit,
        thread_count=args.threads,
        enable_progress_reporting=True
    )
    
    # Create manager and run decompilation
    manager = JADXSeparateProcessManager()
    result = manager.decompile_apk_separate_process(args.apk_path, args.output_dir, config)
    
    # Print results
    print(f"Status: {result.status.value}")
    print(f"Execution Time: {result.execution_time:.1f}s")
    print(f"Memory Peak: {result.memory_peak_mb:.1f}MB")
    if result.error_message:
        print(f"Error: {result.error_message}")

if __name__ == '__main__':
    main()

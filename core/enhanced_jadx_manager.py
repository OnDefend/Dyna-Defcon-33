#!/usr/bin/env python3
"""
Enhanced JADX Manager for Error 8 Resolution

This module provides improved JADX decompilation capabilities with:
- Adaptive timeout management based on APK size and system resources
- Intelligent memory management with JVM heap sizing
- Multi-tier fallback analysis strategies
- Robust error recovery and progress monitoring
- Resource-aware processing for large APKs

Addresses Error 8: JADX Static Analysis Decompilation Failures
"""

import os
import sys
import time
import logging
import psutil
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import threading
import signal
from datetime import datetime

logger = logging.getLogger(__name__)

class ProcessingStrategy(Enum):
    """JADX processing strategies based on APK characteristics."""
    FAST = "fast"              # Small APKs (<50MB), quick processing
    BALANCED = "balanced"      # Medium APKs (50-200MB), balanced approach
    MEMORY_OPTIMIZED = "memory_optimized"  # Large APKs (200-500MB), memory conservation
    ULTRA_CONSERVATIVE = "ultra_conservative"  # Very large APKs (>500MB), maximum safety

class DecompilationResult(Enum):
    """Decompilation result states."""
    SUCCESS = "success"
    TIMEOUT = "timeout"
    MEMORY_ERROR = "memory_error"
    PROCESS_ERROR = "process_error"
    FALLBACK_SUCCESS = "fallback_success"
    COMPLETE_FAILURE = "complete_failure"

@dataclass
class SystemResources:
    """Current system resource information."""
    total_memory_gb: float
    available_memory_gb: float
    cpu_count: int
    memory_pressure: float  # 0.0-1.0, higher means more pressure
    disk_space_gb: float
    
    @classmethod
    def detect_current(cls) -> 'SystemResources':
        """Detect current system resources."""
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        total_memory_gb = memory.total / (1024**3)
        available_memory_gb = memory.available / (1024**3)
        memory_pressure = 1.0 - (available_memory_gb / total_memory_gb)
        
        return cls(
            total_memory_gb=total_memory_gb,
            available_memory_gb=available_memory_gb,
            cpu_count=os.cpu_count(),
            memory_pressure=memory_pressure,
            disk_space_gb=disk.free / (1024**3)
        )

@dataclass
class APKCharacteristics:
    """APK file characteristics for processing optimization."""
    size_mb: float
    complexity_score: float = 0.0  # 0.0-1.0, higher means more complex
    has_native_code: bool = False
    is_obfuscated: bool = False
    dex_count: int = 1
    
    @classmethod
    def analyze_apk(cls, apk_path: str) -> 'APKCharacteristics':
        """Analyze APK characteristics."""
        try:
            size_mb = os.path.getsize(apk_path) / (1024 * 1024)
            
            # Basic complexity estimation based on size
            if size_mb > 500:
                complexity_score = 0.9
            elif size_mb > 200:
                complexity_score = 0.7
            elif size_mb > 50:
                complexity_score = 0.5
            else:
                complexity_score = 0.3
            
            # Enhanced APK analysis: DEX count, native libraries, obfuscation detection
            dex_count = 1
            has_native_code = False
            is_obfuscated = False
            
            try:
                import zipfile
                
                with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                    file_list = apk_zip.namelist()
                    
                    # Count DEX files
                    dex_files = [f for f in file_list if f.startswith('classes') and f.endswith('.dex')]
                    dex_count = max(len(dex_files), 1)  # At least 1 DEX file
                    
                    # Detect native libraries
                    native_libs = [f for f in file_list if f.startswith('lib/') and f.endswith('.so')]
                    has_native_code = len(native_libs) > 0
                    
                    # Basic obfuscation detection (heuristics)
                    java_files = [f for f in file_list if f.endswith('.java') or 'classes.dex' in f]
                    
                    # Check for signs of obfuscation
                    obfuscation_indicators = 0
                    
                    # Indicator 1: High DEX count (multidex can indicate complexity/obfuscation)
                    if dex_count > 3:
                        obfuscation_indicators += 1
                    
                    # Indicator 2: Presence of native libraries (can hide logic)
                    if has_native_code:
                        obfuscation_indicators += 1
                    
                    # Indicator 3: Check for common obfuscation patterns in file names
                    short_names = [f for f in file_list if len(os.path.basename(f)) <= 2 and '.' in f]
                    if len(short_names) > 5:  # Many single-character filenames
                        obfuscation_indicators += 1
                    
                    # Indicator 4: Large number of small files (code splitting)
                    small_files = [f for f in file_list if apk_zip.getinfo(f).file_size < 1024]
                    if len(small_files) > len(file_list) * 0.3:  # More than 30% are small files
                        obfuscation_indicators += 1
                    
                    is_obfuscated = obfuscation_indicators >= 2
                    
            except Exception as e:
                logger.debug(f"Enhanced APK analysis failed, using basic analysis: {e}")
            
            # Adjust complexity score based on enhanced analysis
            enhanced_complexity = complexity_score
            
            # DEX count contribution (more DEX files = more complex)
            if dex_count > 1:
                enhanced_complexity += min(0.1 * (dex_count - 1), 0.2)  # Up to +0.2
            
            # Native code contribution (JNI complexity)
            if has_native_code:
                enhanced_complexity += 0.15
            
            # Obfuscation contribution (reverse engineering complexity)
            if is_obfuscated:
                enhanced_complexity += 0.2
            
            # Cap complexity score at 1.0
            enhanced_complexity = min(enhanced_complexity, 1.0)
            
            logger.debug(f"APK analysis: size={size_mb:.1f}MB, dex_count={dex_count}, "
                        f"native={has_native_code}, obfuscated={is_obfuscated}, "
                        f"complexity={enhanced_complexity:.2f}")
            
            return cls(
                size_mb=size_mb,
                complexity_score=enhanced_complexity,
                has_native_code=has_native_code,
                is_obfuscated=is_obfuscated,
                dex_count=dex_count
            )
        except Exception as e:
            logger.warning(f"Failed to analyze APK characteristics: {e}")
            return cls(size_mb=0.0)

@dataclass
class ProcessingConfiguration:
    """Configuration for JADX processing."""
    strategy: ProcessingStrategy
    timeout_seconds: int
    memory_limit_gb: float
    thread_count: int
    jadx_options: List[str]
    retry_attempts: int = 2
    enable_fallback: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            'strategy': self.strategy.value,
            'timeout_seconds': self.timeout_seconds,
            'memory_limit_gb': self.memory_limit_gb,
            'thread_count': self.thread_count,
            'retry_attempts': self.retry_attempts,
            'enable_fallback': self.enable_fallback,
            'jadx_options_count': len(self.jadx_options)
        }

@dataclass
class DecompilationReport:
    """Comprehensive decompilation report."""
    result: DecompilationResult
    execution_time: float
    memory_peak_mb: float
    output_directory: Optional[str] = None
    files_extracted: int = 0
    java_files: int = 0
    kotlin_files: int = 0
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    strategy_used: Optional[ProcessingStrategy] = None
    fallback_used: bool = False

class EnhancedJADXManager:
    """
    Enhanced JADX manager with intelligent processing strategies.
    
    Features:
    - Adaptive timeout and memory management
    - Multi-tier fallback analysis
    - Resource monitoring and optimization
    - Intelligent strategy selection
    """
    
    def __init__(self, base_output_dir: Optional[str] = None):
        """Initialize enhanced JADX manager."""
        self.base_output_dir = Path(base_output_dir) if base_output_dir else Path(tempfile.gettempdir()) / "enhanced_jadx"
        self.base_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Find JADX executable
        self.jadx_executable = self._find_jadx_executable()
        if not self.jadx_executable:
            raise RuntimeError("JADX executable not found. Please install JADX.")
        
        # Resource management
        self.system_resources = SystemResources.detect_current()
        self.active_processes: Dict[str, subprocess.Popen] = {}
        self.processing_history: List[DecompilationReport] = []
        
        # Safety limits
        self.max_concurrent_jobs = min(self.system_resources.cpu_count // 2, 3)
        self.memory_safety_threshold = 0.8  # Don't use more than 80% of available memory
        
        logger.info(f"Enhanced JADX Manager initialized")
        logger.info(f"System resources: {self.system_resources.available_memory_gb:.1f}GB memory, {self.system_resources.cpu_count} CPUs")
        logger.info(f"JADX executable: {self.jadx_executable}")
    
    def _find_jadx_executable(self) -> Optional[str]:
        """Find JADX executable in system PATH."""
        candidates = [
            "jadx",
            "/usr/bin/jadx", 
            "/usr/local/bin/jadx",
            "/opt/jadx/bin/jadx",
            "jadx-cli",
            "/usr/bin/jadx-cli"
        ]
        
        for candidate in candidates:
            if shutil.which(candidate):
                logger.info(f"Found JADX executable: {candidate}")
                return candidate
        
        logger.error("JADX executable not found in system PATH")
        return None
    
    def _determine_processing_strategy(self, apk_chars: APKCharacteristics) -> ProcessingConfiguration:
        """Determine optimal processing strategy based on APK and system characteristics."""
        
        # Refresh system resources
        current_resources = SystemResources.detect_current()
        
        # Strategy selection logic
        if apk_chars.size_mb > 500 or current_resources.memory_pressure > 0.7:
            strategy = ProcessingStrategy.ULTRA_CONSERVATIVE
            timeout = 1200  # 20 minutes
            memory_limit = min(2.0, current_resources.available_memory_gb * 0.4)
            threads = 1
            jadx_options = [
                "--no-res", "--no-imports", "--no-debug-info", 
                "--no-inline-anonymous", "--classes-only", "--no-replace-consts"
            ]
        elif apk_chars.size_mb > 200 or current_resources.memory_pressure > 0.5:
            strategy = ProcessingStrategy.MEMORY_OPTIMIZED
            timeout = 900  # 15 minutes
            memory_limit = min(4.0, current_resources.available_memory_gb * 0.5)
            threads = min(2, current_resources.cpu_count // 4)
            jadx_options = [
                "--no-res", "--no-imports", "--no-debug-info", "--no-inline-anonymous"
            ]
        elif apk_chars.size_mb > 50:
            strategy = ProcessingStrategy.BALANCED
            timeout = 600  # 10 minutes
            memory_limit = min(6.0, current_resources.available_memory_gb * 0.6)
            threads = min(4, current_resources.cpu_count // 2)
            jadx_options = ["--no-res", "--no-imports"]
        else:
            strategy = ProcessingStrategy.FAST
            timeout = 300  # 5 minutes
            memory_limit = min(8.0, current_resources.available_memory_gb * 0.7)
            threads = min(6, current_resources.cpu_count)
            jadx_options = ["--no-res"]
        
        return ProcessingConfiguration(
            strategy=strategy,
            timeout_seconds=timeout,
            memory_limit_gb=memory_limit,
            thread_count=threads,
            jadx_options=jadx_options
        )
    
    def decompile_apk(self, apk_path: str, output_dir: Optional[str] = None) -> DecompilationReport:
        """
        Decompile APK with enhanced error handling and fallback strategies.
        
        Args:
            apk_path: Path to APK file
            output_dir: Optional output directory (auto-generated if not provided)
            
        Returns:
            Comprehensive decompilation report
        """
        start_time = time.time()
        apk_path = os.path.abspath(apk_path)
        
        if not os.path.exists(apk_path):
            return DecompilationReport(
                result=DecompilationResult.COMPLETE_FAILURE,
                execution_time=0.0,
                memory_peak_mb=0.0,
                error_message=f"APK file not found: {apk_path}"
            )
        
        # Analyze APK characteristics
        apk_chars = APKCharacteristics.analyze_apk(apk_path)
        logger.info(f"APK characteristics: {apk_chars.size_mb:.1f}MB, complexity: {apk_chars.complexity_score:.2f}")
        
        # Determine processing strategy
        config = self._determine_processing_strategy(apk_chars)
        logger.info(f"Processing strategy: {config.strategy.value}")
        logger.info(f"Configuration: {config.to_dict()}")
        
        # Prepare output directory
        if not output_dir:
            output_dir = str(self.base_output_dir / f"jadx_{int(time.time())}")
        os.makedirs(output_dir, exist_ok=True)
        
        # Primary decompilation attempt
        report = self._attempt_decompilation(apk_path, output_dir, config)
        
        # Fallback strategies if primary attempt failed
        if report.result != DecompilationResult.SUCCESS and config.enable_fallback:
            logger.warning(f"Primary decompilation failed: {report.result.value}. Attempting fallback strategies.")
            report = self._attempt_fallback_strategies(apk_path, output_dir, config, report)
        
        # Record processing history
        self.processing_history.append(report)
        
        # Log final result
        final_time = time.time() - start_time
        report.execution_time = final_time
        
        if report.result in [DecompilationResult.SUCCESS, DecompilationResult.FALLBACK_SUCCESS]:
            logger.info(f"✅ Decompilation completed: {report.result.value} in {final_time:.1f}s")
            logger.info(f"📊 Extracted {report.files_extracted} files ({report.java_files} Java, {report.kotlin_files} Kotlin)")
        else:
            logger.error(f"❌ Decompilation failed: {report.result.value} after {final_time:.1f}s")
            if report.error_message:
                logger.error(f"Error details: {report.error_message}")
        
        return report
    
    def _attempt_decompilation(self, apk_path: str, output_dir: str, config: ProcessingConfiguration) -> DecompilationReport:
        """Attempt decompilation with specified configuration."""
        
        # Build JADX command
        cmd = self._build_jadx_command(apk_path, output_dir, config)
        
        # Set up environment with memory limits
        env = os.environ.copy()
        heap_size_mb = int(config.memory_limit_gb * 1024 * 0.8)  # 80% of limit for heap
        env['JAVA_OPTS'] = f"-Xmx{heap_size_mb}m -Xms512m"
        env['_JAVA_OPTIONS'] = f"-Xmx{heap_size_mb}m -Xms512m"
        
        process_start_time = time.time()
        peak_memory_mb = 0.0
        
        try:
            # Start JADX process
            logger.info(f"Starting JADX process with {config.timeout_seconds}s timeout")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            process_id = str(process.pid)
            self.active_processes[process_id] = process
            
            # Monitor process with timeout
            try:
                stdout, stderr = process.communicate(timeout=config.timeout_seconds)
                
                # Monitor peak memory usage
                try:
                    if process.pid:
                        proc = psutil.Process(process.pid)
                        peak_memory_mb = proc.memory_info().rss / (1024 * 1024)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                # Check result
                if process.returncode == 0:
                    # Count extracted files
                    file_counts = self._count_extracted_files(output_dir)
                    
                    return DecompilationReport(
                        result=DecompilationResult.SUCCESS,
                        execution_time=time.time() - process_start_time,
                        memory_peak_mb=peak_memory_mb,
                        output_directory=output_dir,
                        files_extracted=file_counts['total'],
                        java_files=file_counts['java'],
                        kotlin_files=file_counts['kotlin'],
                        strategy_used=config.strategy,
                        warnings=[stderr] if stderr else []
                    )
                else:
                    return DecompilationReport(
                        result=DecompilationResult.PROCESS_ERROR,
                        execution_time=time.time() - process_start_time,
                        memory_peak_mb=peak_memory_mb,
                        error_message=f"JADX process failed with code {process.returncode}: {stderr}",
                        strategy_used=config.strategy
                    )
                    
            except subprocess.TimeoutExpired:
                # Handle timeout
                logger.warning(f"JADX process timed out after {config.timeout_seconds}s")
                
                # Terminate process
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    process.wait(timeout=10)
                except (subprocess.TimeoutExpired, ProcessLookupError):
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                
                return DecompilationReport(
                    result=DecompilationResult.TIMEOUT,
                    execution_time=time.time() - process_start_time,
                    memory_peak_mb=peak_memory_mb,
                    error_message=f"Process timed out after {config.timeout_seconds}s",
                    strategy_used=config.strategy
                )
                
        except MemoryError:
            return DecompilationReport(
                result=DecompilationResult.MEMORY_ERROR,
                execution_time=time.time() - process_start_time,
                memory_peak_mb=peak_memory_mb,
                error_message="Memory error during decompilation",
                strategy_used=config.strategy
            )
        except Exception as e:
            return DecompilationReport(
                result=DecompilationResult.PROCESS_ERROR,
                execution_time=time.time() - process_start_time,
                memory_peak_mb=peak_memory_mb,
                error_message=f"Unexpected error: {str(e)}",
                strategy_used=config.strategy
            )
        finally:
            # Cleanup
            if process_id in self.active_processes:
                del self.active_processes[process_id]
    
    def _attempt_fallback_strategies(self, apk_path: str, output_dir: str, 
                                   original_config: ProcessingConfiguration,
                                   original_report: DecompilationReport) -> DecompilationReport:
        """Attempt fallback strategies for failed decompilation."""
        
        logger.info("Attempting fallback strategies...")
        
        # Strategy 1: Ultra-conservative settings
        if original_config.strategy != ProcessingStrategy.ULTRA_CONSERVATIVE:
            logger.info("Fallback 1: Ultra-conservative settings")
            
            fallback_config = ProcessingConfiguration(
                strategy=ProcessingStrategy.ULTRA_CONSERVATIVE,
                timeout_seconds=600,  # 10 minutes
                memory_limit_gb=min(1.5, self.system_resources.available_memory_gb * 0.3),
                thread_count=1,
                jadx_options=["--no-res", "--no-imports", "--no-debug-info", "--classes-only"],
                enable_fallback=False
            )
            
            fallback_output = output_dir + "_fallback1"
            os.makedirs(fallback_output, exist_ok=True)
            
            report = self._attempt_decompilation(apk_path, fallback_output, fallback_config)
            if report.result == DecompilationResult.SUCCESS:
                report.result = DecompilationResult.FALLBACK_SUCCESS
                report.fallback_used = True
                report.output_directory = fallback_output
                return report
        
        # Strategy 2: Structure-only analysis (no source code)
        logger.info("Fallback 2: Structure-only analysis")
        structure_report = self._extract_apk_structure(apk_path, output_dir + "_structure")
        if structure_report.result == DecompilationResult.SUCCESS:
            structure_report.result = DecompilationResult.FALLBACK_SUCCESS
            structure_report.fallback_used = True
            return structure_report
        
        # Strategy 3: Minimal extraction (metadata only)
        logger.info("Fallback 3: Minimal extraction")
        minimal_report = self._extract_minimal_info(apk_path, output_dir + "_minimal")
        if minimal_report.result == DecompilationResult.SUCCESS:
            minimal_report.result = DecompilationResult.FALLBACK_SUCCESS
            minimal_report.fallback_used = True
            return minimal_report
        
        # If all fallbacks failed, return original report
        logger.error("All fallback strategies failed")
        original_report.result = DecompilationResult.COMPLETE_FAILURE
        return original_report
    
    def _build_jadx_command(self, apk_path: str, output_dir: str, config: ProcessingConfiguration) -> List[str]:
        """Build JADX command with specified configuration."""
        cmd = [
            self.jadx_executable,
            "--output-dir", output_dir,
            "--threads-count", str(config.thread_count)
        ]
        
        # Add configuration-specific options
        cmd.extend(config.jadx_options)
        
        # Add APK path
        cmd.append(apk_path)
        
        return cmd
    
    def _count_extracted_files(self, directory: str) -> Dict[str, int]:
        """Count extracted files by type."""
        counts = {'total': 0, 'java': 0, 'kotlin': 0, 'xml': 0}
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    counts['total'] += 1
                    if file.endswith('.java'):
                        counts['java'] += 1
                    elif file.endswith('.kt'):
                        counts['kotlin'] += 1
                    elif file.endswith('.xml'):
                        counts['xml'] += 1
        except Exception as e:
            logger.warning(f"Failed to count extracted files: {e}")
        
        return counts
    
    def _extract_apk_structure(self, apk_path: str, output_dir: str) -> DecompilationReport:
        """Extract APK structure without full decompilation."""
        start_time = time.time()
        
        try:
            import zipfile
            
            os.makedirs(output_dir, exist_ok=True)
            
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                # Extract only essential files
                essential_files = [
                    'AndroidManifest.xml',
                    'META-INF/',
                    'resources.arsc'
                ]
                
                extracted_count = 0
                for file_name in zip_ref.namelist():
                    if any(file_name.startswith(essential) for essential in essential_files):
                        zip_ref.extract(file_name, output_dir)
                        extracted_count += 1
            
            return DecompilationReport(
                result=DecompilationResult.SUCCESS,
                execution_time=time.time() - start_time,
                memory_peak_mb=0.0,
                output_directory=output_dir,
                files_extracted=extracted_count,
                strategy_used=ProcessingStrategy.ULTRA_CONSERVATIVE
            )
            
        except Exception as e:
            return DecompilationReport(
                result=DecompilationResult.PROCESS_ERROR,
                execution_time=time.time() - start_time,
                memory_peak_mb=0.0,
                error_message=f"Structure extraction failed: {str(e)}"
            )
    
    def _extract_minimal_info(self, apk_path: str, output_dir: str) -> DecompilationReport:
        """Extract minimal APK information."""
        start_time = time.time()
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            # Create basic info file
            info_file = os.path.join(output_dir, "apk_info.txt")
            with open(info_file, 'w') as f:
                f.write(f"APK Path: {apk_path}\n")
                f.write(f"File Size: {os.path.getsize(apk_path)} bytes\n")
                f.write(f"Analysis Time: {datetime.now().isoformat()}\n")
                f.write("Note: Full decompilation failed, minimal extraction performed\n")
            
            return DecompilationReport(
                result=DecompilationResult.SUCCESS,
                execution_time=time.time() - start_time,
                memory_peak_mb=0.0,
                output_directory=output_dir,
                files_extracted=1,
                strategy_used=ProcessingStrategy.ULTRA_CONSERVATIVE
            )
            
        except Exception as e:
            return DecompilationReport(
                result=DecompilationResult.PROCESS_ERROR,
                execution_time=time.time() - start_time,
                memory_peak_mb=0.0,
                error_message=f"Minimal extraction failed: {str(e)}"
            )
    
    def get_processing_statistics(self) -> Dict[str, Any]:
        """Get processing statistics from history."""
        if not self.processing_history:
            return {"total_processed": 0}
        
        total = len(self.processing_history)
        successful = sum(1 for r in self.processing_history 
                        if r.result in [DecompilationResult.SUCCESS, DecompilationResult.FALLBACK_SUCCESS])
        
        avg_time = sum(r.execution_time for r in self.processing_history) / total
        avg_memory = sum(r.memory_peak_mb for r in self.processing_history) / total
        
        strategy_counts = {}
        for report in self.processing_history:
            if report.strategy_used:
                strategy = report.strategy_used.value
                strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1
        
        return {
            "total_processed": total,
            "success_rate": successful / total,
            "average_time_seconds": avg_time,
            "average_memory_mb": avg_memory,
            "strategy_distribution": strategy_counts,
            "fallback_usage_rate": sum(1 for r in self.processing_history if r.fallback_used) / total
        }

# Factory function for global access
_global_jadx_manager = None

def get_enhanced_jadx_manager() -> EnhancedJADXManager:
    """Get global enhanced JADX manager instance."""
    global _global_jadx_manager
    if _global_jadx_manager is None:
        _global_jadx_manager = EnhancedJADXManager()
    return _global_jadx_manager 
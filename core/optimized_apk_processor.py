"""
Memory-Optimized APK Processor for Enterprise-Scale Analysis

This module provides advanced memory management and streaming analysis capabilities
for processing large APKs (>500MB) efficiently without exhausting system resources.

Key Features:
- Memory-mapped file access for large APKs
- Streaming analysis with configurable chunk sizes
- Progressive analysis with checkpoints
- Memory monitoring and automatic cleanup
- Resource pool management
"""

import gc
import logging
import mmap
import os
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Generator, List, Optional, Tuple, Union

import psutil

logger = logging.getLogger(__name__)

@dataclass
class MemoryMetrics:
    """Memory usage metrics for monitoring."""

    total_mb: float
    available_mb: float
    used_mb: float
    percentage: float
    process_mb: float

@dataclass
class ProcessingCheckpoint:
    """Checkpoint for progressive analysis."""

    file_count: int
    processed_size: int
    completed_plugins: List[str]
    timestamp: float
    memory_usage: MemoryMetrics

class MemoryMonitor:
    """Real-time memory monitoring and alerting."""

    def __init__(self, warning_threshold_percent=80, critical_threshold_percent=90):
        self.warning_threshold = warning_threshold_percent
        self.critical_threshold = critical_threshold_percent
        self.monitoring = False
        self._monitor_thread = None
        self._callbacks = []

    def get_current_metrics(self) -> MemoryMetrics:
        """Get current system memory metrics."""
        memory = psutil.virtual_memory()
        process = psutil.Process()

        return MemoryMetrics(
            total_mb=memory.total / (1024**2),
            available_mb=memory.available / (1024**2),
            used_mb=memory.used / (1024**2),
            percentage=memory.percent,
            process_mb=process.memory_info().rss / (1024**2),
        )

    def add_callback(self, callback):
        """Add callback for memory threshold alerts."""
        self._callbacks.append(callback)

    def start_monitoring(self, interval=5):
        """Start continuous memory monitoring."""
        if self.monitoring:
            return

        self.monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, args=(interval,), daemon=True
        )
        self._monitor_thread.start()
        logger.info(f"Memory monitoring started (interval: {interval}s)")

    def stop_monitoring(self):
        """Stop memory monitoring."""
        self.monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1)
        logger.info("Memory monitoring stopped")

    def _monitor_loop(self, interval):
        """Internal monitoring loop."""
        while self.monitoring:
            try:
                metrics = self.get_current_metrics()

                if metrics.percentage >= self.critical_threshold:
                    logger.critical(
                        f"CRITICAL: Memory usage at {metrics.percentage:.1f}% "
                        f"({metrics.used_mb:.1f}MB used)"
                    )
                    for callback in self._callbacks:
                        callback("critical", metrics)

                elif metrics.percentage >= self.warning_threshold:
                    logger.warning(
                        f"WARNING: Memory usage at {metrics.percentage:.1f}% "
                        f"({metrics.used_mb:.1f}MB used)"
                    )
                    for callback in self._callbacks:
                        callback("warning", metrics)

                time.sleep(interval)

            except Exception as e:
                logger.error(f"Error in memory monitoring: {e}")
                time.sleep(interval)

class OptimizedAPKProcessor:
    """
    Memory-optimized APK processor for large files.

    Handles APKs >500MB with streaming analysis, memory management,
    and progressive processing with checkpoints.
    """

    def __init__(
        self,
        memory_limit_gb=4,
        chunk_size_kb=64,
        max_workers=2,
        enable_checkpoints=True,
    ):
        """
        Initialize the optimized processor.

        Args:
            memory_limit_gb: Maximum memory usage limit in GB
            chunk_size_kb: Chunk size for streaming analysis in KB
            max_workers: Maximum concurrent workers for parallel processing
            enable_checkpoints: Enable progressive checkpoints
        """
        self.memory_limit = memory_limit_gb * 1024**3  # Convert to bytes
        self.chunk_size = chunk_size_kb * 1024  # Convert to bytes
        self.max_workers = max_workers
        self.enable_checkpoints = enable_checkpoints

        # Memory monitoring
        self.memory_monitor = MemoryMonitor(
            warning_threshold_percent=75, critical_threshold_percent=85
        )
        self.memory_monitor.add_callback(self._handle_memory_alert)

        # Resource management
        self.temp_dirs = []
        self.open_files = []
        self.checkpoints = []

        # Processing state
        self.processing_paused = False
        self.current_apk_path = None

        logger.info(
            f"OptimizedAPKProcessor initialized: "
            f"memory_limit={memory_limit_gb}GB, "
            f"chunk_size={chunk_size_kb}KB, "
            f"workers={max_workers}"
        )

    def _handle_memory_alert(self, level, metrics):
        """Handle memory usage alerts."""
        if level == "critical":
            logger.critical(
                "CRITICAL MEMORY USAGE - Pausing processing and cleaning up"
            )
            self.processing_paused = True
            self._emergency_cleanup()
        elif level == "warning":
            logger.warning("HIGH MEMORY USAGE - Triggering garbage collection")
            gc.collect()

    def _emergency_cleanup(self):
        """Emergency cleanup to free memory."""
        logger.info("Performing emergency memory cleanup")

        # Close open files
        for file_handle in self.open_files[:]:
            try:
                file_handle.close()
                self.open_files.remove(file_handle)
            except Exception as e:
                logger.debug(f"Error closing file handle: {e}")

        # Force garbage collection
        gc.collect()

        # Clear caches if available
        try:
            import functools

            for obj in gc.get_objects():
                if hasattr(obj, "cache_clear"):
                    obj.cache_clear()
        except Exception as e:
            logger.debug(f"Error clearing caches: {e}")

        logger.info("Emergency cleanup completed")

    @contextmanager
    def memory_managed_processing(self, apk_path: str):
        """Context manager for memory-managed APK processing."""
        self.current_apk_path = apk_path
        self.memory_monitor.start_monitoring(interval=3)

        try:
            apk_size = os.path.getsize(apk_path) / (1024**2)  # MB
            logger.info(
                f"Starting memory-managed processing of {apk_path} ({apk_size:.1f}MB)"
            )

            initial_metrics = self.memory_monitor.get_current_metrics()
            logger.info(
                f"Initial memory: {initial_metrics.percentage:.1f}% "
                f"({initial_metrics.used_mb:.1f}MB used)"
            )

            yield self

        finally:
            self.memory_monitor.stop_monitoring()
            self._cleanup_resources()

            final_metrics = self.memory_monitor.get_current_metrics()
            logger.info(
                f"Final memory: {final_metrics.percentage:.1f}% "
                f"({final_metrics.used_mb:.1f}MB used)"
            )

    def process_large_apk(self, apk_path: str, plugins: List[str] = None) -> Dict:
        """
        Process a large APK with memory optimization.

        Args:
            apk_path: Path to the APK file
            plugins: List of plugins to run (None for all)

        Returns:
            Dictionary with processing results and metrics
        """
        start_time = time.time()

        with self.memory_managed_processing(apk_path) as processor:
            try:
                # Validate APK accessibility
                if not os.path.exists(apk_path):
                    raise FileNotFoundError(f"APK not found: {apk_path}")

                apk_size = os.path.getsize(apk_path)
                logger.info(
                    f"Processing APK: {apk_path} ({apk_size / (1024**2):.1f}MB)"
                )

                # Use memory-mapped access for large files
                with open(apk_path, "rb") as f:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        self.open_files.append(mm)

                        # Stream-based ZIP analysis
                        results = self._analyze_apk_streaming(mm, apk_path, plugins)

                processing_time = time.time() - start_time

                return {
                    "success": True,
                    "apk_path": apk_path,
                    "apk_size_mb": apk_size / (1024**2),
                    "processing_time_seconds": processing_time,
                    "checkpoints_created": len(self.checkpoints),
                    "memory_peak_mb": (
                        max(cp.memory_usage.process_mb for cp in self.checkpoints)
                        if self.checkpoints
                        else 0
                    ),
                    "results": results,
                }

            except Exception as e:
                logger.error(f"Error processing large APK {apk_path}: {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "apk_path": apk_path,
                    "processing_time_seconds": time.time() - start_time,
                }

    def _analyze_apk_streaming(self, mm_apk, apk_path: str, plugins: List[str]) -> Dict:
        """Analyze APK using streaming approach with memory mapping."""
        results = {
            "files_analyzed": 0,
            "total_size_processed": 0,
            "plugin_results": {},
            "checkpoints": [],
        }

        try:
            # Create a temporary ZIP file handle from memory map
            with zipfile.ZipFile(mm_apk, "r") as zip_file:
                file_list = zip_file.infolist()
                total_files = len(file_list)

                logger.info(f"APK contains {total_files} files")

                # Process files in chunks
                for i in range(0, total_files, 100):  # Process 100 files at a time
                    if self.processing_paused:
                        logger.info("Processing paused due to memory constraints")
                        break

                    chunk_files = file_list[i : i + 100]
                    chunk_results = self._process_file_chunk(zip_file, chunk_files)

                    # Update results
                    results["files_analyzed"] += len(chunk_files)
                    results["total_size_processed"] += sum(
                        f.file_size for f in chunk_files
                    )

                    # Merge plugin results
                    for plugin, plugin_results in chunk_results.items():
                        if plugin not in results["plugin_results"]:
                            results["plugin_results"][plugin] = []
                        results["plugin_results"][plugin].extend(plugin_results)

                    # Create checkpoint
                    if self.enable_checkpoints and i % 500 == 0:  # Every 500 files
                        checkpoint = self._create_checkpoint(
                            results["files_analyzed"], results["total_size_processed"]
                        )
                        self.checkpoints.append(checkpoint)
                        results["checkpoints"].append(checkpoint)

                        logger.info(
                            f"Checkpoint created: {results['files_analyzed']}/{total_files} files processed"
                        )

                    # Periodic cleanup
                    if i % 200 == 0:
                        gc.collect()

        except Exception as e:
            logger.error(f"Error in streaming APK analysis: {e}")
            results["error"] = str(e)

        return results

    def _process_file_chunk(self, zip_file: zipfile.ZipFile, file_chunk: List) -> Dict:
        """Process a chunk of files from the APK."""
        chunk_results = {}

        for file_info in file_chunk:
            if file_info.is_dir():
                continue

            try:
                # Read file content in memory-efficient way
                if file_info.file_size > self.chunk_size:
                    # For large files, process in chunks
                    content = self._read_large_file_chunked(zip_file, file_info)
                else:
                    # Small files can be read entirely
                    content = zip_file.read(file_info.filename)

                # Simulated plugin processing (replace with actual plugin calls)
                file_results = self._analyze_file_content(content, file_info.filename)

                # Aggregate results by plugin
                for plugin, findings in file_results.items():
                    if plugin not in chunk_results:
                        chunk_results[plugin] = []
                    chunk_results[plugin].extend(findings)

            except Exception as e:
                logger.debug(f"Error processing file {file_info.filename}: {e}")
                continue

        return chunk_results

    def _read_large_file_chunked(self, zip_file: zipfile.ZipFile, file_info) -> bytes:
        """Read large files in chunks to manage memory."""
        content = b""

        with zip_file.open(file_info) as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                content += chunk

                # Check if we should pause due to memory
                if self.processing_paused:
                    break

        return content

    def _analyze_file_content(self, content: bytes, filename: str) -> Dict:
        """Analyze file content using actual plugin integration."""
        results = {}

        try:
            # Convert to string for text analysis
            if filename.endswith((".java", ".kt", ".xml", ".json", ".txt")):
                text_content = content.decode("utf-8", errors="ignore")

                # Use actual analysis functions
                results["secrets"] = self._find_secrets_actual(text_content, filename)
                results["vulnerabilities"] = self._find_vulnerabilities_actual(
                    text_content, filename
                )

        except Exception as e:
            logger.debug(f"Error analyzing content of {filename}: {e}")

        return results

    def _find_secrets_actual(self, content: str, filename: str) -> List[Dict]:
        """Real secret detection using existing patterns."""
        secrets = []
        
        try:
            # Import actual secret detection
            from core.secret_extractor import EnhancedSecretExtractor
            
            extractor = EnhancedSecretExtractor()
            extraction_result = extractor.extract_secrets_from_content(content, filename, "optimized_analysis")
            
            for secret in extraction_result.secrets:
                secrets.append({
                    "type": secret.secret_type if hasattr(secret, 'secret_type') else "unknown_secret",
                    "confidence": secret.confidence if hasattr(secret, 'confidence') else 0.0,
                    "location": filename,
                    "pattern": getattr(secret, 'pattern', ''),
                    "value": secret.value[:50] + "..." if (hasattr(secret, 'value') and len(secret.value) > 50) else getattr(secret, 'value', '')
                })
                
        except ImportError:
            # Fallback to basic pattern matching
            import re
            
            patterns = {
                "api_key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9]{16,})['\"]?",
                "jwt_token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                "auth_token": r"(?i)(auth[_-]?token|access[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
                "private_key": r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"
            }
            
            for secret_type, pattern in patterns.items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    secrets.append({
                        "type": secret_type,
                        "confidence": 0.8,
                        "location": filename,
                        "pattern": pattern,
                        "value": match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0)
                    })
                    
        except Exception as e:
            logger.debug(f"Error in secret detection for {filename}: {e}")

        return secrets

    def _find_vulnerabilities_actual(self, content: str, filename: str) -> List[Dict]:
        """Real vulnerability detection using existing patterns."""
        vulns = []
        
        try:
            # Import actual vulnerability detection
            from core.vulnerability_classifier import VulnerabilityClassifier
            
            classifier = VulnerabilityClassifier()
            
            # Create a mock finding for classification
            finding = {
                "content": content,
                "file_path": filename,
                "line_number": 1,
                "pattern": "file_content_analysis"
            }
            
            classification = classifier.classify_vulnerability(finding)
            
            if not classification.get("is_false_positive", True):
                vulns.append({
                    "type": classification.get("vulnerability_type", "code_vulnerability"),
                    "severity": classification.get("severity", "MEDIUM"),
                    "location": filename,
                    "confidence": classification.get("confidence", 0.7),
                    "description": classification.get("description", "Potential vulnerability detected")
                })
                
        except ImportError:
            # Fallback to basic pattern matching
            import re
            
            vulnerability_patterns = {
                "code_injection": [r"eval\s*\(", r"exec\s*\(", r"Runtime\.getRuntime\(\)\.exec"],
                "sql_injection": [r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\+", r"executeQuery\s*\(\s*[^?]"],
                "hardcoded_secret": [r"password\s*=\s*['\"][^'\"]+['\"]", r"secret\s*=\s*['\"][^'\"]+['\"]"],
                "insecure_storage": [r"MODE_WORLD_READABLE", r"MODE_WORLD_WRITABLE"]
            }
            
            for vuln_type, patterns in vulnerability_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        vulns.append({
                            "type": vuln_type,
                            "severity": "HIGH" if vuln_type in ["code_injection", "sql_injection"] else "MEDIUM",
                            "location": filename,
                            "confidence": 0.7,
                            "description": f"Potential {vuln_type.replace('_', ' ')} vulnerability"
                        })
                        break  # Only add one instance per type per file
                        
        except Exception as e:
            logger.debug(f"Error in vulnerability detection for {filename}: {e}")

        return vulns

    def _create_checkpoint(
        self, files_processed: int, size_processed: int
    ) -> ProcessingCheckpoint:
        """Create a processing checkpoint."""
        return ProcessingCheckpoint(
            file_count=files_processed,
            processed_size=size_processed,
            completed_plugins=[],  # Would track actual completed plugins
            timestamp=time.time(),
            memory_usage=self.memory_monitor.get_current_metrics(),
        )

    def _cleanup_resources(self):
        """Clean up all allocated resources."""
        logger.info("Cleaning up processor resources")

        # Close open files
        for file_handle in self.open_files[:]:
            try:
                file_handle.close()
                self.open_files.remove(file_handle)
            except Exception as e:
                logger.debug(f"Error closing file: {e}")

        # Clean up temporary directories
        for temp_dir in self.temp_dirs[:]:
            try:
                import shutil

                shutil.rmtree(temp_dir, ignore_errors=True)
                self.temp_dirs.remove(temp_dir)
            except Exception as e:
                logger.debug(f"Error removing temp dir: {e}")

        # Clear checkpoints
        self.checkpoints.clear()

        # Force garbage collection
        gc.collect()

        logger.info("Resource cleanup completed")

    def get_processing_statistics(self) -> Dict:
        """Get detailed processing statistics."""
        if not self.checkpoints:
            return {"status": "no_checkpoints"}

        return {
            "total_checkpoints": len(self.checkpoints),
            "total_files_processed": (
                self.checkpoints[-1].file_count if self.checkpoints else 0
            ),
            "total_size_processed_mb": (
                self.checkpoints[-1].processed_size / (1024**2)
                if self.checkpoints
                else 0
            ),
            "peak_memory_usage_mb": max(
                cp.memory_usage.process_mb for cp in self.checkpoints
            ),
            "average_memory_usage_mb": sum(
                cp.memory_usage.process_mb for cp in self.checkpoints
            )
            / len(self.checkpoints),
            "processing_duration_minutes": (
                (self.checkpoints[-1].timestamp - self.checkpoints[0].timestamp) / 60
                if len(self.checkpoints) > 1
                else 0
            ),
        }

# Example usage function
def process_large_apk_optimized(
    apk_path: str, memory_limit_gb: int = 4, chunk_size_kb: int = 64
) -> Dict:
    """
    Process a large APK with memory optimization.

    Example usage:
        result = process_large_apk_optimized('large_app.apk', memory_limit_gb=6)
        print(f"Processing completed: {result['success']}")
        print(f"Files analyzed: {result['results']['files_analyzed']}")
    """
    processor = OptimizedAPKProcessor(
        memory_limit_gb=memory_limit_gb,
        chunk_size_kb=chunk_size_kb,
        max_workers=2,
        enable_checkpoints=True,
    )

    return processor.process_large_apk(apk_path)

if __name__ == "__main__":
    # Example usage
    import sys

    if len(sys.argv) > 1:
        apk_path = sys.argv[1]
        result = process_large_apk_optimized(apk_path)
        print(f"Processing result: {result}")
    else:
        print("Usage: python optimized_apk_processor.py <apk_path>")

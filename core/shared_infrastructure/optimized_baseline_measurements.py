#!/usr/bin/env python3
"""
Optimized AODS Baseline Measurements System

Performance-optimized baseline measurement system that resolves timeout issues
through chunked processing, progressive reporting, and advanced optimizations.

Key Optimizations:
- Chunked file processing with progress updates
- Timeout protection for individual operations
- Progressive reporting and intermediate results saving
- Memory-optimized duplication analysis
- Parallel processing where safe
- Intelligent sampling for large codebases

"""

import os
import re
import json
import time
import hashlib
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError, as_completed
from contextlib import contextmanager
from typing import Dict, List, Any, Optional, Tuple, Set, Callable
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime
import gc

# Import timeout management
try:
    from ..performance_optimizer.timeout_manager import EnterpriseTimeoutManager
    TIMEOUT_MANAGER_AVAILABLE = True
except ImportError:
    TIMEOUT_MANAGER_AVAILABLE = False

logger = logging.getLogger(__name__)

# Performance constants
MAX_CHUNK_SIZE = 50  # Process files in chunks of 50
MAX_ANALYSIS_TIME = 300  # 5 minutes maximum total analysis time
MAX_FILE_SIZE_MB = 10  # Skip files larger than 10MB for performance
DUPLICATION_SAMPLE_SIZE = 100  # Maximum files for duplication analysis
PROGRESS_REPORT_INTERVAL = 10  # Report progress every 10 processed items

@dataclass
class OptimizedFileMetrics:
    """Optimized metrics for individual files with performance tracking."""
    file_path: str
    size_bytes: int
    line_count: int
    function_count: int
    class_count: int
    import_count: int
    complexity_score: float
    duplication_hash: str
    last_modified: datetime
    file_type: str
    plugin_name: str
    processing_time_ms: float = 0.0
    analysis_status: str = "success"  # success, timeout, error, skipped

@dataclass
class OptimizationMetrics:
    """Metrics tracking optimization performance."""
    total_processing_time: float
    files_processed: int
    files_skipped: int
    files_timeout: int
    files_error: int
    chunks_processed: int
    duplication_analysis_time: float
    memory_peak_mb: float
    optimization_applied: List[str]

@dataclass
class ProgressReport:
    """Progressive reporting structure."""
    timestamp: datetime
    files_processed: int
    total_files: int
    current_phase: str
    phase_progress: float
    estimated_time_remaining: Optional[float]
    optimization_metrics: OptimizationMetrics

class OptimizedCodeAnalyzer:
    """Performance-optimized code analyzer with timeout protection."""
    
    def __init__(self):
        self.timeout_manager = None
        if TIMEOUT_MANAGER_AVAILABLE:
            try:
                self.timeout_manager = EnterpriseTimeoutManager()
            except Exception:
                pass
    
    def analyze_python_file_optimized(self, file_path: str, max_timeout: float = 5.0) -> Dict[str, Any]:
        """Analyze Python file with timeout protection and performance optimization."""
        start_time = time.perf_counter()
        
        try:
            # Check file size first
            file_size = Path(file_path).stat().st_size
            if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
                return self._create_skipped_result("File too large", start_time)
            
            # Analyze with timeout protection
            if self.timeout_manager:
                result = self.timeout_manager.execute_with_timeout(
                    operation=self._analyze_file_content,
                    timeout_seconds=max_timeout,
                    operation_name=f"analyze_{Path(file_path).name}",
                    file_path=file_path
                )
                
                if result.success:
                    analysis = result.result
                    analysis['processing_time_ms'] = (time.perf_counter() - start_time) * 1000
                    analysis['analysis_status'] = 'success'
                    return analysis
                elif result.timed_out:
                    return self._create_timeout_result(start_time)
                else:
                    return self._create_error_result(result.error_message, start_time)
            else:
                # Fallback without timeout manager
                return self._analyze_file_content(file_path)
                
        except Exception as e:
            return self._create_error_result(str(e), start_time)
    
    def _analyze_file_content(self, file_path: str) -> Dict[str, Any]:
        """Core file analysis logic."""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Optimized line counting
        lines = content.split('\n')
        line_count = sum(1 for line in lines if line.strip() and not line.strip().startswith('#'))
        
        # Optimized regex patterns (compiled once)
        function_pattern = re.compile(r'^\s*def\s+\w+', re.MULTILINE)
        class_pattern = re.compile(r'^\s*class\s+\w+', re.MULTILINE)
        import_pattern = re.compile(r'^\s*(import|from)\s+', re.MULTILINE)
        
        function_count = len(function_pattern.findall(content))
        class_count = len(class_pattern.findall(content))
        import_count = len(import_pattern.findall(content))
        
        # Optimized complexity calculation
        complexity_keywords = ['if ', 'else', 'elif ', 'while ', 'for ', 'try:', 'except', 'finally:', 'with ']
        complexity_score = sum(content.lower().count(keyword) for keyword in complexity_keywords)
        
        # Fast hash calculation
        content_hash = hashlib.md5(content.encode('utf-8', errors='ignore')).hexdigest()
        
        return {
            'line_count': line_count,
            'function_count': function_count,
            'class_count': class_count,
            'import_count': import_count,
            'complexity_score': complexity_score / max(1, line_count) * 100,
            'duplication_hash': content_hash,
            'analysis_status': 'success'
        }
    
    def _create_skipped_result(self, reason: str, start_time: float) -> Dict[str, Any]:
        """Create result for skipped files."""
        return {
            'line_count': 0, 'function_count': 0, 'class_count': 0,
            'import_count': 0, 'complexity_score': 0.0, 'duplication_hash': '',
            'analysis_status': 'skipped', 'skip_reason': reason,
            'processing_time_ms': (time.perf_counter() - start_time) * 1000
        }
    
    def _create_timeout_result(self, start_time: float) -> Dict[str, Any]:
        """Create result for timed out analysis."""
        return {
            'line_count': 0, 'function_count': 0, 'class_count': 0,
            'import_count': 0, 'complexity_score': 0.0, 'duplication_hash': '',
            'analysis_status': 'timeout',
            'processing_time_ms': (time.perf_counter() - start_time) * 1000
        }
    
    def _create_error_result(self, error_msg: str, start_time: float) -> Dict[str, Any]:
        """Create result for failed analysis."""
        return {
            'line_count': 0, 'function_count': 0, 'class_count': 0,
            'import_count': 0, 'complexity_score': 0.0, 'duplication_hash': '',
            'analysis_status': 'error', 'error_message': error_msg,
            'processing_time_ms': (time.perf_counter() - start_time) * 1000
        }

class OptimizedDuplicationDetector:
    """Memory-optimized duplication detector with intelligent sampling."""
    
    def __init__(self, max_files: int = DUPLICATION_SAMPLE_SIZE):
        self.max_files = max_files
        self.similarity_threshold = 0.8
    
    def analyze_duplication_optimized(self, file_paths: List[str], 
                                   progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Optimized duplication analysis with intelligent sampling."""
        start_time = time.perf_counter()
        
        # Intelligent sampling for large codebases
        if len(file_paths) > self.max_files:
            sampled_files = self._intelligent_sampling(file_paths)
            logger.info(f"Sampled {len(sampled_files)} files from {len(file_paths)} for duplication analysis")
        else:
            sampled_files = file_paths
        
        # Fast hash-based grouping first
        hash_groups = self._group_by_hash(sampled_files, progress_callback)
        
        # Convert to expected format
        duplication_groups = []
        for group_hash, files in hash_groups.items():
            if len(files) > 1:
                duplication_groups.append({
                    'similarity_hash': group_hash[:12],
                    'files': files,
                    'similarity_score': 1.0,  # Exact hash match
                    'duplicate_lines': self._estimate_duplicate_lines(files[0]),
                    'common_patterns': self._extract_quick_patterns(files[0])
                })
        
        analysis_time = time.perf_counter() - start_time
        logger.info(f"Duplication analysis completed in {analysis_time:.2f}s")
        
        return duplication_groups
    
    def _intelligent_sampling(self, file_paths: List[str]) -> List[str]:
        """Intelligent sampling prioritizing larger and more complex files."""
        # Get file sizes and prioritize larger files
        file_info = []
        for path in file_paths:
            try:
                size = Path(path).stat().st_size
                file_info.append((path, size))
            except:
                continue
        
        # Sort by size (descending) and take mix of large and random files
        file_info.sort(key=lambda x: x[1], reverse=True)
        
        # Take top 60% largest files and 40% random sampling
        large_count = int(self.max_files * 0.6)
        random_count = self.max_files - large_count
        
        sampled = [item[0] for item in file_info[:large_count]]
        
        # Add random sampling from remaining files
        remaining = [item[0] for item in file_info[large_count:]]
        if remaining and random_count > 0:
            import random
            random.seed(42)  # Reproducible sampling
            sampled.extend(random.sample(remaining, min(random_count, len(remaining))))
        
        return sampled
    
    def _group_by_hash(self, file_paths: List[str], 
                      progress_callback: Optional[Callable] = None) -> Dict[str, List[str]]:
        """Group files by content hash for fast duplicate detection."""
        hash_groups = defaultdict(list)
        
        for i, file_path in enumerate(file_paths):
            try:
                # Quick hash calculation
                with open(file_path, 'rb') as f:
                    content = f.read()
                    if len(content) > 1024 * 1024:  # 1MB limit for hashing
                        # Hash first and last 64KB for large files
                        hash_content = content[:65536] + content[-65536:]
                    else:
                        hash_content = content
                    
                    file_hash = hashlib.md5(hash_content).hexdigest()
                    hash_groups[file_hash].append(file_path)
                
                # Progress reporting
                if progress_callback and i % 10 == 0:
                    progress_callback(i, len(file_paths), "Analyzing duplicates")
                    
            except Exception as e:
                logger.debug(f"Failed to hash {file_path}: {e}")
        
        return hash_groups
    
    def _estimate_duplicate_lines(self, file_path: str) -> int:
        """Quick estimate of lines in a file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for line in f if line.strip())
        except:
            return 0
    
    def _extract_quick_patterns(self, file_path: str) -> List[str]:
        """Quick extraction of common patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(8192)  # Read first 8KB only
                
                # Extract class and function names quickly
                patterns = []
                patterns.extend(re.findall(r'class\s+(\w+)', content)[:3])
                patterns.extend(re.findall(r'def\s+(\w+)', content)[:5])
                return patterns
        except:
            return []

class OptimizedBaselineCollector:
    """Main optimized baseline measurement collector with progress tracking."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.code_analyzer = OptimizedCodeAnalyzer()
        self.duplication_detector = OptimizedDuplicationDetector()
        
        self.plugin_dirs = ['plugins', 'core']
        self.file_patterns = ['*.py']
        
        # Progress tracking
        self.progress_callbacks: List[Callable] = []
        self.current_progress = 0
        self.total_items = 0
        
        # Optimization metrics
        self.optimization_metrics = OptimizationMetrics(
            total_processing_time=0.0,
            files_processed=0,
            files_skipped=0,
            files_timeout=0,
            files_error=0,
            chunks_processed=0,
            duplication_analysis_time=0.0,
            memory_peak_mb=0.0,
            optimization_applied=[]
        )
    
    def add_progress_callback(self, callback: Callable[[ProgressReport], None]):
        """Add a progress callback function."""
        self.progress_callbacks.append(callback)
    
    def collect_baseline_optimized(self, save_intermediate: bool = True) -> Dict[str, Any]:
        """Collect baseline measurements with optimization and progress tracking."""
        logger.info("Starting optimized baseline measurement collection...")
        start_time = time.perf_counter()
        
        try:
            # Phase 1: File Collection
            self._report_progress("Collecting files", 0.0)
            all_files = self._collect_files_optimized()
            self.total_items = len(all_files)
            logger.info(f"Found {len(all_files)} Python files to analyze")
            
            # Phase 2: Chunked File Analysis
            self._report_progress("Analyzing files", 0.1)
            file_metrics = self._analyze_files_chunked(all_files, save_intermediate)
            
            # Phase 3: Plugin Analysis
            self._report_progress("Analyzing plugins", 0.7)
            plugin_metrics = self._analyze_plugins_optimized(file_metrics)
            
            # Phase 4: Duplication Analysis (optimized)
            self._report_progress("Analyzing duplicates", 0.8)
            duplication_groups = self._analyze_duplication_optimized(all_files)
            
            # Phase 5: Final Assembly
            self._report_progress("Finalizing results", 0.9)
            baseline = self._assemble_final_baseline(
                all_files, file_metrics, plugin_metrics, duplication_groups
            )
            
            # Record final metrics
            self.optimization_metrics.total_processing_time = time.perf_counter() - start_time
            baseline['optimization_metrics'] = asdict(self.optimization_metrics)
            
            self._report_progress("Complete", 1.0)
            logger.info(f"Optimized baseline collection completed in {self.optimization_metrics.total_processing_time:.2f}s")
            
            return baseline
            
        except Exception as e:
            logger.error(f"Optimized baseline collection failed: {e}")
            raise
        finally:
            # Cleanup
            gc.collect()
    
    def _collect_files_optimized(self) -> List[str]:
        """Optimized file collection with filtering."""
        files = []
        
        for dir_name in self.plugin_dirs:
            dir_path = self.project_root / dir_name
            if dir_path.exists():
                for pattern in self.file_patterns:
                    found_files = list(dir_path.rglob(pattern))
                    files.extend(str(p) for p in found_files)
        
        # Optimized filtering
        filtered_files = [
            f for f in files 
            if '__pycache__' not in f 
            and not f.endswith('_test.py')
            and not f.endswith('.pyc')
        ]
        
        self.optimization_metrics.optimization_applied.append("file_filtering")
        return filtered_files
    
    def _analyze_files_chunked(self, file_paths: List[str], save_intermediate: bool) -> List[OptimizedFileMetrics]:
        """Analyze files in chunks with progress reporting."""
        file_metrics = []
        chunks = [file_paths[i:i + MAX_CHUNK_SIZE] for i in range(0, len(file_paths), MAX_CHUNK_SIZE)]
        
        self.optimization_metrics.chunks_processed = len(chunks)
        self.optimization_metrics.optimization_applied.append("chunked_processing")
        
        for chunk_idx, chunk in enumerate(chunks):
            chunk_start_time = time.perf_counter()
            
            # Process chunk
            chunk_metrics = self._process_file_chunk(chunk)
            file_metrics.extend(chunk_metrics)
            
            # Update metrics
            self.optimization_metrics.files_processed += len(chunk_metrics)
            
            # Progress reporting
            progress = 0.1 + (chunk_idx + 1) / len(chunks) * 0.6  # 10% to 70%
            self._report_progress(f"Analyzing files (chunk {chunk_idx + 1}/{len(chunks)})", progress)
            
            # Save intermediate results
            if save_intermediate and chunk_idx % 5 == 0:
                self._save_intermediate_results(file_metrics, f"intermediate_chunk_{chunk_idx}.json")
            
            # Memory management
            if chunk_idx % 10 == 0:
                gc.collect()
                self._update_memory_usage()
            
            chunk_time = time.perf_counter() - chunk_start_time
            logger.debug(f"Processed chunk {chunk_idx + 1}/{len(chunks)} in {chunk_time:.2f}s")
        
        return file_metrics
    
    def _process_file_chunk(self, file_paths: List[str]) -> List[OptimizedFileMetrics]:
        """Process a chunk of files with parallel optimization when safe."""
        chunk_metrics = []
        
        # Use parallel processing for I/O bound operations when safe
        if len(file_paths) > 10:
            self.optimization_metrics.optimization_applied.append("parallel_processing")
            
            with ThreadPoolExecutor(max_workers=4) as executor:
                # Submit all files in chunk
                futures = {
                    executor.submit(self._analyze_single_file, file_path): file_path
                    for file_path in file_paths
                }
                
                # Collect results with timeout
                for future in as_completed(futures, timeout=30):
                    try:
                        metrics = future.result(timeout=5)
                        if metrics:
                            chunk_metrics.append(metrics)
                    except FutureTimeoutError:
                        self.optimization_metrics.files_timeout += 1
                        logger.warning(f"File analysis timeout: {futures[future]}")
                    except Exception as e:
                        self.optimization_metrics.files_error += 1
                        logger.warning(f"File analysis error: {futures[future]}: {e}")
        else:
            # Sequential processing for small chunks
            for file_path in file_paths:
                metrics = self._analyze_single_file(file_path)
                if metrics:
                    chunk_metrics.append(metrics)
        
        return chunk_metrics
    
    def _analyze_single_file(self, file_path: str) -> Optional[OptimizedFileMetrics]:
        """Analyze a single file with optimization."""
        try:
            path_obj = Path(file_path)
            
            # Quick size check
            stats = path_obj.stat()
            if stats.st_size > MAX_FILE_SIZE_MB * 1024 * 1024:
                self.optimization_metrics.files_skipped += 1
                self.optimization_metrics.optimization_applied.append("large_file_skipping")
                return None
            
            # Analyze with timeout
            analysis = self.code_analyzer.analyze_python_file_optimized(file_path)
            
            # Track status
            if analysis['analysis_status'] == 'timeout':
                self.optimization_metrics.files_timeout += 1
            elif analysis['analysis_status'] == 'error':
                self.optimization_metrics.files_error += 1
            elif analysis['analysis_status'] == 'skipped':
                self.optimization_metrics.files_skipped += 1
            
            # Create metrics object
            plugin_name = self._extract_plugin_name_fast(file_path)
            
            return OptimizedFileMetrics(
                file_path=file_path,
                size_bytes=stats.st_size,
                line_count=analysis['line_count'],
                function_count=analysis['function_count'],
                class_count=analysis['class_count'],
                import_count=analysis['import_count'],
                complexity_score=analysis['complexity_score'],
                duplication_hash=analysis['duplication_hash'],
                last_modified=datetime.fromtimestamp(stats.st_mtime),
                file_type='python',
                plugin_name=plugin_name,
                processing_time_ms=analysis.get('processing_time_ms', 0.0),
                analysis_status=analysis['analysis_status']
            )
            
        except Exception as e:
            self.optimization_metrics.files_error += 1
            logger.debug(f"Failed to analyze {file_path}: {e}")
            return None
    
    def _analyze_plugins_optimized(self, file_metrics: List[OptimizedFileMetrics]) -> List[Dict[str, Any]]:
        """Optimized plugin analysis."""
        plugin_data = defaultdict(list)
        
        # Group files by plugin
        for fm in file_metrics:
            plugin_data[fm.plugin_name].append(fm)
        
        plugin_metrics = []
        for plugin_name, files in plugin_data.items():
            if not files:
                continue
            
            # Quick calculations
            total_files = len(files)
            total_lines = sum(f.line_count for f in files)
            total_size = sum(f.size_bytes for f in files)
            avg_complexity = sum(f.complexity_score for f in files) / total_files if total_files > 0 else 0
            
            metrics = {
                'plugin_name': plugin_name,
                'total_files': total_files,
                'total_lines': total_lines,
                'total_size_bytes': total_size,
                'avg_file_size': total_size / total_files if total_files > 0 else 0,
                'avg_complexity': avg_complexity,
                'modularization_status': self._assess_modularization_status_fast(plugin_name, files),
                'dependency_count': sum(f.import_count for f in files),
                'successful_analysis': sum(1 for f in files if f.analysis_status == 'success'),
                'analysis_issues': sum(1 for f in files if f.analysis_status != 'success')
            }
            
            plugin_metrics.append(metrics)
        
        return plugin_metrics
    
    def _analyze_duplication_optimized(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """Optimized duplication analysis with progress callback."""
        duplication_start = time.perf_counter()
        
        def progress_callback(current: int, total: int, phase: str):
            progress = 0.8 + (current / total) * 0.1  # 80% to 90%
            self._report_progress(f"{phase} ({current}/{total})", progress)
        
        duplication_groups = self.duplication_detector.analyze_duplication_optimized(
            file_paths, progress_callback
        )
        
        self.optimization_metrics.duplication_analysis_time = time.perf_counter() - duplication_start
        self.optimization_metrics.optimization_applied.append("optimized_duplication_analysis")
        
        return duplication_groups
    
    def _assemble_final_baseline(self, all_files: List[str], file_metrics: List[OptimizedFileMetrics],
                               plugin_metrics: List[Dict[str, Any]], duplication_groups: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assemble final baseline measurement."""
        # Calculate summary metrics
        total_lines = sum(fm.line_count for fm in file_metrics)
        total_size_mb = sum(fm.size_bytes for fm in file_metrics) / (1024 * 1024)
        
        # Calculate duplication percentage
        duplicated_files = set()
        for group in duplication_groups:
            duplicated_files.update(group['files'])
        duplication_percentage = len(duplicated_files) / len(all_files) * 100 if all_files else 0
        
        return {
            'measurement_date': datetime.now().isoformat(),
            'summary': {
                'total_plugins': len(plugin_metrics),
                'total_files': len(all_files),
                'total_lines': total_lines,
                'total_size_mb': total_size_mb,
                'duplication_percentage': duplication_percentage,
                'avg_file_complexity': sum(fm.complexity_score for fm in file_metrics) / len(file_metrics) if file_metrics else 0,
                'successful_analysis_rate': sum(1 for fm in file_metrics if fm.analysis_status == 'success') / len(file_metrics) * 100 if file_metrics else 0
            },
            'plugin_metrics': plugin_metrics,
            'duplication_groups': duplication_groups,
            'file_metrics_summary': {
                'total_analyzed': len(file_metrics),
                'successful': sum(1 for fm in file_metrics if fm.analysis_status == 'success'),
                'timeouts': sum(1 for fm in file_metrics if fm.analysis_status == 'timeout'),
                'errors': sum(1 for fm in file_metrics if fm.analysis_status == 'error'),
                'skipped': sum(1 for fm in file_metrics if fm.analysis_status == 'skipped')
            },
            'consolidation_opportunities': self._identify_opportunities_fast(plugin_metrics, duplication_groups)
        }
    
    def _extract_plugin_name_fast(self, file_path: str) -> str:
        """Fast plugin name extraction."""
        parts = Path(file_path).parts
        if 'plugins' in parts:
            idx = parts.index('plugins')
            return parts[idx + 1] if idx + 1 < len(parts) else 'unknown'
        elif 'core' in parts:
            return 'core'
        return 'unknown'
    
    def _assess_modularization_status_fast(self, plugin_name: str, files: List[OptimizedFileMetrics]) -> str:
        """Fast modularization status assessment."""
        if len(files) > 5:
            return 'MODULAR'
        elif len(files) > 1:
            return 'PARTIALLY_MODULAR'
        else:
            return 'MONOLITHIC'
    
    def _identify_opportunities_fast(self, plugin_metrics: List[Dict[str, Any]], 
                                   duplication_groups: List[Dict[str, Any]]) -> List[str]:
        """Fast consolidation opportunity identification."""
        opportunities = []
        
        # Large plugins
        for plugin in plugin_metrics:
            if plugin['modularization_status'] == 'MONOLITHIC' and plugin['total_lines'] > 1000:
                opportunities.append(f"Modularize {plugin['plugin_name']} ({plugin['total_lines']} lines)")
        
        # High duplication
        for group in duplication_groups[:5]:  # Top 5 only
            if len(group['files']) > 2:
                opportunities.append(f"Consolidate {len(group['files'])} duplicate files")
        
        return opportunities[:10]
    
    def _report_progress(self, phase: str, progress: float):
        """Report progress to all registered callbacks."""
        if not self.progress_callbacks:
            return
        
        report = ProgressReport(
            timestamp=datetime.now(),
            files_processed=self.optimization_metrics.files_processed,
            total_files=self.total_items,
            current_phase=phase,
            phase_progress=progress,
            estimated_time_remaining=None,  # Could be calculated
            optimization_metrics=self.optimization_metrics
        )
        
        for callback in self.progress_callbacks:
            try:
                callback(report)
            except Exception as e:
                logger.debug(f"Progress callback error: {e}")
    
    def _save_intermediate_results(self, file_metrics: List[OptimizedFileMetrics], filename: str):
        """Save intermediate results for recovery."""
        try:
            intermediate_data = {
                'timestamp': datetime.now().isoformat(),
                'file_metrics_count': len(file_metrics),
                'optimization_metrics': asdict(self.optimization_metrics)
            }
            
            with open(filename, 'w') as f:
                json.dump(intermediate_data, f, indent=2)
                
        except Exception as e:
            logger.debug(f"Failed to save intermediate results: {e}")
    
    def _update_memory_usage(self):
        """Update peak memory usage tracking."""
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            self.optimization_metrics.memory_peak_mb = max(
                self.optimization_metrics.memory_peak_mb, memory_mb
            )
        except ImportError:
            pass

def create_progress_reporter():
    """Create a console progress reporter."""
    def progress_reporter(report: ProgressReport):
        print(f"[{report.timestamp.strftime('%H:%M:%S')}] "
              f"{report.current_phase}: {report.phase_progress*100:.1f}% "
              f"({report.files_processed}/{report.total_files} files)")
    
    return progress_reporter

def run_optimized_baseline_collection(project_root: str = ".", 
                                     show_progress: bool = True,
                                     save_intermediate: bool = True) -> Dict[str, Any]:
    """Run optimized baseline collection with progress reporting."""
    collector = OptimizedBaselineCollector(project_root)
    
    if show_progress:
        collector.add_progress_callback(create_progress_reporter())
    
    return collector.collect_baseline_optimized(save_intermediate)

if __name__ == "__main__":
    print("🚀 AODS Optimized Baseline Measurements")
    print("=" * 50)
    
    start_time = time.perf_counter()
    
    try:
        baseline = run_optimized_baseline_collection()
        
        collection_time = time.perf_counter() - start_time
        
        print(f"\n✅ Optimized collection completed in {collection_time:.2f}s")
        print(f"📊 Files analyzed: {baseline['summary']['total_files']:,}")
        print(f"📈 Total lines: {baseline['summary']['total_lines']:,}")
        print(f"💾 Total size: {baseline['summary']['total_size_mb']:.1f} MB")
        print(f"🔄 Success rate: {baseline['summary']['successful_analysis_rate']:.1f}%")
        
        # Save results
        with open('optimized_baseline_report.json', 'w') as f:
            json.dump(baseline, f, indent=2)
        print(f"💾 Results saved to optimized_baseline_report.json")
        
    except Exception as e:
        print(f"❌ Collection failed: {e}")
        raise 
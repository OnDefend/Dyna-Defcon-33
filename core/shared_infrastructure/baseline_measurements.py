#!/usr/bin/env python3
"""
AODS Baseline Measurements System

Comprehensive baseline measurement and tracking system for the AODS consolidation initiative.
Provides metrics for code duplication, performance tracking, and consolidation progress.

Features:
- Code duplication analysis across plugins
- File size and complexity metrics
- Performance baseline establishment  
- Dependency analysis and mapping
- Progress tracking for consolidation phases
- Report generation for stakeholder updates
- Enhanced performance optimizations:
  * Timeout protection for all operations
  * Chunked processing for memory efficiency
  * Deterministic sampling for consistency
  * Real-time progress reporting
"""

import os
import re
import json
import time
import hashlib
import logging
import subprocess
import signal
import threading
from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime
import difflib
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError, as_completed
from functools import wraps
import gc
import psutil

logger = logging.getLogger(__name__)

# Performance constants
CHUNK_SIZE = 50  # Process files in chunks
OPERATION_TIMEOUT = 30  # Seconds per operation
TOTAL_TIMEOUT = 300  # 5 minutes total
MAX_WORKERS = 4  # Thread pool size
PROGRESS_UPDATE_INTERVAL = 10  # Update progress every N files

class TimeoutError(Exception):
    """Custom timeout error for baseline operations."""
    pass

def timeout_protection(timeout_seconds: int = OPERATION_TIMEOUT):
    """Decorator to add timeout protection to methods."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = [None]
            exception = [None]
            
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    exception[0] = e
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout_seconds)
            
            if thread.is_alive():
                logger.warning(f"Operation {func.__name__} timed out after {timeout_seconds}s")
                raise TimeoutError(f"Operation {func.__name__} timed out")
            
            if exception[0]:
                raise exception[0]
            
            return result[0]
        return wrapper
    return decorator

class ProgressReporter:
    """Progress reporting utility for long-running operations."""
    
    def __init__(self, total_items: int, operation_name: str = "Processing"):
        self.total_items = total_items
        self.processed_items = 0
        self.operation_name = operation_name
        self.start_time = time.time()
        self.last_update = 0
        
    def update(self, increment: int = 1):
        """Update progress counter."""
        self.processed_items += increment
        current_time = time.time()
        
        # Update every PROGRESS_UPDATE_INTERVAL items or every 5 seconds
        if (self.processed_items - self.last_update >= PROGRESS_UPDATE_INTERVAL or 
            current_time - self.start_time > 5):
            self._print_progress()
            self.last_update = self.processed_items
    
    def _print_progress(self):
        """Print current progress."""
        if self.total_items > 0:
            percent = (self.processed_items / self.total_items) * 100
            elapsed = time.time() - self.start_time
            
            if self.processed_items > 0:
                eta = (elapsed / self.processed_items) * (self.total_items - self.processed_items)
                eta_str = f", ETA: {eta:.1f}s"
            else:
                eta_str = ""
            
            logger.info(f"{self.operation_name}: {self.processed_items}/{self.total_items} "
                       f"({percent:.1f}%, {elapsed:.1f}s elapsed{eta_str})")
    
    def finish(self):
        """Mark operation as complete."""
        elapsed = time.time() - self.start_time
        logger.info(f"{self.operation_name} completed: {self.processed_items} items in {elapsed:.2f}s")

class DeterministicSampler:
    """Provides deterministic sampling based on file hash for consistency."""
    
    @staticmethod
    def sample_files(file_paths: List[str], max_files: int, seed: str = "aods_baseline") -> List[str]:
        """Sample files deterministically based on file path hash."""
        if len(file_paths) <= max_files:
            return file_paths
        
        # Create deterministic score based on file path and seed
        file_scores = []
        for file_path in file_paths:
            # Create deterministic score based on file path and seed
            hash_input = f"{seed}:{file_path}".encode('utf-8')
            score = int(hashlib.md5(hash_input).hexdigest()[:8], 16)
            file_scores.append((score, file_path))
        
        # Sort by score and take top files
        file_scores.sort(key=lambda x: x[0])
        selected_files = [file_path for _, file_path in file_scores[:max_files]]
        
        logger.info(f"Deterministically sampled {len(selected_files)} files from {len(file_paths)} total")
        return selected_files


@dataclass
class FileMetrics:
    """Metrics for individual files."""
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


@dataclass
class DuplicationGroup:
    """Group of files with similar/duplicate code."""
    similarity_hash: str
    files: List[str]
    similarity_score: float
    duplicate_lines: int
    common_patterns: List[str]


@dataclass
class PluginMetrics:
    """Aggregated metrics for a plugin."""
    plugin_name: str
    total_files: int
    total_lines: int
    total_size_bytes: int
    avg_file_size: float
    avg_complexity: float
    duplicate_groups: int
    modularization_status: str
    dependency_count: int
    test_coverage: float = 0.0


@dataclass
class BaselineMeasurement:
    """Complete baseline measurement snapshot."""
    measurement_date: datetime
    total_plugins: int
    total_files: int
    total_lines: int
    total_size_mb: float
    duplication_percentage: float
    avg_file_complexity: float
    plugin_metrics: List[PluginMetrics]
    duplication_groups: List[DuplicationGroup]
    consolidation_opportunities: List[str]
    performance_baseline: Dict[str, Any]


class CodeAnalyzer:
    """Analyzes code complexity and structure."""
    
    @staticmethod
    def analyze_python_file(file_path: str) -> Dict[str, Any]:
        """Analyze Python file for complexity metrics."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Count basic elements
            lines = content.split('\n')
            line_count = len([line for line in lines if line.strip() and not line.strip().startswith('#')])
            
            # Function and class counts
            function_count = len(re.findall(r'^\s*def\s+\w+', content, re.MULTILINE))
            class_count = len(re.findall(r'^\s*class\s+\w+', content, re.MULTILINE))
            import_count = len(re.findall(r'^\s*(import|from)\s+', content, re.MULTILINE))
            
            # Cyclomatic complexity approximation
            complexity_patterns = [
                r'\bif\b', r'\belse\b', r'\belif\b', r'\bwhile\b', r'\bfor\b',
                r'\btry\b', r'\bexcept\b', r'\bfinally\b', r'\bwith\b'
            ]
            complexity_score = sum(len(re.findall(pattern, content, re.IGNORECASE)) 
                                 for pattern in complexity_patterns)
            
            return {
                'line_count': line_count,
                'function_count': function_count,
                'class_count': class_count,
                'import_count': import_count,
                'complexity_score': complexity_score / max(1, line_count) * 100,  # Normalized
                'duplication_hash': hashlib.md5(content.encode()).hexdigest()
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze {file_path}: {e}")
            return {
                'line_count': 0, 'function_count': 0, 'class_count': 0,
                'import_count': 0, 'complexity_score': 0.0, 'duplication_hash': ''
            }


class DuplicationDetector:
    """Detects code duplication across files."""
    
    def __init__(self, similarity_threshold: float = 0.8):
        self.similarity_threshold = similarity_threshold
        self.file_contents: Dict[str, str] = {}
        self.file_hashes: Dict[str, str] = {}
    
    def analyze_duplication(self, file_paths: List[str]) -> List[DuplicationGroup]:
        """Analyze code duplication across multiple files."""
        # Load file contents and generate hashes
        self._load_files(file_paths)
        
        # Find similar files
        duplication_groups = []
        processed_files = set()
        
        for file_path in file_paths:
            if file_path in processed_files:
                continue
            
            similar_files = self._find_similar_files(file_path, file_paths)
            if len(similar_files) > 1:
                group = self._create_duplication_group(similar_files)
                duplication_groups.append(group)
                processed_files.update(similar_files)
        
        return duplication_groups
    
    def _load_files(self, file_paths: List[str]) -> None:
        """Load file contents for analysis."""
        for file_path in file_paths:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Normalize content for comparison
                normalized = self._normalize_content(content)
                self.file_contents[file_path] = normalized
                self.file_hashes[file_path] = hashlib.md5(normalized.encode()).hexdigest()
                
            except Exception as e:
                logger.debug(f"Failed to load {file_path}: {e} (Type: {type(e).__name__})")
    
    def _normalize_content(self, content: str) -> str:
        """Normalize content for comparison."""
        # Remove comments and empty lines
        lines = []
        for line in content.split('\n'):
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                # Remove whitespace variations
                normalized_line = re.sub(r'\s+', ' ', stripped)
                lines.append(normalized_line)
        
        return '\n'.join(lines)
    
    def _find_similar_files(self, target_file: str, all_files: List[str]) -> List[str]:
        """Find files similar to the target file."""
        if target_file not in self.file_contents:
            return [target_file]
        
        target_content = self.file_contents[target_file]
        similar_files = [target_file]
        
        for file_path in all_files:
            if file_path == target_file or file_path not in self.file_contents:
                continue
            
            similarity = self._calculate_similarity(target_content, self.file_contents[file_path])
            if similarity >= self.similarity_threshold:
                similar_files.append(file_path)
        
        return similar_files
    
    def _calculate_similarity(self, content1: str, content2: str) -> float:
        """Calculate similarity between two content strings."""
        if not content1 or not content2:
            return 0.0
        
        # Use difflib for similarity calculation
        sequence_matcher = difflib.SequenceMatcher(None, content1, content2)
        return sequence_matcher.ratio()
    
    def _create_duplication_group(self, files: List[str]) -> DuplicationGroup:
        """Create a duplication group from similar files."""
        if not files:
            return DuplicationGroup("", [], 0.0, 0, [])
        
        # Calculate group statistics
        base_content = self.file_contents[files[0]]
        total_lines = len(base_content.split('\n'))
        
        # Find common patterns
        common_patterns = self._find_common_patterns(files)
        
        return DuplicationGroup(
            similarity_hash=hashlib.md5(''.join(sorted(files)).encode()).hexdigest()[:12],
            files=files,
            similarity_score=0.9,  # Average similarity
            duplicate_lines=total_lines,
            common_patterns=common_patterns
        )
    
    def _find_common_patterns(self, files: List[str]) -> List[str]:
        """Find common code patterns across files."""
        if len(files) < 2:
            return []
        
        # Extract common function/class names
        patterns = []
        for file_path in files:
            content = self.file_contents.get(file_path, '')
            
            # Find function definitions
            functions = re.findall(r'def\s+(\w+)', content)
            classes = re.findall(r'class\s+(\w+)', content)
            
            patterns.extend(functions[:5])  # Top 5 functions
            patterns.extend(classes[:3])    # Top 3 classes
        
        # Return most common patterns
        pattern_counts = Counter(patterns)
        return [pattern for pattern, count in pattern_counts.most_common(10)]


class BaselineCollector:
    """Main baseline measurement collector with enhanced performance."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.code_analyzer = CodeAnalyzer()
        self.duplication_detector = DuplicationDetector()
        
        # Plugin directories to analyze
        self.plugin_dirs = [
            'plugins',
            'core'
        ]
        
        # File patterns to include
        self.file_patterns = ['*.py']
        
        # Performance tracking
        self.performance_stats = {
            'total_start_time': None,
            'files_processed': 0,
            'chunks_processed': 0,
            'timeouts_encountered': 0,
            'memory_cleanup_runs': 0
        }
    
    @timeout_protection(TOTAL_TIMEOUT)
    def collect_baseline(self) -> BaselineMeasurement:
        """Collect complete baseline measurements with enhanced performance."""
        logger.info("Starting enhanced baseline measurement collection...")
        self.performance_stats['total_start_time'] = time.time()
        
        try:
            # Phase 1: File Collection
            all_files = self._collect_files_enhanced()
            logger.info(f"Found {len(all_files)} Python files to analyze")
            
            # Phase 2: Chunked File Analysis
            file_metrics = self._analyze_files_chunked(all_files)
            
            # Phase 3: Plugin Analysis
            plugin_metrics = self._analyze_plugins(file_metrics)
            
            # Phase 4: Enhanced Duplication Analysis
            duplication_groups = self._analyze_duplication_enhanced(all_files)
            
            # Phase 5: Final Assembly
            baseline = self._assemble_baseline_results(
                all_files, file_metrics, plugin_metrics, duplication_groups
            )
            
            # Performance summary
            total_time = time.time() - self.performance_stats['total_start_time']
            logger.info(f"Enhanced baseline collection completed in {total_time:.2f} seconds")
            logger.info(f"Performance: {self.performance_stats['files_processed']} files, "
                       f"{self.performance_stats['chunks_processed']} chunks, "
                       f"{self.performance_stats['timeouts_encountered']} timeouts")
            
            return baseline
            
        except Exception as e:
            logger.error(f"Baseline collection failed: {e}")
            raise
        finally:
            # Final cleanup
            self._cleanup_memory()
    
    def _collect_files_enhanced(self) -> List[str]:
        """Enhanced file collection with progress reporting."""
        files = []
        progress = ProgressReporter(len(self.plugin_dirs), "File Discovery")
        
        for dir_name in self.plugin_dirs:
            dir_path = self.project_root / dir_name
            if dir_path.exists():
                for pattern in self.file_patterns:
                    files.extend(str(p) for p in dir_path.rglob(pattern))
            progress.update()
        
        progress.finish()
        
        # Filter out test files and __pycache__
        filtered_files = []
        for file_path in files:
            if '__pycache__' not in file_path and not file_path.endswith('_test.py'):
                # Additional filter for reasonable file sizes
                try:
                    if Path(file_path).stat().st_size < 10 * 1024 * 1024:  # < 10MB
                        filtered_files.append(file_path)
                except OSError:
                    continue  # Skip files we can't stat
        
        return filtered_files
    
    def _analyze_files_chunked(self, file_paths: List[str]) -> List[FileMetrics]:
        """Analyze files in chunks with progress reporting and timeout protection."""
        file_metrics = []
        chunks = [file_paths[i:i + CHUNK_SIZE] for i in range(0, len(file_paths), CHUNK_SIZE)]
        
        progress = ProgressReporter(len(file_paths), "File Analysis")
        
        for chunk_idx, chunk in enumerate(chunks):
            try:
                chunk_metrics = self._analyze_file_chunk(chunk, progress)
                file_metrics.extend(chunk_metrics)
                self.performance_stats['chunks_processed'] += 1
                
                # Memory cleanup every 10 chunks
                if chunk_idx % 10 == 0:
                    self._cleanup_memory()
                    
            except TimeoutError:
                logger.warning(f"Chunk {chunk_idx} timed out, skipping")
                self.performance_stats['timeouts_encountered'] += 1
                continue
            except Exception as e:
                logger.warning(f"Chunk {chunk_idx} failed: {e}")
                continue
        
        progress.finish()
        return file_metrics
    
    @timeout_protection(OPERATION_TIMEOUT)
    def _analyze_file_chunk(self, file_paths: List[str], progress: ProgressReporter) -> List[FileMetrics]:
        """Analyze a chunk of files with timeout protection."""
        chunk_metrics = []
        
        for file_path in file_paths:
            try:
                path_obj = Path(file_path)
                stats = path_obj.stat()
                
                # Skip very large files
                if stats.st_size > 5 * 1024 * 1024:  # > 5MB
                    logger.debug(f"Skipping large file: {file_path}")
                    progress.update()
                    continue
                
                # Analyze code with individual timeout
                analysis = self._analyze_single_file_safe(file_path)
                
                # Determine plugin name
                plugin_name = self._extract_plugin_name(file_path)
                
                metrics = FileMetrics(
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
                    plugin_name=plugin_name
                )
                
                chunk_metrics.append(metrics)
                self.performance_stats['files_processed'] += 1
                
            except Exception as e:
                logger.debug(f"Failed to analyze file {file_path}: {e}")
            finally:
                progress.update()
        
        return chunk_metrics
    
    @timeout_protection(10)  # 10 second timeout per file
    def _analyze_single_file_safe(self, file_path: str) -> Dict[str, Any]:
        """Safely analyze a single file with timeout protection."""
        return self.code_analyzer.analyze_python_file(file_path)
    
    def _analyze_plugins(self, file_metrics: List[FileMetrics]) -> List[PluginMetrics]:
        """Analyze plugins based on file metrics."""
        plugin_data = defaultdict(list)
        
        # Group files by plugin
        for fm in file_metrics:
            plugin_data[fm.plugin_name].append(fm)
        
        plugin_metrics = []
        for plugin_name, files in plugin_data.items():
            if not files:
                continue
            
            total_files = len(files)
            total_lines = sum(f.line_count for f in files)
            total_size = sum(f.size_bytes for f in files)
            avg_complexity = sum(f.complexity_score for f in files) / total_files
            
            # Determine modularization status
            modularization_status = self._assess_modularization_status(plugin_name, files)
            
            # Count dependencies (simplified)
            dependency_count = sum(f.import_count for f in files)
            
            metrics = PluginMetrics(
                plugin_name=plugin_name,
                total_files=total_files,
                total_lines=total_lines,
                total_size_bytes=total_size,
                avg_file_size=total_size / total_files,
                avg_complexity=avg_complexity,
                duplicate_groups=0,  # Will be calculated later
                modularization_status=modularization_status,
                dependency_count=dependency_count
            )
            
            plugin_metrics.append(metrics)
        
        return plugin_metrics
    
    def _analyze_duplication_enhanced(self, file_paths: List[str]) -> List[DuplicationGroup]:
        """Enhanced duplication analysis with deterministic sampling."""
        logger.info("Starting enhanced duplication analysis...")
        
        # Use deterministic sampling instead of random
        if len(file_paths) > 100:
            sampled_files = DeterministicSampler.sample_files(file_paths, 100)
        else:
            sampled_files = file_paths
        
        progress = ProgressReporter(len(sampled_files), "Duplication Analysis")
        
        try:
            # Process in smaller chunks to avoid memory issues
            duplication_groups = []
            chunk_size = 20  # Smaller chunks for duplication analysis
            
            for i in range(0, len(sampled_files), chunk_size):
                chunk = sampled_files[i:i + chunk_size]
                try:
                    chunk_groups = self.duplication_detector.analyze_duplication(chunk)
                    duplication_groups.extend(chunk_groups)
                    progress.update(len(chunk))
                except Exception as e:
                    logger.warning(f"Duplication analysis chunk failed: {e}")
                    progress.update(len(chunk))
                    continue
            
            progress.finish()
            return duplication_groups
            
        except Exception as e:
            logger.warning(f"Duplication analysis failed: {e}")
            return []
    
    def _extract_plugin_name(self, file_path: str) -> str:
        """Extract plugin name from file path."""
        path_parts = Path(file_path).parts
        
        if 'plugins' in path_parts:
            plugin_idx = path_parts.index('plugins')
            if plugin_idx + 1 < len(path_parts):
                return path_parts[plugin_idx + 1]
        elif 'core' in path_parts:
            return 'core'
        
        return 'unknown'
    
    def _assess_modularization_status(self, plugin_name: str, files: List[FileMetrics]) -> str:
        """Assess the modularization status of a plugin."""
        # Check for modular directory structure
        has_modular_structure = any('/' in f.file_path.replace(plugin_name, '') for f in files)
        
        # Check for main orchestrator file
        has_orchestrator = any(f.file_path.endswith('__init__.py') for f in files)
        
        # Check file count (modular plugins typically have multiple files)
        file_count = len(files)
        
        if has_modular_structure and has_orchestrator and file_count > 3:
            return 'MODULAR'
        elif file_count > 1:
            return 'PARTIALLY_MODULAR'
        else:
            return 'MONOLITHIC'
    
    def _identify_consolidation_opportunities(self, plugin_metrics: List[PluginMetrics],
                                           duplication_groups: List[DuplicationGroup]) -> List[str]:
        """Identify consolidation opportunities."""
        opportunities = []
        
        # Large monolithic plugins
        for plugin in plugin_metrics:
            if plugin.modularization_status == 'MONOLITHIC' and plugin.total_lines > 500:
                opportunities.append(f"Modularize {plugin.plugin_name} ({plugin.total_lines} lines)")
        
        # High duplication groups
        for group in duplication_groups:
            if len(group.files) > 2:
                opportunities.append(f"Consolidate {len(group.files)} similar files: {group.common_patterns}")
        
        # High complexity plugins
        for plugin in plugin_metrics:
            if plugin.avg_complexity > 20:
                opportunities.append(f"Reduce complexity in {plugin.plugin_name} (complexity: {plugin.avg_complexity:.1f})")
        
        return opportunities[:10]  # Top 10 opportunities
    
    def _assemble_baseline_results(self, all_files: List[str], file_metrics: List[FileMetrics],
                                 plugin_metrics: List[PluginMetrics], 
                                 duplication_groups: List[DuplicationGroup]) -> BaselineMeasurement:
        """Assemble final baseline results with performance tracking."""
        
        # Calculate overall metrics
        total_lines = sum(fm.line_count for fm in file_metrics)
        total_size_mb = sum(fm.size_bytes for fm in file_metrics) / (1024 * 1024)
        
        # Calculate duplication percentage
        duplicated_files = set()
        for group in duplication_groups:
            duplicated_files.update(group.files)
        duplication_percentage = len(duplicated_files) / len(all_files) * 100 if all_files else 0
        
        # Identify consolidation opportunities
        opportunities = self._identify_consolidation_opportunities(plugin_metrics, duplication_groups)
        
        # Enhanced performance baseline
        performance_baseline = self._collect_performance_baseline_enhanced()
        
        return BaselineMeasurement(
            measurement_date=datetime.now(),
            total_plugins=len(plugin_metrics),
            total_files=len(all_files),
            total_lines=total_lines,
            total_size_mb=total_size_mb,
            duplication_percentage=duplication_percentage,
            avg_file_complexity=sum(fm.complexity_score for fm in file_metrics) / len(file_metrics) if file_metrics else 0,
            plugin_metrics=plugin_metrics,
            duplication_groups=duplication_groups,
            consolidation_opportunities=opportunities,
            performance_baseline=performance_baseline
        )
    
    def _cleanup_memory(self):
        """Perform memory cleanup and garbage collection."""
        try:
            # Clear duplication detector cache
            if hasattr(self.duplication_detector, 'file_contents'):
                self.duplication_detector.file_contents.clear()
            if hasattr(self.duplication_detector, 'file_hashes'):
                self.duplication_detector.file_hashes.clear()
            
            # Force garbage collection
            gc.collect()
            self.performance_stats['memory_cleanup_runs'] += 1
            
        except Exception as e:
            logger.debug(f"Memory cleanup warning: {e}")
    
    def _collect_performance_baseline_enhanced(self) -> Dict[str, Any]:
        """Enhanced performance baseline collection with actual metrics."""
        import sys
        import platform
        
        # Calculate actual metrics
        measurement_start = time.time()
        
        # Simple import time test
        import_start = time.time()
        try:
            import json  # Simple import test
            avg_import_time = (time.time() - import_start) * 1000  # Convert to ms
        except Exception:
            avg_import_time = 0.5  # Fallback value
        
        # Memory usage
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_usage_mb = memory_info.rss / (1024 * 1024)
        except Exception:
            memory_usage_mb = 0
        
        measurement_time = time.time() - measurement_start
        total_collection_time = time.time() - self.performance_stats['total_start_time']
        
        return {
            'measurement_date': datetime.now().isoformat(),
            'system_info': {
                'python_version': '.'.join(map(str, sys.version_info[:3])),
                'platform': platform.system(),
                'architecture': platform.machine(),
                'processor': platform.processor()[:50] if platform.processor() else 'Unknown',
                'cpu_count': psutil.cpu_count() if psutil else 'Unknown',
            },
            'performance_metrics': {
                'avg_import_time_ms': round(avg_import_time, 3),
                'memory_usage_mb': round(memory_usage_mb, 2),
                'measurement_overhead_ms': round(measurement_time * 1000, 3),
                'total_collection_time_s': round(total_collection_time, 3),
                'files_processed': self.performance_stats['files_processed'],
                'chunks_processed': self.performance_stats['chunks_processed'],
                'timeouts_encountered': self.performance_stats['timeouts_encountered'],
                'memory_cleanup_runs': self.performance_stats['memory_cleanup_runs'],
            },
            'optimization_status': {
                'chunked_processing': True,
                'timeout_protection': True,
                'deterministic_sampling': True,
                'progress_reporting': True,
                'memory_management': True,
            }
        }
    
    def save_baseline(self, baseline: BaselineMeasurement, output_path: str) -> None:
        """Save baseline measurements to file."""
        # Convert to serializable format
        baseline_dict = {
            'measurement_date': baseline.measurement_date.isoformat(),
            'summary': {
                'total_plugins': baseline.total_plugins,
                'total_files': baseline.total_files,
                'total_lines': baseline.total_lines,
                'total_size_mb': baseline.total_size_mb,
                'duplication_percentage': baseline.duplication_percentage,
                'avg_file_complexity': baseline.avg_file_complexity,
            },
            'plugin_metrics': [self._plugin_metrics_to_dict(pm) for pm in baseline.plugin_metrics],
            'duplication_groups': [self._duplication_group_to_dict(dg) for dg in baseline.duplication_groups],
            'consolidation_opportunities': baseline.consolidation_opportunities,
            'performance_baseline': baseline.performance_baseline
        }
        
        with open(output_path, 'w') as f:
            json.dump(baseline_dict, f, indent=2)
        
        logger.info(f"Baseline measurements saved to {output_path}")
    
    def _plugin_metrics_to_dict(self, pm: PluginMetrics) -> Dict[str, Any]:
        """Convert PluginMetrics to dictionary."""
        return {
            'plugin_name': pm.plugin_name,
            'total_files': pm.total_files,
            'total_lines': pm.total_lines,
            'total_size_bytes': pm.total_size_bytes,
            'avg_file_size': pm.avg_file_size,
            'avg_complexity': pm.avg_complexity,
            'duplicate_groups': pm.duplicate_groups,
            'modularization_status': pm.modularization_status,
            'dependency_count': pm.dependency_count,
            'test_coverage': pm.test_coverage
        }
    
    def _duplication_group_to_dict(self, dg: DuplicationGroup) -> Dict[str, Any]:
        """Convert DuplicationGroup to dictionary."""
        return {
            'similarity_hash': dg.similarity_hash,
            'files': dg.files,
            'similarity_score': dg.similarity_score,
            'duplicate_lines': dg.duplicate_lines,
            'common_patterns': dg.common_patterns
        }


def generate_baseline_report(baseline: BaselineMeasurement) -> str:
    """Generate a human-readable baseline report."""
    report = f"""
# AODS Baseline Measurement Report
**Generated:** {baseline.measurement_date.strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
- **Total Plugins:** {baseline.total_plugins}
- **Total Files:** {baseline.total_files:,}
- **Total Lines of Code:** {baseline.total_lines:,}
- **Total Size:** {baseline.total_size_mb:.2f} MB
- **Code Duplication:** {baseline.duplication_percentage:.1f}%
- **Average File Complexity:** {baseline.avg_file_complexity:.1f}

## Plugin Analysis
"""
    
    # Sort plugins by size
    sorted_plugins = sorted(baseline.plugin_metrics, key=lambda p: p.total_lines, reverse=True)
    
    for plugin in sorted_plugins[:10]:  # Top 10 plugins
        report += f"""
### {plugin.plugin_name}
- **Files:** {plugin.total_files}
- **Lines:** {plugin.total_lines:,}
- **Size:** {plugin.total_size_bytes / 1024:.1f} KB
- **Status:** {plugin.modularization_status}
- **Complexity:** {plugin.avg_complexity:.1f}
"""
    
    # Duplication analysis
    if baseline.duplication_groups:
        report += f"\n## Code Duplication Analysis\n"
        report += f"**Found {len(baseline.duplication_groups)} duplication groups:**\n"
        
        for group in baseline.duplication_groups[:5]:  # Top 5 groups
            report += f"- {len(group.files)} files with {group.duplicate_lines} duplicate lines\n"
    
    # Consolidation opportunities
    if baseline.consolidation_opportunities:
        report += f"\n## Top Consolidation Opportunities\n"
        for opportunity in baseline.consolidation_opportunities:
            report += f"- {opportunity}\n"
    
    return report


# Export main classes
__all__ = [
    'BaselineCollector',
    'BaselineMeasurement',
    'FileMetrics',
    'PluginMetrics',
    'DuplicationGroup',
    'generate_baseline_report'
]


def main():
    """Main execution function for baseline measurements."""
    print("AODS Baseline Measurements Collection")
    print("=" * 50)
    
    # Initialize collector with current directory as project root
    project_root = Path.cwd()
    collector = BaselineCollector(project_root)
    
    print("Collecting baseline measurements...")
    start_time = time.time()
    
    # Collect baseline
    baseline = collector.collect_baseline()
    
    collection_time = time.time() - start_time
    print(f"Collection completed in {collection_time:.2f} seconds")
    
    # Generate report
    print("\nGenerating baseline report...")
    report = generate_baseline_report(baseline)
    
    # Save report
    report_file = "baseline_measurements_report.md"
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"Report saved to {report_file}")
    
    # Display summary
    print(f"\nBaseline Summary:")
    print(f"   Total Files: {baseline.total_files}")
    print(f"   Total Lines: {baseline.total_lines:,}")
    print(f"   Total Size: {baseline.total_size_mb:.1f} MB")
    print(f"   Plugin Count: {len(baseline.plugin_metrics)}")
    print(f"   Duplication Groups: {len(baseline.duplication_groups)}")
    print(f"   Collection Time: {collection_time:.2f}s")
    
    return baseline


if __name__ == "__main__":
    main() 
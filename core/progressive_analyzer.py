"""
Progressive Analysis Architecture

This module implements intelligent, sample-based analysis for enterprise-scale APKs
to prevent memory overflow and improve analysis performance while maintaining
detection quality.

Key Features:
- Sample-based analysis for apps >100MB
- Chunked processing to prevent memory overflow
- Confidence-threshold filtering for enterprise apps
- Framework-specific extraction strategies
- Adaptive resource management

MASVS Controls Covered:
- MSTG-CODE-1: Code Quality and Build Settings
- MSTG-ARCH-1: Architecture, Design and Threat Modeling
"""

import logging
import math
import time
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from rich.console import Console
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                           TimeElapsedColumn)

from core.apk_ctx import APKContext

class AnalysisStrategy(Enum):
    """Analysis strategy types based on APK characteristics."""

    STANDARD = "standard"  # <50MB, standard analysis
    OPTIMIZED = "optimized"  # 50-100MB, light optimization
    PROGRESSIVE = "progressive"  # 100-200MB, progressive sampling
    ENTERPRISE = "enterprise"  # >200MB, aggressive sampling
    FRAMEWORK_AWARE = "framework"  # Framework-specific optimizations

@dataclass
class AnalysisConfig:
    """Configuration for progressive analysis."""

    strategy: AnalysisStrategy
    max_files_to_analyze: int = 500
    chunk_size: int = 100
    memory_limit_mb: int = 512
    timeout_seconds: int = 300
    confidence_threshold: float = 0.7
    sample_rate: float = 1.0  # 1.0 = 100%, 0.1 = 10%
    max_file_size_mb: int = 20
    prioritize_by_type: bool = True
    enable_deep_analysis: bool = True

    # Framework-specific settings
    framework_name: Optional[str] = None
    framework_optimizations: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FileAnalysisResult:
    """Result of analyzing a single file."""

    file_path: str
    file_size: int
    analysis_time: float
    findings_count: int
    confidence_scores: List[float] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: Optional[str] = None

@dataclass
class ProgressiveAnalysisResult:
    """Result of progressive analysis."""

    strategy_used: AnalysisStrategy
    total_files: int
    analyzed_files: int
    skipped_files: int
    total_analysis_time: float
    memory_usage_peak_mb: float
    file_results: List[FileAnalysisResult] = field(default_factory=list)
    summary_stats: Dict[str, Any] = field(default_factory=dict)
    optimization_details: Dict[str, Any] = field(default_factory=dict)

class ProgressiveAnalyzer:
    """Advanced progressive analysis engine for enterprise APKs."""

    def __init__(self):
        """Initialize the progressive analyzer."""
        self.console = Console()

        # File type priorities (lower number = higher priority)
        self.file_type_priorities = {
            # Configuration files (highest priority)
            ".xml": 1,
            ".json": 1,
            ".properties": 1,
            ".yml": 1,
            ".yaml": 1,
            # Source code (high priority)
            ".java": 2,
            ".kt": 2,
            ".smali": 3,
            # Resources (medium priority)
            ".txt": 4,
            ".sql": 4,
            ".js": 4,
            ".html": 4,
            ".css": 4,
            # Binary files (lower priority)
            ".so": 5,
            ".dex": 5,
            ".jar": 5,
            ".zip": 6,
            # Asset files (lowest priority)
            ".png": 7,
            ".jpg": 7,
            ".jpeg": 7,
            ".gif": 7,
            ".mp4": 8,
            ".mp3": 8,
        }

        # Framework-specific file patterns to prioritize or skip
        self.framework_patterns = {
            "meta_react_native": {
                "priority_files": [
                    "AndroidManifest.xml",
                    "index.android.bundle",
                    "assets/hermes/",
                    "classes.dex",
                ],
                "skip_patterns": ["node_modules/", "assets/flipper/"],
            },
            "google_flutter": {
                "priority_files": [
                    "AndroidManifest.xml",
                    "assets/flutter_assets/",
                    "isolate_snapshot_data",
                    "vm_snapshot_data",
                ],
                "skip_patterns": ["assets/fonts/", "assets/packages/"],
            },
        }

    def determine_analysis_strategy(self, apk_ctx: APKContext) -> AnalysisConfig:
        """Determine optimal analysis strategy based on APK characteristics."""

        # Get APK size
        apk_size_mb = apk_ctx.apk_path.stat().st_size / (1024 * 1024)

        # Check for enterprise framework detection
        framework_info = apk_ctx.get_cache("enterprise_framework")
        framework_name = framework_info.get("primary") if framework_info else None

        logging.debug(f"Determining analysis strategy for {apk_size_mb:.1f}MB APK")
        if framework_name:
            logging.debug(f"Enterprise framework detected: {framework_name}")

        # Base configuration selection
        if apk_size_mb < 50:
            strategy = AnalysisStrategy.STANDARD
            config = AnalysisConfig(
                strategy=strategy,
                max_files_to_analyze=1000,
                chunk_size=200,
                memory_limit_mb=512,
                timeout_seconds=300,
                confidence_threshold=0.6,
                sample_rate=1.0,
                enable_deep_analysis=True,
            )

        elif apk_size_mb < 100:
            strategy = AnalysisStrategy.OPTIMIZED
            config = AnalysisConfig(
                strategy=strategy,
                max_files_to_analyze=500,
                chunk_size=150,
                memory_limit_mb=384,
                timeout_seconds=240,
                confidence_threshold=0.7,
                sample_rate=0.8,
                max_file_size_mb=30,
            )

        elif apk_size_mb < 200:
            strategy = AnalysisStrategy.PROGRESSIVE
            config = AnalysisConfig(
                strategy=strategy,
                max_files_to_analyze=300,
                chunk_size=100,
                memory_limit_mb=256,
                timeout_seconds=180,
                confidence_threshold=0.75,
                sample_rate=0.5,
                max_file_size_mb=20,
            )

        else:
            strategy = AnalysisStrategy.ENTERPRISE
            config = AnalysisConfig(
                strategy=strategy,
                max_files_to_analyze=150,
                chunk_size=50,
                memory_limit_mb=256,
                timeout_seconds=120,
                confidence_threshold=0.8,
                sample_rate=0.3,
                max_file_size_mb=10,
                enable_deep_analysis=False,
            )

        # Apply framework-specific optimizations
        if framework_name and framework_name in self.framework_patterns:
            strategy = AnalysisStrategy.FRAMEWORK_AWARE
            config.strategy = strategy
            config.framework_name = framework_name
            config.framework_optimizations = self._get_framework_optimizations(
                framework_name
            )

            # Apply framework-specific limits from enterprise detector
            if framework_info and "strategy" in framework_info:
                fw_strategy = framework_info["strategy"]
                config.max_files_to_analyze = min(
                    config.max_files_to_analyze,
                    fw_strategy.get(
                        "file_processing_limit", config.max_files_to_analyze
                    ),
                )
                config.memory_limit_mb = min(
                    config.memory_limit_mb,
                    fw_strategy.get("memory_limit_mb", config.memory_limit_mb),
                )
                config.timeout_seconds = min(
                    config.timeout_seconds,
                    fw_strategy.get("timeout_seconds", config.timeout_seconds),
                )
                config.confidence_threshold = max(
                    config.confidence_threshold,
                    fw_strategy.get(
                        "confidence_threshold", config.confidence_threshold
                    ),
                )

        logging.debug(f"Selected strategy: {strategy.value}")
        logging.debug(
            f"File limit: {config.max_files_to_analyze}, Memory: {config.memory_limit_mb}MB"
        )
        logging.debug(
            f"Sample rate: {config.sample_rate:.1%}, Timeout: {config.timeout_seconds}s"
        )

        return config

    def _get_framework_optimizations(self, framework_name: str) -> Dict[str, Any]:
        """Get framework-specific optimization settings."""
        return self.framework_patterns.get(framework_name, {})

    def get_prioritized_file_list(
        self, apk_zip: zipfile.ZipFile, config: AnalysisConfig
    ) -> List[Tuple[int, zipfile.ZipInfo]]:
        """Get prioritized list of files to analyze based on strategy."""

        file_info_list = []
        framework_opts = config.framework_optimizations

        for file_info in apk_zip.infolist():
            if file_info.is_dir():
                continue

            file_path = file_info.filename
            file_size_mb = file_info.file_size / (1024 * 1024)

            # Skip files that are too large
            if file_size_mb > config.max_file_size_mb:
                logging.debug(
                    f"Skipping large file: {file_path} ({file_size_mb:.1f}MB)"
                )
                continue

            # Framework-specific filtering
            if config.framework_name and framework_opts:
                # Check skip patterns
                skip_patterns = framework_opts.get("skip_patterns", [])
                if any(pattern in file_path for pattern in skip_patterns):
                    logging.debug(f"Skipping framework noise file: {file_path}")
                    continue

                # Special handling for DEX files in large apps
                if (
                    file_path.startswith("classes")
                    and file_path.endswith(".dex")
                ):
                    max_dex = framework_opts.get("max_dex_files", 10)
                    dex_num = self._extract_dex_number(file_path)
                    if dex_num and dex_num > max_dex:
                        logging.debug(f"Skipping DEX file beyond limit: {file_path}")
                        continue

            # Calculate priority
            priority = self._calculate_file_priority(file_path, config)
            file_info_list.append((priority, file_info))

        # Sort by priority (lower number = higher priority)
        file_info_list.sort(key=lambda x: x[0])

        # Apply sampling if needed
        if config.sample_rate < 1.0:
            sample_size = int(len(file_info_list) * config.sample_rate)
            file_info_list = file_info_list[:sample_size]
            logging.debug(
                f"Sampling {sample_size}/{len(file_info_list)} files ({config.sample_rate:.1%})"
            )

        # Apply file count limit
        if len(file_info_list) > config.max_files_to_analyze:
            file_info_list = file_info_list[: config.max_files_to_analyze]
            logging.debug(
                f"Limited to {config.max_files_to_analyze} highest priority files"
            )

        return file_info_list

    def _extract_dex_number(self, dex_filename: str) -> Optional[int]:
        """Extract DEX file number from filename (e.g., classes15.dex -> 15)."""
        try:
            if dex_filename == "classes.dex":
                return 1
            elif dex_filename.startswith("classes") and dex_filename.endswith(".dex"):
                num_str = dex_filename[7:-4]  # Remove "classes" and ".dex"
                return int(num_str)
        except ValueError:
            pass
        return None

    def _calculate_file_priority(self, file_path: str, config: AnalysisConfig) -> int:
        """Calculate file analysis priority (lower = higher priority)."""

        # Framework-specific priority files
        if config.framework_optimizations:
            priority_files = config.framework_optimizations.get("priority_files", [])
            for i, priority_file in enumerate(priority_files):
                if priority_file in file_path:
                    return i  # Highest priority (0, 1, 2, ...)

        # File type priority
        file_ext = Path(file_path).suffix.lower()
        type_priority = self.file_type_priorities.get(
            file_ext, 9
        )  # Default to lowest priority

        # Boost priority for certain file names
        filename = Path(file_path).name.lower()

        if "manifest" in filename:
            return 1
        elif "string" in filename:
            return 2
        elif "config" in filename:
            return 3
        elif "security" in filename:
            return 3
        elif "network" in filename:
            return 4
        elif filename == "classes.dex":
            return 5

        # Directory-based priority adjustments
        if "/res/xml/" in file_path:
            type_priority -= 1  # Boost XML resources
        elif "/assets/" in file_path and file_ext in [".json", ".xml", ".properties"]:
            type_priority -= 1  # Boost config assets
        elif "/smali/" in file_path:
            type_priority += 2  # Lower smali priority

        return max(1, type_priority)

    def analyze_files_progressively(
        self,
        file_list: List[Tuple[int, zipfile.ZipInfo]],
        apk_zip: zipfile.ZipFile,
        config: AnalysisConfig,
        analyzer_func: callable,
    ) -> ProgressiveAnalysisResult:
        """Analyze files progressively with chunking and monitoring."""

        start_time = time.time()
        result = ProgressiveAnalysisResult(
            strategy_used=config.strategy,
            total_files=len(file_list),
            analyzed_files=0,
            skipped_files=0,
            total_analysis_time=0.0,
            memory_usage_peak_mb=0.0,
        )

        # Progress tracking
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:

            task = progress.add_task(
                f"Progressive analysis ({config.strategy.value})", total=len(file_list)
            )

            # Process files in chunks
            for chunk_start in range(0, len(file_list), config.chunk_size):
                chunk_end = min(chunk_start + config.chunk_size, len(file_list))
                chunk = file_list[chunk_start:chunk_end]

                logging.debug(
                    f"Processing chunk {chunk_start//config.chunk_size + 1}: files {chunk_start}-{chunk_end}"
                )

                # Analyze chunk
                chunk_results = self._analyze_chunk(
                    chunk, apk_zip, config, analyzer_func
                )
                result.file_results.extend(chunk_results)

                # Update progress
                progress.update(task, advance=len(chunk))
                result.analyzed_files += sum(1 for r in chunk_results if not r.skipped)
                result.skipped_files += sum(1 for r in chunk_results if r.skipped)

                # Check timeout
                elapsed = time.time() - start_time
                if elapsed > config.timeout_seconds:
                    logging.warning(
                        f"Progressive analysis timeout after {elapsed:.1f}s"
                    )
                    break

                # Memory check (simplified)
                # In production, you would use psutil or similar

        result.total_analysis_time = time.time() - start_time

        # Generate summary statistics
        result.summary_stats = self._generate_summary_stats(result)
        result.optimization_details = {
            "strategy": config.strategy.value,
            "sample_rate": config.sample_rate,
            "file_limit": config.max_files_to_analyze,
            "chunk_size": config.chunk_size,
            "framework": config.framework_name,
            "total_files_in_apk": result.total_files,
            "analysis_efficiency": (
                result.analyzed_files / result.total_files
                if result.total_files > 0
                else 0
            ),
        }

        logging.debug(
            f"Progressive analysis completed: {result.analyzed_files}/{result.total_files} files in {result.total_analysis_time:.1f}s"
        )

        return result

    def _analyze_chunk(
        self,
        chunk: List[Tuple[int, zipfile.ZipInfo]],
        apk_zip: zipfile.ZipFile,
        config: AnalysisConfig,
        analyzer_func: callable,
    ) -> List[FileAnalysisResult]:
        """Analyze a chunk of files."""

        chunk_results = []

        for priority, file_info in chunk:
            file_start_time = time.time()
            file_result = FileAnalysisResult(
                file_path=file_info.filename,
                file_size=file_info.file_size,
                analysis_time=0.0,
                findings_count=0,
            )

            try:
                # Check if file should be skipped
                skip_reason = self._should_skip_file(file_info, config)
                if skip_reason:
                    file_result.skipped = True
                    file_result.skip_reason = skip_reason
                    chunk_results.append(file_result)
                    continue

                # Read file content
                file_content = apk_zip.read(file_info.filename)

                # Apply framework-specific filtering
                if config.framework_name == "bytedance_tiktok":
                    if config.framework_optimizations.get("chinese_string_filter"):
                        file_content = self._filter_chinese_strings(file_content)

                # Call the actual analyzer function
                analysis_result = analyzer_func(
                    file_content, file_info.filename, config
                )

                if analysis_result:
                    file_result.findings_count = len(
                        analysis_result.get("findings", [])
                    )
                    file_result.confidence_scores = [
                        finding.get("confidence", 0.0)
                        for finding in analysis_result.get("findings", [])
                    ]

            except Exception as e:
                file_result.errors.append(str(e))
                logging.debug(f"Error analyzing {file_info.filename}: {e}")

            file_result.analysis_time = time.time() - file_start_time
            chunk_results.append(file_result)

        return chunk_results

    def _should_skip_file(
        self, file_info: zipfile.ZipInfo, config: AnalysisConfig
    ) -> Optional[str]:
        """Determine if file should be skipped and return reason."""

        file_path = file_info.filename
        file_size_mb = file_info.file_size / (1024 * 1024)

        # Size check
        if file_size_mb > config.max_file_size_mb:
            return f"file too large ({file_size_mb:.1f}MB)"

        # Framework-specific skips
        if config.framework_optimizations:
            skip_patterns = config.framework_optimizations.get("skip_patterns", [])
            for pattern in skip_patterns:
                if pattern in file_path:
                    return f"framework noise ({pattern})"

        # Binary file checks for enterprise strategy
        if config.strategy == AnalysisStrategy.ENTERPRISE:
            file_ext = Path(file_path).suffix.lower()
            if file_ext in [".png", ".jpg", ".jpeg", ".gif", ".mp4", ".mp3", ".so"]:
                return "binary file in enterprise mode"

        return None

    def _filter_chinese_strings(self, file_content: bytes) -> bytes:
        """Filter out Chinese characters to reduce false positives."""
        try:
            # Convert to string and filter Chinese characters
            content_str = file_content.decode("utf-8", errors="ignore")

            # Simple Chinese character range filtering
            filtered_chars = []
            for char in content_str:
                # Skip Chinese characters (simplified check)
                if ord(char) < 0x4E00 or ord(char) > 0x9FFF:
                    filtered_chars.append(char)

            return "".join(filtered_chars).encode("utf-8", errors="ignore")
        except:
            return file_content

    def _generate_summary_stats(
        self, result: ProgressiveAnalysisResult
    ) -> Dict[str, Any]:
        """Generate summary statistics for the analysis."""

        total_findings = sum(r.findings_count for r in result.file_results)
        high_confidence_findings = sum(
            1
            for r in result.file_results
            for score in r.confidence_scores
            if score >= 0.8
        )

        avg_analysis_time = (
            sum(r.analysis_time for r in result.file_results) / len(result.file_results)
            if result.file_results
            else 0.0
        )

        return {
            "total_findings": total_findings,
            "high_confidence_findings": high_confidence_findings,
            "average_analysis_time_per_file": avg_analysis_time,
            "files_with_findings": sum(
                1 for r in result.file_results if r.findings_count > 0
            ),
            "files_with_errors": sum(1 for r in result.file_results if r.errors),
            "skip_reasons": {
                reason: sum(1 for r in result.file_results if r.skip_reason == reason)
                for reason in set(
                    r.skip_reason for r in result.file_results if r.skip_reason
                )
            },
        }

    def configure_enterprise_strategy(
        self, strategy_name: str, sample_rate: float
    ) -> bool:
        """
        Configure enterprise-specific analysis strategy.

        Args:
            strategy_name: Strategy name (minimal, reduced, standard)
            sample_rate: Sampling rate (0.02 = 2%, 0.05 = 5%, 0.10 = 10%)

        Returns:
            bool: True if configuration successful
        """
        try:
            logging.debug(
                f"Configuring enterprise strategy: {strategy_name} with {sample_rate:.1%} sampling"
            )

            # Store configuration for later use
            self.enterprise_config = {
                "strategy_name": strategy_name,
                "sample_rate": sample_rate,
                "configured": True,
            }

            # Set strategy-specific parameters
            if strategy_name == "minimal":
                self.file_type_priorities.update(
                    {
                        ".png": 20,
                        ".jpg": 20,
                        ".jpeg": 20,
                        ".gif": 20,  # Deprioritize media
                        ".mp4": 25,
                        ".mp3": 25,
                        ".wav": 25,  # Very low priority for media
                        ".so": 15,  # Reduce native library priority
                    }
                )

            elif strategy_name == "reduced":
                self.file_type_priorities.update(
                    {
                        ".png": 10,
                        ".jpg": 10,
                        ".jpeg": 10,  # Moderate media priority
                        ".mp4": 15,
                        ".mp3": 15,  # Lower media priority
                    }
                )

            # Standard strategy uses default priorities

            logging.debug(
                f"Enterprise strategy configured successfully: {strategy_name}"
            )
            return True

        except Exception as e:
            logging.error(f"Failed to configure enterprise strategy: {e}")
            return False

def get_progressive_analyzer() -> ProgressiveAnalyzer:
    """Get the global progressive analyzer instance."""
    return ProgressiveAnalyzer()

# Example usage function for integration with existing plugins
def apply_progressive_analysis(
    apk_ctx: APKContext, analyzer_func: callable
) -> ProgressiveAnalysisResult:
    """
    Apply progressive analysis to an APK with the given analyzer function.

    Args:
        apk_ctx: APK context
        analyzer_func: Function that analyzes file content and returns results

    Returns:
        ProgressiveAnalysisResult with analysis details
    """

    progressive_analyzer = get_progressive_analyzer()

    # Determine analysis strategy
    config = progressive_analyzer.determine_analysis_strategy(apk_ctx)

    # Analyze progressively
    with zipfile.ZipFile(apk_ctx.apk_path, "r") as apk_zip:
        # Get prioritized file list
        file_list = progressive_analyzer.get_prioritized_file_list(apk_zip, config)

        # Run progressive analysis
        result = progressive_analyzer.analyze_files_progressively(
            file_list, apk_zip, config, analyzer_func
        )

    return result

if __name__ == "__main__":
    # Example test
    from pathlib import Path

    def dummy_analyzer(content: bytes, filename: str, config: AnalysisConfig) -> Dict:
        """Dummy analyzer for testing."""
        return (
            {"findings": [{"confidence": 0.8}]}
            if len(content) > 1000
            else {"findings": []}
        )

    apk_path = Path("tiktok-35-6-3-unpinned.apk")
    if apk_path.exists():
        from core.apk_ctx import APKContext

        apk_ctx = APKContext(apk_path, "com.zhiliaoapp.musically")
        result = apply_progressive_analysis(apk_ctx, dummy_analyzer)

        print(f"Strategy: {result.strategy_used.value}")
        print(f"Files analyzed: {result.analyzed_files}/{result.total_files}")
        print(f"Time: {result.total_analysis_time:.1f}s")
        print(f"Findings: {result.summary_stats['total_findings']}")
    else:
        print("Test APK not found")

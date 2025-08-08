"""
AODS APK Size-Based Processing Optimization

Implements APK size classification and processing strategy selection
with processing time estimation, ETA reporting, and system resource optimization.

Features:
- APK size classification (Small: 0-50MB, Medium: 50-200MB, Large: 200-500MB, Extra Large: >500MB)
- Size-based timeout determination with scaling
- Thread allocation optimization based on size and system resources
- Memory limit enforcement per size category (512MB-4GB)
- Processing time estimation and ETA reporting
- Background processing determination for large APKs (>200MB)
- Integration with JADX Separate Process Manager

"""

import os
import sys
import time
import psutil
import logging
import statistics
from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

class ProcessingStrategy(Enum):
    """Processing strategy based on APK size and complexity."""
    STANDARD = "standard"        # Small APKs (0-50MB)
    ENHANCED = "enhanced"        # Medium APKs (50-200MB)
    STAGED = "staged"           # Large APKs (200-500MB)
    SELECTIVE = "selective"     # Extra Large APKs (>500MB)

@dataclass
class SystemResources:
    """Current system resource availability."""
    total_memory_gb: float
    available_memory_gb: float
    cpu_cores: int
    cpu_usage_percent: float
    disk_free_gb: float
    memory_pressure: str  # LOW, MEDIUM, HIGH

@dataclass
class ProcessingTimeEstimate:
    """Processing time estimation with confidence intervals."""
    estimated_seconds: int
    min_seconds: int
    max_seconds: int
    confidence_level: float
    factors_considered: List[str]
    eta_description: str

@dataclass
class APKSizeClassification:
    """APK size classification with processing recommendations."""
    size_mb: float
    category: str
    strategy: ProcessingStrategy
    timeout_seconds: int
    max_threads: int
    max_memory_mb: int
    reasoning: str
    background_processing: bool
    processing_estimate: ProcessingTimeEstimate
    system_resources: SystemResources
    optimization_flags: Dict[str, Any]

@dataclass
class ProcessingConfig:
    """Configuration for APK processing optimization."""
    # Size thresholds in MB (Task SO.2 requirement)
    small_threshold: float = 50.0      # 0-50MB
    medium_threshold: float = 200.0    # 50-200MB
    large_threshold: float = 500.0     # 200-500MB
    # Extra Large: >500MB
    
    # Default timeouts in seconds (Task SO.2 requirement)
    standard_timeout: int = 180    # 3 minutes
    enhanced_timeout: int = 300    # 5 minutes
    staged_timeout: int = 600      # 10 minutes
    selective_timeout: int = 900   # 15 minutes
    
    # Resource limits (Task SO.2 requirement: 512MB-4GB)
    max_memory_standard: int = 512   # MB
    max_memory_enhanced: int = 1024  # MB
    max_memory_staged: int = 2048    # MB
    max_memory_selective: int = 4096 # MB
    
    # Threading configuration (Task SO.2 requirement: 1-4 threads)
    max_threads_standard: int = 4
    max_threads_enhanced: int = 3
    max_threads_staged: int = 2
    max_threads_selective: int = 1
    
    # Processing time estimation parameters
    base_processing_time_per_mb: float = 2.5  # seconds per MB
    complexity_multiplier_range: Tuple[float, float] = (0.8, 2.5)
    system_load_adjustment: bool = True
    confidence_threshold: float = 0.75

class EnhancedAPKSizeOptimizer:
    """
    APK Size-Based Processing Optimizer
    
    Analyzes APK size and system resources to determine optimal processing strategy
    with processing time estimation, ETA reporting, and resource optimization.
    """
    
    def __init__(self, config: Optional[ProcessingConfig] = None):
        """Initialize optimizer with configuration."""
        self.config = config or ProcessingConfig()
        self.processing_history: List[Dict[str, Any]] = []
        self.system_baseline = self._establish_system_baseline()
        logger.info("APK Size Optimizer initialized")
    
    def analyze_apk_with_estimation(self, apk_path: str) -> APKSizeClassification:
        """
        APK analysis with processing time estimation.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            APKSizeClassification with processing recommendations
        """
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        
        # Get APK size and system resources
        size_bytes = os.path.getsize(apk_path)
        size_mb = size_bytes / (1024 * 1024)
        system_resources = self._get_system_resources()
        
        # Classify size and determine strategy
        category, strategy = self._classify_apk_size(size_mb)
        
        # Get processing parameters with system resource optimization
        timeout = self._get_timeout_for_strategy(strategy, size_mb, system_resources)
        max_threads = self._get_optimized_threads(strategy, system_resources)
        max_memory = self._get_optimized_memory(strategy, system_resources)
        
        # Determine background processing (Implementation: >200MB)
        background_processing = self._should_use_background_processing(size_mb, strategy)
        
        # Generate processing time estimate with ETA
        processing_estimate = self._estimate_processing_time(size_mb, strategy, system_resources)
        
        # Generate optimization flags
        optimization_flags = self._generate_optimization_flags(size_mb, strategy, system_resources)
        
        # Generate reasoning
        reasoning = self._generate_enhanced_reasoning(size_mb, category, strategy, processing_estimate)
        
        classification = APKSizeClassification(
            size_mb=size_mb,
            category=category,
            strategy=strategy,
            timeout_seconds=timeout,
            max_threads=max_threads,
            max_memory_mb=max_memory,
            reasoning=reasoning,
            background_processing=background_processing,
            processing_estimate=processing_estimate,
            system_resources=system_resources,
            optimization_flags=optimization_flags
        )
        
        logger.info(f"APK {apk_path} classified as {category} ({size_mb:.1f}MB) -> {strategy.value}")
        logger.info(f"Estimated processing time: {processing_estimate.estimated_seconds}s (±{processing_estimate.confidence_level*100:.0f}%)")
        logger.info(f"Background processing: {background_processing}")
        
        return classification
    
    def _classify_apk_size(self, size_mb: float) -> Tuple[str, ProcessingStrategy]:
        """Classify APK size into processing category."""
        if size_mb <= self.config.small_threshold:
            return "SMALL", ProcessingStrategy.STANDARD
        elif size_mb <= self.config.medium_threshold:
            return "MEDIUM", ProcessingStrategy.ENHANCED
        elif size_mb <= self.config.large_threshold:
            return "LARGE", ProcessingStrategy.STAGED
        else:
            return "EXTRA_LARGE", ProcessingStrategy.SELECTIVE
    
    def _get_timeout_for_strategy(self, strategy: ProcessingStrategy, size_mb: float, 
                                 system_resources: SystemResources) -> int:
        """Get timeout configuration with size and system-based scaling."""
        base_timeout_map = {
            ProcessingStrategy.STANDARD: self.config.standard_timeout,
            ProcessingStrategy.ENHANCED: self.config.enhanced_timeout,
            ProcessingStrategy.STAGED: self.config.staged_timeout,
            ProcessingStrategy.SELECTIVE: self.config.selective_timeout
        }
        
        base_timeout = base_timeout_map[strategy]
        
        # Apply size-based scaling for edge cases
        if strategy == ProcessingStrategy.STAGED and size_mb > 400:
            base_timeout = int(base_timeout * 1.2)  # 20% increase for very large APKs
        elif strategy == ProcessingStrategy.SELECTIVE and size_mb > 800:
            base_timeout = int(base_timeout * 1.3)  # 30% increase for massive APKs
        
        # Apply system resource adjustments
        if system_resources.memory_pressure == "HIGH":
            base_timeout = int(base_timeout * 1.4)  # More time under memory pressure
        elif system_resources.cpu_usage_percent > 80:
            base_timeout = int(base_timeout * 1.2)  # More time under CPU pressure
        
        return base_timeout
    
    def _get_optimized_threads(self, strategy: ProcessingStrategy, 
                              system_resources: SystemResources) -> int:
        """Get optimized thread count based on strategy and system resources."""
        base_thread_map = {
            ProcessingStrategy.STANDARD: self.config.max_threads_standard,
            ProcessingStrategy.ENHANCED: self.config.max_threads_enhanced,
            ProcessingStrategy.STAGED: self.config.max_threads_staged,
            ProcessingStrategy.SELECTIVE: self.config.max_threads_selective
        }
        
        base_threads = base_thread_map[strategy]
        
        # Adjust based on system resources
        available_cores = max(1, system_resources.cpu_cores - 1)  # Leave 1 core for system
        
        # Reduce threads under high CPU usage
        if system_resources.cpu_usage_percent > 80:
            base_threads = max(1, base_threads - 1)
        
        # Reduce threads under memory pressure
        if system_resources.memory_pressure == "HIGH":
            base_threads = max(1, base_threads - 1)
        
        # Ensure we don't exceed available cores
        optimized_threads = min(base_threads, available_cores)
        
        return optimized_threads
    
    def _get_optimized_memory(self, strategy: ProcessingStrategy, 
                             system_resources: SystemResources) -> int:
        """Get optimized memory limit based on strategy and system resources."""
        base_memory_map = {
            ProcessingStrategy.STANDARD: self.config.max_memory_standard,
            ProcessingStrategy.ENHANCED: self.config.max_memory_enhanced,
            ProcessingStrategy.STAGED: self.config.max_memory_staged,
            ProcessingStrategy.SELECTIVE: self.config.max_memory_selective
        }
        
        base_memory = base_memory_map[strategy]
        
        # Adjust based on available memory
        available_memory_mb = system_resources.available_memory_gb * 1024
        safe_memory_limit = available_memory_mb * 0.6  # Use max 60% of available memory
        
        # Apply memory pressure adjustments
        if system_resources.memory_pressure == "HIGH":
            safe_memory_limit *= 0.7  # Further reduce under pressure
        elif system_resources.memory_pressure == "MEDIUM":
            safe_memory_limit *= 0.8
        
        optimized_memory = min(base_memory, int(safe_memory_limit))
        
        # Ensure minimum memory requirements
        min_memory_map = {
            ProcessingStrategy.STANDARD: 256,
            ProcessingStrategy.ENHANCED: 512,
            ProcessingStrategy.STAGED: 1024,
            ProcessingStrategy.SELECTIVE: 1536
        }
        
        optimized_memory = max(optimized_memory, min_memory_map[strategy])
        
        return optimized_memory
    
    def _should_use_background_processing(self, size_mb: float, strategy: ProcessingStrategy) -> bool:
        """Determine if background processing should be used (Implementation: >200MB)."""
        # Background processing for large APKs (>200MB as per Task SO.2)
        background_by_size = size_mb > 200.0
        background_by_strategy = strategy in [ProcessingStrategy.STAGED, ProcessingStrategy.SELECTIVE]
        
        return background_by_size or background_by_strategy
    
    def _estimate_processing_time(self, size_mb: float, strategy: ProcessingStrategy, 
                                 system_resources: SystemResources) -> ProcessingTimeEstimate:
        """Generate processing time estimate with ETA reporting (Task SO.2)."""
        # Base processing time calculation
        base_time = size_mb * self.config.base_processing_time_per_mb
        
        # Strategy-based multipliers
        strategy_multipliers = {
            ProcessingStrategy.STANDARD: 1.0,
            ProcessingStrategy.ENHANCED: 1.3,
            ProcessingStrategy.STAGED: 1.6,
            ProcessingStrategy.SELECTIVE: 2.2
        }
        
        strategy_adjusted_time = base_time * strategy_multipliers[strategy]
        
        # System resource adjustments
        resource_multiplier = 1.0
        factors_considered = ["APK size", "processing strategy"]
        
        # CPU usage adjustment
        if system_resources.cpu_usage_percent > 80:
            resource_multiplier *= 1.4
            factors_considered.append("high CPU usage")
        elif system_resources.cpu_usage_percent > 60:
            resource_multiplier *= 1.2
            factors_considered.append("moderate CPU usage")
        
        # Memory pressure adjustment
        if system_resources.memory_pressure == "HIGH":
            resource_multiplier *= 1.5
            factors_considered.append("high memory pressure")
        elif system_resources.memory_pressure == "MEDIUM":
            resource_multiplier *= 1.2
            factors_considered.append("moderate memory pressure")
        
        # Apply historical data if available
        if self.processing_history:
            historical_factor = self._calculate_historical_factor(size_mb, strategy)
            resource_multiplier *= historical_factor
            factors_considered.append("historical performance data")
        
        # Calculate final estimate
        estimated_seconds = int(strategy_adjusted_time * resource_multiplier)
        
        # Calculate confidence intervals (±25% for complexity variation)
        confidence_range = 0.25
        min_seconds = int(estimated_seconds * (1 - confidence_range))
        max_seconds = int(estimated_seconds * (1 + confidence_range))
        
        # Generate ETA description
        eta_description = self._generate_eta_description(estimated_seconds, strategy)
        
        return ProcessingTimeEstimate(
            estimated_seconds=estimated_seconds,
            min_seconds=min_seconds,
            max_seconds=max_seconds,
            confidence_level=self.config.confidence_threshold,
            factors_considered=factors_considered,
            eta_description=eta_description
        )
    
    def _generate_eta_description(self, estimated_seconds: int, strategy: ProcessingStrategy) -> str:
        """Generate human-readable ETA description."""
        if estimated_seconds < 60:
            time_desc = f"{estimated_seconds} seconds"
        elif estimated_seconds < 3600:
            minutes = estimated_seconds // 60
            seconds = estimated_seconds % 60
            time_desc = f"{minutes}m {seconds}s" if seconds > 0 else f"{minutes} minutes"
        else:
            hours = estimated_seconds // 3600
            minutes = (estimated_seconds % 3600) // 60
            time_desc = f"{hours}h {minutes}m" if minutes > 0 else f"{hours} hours"
        
        strategy_notes = {
            ProcessingStrategy.STANDARD: "Fast processing expected",
            ProcessingStrategy.ENHANCED: "Moderate processing with optimization",
            ProcessingStrategy.STAGED: "Background processing recommended",
            ProcessingStrategy.SELECTIVE: "Extended processing with smart caching"
        }
        
        return f"Estimated completion: {time_desc} - {strategy_notes[strategy]}"
    
    def _generate_optimization_flags(self, size_mb: float, strategy: ProcessingStrategy, 
                                   system_resources: SystemResources) -> Dict[str, Any]:
        """Generate JADX optimization flags based on size and resources."""
        flags = {
            "no_imports": True,  # Always reduce memory usage
            "no_debug_info": True,  # Always reduce output size
            "show_bad_code": True,  # Always include problematic code
        }
        
        # Size-based optimizations
        if size_mb > 100:
            flags["no_inline_anonymous"] = True
            flags["no_replace_consts"] = True
        
        if size_mb > 300:
            flags["no_inline_methods"] = True
            flags["skip_resources"] = True
        
        if size_mb > 500:
            flags["skip_sources"] = True
            flags["classes_only"] = True
        
        # Memory pressure optimizations
        if system_resources.memory_pressure in ["MEDIUM", "HIGH"]:
            flags["no_inline_anonymous"] = True
            flags["no_replace_consts"] = True
            
        if system_resources.memory_pressure == "HIGH":
            flags["skip_resources"] = True
            flags["no_inline_methods"] = True
        
        return flags
    
    def _get_system_resources(self) -> SystemResources:
        """Get current system resource information."""
        # Memory information
        memory = psutil.virtual_memory()
        total_memory_gb = memory.total / (1024**3)
        available_memory_gb = memory.available / (1024**3)
        
        # Determine memory pressure
        memory_usage_percent = (memory.total - memory.available) / memory.total * 100
        if memory_usage_percent > 85:
            memory_pressure = "HIGH"
        elif memory_usage_percent > 70:
            memory_pressure = "MEDIUM"
        else:
            memory_pressure = "LOW"
        
        # CPU information
        cpu_cores = psutil.cpu_count(logical=True)
        cpu_usage_percent = psutil.cpu_percent(interval=1)
        
        # Disk information
        disk = psutil.disk_usage('.')
        disk_free_gb = disk.free / (1024**3)
        
        return SystemResources(
            total_memory_gb=total_memory_gb,
            available_memory_gb=available_memory_gb,
            cpu_cores=cpu_cores,
            cpu_usage_percent=cpu_usage_percent,
            disk_free_gb=disk_free_gb,
            memory_pressure=memory_pressure
        )
    
    def _establish_system_baseline(self) -> Dict[str, float]:
        """Establish system performance baseline."""
        try:
            memory = psutil.virtual_memory()
            return {
                'cpu_cores': psutil.cpu_count(logical=True),
                'total_memory_gb': memory.total / (1024**3),
                'baseline_cpu_usage': psutil.cpu_percent(interval=1)
            }
        except Exception as e:
            logger.warning(f"Could not establish system baseline: {e}")
            return {}
    
    def _calculate_historical_factor(self, size_mb: float, strategy: ProcessingStrategy) -> float:
        """Calculate historical performance factor if data is available."""
        # Simple implementation - can be enhanced with machine learning
        relevant_history = [
            record for record in self.processing_history 
            if abs(record['size_mb'] - size_mb) < 50 and record['strategy'] == strategy
        ]
        
        if len(relevant_history) < 3:
            return 1.0  # Not enough data
        
        # Calculate average performance factor
        factors = [record['actual_time'] / record['estimated_time'] for record in relevant_history]
        return statistics.median(factors)
    
    def _generate_enhanced_reasoning(self, size_mb: float, category: str, strategy: ProcessingStrategy, 
                                   estimate: ProcessingTimeEstimate) -> str:
        """Generate enhanced human-readable reasoning for strategy selection."""
        base_reasoning = {
            ProcessingStrategy.STANDARD: f"Small APK ({size_mb:.1f}MB) - using standard JADX processing for optimal speed",
            ProcessingStrategy.ENHANCED: f"Medium APK ({size_mb:.1f}MB) - using enhanced processing with optimized resource allocation",
            ProcessingStrategy.STAGED: f"Large APK ({size_mb:.1f}MB) - using staged processing with separate process execution",
            ProcessingStrategy.SELECTIVE: f"Extra large APK ({size_mb:.1f}MB) - using selective analysis with smart caching and optimization"
        }
        
        reasoning = base_reasoning[strategy]
        reasoning += f" - {estimate.eta_description}"
        
        return reasoning
    
    def record_processing_result(self, classification: APKSizeClassification, 
                               actual_time_seconds: int, success: bool) -> None:
        """Record processing result for historical analysis."""
        record = {
            'size_mb': classification.size_mb,
            'strategy': classification.strategy,
            'estimated_time': classification.processing_estimate.estimated_seconds,
            'actual_time': actual_time_seconds,
            'success': success,
            'timestamp': time.time()
        }
        
        self.processing_history.append(record)
        
        # Keep only recent history (last 100 records)
        if len(self.processing_history) > 100:
            self.processing_history = self.processing_history[-100:]
    
    def get_processing_statistics(self) -> Dict[str, Any]:
        """Get processing statistics and accuracy metrics."""
        if not self.processing_history:
            return {"message": "No processing history available"}
        
        successful_records = [r for r in self.processing_history if r['success']]
        
        if not successful_records:
            return {"message": "No successful processing records"}
        
        # Calculate accuracy metrics
        time_diffs = [abs(r['actual_time'] - r['estimated_time']) for r in successful_records]
        avg_time_diff = statistics.mean(time_diffs)
        median_time_diff = statistics.median(time_diffs)
        
        # Calculate estimation accuracy
        accuracy_within_25_percent = sum(
            1 for r in successful_records 
            if abs(r['actual_time'] - r['estimated_time']) / r['estimated_time'] <= 0.25
        ) / len(successful_records) * 100
        
        return {
            'total_records': len(self.processing_history),
            'successful_records': len(successful_records),
            'success_rate': len(successful_records) / len(self.processing_history) * 100,
            'avg_time_difference_seconds': avg_time_diff,
            'median_time_difference_seconds': median_time_diff,
            'estimation_accuracy_25_percent': accuracy_within_25_percent
        }

# Backward compatibility - maintain old class name
APKSizeOptimizer = EnhancedAPKSizeOptimizer 
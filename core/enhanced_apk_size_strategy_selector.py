#!/usr/bin/env python3
"""
APK Size Strategy Selector

APK size-based processing strategy selection system providing
analysis workflows for different application sizes and complexities.

Features:
- Automatic strategy selection based on APK characteristics
- Memory-efficient processing for large applications
- Performance optimization for small applications
- Scalable architecture for deployment

"""

import os
import sys
import time
import psutil
import logging
import statistics
import json
from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Import existing APK size optimizer for backward compatibility
from core.apk_size_optimizer import APKSizeOptimizer, ProcessingStrategy, ProcessingConfig

# Import JADX separate process manager configuration
try:
    from core.jadx_separate_process_manager import ProcessConfig
    JADX_PROCESS_CONFIG_AVAILABLE = True
except ImportError:
    ProcessConfig = None
    JADX_PROCESS_CONFIG_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class SystemResourceMonitor:
    """System resource monitoring."""
    total_memory_gb: float
    available_memory_gb: float
    cpu_cores: int
    cpu_usage_percent: float
    disk_free_gb: float
    memory_pressure: str  # LOW, MEDIUM, HIGH
    load_average: float
    system_health_score: float

@dataclass
class ProcessingTimeEstimate:
    """Processing time estimation with confidence intervals."""
    estimated_seconds: int
    min_seconds: int
    max_seconds: int
    confidence_level: float
    factors_considered: List[str]
    eta_description: str
    completion_probability: Dict[str, float]  # {'1min': 0.1, '5min': 0.7, '10min': 0.95}

@dataclass
class EnhancedAPKClassification:
    """APK classification with processing requirements."""
    # Core classification data
    size_mb: float
    category: str  # SMALL, MEDIUM, LARGE, EXTRA_LARGE
    strategy: ProcessingStrategy
    
    # Resource allocation requirements
    timeout_seconds: int  # 180s-900s based on size
    max_threads: int      # 1-4 threads optimized for system
    max_memory_mb: int    # 512MB-4GB based on category
    
    # Processing features
    background_processing: bool  # True for >200MB APKs
    processing_estimate: ProcessingTimeEstimate
    system_resources: SystemResourceMonitor
    optimization_flags: Dict[str, Any]
    reasoning: str
    
    # Integration points
    separate_process_config: Dict[str, Any]
    fallback_strategies: List[str]
    success_probability: float

class EnhancedAPKSizeStrategySelector:
    """
    APK Size Strategy Selector
    
    Implements APK processing strategy selection with:
    - Processing time estimation and ETA reporting
    - System resource optimization 
    - Background processing determination
    - Integration with JADX Separate Process Manager
    """
    
    def __init__(self, config: Optional[ProcessingConfig] = None):
        """Initialize strategy selector."""
        self.config = config or ProcessingConfig()
        self.base_optimizer = APKSizeOptimizer(config)
        self.processing_history: List[Dict[str, Any]] = []
        self.system_baseline = self._establish_system_baseline()
        
        # Load historical data from persistent storage
        self._load_processing_history()
        
        logger.info("APK Size Strategy Selector initialized")
    
    def _load_processing_history(self):
        """Load processing history from persistent storage."""
        history_file = Path("data/processing_history.json")
        if history_file.exists():
            try:
                with open(history_file) as f:
                    self.processing_history = json.load(f)
                    logger.info(f"Loaded {len(self.processing_history)} historical records")
            except Exception as e:
                logger.warning(f"Failed to load processing history: {e}")
                self.processing_history = []
    
    def _save_processing_history(self):
        """Save processing history to persistent storage."""
        history_file = Path("data/processing_history.json")
        history_file.parent.mkdir(exist_ok=True)
        try:
            with open(history_file, 'w') as f:
                json.dump(self.processing_history[-50:], f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save processing history: {e}")
    
    def select_processing_strategy(self, apk_path: str) -> EnhancedAPKClassification:
        """
        Select optimal processing strategy.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            EnhancedAPKClassification with processing recommendations
        """
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        
        logger.info(f"Analyzing APK for strategy selection: {apk_path}")
        
        # Get basic classification from existing optimizer
        base_classification = self.base_optimizer.analyze_apk(apk_path)
        
        # System resource monitoring
        system_resources = self._get_enhanced_system_resources()
        
        # Timeout calculation with system optimization
        optimized_timeout = self._calculate_optimized_timeout(
            base_classification.strategy, 
            base_classification.size_mb, 
            system_resources
        )
        
        # Thread allocation with system awareness
        optimized_threads = self._calculate_optimized_threads(
            base_classification.strategy, 
            system_resources
        )
        
        # Memory allocation with pressure awareness
        optimized_memory = self._calculate_optimized_memory(
            base_classification.strategy, 
            system_resources
        )
        
        # Background processing determination (Implementation: >200MB)
        background_processing = self._determine_background_processing(
            base_classification.size_mb, 
            base_classification.strategy
        )
        
        # Processing time estimation with ETA
        processing_estimate = self._estimate_processing_time_enhanced(
            base_classification.size_mb,
            base_classification.strategy,
            system_resources,
            optimized_threads,
            optimized_memory
        )
        
        # Generate optimization flags for JADX
        optimization_flags = self._generate_jadx_optimization_flags(
            base_classification.size_mb,
            base_classification.strategy,
            system_resources
        )
        
        # Create separate process configuration
        separate_process_config = self._create_separate_process_config(
            optimized_timeout,
            optimized_memory,
            optimized_threads,
            background_processing
        )
        
        # Determine fallback strategies
        fallback_strategies = self._determine_fallback_strategies(
            base_classification.strategy,
            system_resources
        )
        
        # Calculate success probability
        success_probability = self._calculate_success_probability(
            base_classification.size_mb,
            base_classification.strategy,
            system_resources
        )
        
        # Reasoning
        enhanced_reasoning = self._generate_enhanced_reasoning(
            base_classification,
            processing_estimate,
            system_resources,
            background_processing
        )
        
        enhanced_classification = EnhancedAPKClassification(
            size_mb=base_classification.size_mb,
            category=base_classification.category,
            strategy=base_classification.strategy,
            timeout_seconds=optimized_timeout,
            max_threads=optimized_threads,
            max_memory_mb=optimized_memory,
            background_processing=background_processing,
            processing_estimate=processing_estimate,
            system_resources=system_resources,
            optimization_flags=optimization_flags,
            reasoning=enhanced_reasoning,
            separate_process_config=separate_process_config,
            fallback_strategies=fallback_strategies,
            success_probability=success_probability
        )
        
        logger.info(f"Strategy selected: {base_classification.strategy.value} "
                   f"(timeout: {optimized_timeout}s, threads: {optimized_threads}, "
                   f"memory: {optimized_memory}MB, background: {background_processing})")
        logger.info(f"Processing estimate: {processing_estimate.eta_description}")
        
        return enhanced_classification
    
    def _get_enhanced_system_resources(self) -> SystemResourceMonitor:
        """System resource monitoring with comprehensive error handling."""
        try:
            # Memory information
            memory = psutil.virtual_memory()
            total_memory_gb = memory.total / (1024**3)
            available_memory_gb = memory.available / (1024**3)
            
            # Memory pressure calculation
            memory_usage_percent = (memory.total - memory.available) / memory.total * 100
            if memory_usage_percent > 85:
                memory_pressure = "HIGH"
            elif memory_usage_percent > 70:
                memory_pressure = "MEDIUM"
            else:
                memory_pressure = "LOW"
            
            # CPU information
            cpu_cores = psutil.cpu_count(logical=True) or 4  # Fallback to 4 cores
            cpu_usage_percent = psutil.cpu_percent(interval=1)
            
            # Load average (Unix-like systems)
            try:
                load_average = os.getloadavg()[0] if hasattr(os, 'getloadavg') else cpu_usage_percent / 100
            except:
                load_average = cpu_usage_percent / 100
            
            # Disk information
            disk = psutil.disk_usage('.')
            disk_free_gb = disk.free / (1024**3)
            
            # System health score (0.0-1.0)
            health_factors = [
                1.0 - (memory_usage_percent / 100),  # Memory availability
                1.0 - (cpu_usage_percent / 100),     # CPU availability
                min(1.0, disk_free_gb / 10),         # Disk availability (10GB baseline)
                1.0 - min(1.0, load_average / cpu_cores)  # Load balance
            ]
            
            # Calculate system health score with bounds checking
            if health_factors:
                system_health_score = sum(health_factors) / len(health_factors)
                system_health_score = max(0.0, min(1.0, system_health_score))  # Clamp 0-1
            else:
                system_health_score = 0.5  # Default moderate health
            
            return SystemResourceMonitor(
                total_memory_gb=total_memory_gb,
                available_memory_gb=available_memory_gb,
                cpu_cores=cpu_cores,
                cpu_usage_percent=cpu_usage_percent,
                disk_free_gb=disk_free_gb,
                memory_pressure=memory_pressure,
                load_average=load_average,
                system_health_score=system_health_score
            )
        except Exception as e:
            logger.warning(f"System resource monitoring failed: {e}")
            # Return safe defaults
            return SystemResourceMonitor(
                total_memory_gb=8.0,
                available_memory_gb=4.0,
                cpu_cores=4,
                cpu_usage_percent=50.0,
                disk_free_gb=10.0,
                memory_pressure="MEDIUM",
                load_average=1.0,
                system_health_score=0.6
            )
    
    def _calculate_optimized_timeout(self, strategy: ProcessingStrategy, size_mb: float, 
                                    system_resources: SystemResourceMonitor) -> int:
        """Calculate optimized timeout with system resource consideration."""
        # Base timeouts for different processing strategies
        base_timeouts = {
            ProcessingStrategy.STANDARD: 180,   # Small: 180s (3 min)
            ProcessingStrategy.ENHANCED: 300,   # Medium: 300s (5 min)
            ProcessingStrategy.STAGED: 600,     # Large: 600s (10 min)
            ProcessingStrategy.SELECTIVE: 900   # Extra Large: 900s (15 min)
        }
        
        base_timeout = base_timeouts[strategy]
        
        # System health adjustments
        health_multiplier = 1.0
        if system_resources.system_health_score < 0.3:
            health_multiplier = 2.0  # Poor system health - double timeout
        elif system_resources.system_health_score < 0.6:
            health_multiplier = 1.5  # Moderate system health - 50% more time
        elif system_resources.system_health_score < 0.8:
            health_multiplier = 1.2  # Good system health - 20% more time
        
        # Memory pressure adjustments
        if system_resources.memory_pressure == "HIGH":
            health_multiplier *= 1.4
        elif system_resources.memory_pressure == "MEDIUM":
            health_multiplier *= 1.2
        
        # Size-based edge case adjustments
        if strategy == ProcessingStrategy.STAGED and size_mb > 400:
            health_multiplier *= 1.2  # Large APKs within staged category
        elif strategy == ProcessingStrategy.SELECTIVE and size_mb > 800:
            health_multiplier *= 1.3  # Massive APKs
        
        optimized_timeout = int(base_timeout * health_multiplier)
        
        # Ensure we stay within reasonable bounds
        min_timeout = base_timeout
        max_timeout = base_timeout * 3
        optimized_timeout = max(min_timeout, min(max_timeout, optimized_timeout))
        
        return optimized_timeout
    
    def _calculate_optimized_threads(self, strategy: ProcessingStrategy, 
                                   system_resources: SystemResourceMonitor) -> int:
        """Calculate optimized thread count (1-4 threads)."""
        # Base thread allocation for different strategies
        base_threads = {
            ProcessingStrategy.STANDARD: 4,   # Small APKs - maximum performance
            ProcessingStrategy.ENHANCED: 3,   # Medium APKs - balanced
            ProcessingStrategy.STAGED: 2,     # Large APKs - conservative
            ProcessingStrategy.SELECTIVE: 1   # Extra Large APKs - minimal
        }
        
        base_thread_count = base_threads[strategy]
        
        # System resource adjustments
        available_cores = max(1, system_resources.cpu_cores - 1)  # Leave 1 core for system
        
        # High CPU usage - reduce threads
        if system_resources.cpu_usage_percent > 80:
            base_thread_count = max(1, base_thread_count - 1)
        
        # High load average - reduce threads
        if system_resources.load_average > system_resources.cpu_cores * 0.8:
            base_thread_count = max(1, base_thread_count - 1)
        
        # Memory pressure - reduce threads to lower memory usage
        if system_resources.memory_pressure == "HIGH":
            base_thread_count = max(1, base_thread_count - 1)
        
        # Ensure we don't exceed available cores or system limits
        optimized_threads = min(base_thread_count, available_cores, 4)  # Max 4 threads
        optimized_threads = max(1, optimized_threads)  # Min 1 thread
        
        return optimized_threads
    
    def _calculate_optimized_memory(self, strategy: ProcessingStrategy, 
                                   system_resources: SystemResourceMonitor) -> int:
        """Calculate optimized memory allocation (512MB-4GB)."""
        # Base memory allocation for different strategies
        base_memory = {
            ProcessingStrategy.STANDARD: 512,    # Small APKs - 512MB minimum
            ProcessingStrategy.ENHANCED: 1024,   # Medium APKs - 1GB
            ProcessingStrategy.STAGED: 2048,     # Large APKs - 2GB
            ProcessingStrategy.SELECTIVE: 4096   # Extra Large APKs - 4GB maximum
        }
        
        base_memory_mb = base_memory[strategy]
        
        # Available memory calculation
        available_memory_mb = system_resources.available_memory_gb * 1024
        safe_memory_limit = available_memory_mb * 0.6  # Use max 60% of available memory
        
        # Memory pressure adjustments
        if system_resources.memory_pressure == "HIGH":
            safe_memory_limit *= 0.7  # Further reduce under high pressure
        elif system_resources.memory_pressure == "MEDIUM":
            safe_memory_limit *= 0.8  # Moderate reduction
        
        # System health adjustments
        if system_resources.system_health_score < 0.5:
            safe_memory_limit *= 0.8  # Reduce memory under poor system health
        
        # Calculate optimized memory
        optimized_memory = min(base_memory_mb, int(safe_memory_limit))
        
        # Ensure memory allocation within acceptable range (512MB-4GB)
        min_memory_map = {
            ProcessingStrategy.STANDARD: 512,
            ProcessingStrategy.ENHANCED: 512,
            ProcessingStrategy.STAGED: 1024,
            ProcessingStrategy.SELECTIVE: 1536
        }
        
        min_memory = min_memory_map[strategy]
        optimized_memory = max(min_memory, min(optimized_memory, 4096))  # System limits
        
        return optimized_memory
    
    def _determine_background_processing(self, size_mb: float, strategy: ProcessingStrategy) -> bool:
        """Determine background processing for large APKs (>200MB)."""
        # Background processing for large APKs (>200MB)
        background_by_size = size_mb > 200.0
        
        # Strategy-based determination
        background_by_strategy = strategy in [ProcessingStrategy.STAGED, ProcessingStrategy.SELECTIVE]
        
        # Either condition triggers background processing
        return background_by_size or background_by_strategy
    
    def _estimate_processing_time_enhanced(self, size_mb: float, strategy: ProcessingStrategy,
                                          system_resources: SystemResourceMonitor,
                                          threads: int, memory_mb: int) -> ProcessingTimeEstimate:
        """Processing time estimation with ETA reporting."""
        # Base processing time estimation (seconds per MB)
        base_time_per_mb = {
            ProcessingStrategy.STANDARD: 2.0,   # Fast processing
            ProcessingStrategy.ENHANCED: 2.5,   # Moderate processing
            ProcessingStrategy.STAGED: 3.0,     # Careful processing
            ProcessingStrategy.SELECTIVE: 4.0   # Thorough processing
        }
        
        base_time = size_mb * base_time_per_mb[strategy]
        
        # System resource multipliers
        resource_multiplier = 1.0
        factors_considered = ["APK size", "processing strategy"]
        
        # CPU usage impact
        if system_resources.cpu_usage_percent > 80:
            resource_multiplier *= 1.5
            factors_considered.append("high CPU usage")
        elif system_resources.cpu_usage_percent > 60:
            resource_multiplier *= 1.2
            factors_considered.append("moderate CPU usage")
        
        # Memory pressure impact
        if system_resources.memory_pressure == "HIGH":
            resource_multiplier *= 1.6
            factors_considered.append("high memory pressure")
        elif system_resources.memory_pressure == "MEDIUM":
            resource_multiplier *= 1.3
            factors_considered.append("moderate memory pressure")
        
        # System health impact
        if system_resources.system_health_score < 0.5:
            resource_multiplier *= 1.8
            factors_considered.append("poor system health")
        elif system_resources.system_health_score < 0.7:
            resource_multiplier *= 1.3
            factors_considered.append("moderate system health")
        
        # Thread efficiency (fewer threads = longer processing)
        thread_efficiency = threads / 4.0  # Normalize to max 4 threads
        if thread_efficiency < 1.0:
            thread_multiplier = 1.0 / thread_efficiency
            resource_multiplier *= thread_multiplier
            factors_considered.append(f"reduced thread count ({threads})")
        
        # Memory efficiency (less memory = potential slower processing)
        expected_memory_map = {
            ProcessingStrategy.STANDARD: 512,
            ProcessingStrategy.ENHANCED: 1024,
            ProcessingStrategy.STAGED: 2048,
            ProcessingStrategy.SELECTIVE: 4096
        }
        
        expected_memory = expected_memory_map[strategy]
        if memory_mb < expected_memory:
            memory_efficiency = memory_mb / expected_memory
            memory_multiplier = 1.0 + (1.0 - memory_efficiency) * 0.5
            resource_multiplier *= memory_multiplier
            factors_considered.append(f"reduced memory allocation ({memory_mb}MB)")
        
        # Historical data adjustment
        if self.processing_history:
            historical_factor = self._calculate_historical_factor(size_mb, strategy)
            resource_multiplier *= historical_factor
            factors_considered.append("historical performance data")
        
        # Calculate final estimate
        estimated_seconds = int(base_time * resource_multiplier)
        
        # Confidence intervals (±30% for various factors)
        confidence_range = 0.30
        min_seconds = int(estimated_seconds * (1 - confidence_range))
        max_seconds = int(estimated_seconds * (1 + confidence_range))
        
        # Completion probability distribution
        completion_probability = self._calculate_completion_probability(estimated_seconds)
        
        # Generate ETA description
        eta_description = self._generate_enhanced_eta_description(estimated_seconds, strategy, size_mb)
        
        return ProcessingTimeEstimate(
            estimated_seconds=estimated_seconds,
            min_seconds=min_seconds,
            max_seconds=max_seconds,
            confidence_level=0.75,  # 75% confidence level
            factors_considered=factors_considered,
            eta_description=eta_description,
            completion_probability=completion_probability
        )
    
    def _generate_enhanced_eta_description(self, estimated_seconds: int,
                                          strategy: ProcessingStrategy, size_mb: float) -> str:
        """Generate ETA description."""
        # Time formatting
        if estimated_seconds < 60:
            time_desc = f"{estimated_seconds} seconds"
        elif estimated_seconds < 3600:
            minutes = estimated_seconds // 60
            seconds = estimated_seconds % 60
            if seconds > 0:
                time_desc = f"{minutes}m {seconds}s"
            else:
                time_desc = f"{minutes} minutes"
        else:
            hours = estimated_seconds // 3600
            minutes = (estimated_seconds % 3600) // 60
            if minutes > 0:
                time_desc = f"{hours}h {minutes}m"
            else:
                time_desc = f"{hours} hours"
        
        # Strategy-specific descriptions
        strategy_descriptions = {
            ProcessingStrategy.STANDARD: "Fast standard processing",
            ProcessingStrategy.ENHANCED: "Enhanced processing with optimization",
            ProcessingStrategy.STAGED: "Staged processing with background execution",
            ProcessingStrategy.SELECTIVE: "Selective analysis with smart caching"
        }
        
        strategy_desc = strategy_descriptions[strategy]
        
        # Size-based additional information
        if size_mb > 500:
            size_note = " (extra large APK - complex processing expected)"
        elif size_mb > 200:
            size_note = " (large APK - background processing recommended)"
        elif size_mb > 50:
            size_note = " (medium APK - balanced processing)"
        else:
            size_note = " (small APK - fast processing)"
        
        return f"ETA: {time_desc} - {strategy_desc}{size_note}"
    
    def _calculate_completion_probability(self, estimated_seconds: int) -> Dict[str, float]:
        """Calculate completion probability at different time intervals."""
        # Define time checkpoints (in seconds)
        checkpoints = [60, 300, 600, 1800, 3600]  # 1min, 5min, 10min, 30min, 1hour
        
        probability_distribution = {}
        
        for checkpoint in checkpoints:
            if checkpoint <= estimated_seconds:
                # Lower probability for times before estimated completion
                prob = min(0.9, checkpoint / estimated_seconds * 0.8)
            else:
                # Higher probability for times after estimated completion
                excess_factor = (checkpoint - estimated_seconds) / estimated_seconds
                prob = 0.8 + (0.2 * min(1.0, excess_factor))
            
            # Format checkpoint label
            if checkpoint < 60:
                label = f"{checkpoint}s"
            elif checkpoint < 3600:
                label = f"{checkpoint // 60}min"
            else:
                label = f"{checkpoint // 3600}h"
            
            probability_distribution[label] = round(prob, 2)
        
        return probability_distribution
    
    def _generate_jadx_optimization_flags(self, size_mb: float, strategy: ProcessingStrategy,
                                         system_resources: SystemResourceMonitor) -> Dict[str, Any]:
        """Generate JADX optimization flags for enhanced processing."""
        flags = {
            "no_imports": True,       # Always reduce memory usage
            "no_debug_info": True,    # Always reduce output size
            "show_bad_code": True,    # Always include problematic code
        }
        
        # Size-based optimizations
        if size_mb > 100:
            flags["no_inline_anonymous"] = True
            flags["no_replace_consts"] = True
        
        if size_mb > 300:
            flags["no_inline_methods"] = True
            flags["skip_resources"] = system_resources.memory_pressure in ["MEDIUM", "HIGH"]
        
        if size_mb > 500:
            flags["skip_sources"] = system_resources.memory_pressure == "HIGH"
            flags["classes_only"] = system_resources.system_health_score < 0.5
        
        # Memory pressure specific optimizations
        if system_resources.memory_pressure == "HIGH":
            flags.update({
                "no_inline_anonymous": True,
                "no_replace_consts": True,
                "no_inline_methods": True,
                "skip_resources": True
            })
        
        # System health optimizations
        if system_resources.system_health_score < 0.3:
            flags.update({
                "skip_sources": True,
                "classes_only": True,
                "no_xml_pretty": True
            })
        
        return flags
    
    def _create_separate_process_config(self, timeout: int, memory_mb: int, threads: int,
                                       background: bool) -> Dict[str, Any]:
        """Create configuration for JADX Separate Process Manager integration."""
        if not JADX_PROCESS_CONFIG_AVAILABLE:
            logger.warning("JADX Separate Process Manager is not available. "
                           "Cannot create separate process config.")
            return {}

        config = {
            "timeout_seconds": timeout,
            "memory_limit_mb": memory_mb,
            "thread_count": threads,
            "background_processing": background,
            "enable_progress_reporting": True,
            "cleanup_on_failure": True,
            "max_retries": 2 if background else 1
        }
        
        return config
    
    def _determine_fallback_strategies(self, strategy: ProcessingStrategy,
                                      system_resources: SystemResourceMonitor) -> List[str]:
        """Determine fallback strategies if primary strategy fails."""
        fallback_map = {
            ProcessingStrategy.STANDARD: ["enhanced", "staged"],
            ProcessingStrategy.ENHANCED: ["staged", "selective"],
            ProcessingStrategy.STAGED: ["selective", "enhanced"],
            ProcessingStrategy.SELECTIVE: ["staged", "enhanced"]
        }
        
        fallbacks = fallback_map[strategy].copy()
        
        # Adjust based on system health
        if system_resources.system_health_score < 0.5:
            # Poor system health - prefer lighter strategies
            if "selective" in fallbacks:
                fallbacks.remove("selective")
            if "staged" in fallbacks:
                fallbacks.insert(0, "staged")  # Prefer staged for isolation
        
        return fallbacks
    
    def _calculate_success_probability(self, size_mb: float, strategy: ProcessingStrategy,
                                      system_resources: SystemResourceMonitor) -> float:
        """Calculate probability of successful processing."""
        base_success_rates = {
            ProcessingStrategy.STANDARD: 0.95,   # 95% success for small APKs
            ProcessingStrategy.ENHANCED: 0.90,   # 90% success for medium APKs
            ProcessingStrategy.STAGED: 0.85,     # 85% success for large APKs
            ProcessingStrategy.SELECTIVE: 0.80   # 80% success for extra large APKs
        }
        
        base_success = base_success_rates[strategy]
        
        # Adjust based on system health
        health_factor = system_resources.system_health_score
        success_probability = base_success * (0.7 + 0.3 * health_factor)
        
        # Memory pressure penalty
        if system_resources.memory_pressure == "HIGH":
            success_probability *= 0.85
        elif system_resources.memory_pressure == "MEDIUM":
            success_probability *= 0.92
        
        # Size penalty for edge cases
        if strategy == ProcessingStrategy.SELECTIVE and size_mb > 800:
            success_probability *= 0.90  # Very large APKs have lower success rate
        
        return round(success_probability, 3)
    
    def _generate_enhanced_reasoning(self, base_classification, processing_estimate,
                                    system_resources: SystemResourceMonitor,
                                    background_processing: bool) -> str:
        """Generate enhanced reasoning for strategy selection."""
        reasoning = f"{base_classification.category} APK ({base_classification.size_mb:.1f}MB) "
        reasoning += f"classified for {base_classification.strategy.value} processing. "
        reasoning += f"{processing_estimate.eta_description}. "
        
        if background_processing:
            reasoning += "Background processing enabled due to size >200MB. "
        
        if system_resources.memory_pressure in ["MEDIUM", "HIGH"]:
            reasoning += f"System under {system_resources.memory_pressure.lower()} memory pressure - "
            reasoning += "optimized resource allocation applied. "
        
        if system_resources.system_health_score < 0.7:
            reasoning += "System health suboptimal - conservative settings applied. "
        
        return reasoning
    
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
        relevant_history = [
            record for record in self.processing_history 
            if abs(record['size_mb'] - size_mb) < 50 and record['strategy'] == strategy
        ]
        
        if len(relevant_history) < 3:
            return 1.0  # Not enough data
        
        # Calculate median performance factor for stability
        factors = [record['actual_time'] / record['estimated_time'] for record in relevant_history]
        return statistics.median(factors)
    
    def record_processing_result(self, classification: EnhancedAPKClassification,
                                actual_time_seconds: int, success: bool) -> None:
        """Record processing result for historical analysis."""
        record = {
            'size_mb': classification.size_mb,
            'strategy': classification.strategy,
            'estimated_time': classification.processing_estimate.estimated_seconds,
            'actual_time': actual_time_seconds,
            'success': success,
            'background_processing': classification.background_processing,
            'system_health': classification.system_resources.system_health_score,
            'timestamp': time.time()
        }
        
        self.processing_history.append(record)
        
        # Keep only recent history (last 50 records for efficiency)
        if len(self.processing_history) > 50:
            self.processing_history = self.processing_history[-50:]
        
        # Save to persistent storage
        self._save_processing_history()
        
        logger.info(f"Recorded processing result: {success}, actual: {actual_time_seconds}s, "
                   f"estimated: {classification.processing_estimate.estimated_seconds}s")

 
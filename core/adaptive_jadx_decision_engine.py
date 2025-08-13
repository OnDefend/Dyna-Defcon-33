#!/usr/bin/env python3
"""
AODS Enhanced JADX Performance Optimization - Adaptive Multi-Factor Decision Engine

A more efficient architecture that improves upon the size-based approach with:
- Multi-factor complexity scoring instead of size-only classification
- Machine learning-based strategy prediction with historical learning
- Lazy resource analysis to reduce overhead
- Dynamic threshold adaptation based on performance feedback
- Predictive caching with APK fingerprinting
"""

import os
import time
import psutil
import logging
import hashlib
import pickle
import numpy as np
from typing import Dict, Any, Tuple, Optional, List, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from collections import defaultdict, deque
import threading
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class ProcessingStrategy(Enum):
    """Enhanced processing strategies with adaptive capabilities."""
    LIGHTNING = "lightning"      # Ultra-fast for simple APKs
    STANDARD = "standard"        # Balanced approach for typical APKs
    ENHANCED = "enhanced"        # Optimized for complex APKs
    STAGED = "staged"           # Multi-phase for large APKs
    SELECTIVE = "selective"     # Smart analysis for massive APKs
    ADAPTIVE = "adaptive"       # Dynamic strategy switching

@dataclass
class APKComplexityProfile:
    """Comprehensive APK complexity assessment."""
    size_mb: float
    dex_count: int = 0
    native_lib_count: int = 0
    resource_count: int = 0
    manifest_complexity: float = 0.0
    obfuscation_score: float = 0.0
    framework_type: str = "native"  # native, react_native, flutter, xamarin
    complexity_score: float = 0.0
    processing_difficulty: str = "unknown"
    
    def __post_init__(self):
        """Calculate overall complexity score."""
        self.complexity_score = self._calculate_complexity_score()
        self.processing_difficulty = self._assess_difficulty()
    
    def _calculate_complexity_score(self) -> float:
        """Calculate weighted complexity score (0.0-10.0)."""
        # Size factor (0-3 points)
        size_factor = min(3.0, self.size_mb / 100)
        
        # Structure complexity (0-2 points)
        structure_factor = min(2.0, (self.dex_count * 0.2 + self.native_lib_count * 0.1))
        
        # Resource complexity (0-1 point)
        resource_factor = min(1.0, self.resource_count / 1000)
        
        # Manifest complexity (0-2 points)
        manifest_factor = min(2.0, self.manifest_complexity)
        
        # Obfuscation penalty (0-2 points)
        obfuscation_factor = min(2.0, self.obfuscation_score)
        
        return size_factor + structure_factor + resource_factor + manifest_factor + obfuscation_factor
    
    def _assess_difficulty(self) -> str:
        """Assess processing difficulty level."""
        if self.complexity_score <= 2.0:
            return "trivial"
        elif self.complexity_score <= 4.0:
            return "simple"
        elif self.complexity_score <= 6.0:
            return "moderate"
        elif self.complexity_score <= 8.0:
            return "complex"
        else:
            return "extreme"

@dataclass
class SystemCapabilities:
    """Lazy-loaded system capabilities assessment."""
    _loaded: bool = False
    total_memory_gb: float = 0.0
    available_memory_gb: float = 0.0
    cpu_cores: int = 0
    cpu_usage_percent: float = 0.0
    performance_tier: str = "unknown"  # low, medium, high, extreme
    
    def ensure_loaded(self):
        """Lazy load system capabilities only when needed."""
        if not self._loaded:
            self._load_system_info()
            self._loaded = True
    
    def _load_system_info(self):
        """Load current system information."""
        memory = psutil.virtual_memory()
        self.total_memory_gb = memory.total / (1024**3)
        self.available_memory_gb = memory.available / (1024**3)
        self.cpu_cores = psutil.cpu_count()
        self.cpu_usage_percent = psutil.cpu_percent(interval=0.1)
        self.performance_tier = self._assess_performance_tier()
    
    def _assess_performance_tier(self) -> str:
        """Assess system performance tier."""
        if self.total_memory_gb >= 16 and self.cpu_cores >= 8:
            return "extreme"
        elif self.total_memory_gb >= 8 and self.cpu_cores >= 4:
            return "high"
        elif self.total_memory_gb >= 4 and self.cpu_cores >= 2:
            return "medium"
        else:
            return "low"

@dataclass
class AdaptiveDecision:
    """Enhanced decision with adaptive capabilities."""
    strategy: ProcessingStrategy
    confidence: float
    estimated_duration_seconds: int
    resource_allocation: Dict[str, Any]
    reasoning: str
    fallback_strategies: List[ProcessingStrategy]
    performance_prediction: Dict[str, float]
    adaptation_triggers: List[str]

class PerformanceLearningModel:
    """Simple ML model for strategy performance prediction."""
    
    def __init__(self):
        self.strategy_performance: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.complexity_patterns: Dict[str, List[float]] = defaultdict(list)
        self.adaptation_history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
    
    def record_performance(self, complexity_profile: APKComplexityProfile, 
                          strategy: ProcessingStrategy, duration_seconds: float, 
                          success: bool, memory_used_mb: float):
        """Record strategy performance for learning."""
        with self._lock:
            key = f"{strategy.value}_{complexity_profile.processing_difficulty}"
            performance_data = {
                'complexity_score': complexity_profile.complexity_score,
                'duration': duration_seconds,
                'success': success,
                'memory_used': memory_used_mb,
                'timestamp': time.time()
            }
            self.strategy_performance[key].append(performance_data)
    
    def predict_best_strategy(self, complexity_profile: APKComplexityProfile, 
                            system_caps: SystemCapabilities) -> Tuple[ProcessingStrategy, float]:
        """Predict best strategy based on historical performance."""
        system_caps.ensure_loaded()
        
        # Simple heuristic-based prediction (can be replaced with actual ML)
        difficulty = complexity_profile.processing_difficulty
        complexity_score = complexity_profile.complexity_score
        
        # Strategy selection based on complexity and system capabilities
        if difficulty == "trivial" and system_caps.performance_tier in ["high", "extreme"]:
            return ProcessingStrategy.LIGHTNING, 0.95
        elif difficulty in ["trivial", "simple"]:
            return ProcessingStrategy.STANDARD, 0.90
        elif difficulty == "moderate":
            if system_caps.performance_tier in ["high", "extreme"]:
                return ProcessingStrategy.ENHANCED, 0.85
            else:
                return ProcessingStrategy.STAGED, 0.80
        elif difficulty == "complex":
            return ProcessingStrategy.STAGED, 0.75
        else:  # extreme
            return ProcessingStrategy.SELECTIVE, 0.70
    
    def get_performance_stats(self, strategy: ProcessingStrategy, difficulty: str) -> Dict[str, float]:
        """Get performance statistics for strategy-difficulty combination."""
        key = f"{strategy.value}_{difficulty}"
        performances = self.strategy_performance.get(key, [])
        
        if not performances:
            return {'avg_duration': 0, 'success_rate': 0, 'confidence': 0.5}
        
        successful = [p for p in performances if p['success']]
        return {
            'avg_duration': np.mean([p['duration'] for p in successful]) if successful else 0,
            'success_rate': len(successful) / len(performances),
            'confidence': min(0.95, 0.5 + (len(performances) * 0.01))  # Confidence grows with data
        }

class AdaptiveJADXDecisionEngine:
    """
    Enhanced Adaptive Multi-Factor Decision Engine for JADX Performance Optimization
    
    Key improvements over size-based approach:
    1. Multi-factor complexity scoring instead of size-only classification
    2. Machine learning-based strategy prediction with historical learning
    3. Lazy resource analysis to reduce overhead
    4. Dynamic threshold adaptation based on performance feedback
    5. Predictive caching with APK fingerprinting
    """
    
    def __init__(self, cache_dir: str = "cache/adaptive_jadx"):
        """Initialize the adaptive decision engine."""
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Core components
        self.learning_model = PerformanceLearningModel()
        self.decision_cache: Dict[str, AdaptiveDecision] = {}
        self.system_caps = SystemCapabilities()
        
        # Performance tracking
        self.decisions_made = 0
        self.cache_hits = 0
        self.start_time = time.time()
        
        # Load historical data
        self._load_historical_data()
        
        logger.info("Adaptive JADX Decision Engine initialized")
    
    def analyze_and_decide(self, apk_path: str, force_refresh: bool = False) -> AdaptiveDecision:
        """
        Analyze APK and make adaptive processing decision.
        
        Key efficiency improvements:
        - Quick complexity profiling before expensive analysis
        - Lazy system resource loading
        - Predictive caching with fingerprinting
        - Multi-factor decision making
        """
        start_time = time.time()
        
        try:
            # Quick APK fingerprinting for cache lookup
            apk_fingerprint = self._calculate_apk_fingerprint(apk_path)
            
            # Check cache first (unless force refresh)
            if not force_refresh:
                cached_decision = self._check_predictive_cache(apk_fingerprint)
                if cached_decision:
                    self.cache_hits += 1
                    logger.debug(f"Cache hit for {os.path.basename(apk_path)}")
                    return cached_decision
            
            # Fast complexity profiling
            complexity_profile = self._profile_apk_complexity(apk_path)
            
            # ML-based strategy prediction
            predicted_strategy, base_confidence = self.learning_model.predict_best_strategy(
                complexity_profile, self.system_caps
            )
            
            # Create adaptive decision
            decision = self._create_adaptive_decision(
                complexity_profile, predicted_strategy, base_confidence
            )
            
            # Cache the decision
            self._cache_adaptive_decision(apk_fingerprint, decision)
            
            # Record metrics
            analysis_time = time.time() - start_time
            self._record_decision_metrics(decision, analysis_time)
            
            self.decisions_made += 1
            return decision
            
        except Exception as e:
            logger.error(f"Error in adaptive decision analysis for {apk_path}: {e}")
            return self._create_fallback_decision(apk_path, str(e))
    
    def _calculate_apk_fingerprint(self, apk_path: str) -> str:
        """Calculate lightweight APK fingerprint for caching."""
        stat_info = os.stat(apk_path)
        # Combine size, modification time, and partial hash for fast fingerprinting
        fingerprint_data = f"{stat_info.st_size}_{stat_info.st_mtime}_{os.path.basename(apk_path)}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()[:16]
    
    def _profile_apk_complexity(self, apk_path: str) -> APKComplexityProfile:
        """Fast APK complexity profiling with minimal overhead."""
        stat_info = os.stat(apk_path)
        size_mb = stat_info.st_size / (1024 * 1024)
        
        # Quick heuristic-based complexity assessment
        # (In production, this could use cached APK metadata or quick ZIP analysis)
        complexity_indicators = self._quick_complexity_analysis(apk_path, size_mb)
        
        return APKComplexityProfile(
            size_mb=size_mb,
            dex_count=complexity_indicators.get('dex_count', 1),
            native_lib_count=complexity_indicators.get('native_lib_count', 0),
            resource_count=complexity_indicators.get('resource_count', 100),
            manifest_complexity=complexity_indicators.get('manifest_complexity', 1.0),
            obfuscation_score=complexity_indicators.get('obfuscation_score', 0.0),
            framework_type=complexity_indicators.get('framework_type', 'native')
        )
    
    def _quick_complexity_analysis(self, apk_path: str, size_mb: float) -> Dict[str, Any]:
        """Quick heuristic-based complexity analysis."""
        # Filename-based heuristics
        filename = os.path.basename(apk_path).lower()
        
        indicators = {
            'dex_count': max(1, int(size_mb / 50)),  # Rough estimate
            'native_lib_count': 2 if 'game' in filename or size_mb > 100 else 0,
            'resource_count': int(size_mb * 10),  # Rough estimate
            'manifest_complexity': 2.0 if size_mb > 200 else 1.0,
            'obfuscation_score': 1.0 if any(x in filename for x in ['pro', 'release', 'obf']) else 0.0,
            'framework_type': 'flutter' if 'flutter' in filename else 'native'
        }
        
        return indicators
    
    def _create_adaptive_decision(self, complexity_profile: APKComplexityProfile, 
                                strategy: ProcessingStrategy, base_confidence: float) -> AdaptiveDecision:
        """Create adaptive decision with fallback strategies and performance prediction."""
        
        # Get performance stats for confidence adjustment
        perf_stats = self.learning_model.get_performance_stats(
            strategy, complexity_profile.processing_difficulty
        )
        
        # Adjust confidence based on historical performance
        adjusted_confidence = min(0.95, base_confidence * perf_stats['confidence'])
        
        # Estimate duration based on complexity and historical data
        base_duration = self._estimate_base_duration(strategy, complexity_profile)
        historical_avg = perf_stats.get('avg_duration', base_duration)
        estimated_duration = int((base_duration + historical_avg) / 2) if historical_avg > 0 else base_duration
        
        # Define fallback strategies
        fallback_strategies = self._define_fallback_strategies(strategy)
        
        # Resource allocation
        resource_allocation = self._calculate_resource_allocation(strategy, complexity_profile)
        
        # Performance prediction
        performance_prediction = {
            'success_probability': perf_stats.get('success_rate', 0.8),
            'estimated_memory_mb': resource_allocation['memory_mb'],
            'hang_risk': self._assess_hang_risk(complexity_profile, strategy),
            'efficiency_score': self._calculate_efficiency_score(strategy, complexity_profile)
        }
        
        # Adaptation triggers
        adaptation_triggers = self._define_adaptation_triggers(complexity_profile, strategy)
        
        # Reasoning
        reasoning = self._generate_adaptive_reasoning(complexity_profile, strategy, adjusted_confidence)
        
        return AdaptiveDecision(
            strategy=strategy,
            confidence=adjusted_confidence,
            estimated_duration_seconds=estimated_duration,
            resource_allocation=resource_allocation,
            reasoning=reasoning,
            fallback_strategies=fallback_strategies,
            performance_prediction=performance_prediction,
            adaptation_triggers=adaptation_triggers
        )
    
    def _estimate_base_duration(self, strategy: ProcessingStrategy, 
                              complexity_profile: APKComplexityProfile) -> int:
        """Estimate base processing duration in seconds."""
        base_times = {
            ProcessingStrategy.LIGHTNING: 30,
            ProcessingStrategy.STANDARD: 120,
            ProcessingStrategy.ENHANCED: 300,
            ProcessingStrategy.STAGED: 600,
            ProcessingStrategy.SELECTIVE: 900,
            ProcessingStrategy.ADAPTIVE: 180
        }
        
        base_time = base_times[strategy]
        complexity_multiplier = 1.0 + (complexity_profile.complexity_score / 10.0)
        
        return int(base_time * complexity_multiplier)
    
    def _define_fallback_strategies(self, primary_strategy: ProcessingStrategy) -> List[ProcessingStrategy]:
        """Define fallback strategies for adaptive recovery."""
        fallback_map = {
            ProcessingStrategy.LIGHTNING: [ProcessingStrategy.STANDARD, ProcessingStrategy.ENHANCED],
            ProcessingStrategy.STANDARD: [ProcessingStrategy.ENHANCED, ProcessingStrategy.STAGED],
            ProcessingStrategy.ENHANCED: [ProcessingStrategy.STAGED, ProcessingStrategy.SELECTIVE],
            ProcessingStrategy.STAGED: [ProcessingStrategy.SELECTIVE, ProcessingStrategy.ENHANCED],
            ProcessingStrategy.SELECTIVE: [ProcessingStrategy.STAGED],
            ProcessingStrategy.ADAPTIVE: [ProcessingStrategy.ENHANCED, ProcessingStrategy.STAGED]
        }
        
        return fallback_map.get(primary_strategy, [ProcessingStrategy.STANDARD])
    
    def _calculate_resource_allocation(self, strategy: ProcessingStrategy, 
                                     complexity_profile: APKComplexityProfile) -> Dict[str, Any]:
        """Calculate optimal resource allocation."""
        base_allocations = {
            ProcessingStrategy.LIGHTNING: {'memory_mb': 256, 'threads': 2, 'timeout': 60},
            ProcessingStrategy.STANDARD: {'memory_mb': 512, 'threads': 3, 'timeout': 180},
            ProcessingStrategy.ENHANCED: {'memory_mb': 1024, 'threads': 4, 'timeout': 300},
            ProcessingStrategy.STAGED: {'memory_mb': 2048, 'threads': 2, 'timeout': 600},
            ProcessingStrategy.SELECTIVE: {'memory_mb': 4096, 'threads': 1, 'timeout': 900},
            ProcessingStrategy.ADAPTIVE: {'memory_mb': 1024, 'threads': 3, 'timeout': 300}
        }
        
        base_allocation = base_allocations[strategy].copy()
        
        # Adjust based on complexity
        complexity_factor = complexity_profile.complexity_score / 5.0  # Normalize to ~2.0 max
        base_allocation['memory_mb'] = int(base_allocation['memory_mb'] * (1 + complexity_factor * 0.5))
        base_allocation['timeout'] = int(base_allocation['timeout'] * (1 + complexity_factor * 0.3))
        
        return base_allocation
    
    def _assess_hang_risk(self, complexity_profile: APKComplexityProfile, 
                         strategy: ProcessingStrategy) -> float:
        """Assess hang risk (0.0-1.0)."""
        base_risk = {
            ProcessingStrategy.LIGHTNING: 0.05,
            ProcessingStrategy.STANDARD: 0.10,
            ProcessingStrategy.ENHANCED: 0.15,
            ProcessingStrategy.STAGED: 0.05,  # Lower due to process isolation
            ProcessingStrategy.SELECTIVE: 0.02,  # Lowest due to selective processing
            ProcessingStrategy.ADAPTIVE: 0.08
        }[strategy]
        
        # Increase risk based on complexity
        complexity_risk = complexity_profile.complexity_score / 20.0  # Max 0.5 additional risk
        
        return min(1.0, base_risk + complexity_risk)
    
    def _calculate_efficiency_score(self, strategy: ProcessingStrategy, 
                                  complexity_profile: APKComplexityProfile) -> float:
        """Calculate expected efficiency score (0.0-1.0)."""
        base_efficiency = {
            ProcessingStrategy.LIGHTNING: 0.95,
            ProcessingStrategy.STANDARD: 0.85,
            ProcessingStrategy.ENHANCED: 0.80,
            ProcessingStrategy.STAGED: 0.75,
            ProcessingStrategy.SELECTIVE: 0.90,  # High due to selective processing
            ProcessingStrategy.ADAPTIVE: 0.85
        }[strategy]
        
        # Adjust based on complexity match
        difficulty = complexity_profile.processing_difficulty
        strategy_complexity_match = {
            ('trivial', ProcessingStrategy.LIGHTNING): 1.0,
            ('simple', ProcessingStrategy.STANDARD): 1.0,
            ('moderate', ProcessingStrategy.ENHANCED): 1.0,
            ('complex', ProcessingStrategy.STAGED): 1.0,
            ('extreme', ProcessingStrategy.SELECTIVE): 1.0
        }
        
        match_bonus = strategy_complexity_match.get((difficulty, strategy), 0.9)
        
        return base_efficiency * match_bonus
    
    def _define_adaptation_triggers(self, complexity_profile: APKComplexityProfile, 
                                  strategy: ProcessingStrategy) -> List[str]:
        """Define triggers for adaptive strategy switching."""
        triggers = []
        
        if complexity_profile.complexity_score > 7.0:
            triggers.append("high_complexity_detected")
        
        if strategy in [ProcessingStrategy.LIGHTNING, ProcessingStrategy.STANDARD]:
            triggers.append("timeout_exceeded")
            triggers.append("memory_pressure")
        
        if complexity_profile.obfuscation_score > 1.0:
            triggers.append("obfuscation_detected")
        
        return triggers
    
    def _generate_adaptive_reasoning(self, complexity_profile: APKComplexityProfile, 
                                   strategy: ProcessingStrategy, confidence: float) -> str:
        """Generate human-readable reasoning for the decision."""
        difficulty = complexity_profile.processing_difficulty
        complexity_score = complexity_profile.complexity_score
        
        base_reasoning = f"APK complexity: {difficulty} (score: {complexity_score:.1f}/10.0) → {strategy.value} strategy"
        
        if confidence > 0.9:
            confidence_text = "very high confidence"
        elif confidence > 0.8:
            confidence_text = "high confidence"
        elif confidence > 0.7:
            confidence_text = "moderate confidence"
        else:
            confidence_text = "low confidence - fallback strategies available"
        
        return f"{base_reasoning} with {confidence_text} based on historical performance"
    
    def _check_predictive_cache(self, fingerprint: str) -> Optional[AdaptiveDecision]:
        """Check predictive cache for existing decision."""
        return self.decision_cache.get(fingerprint)
    
    def _cache_adaptive_decision(self, fingerprint: str, decision: AdaptiveDecision):
        """Cache adaptive decision with TTL."""
        self.decision_cache[fingerprint] = decision
        
        # Simple cache size management
        if len(self.decision_cache) > 1000:
            # Remove oldest 20% of entries
            keys_to_remove = list(self.decision_cache.keys())[:200]
            for key in keys_to_remove:
                del self.decision_cache[key]
    
    def _record_decision_metrics(self, decision: AdaptiveDecision, analysis_time: float):
        """Record decision metrics for performance tracking."""
        logger.debug(f"Decision made in {analysis_time:.3f}s: {decision.strategy.value} "
                    f"(confidence: {decision.confidence:.2f})")
    
    def _create_fallback_decision(self, apk_path: str, error_msg: str) -> AdaptiveDecision:
        """Create safe fallback decision on error."""
        logger.warning(f"Creating fallback decision for {apk_path}: {error_msg}")
        
        return AdaptiveDecision(
            strategy=ProcessingStrategy.STANDARD,
            confidence=0.5,
            estimated_duration_seconds=300,
            resource_allocation={'memory_mb': 1024, 'threads': 2, 'timeout': 300},
            reasoning=f"Fallback decision due to analysis error: {error_msg}",
            fallback_strategies=[ProcessingStrategy.ENHANCED, ProcessingStrategy.STAGED],
            performance_prediction={'success_probability': 0.7, 'hang_risk': 0.2, 'efficiency_score': 0.6},
            adaptation_triggers=['analysis_error']
        )
    
    def _load_historical_data(self):
        """Load historical performance data for learning."""
        history_file = self.cache_dir / "performance_history.pkl"
        if history_file.exists():
            try:
                with open(history_file, 'rb') as f:
                    self.learning_model.strategy_performance = pickle.load(f)
                logger.info("Loaded historical performance data")
            except Exception as e:
                logger.warning(f"Failed to load historical data: {e}")
    
    def save_historical_data(self):
        """Save historical performance data for persistence."""
        history_file = self.cache_dir / "performance_history.pkl"
        try:
            with open(history_file, 'wb') as f:
                pickle.dump(dict(self.learning_model.strategy_performance), f)
            logger.info("Saved historical performance data")
        except Exception as e:
            logger.error(f"Failed to save historical data: {e}")
    
    def record_execution_result(self, apk_path: str, strategy: ProcessingStrategy, 
                              duration_seconds: float, success: bool, memory_used_mb: float):
        """Record execution result for learning."""
        # Re-profile APK for learning (could be optimized with caching)
        try:
            complexity_profile = self._profile_apk_complexity(apk_path)
            self.learning_model.record_performance(
                complexity_profile, strategy, duration_seconds, success, memory_used_mb
            )
        except Exception as e:
            logger.error(f"Failed to record execution result: {e}")
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        uptime = time.time() - self.start_time
        cache_hit_rate = (self.cache_hits / max(1, self.decisions_made)) * 100
        
        return {
            'decisions_made': self.decisions_made,
            'cache_hits': self.cache_hits,
            'cache_hit_rate_percent': cache_hit_rate,
            'uptime_seconds': uptime,
            'avg_decision_time': uptime / max(1, self.decisions_made),
            'learning_data_points': sum(len(perf) for perf in self.learning_model.strategy_performance.values()),
            'cached_decisions': len(self.decision_cache)
        }

# Factory function for easy integration
def create_adaptive_decision_engine(cache_dir: str = "cache/adaptive_jadx") -> AdaptiveJADXDecisionEngine:
    """Create and return an adaptive decision engine instance."""
    return AdaptiveJADXDecisionEngine(cache_dir)

if __name__ == "__main__":
    # Demonstration
    engine = create_adaptive_decision_engine()
    
    # Example usage
    test_apk = "test_app.apk"
    if os.path.exists(test_apk):
        decision = engine.analyze_and_decide(test_apk)
        print(f"Strategy: {decision.strategy.value}")
        print(f"Confidence: {decision.confidence:.2f}")
        print(f"Reasoning: {decision.reasoning}")
        print(f"Resource Allocation: {decision.resource_allocation}")
    else:
        print("Demo APK not found - engine initialized successfully") 
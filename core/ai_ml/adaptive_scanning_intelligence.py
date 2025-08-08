#!/usr/bin/env python3
"""
Adaptive Scanning Intelligence System

AI-powered system that analyzes APK characteristics and dynamically optimizes
scanning strategies, plugin selection, and resource allocation for maximum
efficiency and accuracy.
"""

import logging
import json
import hashlib
import os
import pickle
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import re

# ML imports with fallback
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingRegressor
    from sklearn.cluster import KMeans, DBSCAN
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.metrics import accuracy_score, mean_squared_error
    from sklearn.model_selection import train_test_split
    import pandas as pd
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class APKCharacteristics:
    """Comprehensive APK characteristics for adaptive scanning."""
    file_size: int
    package_name: str
    app_category: str
    complexity_score: float
    security_risk_score: float
    resource_count: int
    activity_count: int
    service_count: int
    permission_count: int
    api_level: int
    framework_type: str
    obfuscation_level: float
    third_party_libraries: List[str]
    encryption_indicators: List[str]
    network_usage_indicators: List[str]
    
@dataclass 
class ScanningStrategy:
    """Optimized scanning strategy for specific APK characteristics."""
    strategy_id: str
    execution_mode: str
    plugin_selection: List[str]
    timeout_multiplier: float
    resource_allocation: Dict[str, int]
    priority_areas: List[str]
    confidence: float
    estimated_duration: float
    
@dataclass
class AdaptiveRecommendation:
    """Adaptive scanning recommendation."""
    recommended_strategy: ScanningStrategy
    rationale: str
    confidence: float
    expected_findings: int
    risk_areas: List[str]
    optimization_tips: List[str]

class AdaptiveScanningIntelligence:
    """
    Adaptive Scanning Intelligence System.
    
    Analyzes APK characteristics and provides intelligent recommendations for:
    - Optimal scanning strategies
    - Plugin selection and prioritization  
    - Resource allocation
    - Execution mode selection
    - Timeout optimization
    """
    
    def __init__(self, model_cache_dir: str = "models/adaptive_scanning"):
        """Initialize the adaptive scanning intelligence system."""
        self.logger = logging.getLogger(__name__)
        self.model_cache_dir = Path(model_cache_dir)
        self.model_cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Core components
        self.apk_analyzer = APKCharacteristicsAnalyzer()
        self.strategy_optimizer = ScanningStrategyOptimizer()
        self.ml_models = {}
        
        # Historical data
        self.scan_history = []
        self.performance_data = []
        self.apk_profiles = {}
        
        # Initialize ML components
        if ML_AVAILABLE:
            self._initialize_ml_components()
            self._load_or_create_models()
        else:
            self.logger.warning("ML libraries not available - using heuristic-based optimization")
        
        # Initialize predefined strategies
        self._initialize_scanning_strategies()
        
        self.logger.info("Adaptive Scanning Intelligence initialized")
    
    def _initialize_ml_components(self):
        """Initialize machine learning components."""
        if not ML_AVAILABLE:
            return
        
        # ML models for different aspects
        self.ml_models = {
            "complexity_predictor": RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                random_state=42
            ),
            "duration_estimator": GradientBoostingRegressor(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=10,
                random_state=42
            ),
            "strategy_selector": RandomForestClassifier(
                n_estimators=150,
                max_depth=25,
                random_state=42,
                class_weight='balanced'
            ),
            "risk_assessor": RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                random_state=42
            ),
            "apk_clusterer": KMeans(
                n_clusters=8,
                random_state=42,
                n_init=10
            )
        }
        
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        self.logger.info("ML components for adaptive scanning initialized")
    
    def _initialize_scanning_strategies(self):
        """Initialize predefined scanning strategies."""
        self.scanning_strategies = {
            "lightweight": ScanningStrategy(
                strategy_id="lightweight",
                execution_mode="parallel",
                plugin_selection=["manifest_analyzer", "permission_analyzer", "basic_static_analysis"],
                timeout_multiplier=0.5,
                resource_allocation={"workers": 2, "memory_gb": 2},
                priority_areas=["permissions", "manifest"],
                confidence=0.8,
                estimated_duration=60.0
            ),
            
            "comprehensive": ScanningStrategy(
                strategy_id="comprehensive",
                execution_mode="adaptive",
                plugin_selection=["all"],
                timeout_multiplier=2.0,
                resource_allocation={"workers": 8, "memory_gb": 8},
                priority_areas=["all"],
                confidence=0.95,
                estimated_duration=600.0
            ),
            
            "security_focused": ScanningStrategy(
                strategy_id="security_focused",
                execution_mode="parallel",
                plugin_selection=["crypto_analyzer", "network_analyzer", "permission_analyzer", 
                                "hardcoded_secrets", "vulnerability_scanner"],
                timeout_multiplier=1.5,
                resource_allocation={"workers": 6, "memory_gb": 6},
                priority_areas=["cryptography", "network", "secrets"],
                confidence=0.9,
                estimated_duration=300.0
            ),
            
            "performance_optimized": ScanningStrategy(
                strategy_id="performance_optimized",
                execution_mode="process_separated",
                plugin_selection=["essential_plugins"],
                timeout_multiplier=0.8,
                resource_allocation={"workers": 4, "memory_gb": 4},
                priority_areas=["high_impact"],
                confidence=0.85,
                estimated_duration=180.0
            ),
            
            "obfuscated_app": ScanningStrategy(
                strategy_id="obfuscated_app", 
                execution_mode="sequential",
                plugin_selection=["deobfuscation", "advanced_static", "behavioral_analysis"],
                timeout_multiplier=3.0,
                resource_allocation={"workers": 2, "memory_gb": 12},
                priority_areas=["deobfuscation", "advanced_analysis"],
                confidence=0.7,
                estimated_duration=900.0
            ),
            
            "enterprise_app": ScanningStrategy(
                strategy_id="enterprise_app",
                execution_mode="adaptive",
                plugin_selection=["compliance_checker", "enterprise_security", "data_protection"],
                timeout_multiplier=1.8,
                resource_allocation={"workers": 6, "memory_gb": 8},
                priority_areas=["compliance", "data_protection", "enterprise_security"],
                confidence=0.9,
                estimated_duration=450.0
            )
        }
    
    def analyze_and_recommend(self, apk_path: str, context: Dict[str, Any] = None) -> AdaptiveRecommendation:
        """
        Analyze APK and provide adaptive scanning recommendation.
        
        Args:
            apk_path: Path to APK file
            context: Additional context information
            
        Returns:
            AdaptiveRecommendation with optimized strategy
        """
        context = context or {}
        
        # Analyze APK characteristics
        apk_characteristics = self.apk_analyzer.analyze_apk(apk_path)
        
        # ML-enhanced analysis
        ml_insights = {}
        if ML_AVAILABLE and self.ml_models:
            ml_insights = self._get_ml_insights(apk_characteristics, context)
        
        # Strategy selection
        recommended_strategy = self._select_optimal_strategy(
            apk_characteristics, ml_insights, context
        )
        
        # Generate recommendation
        recommendation = self._generate_recommendation(
            apk_characteristics, recommended_strategy, ml_insights
        )
        
        # Record for learning
        self._record_analysis(apk_path, apk_characteristics, recommendation, context)
        
        return recommendation
    
    def _get_ml_insights(self, characteristics: APKCharacteristics, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get ML-powered insights about the APK."""
        try:
            # Extract features
            features = self._extract_apk_features(characteristics, context)
            
            # Predict complexity
            complexity = self._predict_complexity(features)
            
            # Estimate duration
            duration = self._estimate_scan_duration(features)
            
            # Assess risk level
            risk_assessment = self._assess_security_risk(features)
            
            # Cluster analysis
            cluster_info = self._get_cluster_insights(features)
            
            return {
                "predicted_complexity": complexity,
                "estimated_duration": duration,
                "risk_assessment": risk_assessment,
                "cluster_info": cluster_info,
                "features": features
            }
            
        except Exception as e:
            self.logger.error(f"ML insights generation failed: {e}")
            return {"error": str(e)}
    
    def _select_optimal_strategy(self, characteristics: APKCharacteristics, 
                               ml_insights: Dict[str, Any], 
                               context: Dict[str, Any]) -> ScanningStrategy:
        """Select optimal scanning strategy based on analysis."""
        
        # Score each strategy
        strategy_scores = {}
        
        for strategy_id, strategy in self.scanning_strategies.items():
            score = self._score_strategy(strategy, characteristics, ml_insights, context)
            strategy_scores[strategy_id] = score
        
        # Select best strategy
        best_strategy_id = max(strategy_scores, key=strategy_scores.get)
        base_strategy = self.scanning_strategies[best_strategy_id]
        
        # Customize strategy based on characteristics
        customized_strategy = self._customize_strategy(
            base_strategy, characteristics, ml_insights
        )
        
        return customized_strategy
    
    def _score_strategy(self, strategy: ScanningStrategy, 
                       characteristics: APKCharacteristics,
                       ml_insights: Dict[str, Any], 
                       context: Dict[str, Any]) -> float:
        """Score a strategy for the given APK characteristics."""
        score = 0.0
        
        # File size considerations
        if characteristics.file_size < 10 * 1024 * 1024:  # < 10MB
            if strategy.strategy_id in ["lightweight", "performance_optimized"]:
                score += 0.3
        elif characteristics.file_size > 100 * 1024 * 1024:  # > 100MB
            if strategy.strategy_id in ["comprehensive", "obfuscated_app"]:
                score += 0.3
        
        # Complexity considerations
        if characteristics.complexity_score > 0.8:
            if strategy.strategy_id in ["comprehensive", "obfuscated_app"]:
                score += 0.4
        elif characteristics.complexity_score < 0.3:
            if strategy.strategy_id in ["lightweight", "performance_optimized"]:
                score += 0.4
        
        # Security risk considerations
        if characteristics.security_risk_score > 0.7:
            if strategy.strategy_id in ["security_focused", "comprehensive"]:
                score += 0.4
        
        # Obfuscation considerations
        if characteristics.obfuscation_level > 0.6:
            if strategy.strategy_id == "obfuscated_app":
                score += 0.5
        
        # Framework type considerations
        if characteristics.framework_type in ["enterprise", "corporate"]:
            if strategy.strategy_id == "enterprise_app":
                score += 0.4
        
        # ML insights considerations
        if ml_insights:
            predicted_complexity = ml_insights.get("predicted_complexity", 0.5)
            estimated_duration = ml_insights.get("estimated_duration", 300)
            
            # Match strategy to predicted characteristics
            if predicted_complexity > 0.8 and strategy.strategy_id in ["comprehensive", "obfuscated_app"]:
                score += 0.2
            if estimated_duration > 600 and strategy.timeout_multiplier > 1.5:
                score += 0.2
        
        # Context considerations
        if context.get("time_constraint") == "low" and strategy.strategy_id in ["lightweight", "performance_optimized"]:
            score += 0.3
        if context.get("thoroughness_required") and strategy.strategy_id == "comprehensive":
            score += 0.3
        
        return score
    
    def _customize_strategy(self, base_strategy: ScanningStrategy, 
                          characteristics: APKCharacteristics,
                          ml_insights: Dict[str, Any]) -> ScanningStrategy:
        """Customize strategy based on specific APK characteristics."""
        
        # Create customized copy
        customized = ScanningStrategy(
            strategy_id=f"{base_strategy.strategy_id}_customized",
            execution_mode=base_strategy.execution_mode,
            plugin_selection=base_strategy.plugin_selection.copy(),
            timeout_multiplier=base_strategy.timeout_multiplier,
            resource_allocation=base_strategy.resource_allocation.copy(),
            priority_areas=base_strategy.priority_areas.copy(),
            confidence=base_strategy.confidence,
            estimated_duration=base_strategy.estimated_duration
        )
        
        # Adjust timeout based on characteristics
        if characteristics.file_size > 50 * 1024 * 1024:  # Large APK
            customized.timeout_multiplier *= 1.5
        if characteristics.obfuscation_level > 0.5:
            customized.timeout_multiplier *= 1.8
        if characteristics.complexity_score > 0.8:
            customized.timeout_multiplier *= 1.3
        
        # Adjust resources based on characteristics
        if characteristics.resource_count > 1000:
            customized.resource_allocation["memory_gb"] = min(
                customized.resource_allocation.get("memory_gb", 4) * 1.5, 16
            )
        
        # Add specific plugins based on characteristics
        if characteristics.encryption_indicators:
            if "crypto_analyzer" not in customized.plugin_selection:
                customized.plugin_selection.append("crypto_analyzer")
        
        if characteristics.network_usage_indicators:
            if "network_analyzer" not in customized.plugin_selection:
                customized.plugin_selection.append("network_analyzer")
        
        if len(characteristics.third_party_libraries) > 10:
            if "library_analyzer" not in customized.plugin_selection:
                customized.plugin_selection.append("library_analyzer")
        
        # Adjust execution mode based on ML insights
        if ml_insights.get("predicted_complexity", 0.5) > 0.9:
            customized.execution_mode = "sequential"  # More stable for complex apps
        
        # Update estimated duration
        if ml_insights.get("estimated_duration"):
            customized.estimated_duration = ml_insights["estimated_duration"] * customized.timeout_multiplier
        
        return customized
    
    def _generate_recommendation(self, characteristics: APKCharacteristics,
                               strategy: ScanningStrategy,
                               ml_insights: Dict[str, Any]) -> AdaptiveRecommendation:
        """Generate comprehensive adaptive recommendation."""
        
        # Generate rationale
        rationale_parts = []
        
        # File size rationale
        size_mb = characteristics.file_size / (1024 * 1024)
        if size_mb < 10:
            rationale_parts.append("Small APK size enables lightweight scanning approach")
        elif size_mb > 50:
            rationale_parts.append("Large APK size requires comprehensive analysis with extended timeouts")
        
        # Complexity rationale
        if characteristics.complexity_score > 0.8:
            rationale_parts.append("High complexity score indicates need for thorough analysis")
        elif characteristics.complexity_score < 0.3:
            rationale_parts.append("Low complexity allows for optimized scanning approach")
        
        # Security risk rationale
        if characteristics.security_risk_score > 0.7:
            rationale_parts.append("High security risk score prioritizes security-focused plugins")
        
        # Obfuscation rationale
        if characteristics.obfuscation_level > 0.5:
            rationale_parts.append("Detected obfuscation requires specialized analysis techniques")
        
        rationale = ". ".join(rationale_parts) + "."
        
        # Predict expected findings
        expected_findings = self._predict_expected_findings(characteristics, ml_insights)
        
        # Identify risk areas
        risk_areas = self._identify_risk_areas(characteristics)
        
        # Generate optimization tips
        optimization_tips = self._generate_optimization_tips(characteristics, strategy)
        
        # Calculate overall confidence
        confidence = self._calculate_recommendation_confidence(characteristics, ml_insights, strategy)
        
        return AdaptiveRecommendation(
            recommended_strategy=strategy,
            rationale=rationale,
            confidence=confidence,
            expected_findings=expected_findings,
            risk_areas=risk_areas,
            optimization_tips=optimization_tips
        )
    
    def _predict_expected_findings(self, characteristics: APKCharacteristics, 
                                 ml_insights: Dict[str, Any]) -> int:
        """Predict expected number of findings."""
        base_findings = 5  # Base expectation
        
        # Adjust based on characteristics
        if characteristics.security_risk_score > 0.8:
            base_findings += 10
        if characteristics.permission_count > 20:
            base_findings += 5
        if len(characteristics.third_party_libraries) > 15:
            base_findings += 8
        if characteristics.obfuscation_level > 0.5:
            base_findings += 7
        
        # ML adjustment
        if ml_insights.get("predicted_complexity", 0.5) > 0.8:
            base_findings = int(base_findings * 1.5)
        
        return min(base_findings, 50)  # Cap at reasonable max
    
    def _identify_risk_areas(self, characteristics: APKCharacteristics) -> List[str]:
        """Identify potential risk areas based on characteristics."""
        risk_areas = []
        
        if characteristics.permission_count > 15:
            risk_areas.append("Excessive permissions")
        
        if characteristics.obfuscation_level > 0.5:
            risk_areas.append("Code obfuscation")
        
        if len(characteristics.encryption_indicators) == 0 and characteristics.security_risk_score > 0.5:
            risk_areas.append("Lack of encryption")
        
        if len(characteristics.network_usage_indicators) > 3:
            risk_areas.append("Extensive network usage")
        
        if len(characteristics.third_party_libraries) > 20:
            risk_areas.append("Heavy third-party dependencies")
        
        if characteristics.api_level < 23:  # Android 6.0
            risk_areas.append("Outdated API level")
        
        return risk_areas
    
    def _generate_optimization_tips(self, characteristics: APKCharacteristics, 
                                  strategy: ScanningStrategy) -> List[str]:
        """Generate optimization tips for the scanning process."""
        tips = []
        
        # Resource optimization tips
        if characteristics.file_size > 100 * 1024 * 1024:
            tips.append("Consider increasing memory allocation for large APK analysis")
        
        if characteristics.obfuscation_level > 0.7:
            tips.append("Enable advanced deobfuscation techniques for better analysis")
        
        if len(characteristics.third_party_libraries) > 25:
            tips.append("Focus on known vulnerable libraries for efficiency")
        
        # Execution optimization tips
        if strategy.execution_mode == "parallel" and characteristics.complexity_score > 0.9:
            tips.append("Consider sequential execution for very complex applications")
        
        if strategy.timeout_multiplier < 1.5 and characteristics.obfuscation_level > 0.6:
            tips.append("Increase timeout values for obfuscated applications")
        
        # Plugin optimization tips
        if "crypto_analyzer" not in strategy.plugin_selection and len(characteristics.encryption_indicators) > 0:
            tips.append("Add cryptography analysis plugins for apps with encryption")
        
        return tips
    
    def _calculate_recommendation_confidence(self, characteristics: APKCharacteristics,
                                           ml_insights: Dict[str, Any], 
                                           strategy: ScanningStrategy) -> float:
        """Calculate confidence in the recommendation."""
        confidence = 0.7  # Base confidence
        
        # Increase confidence based on available data
        if ml_insights and not ml_insights.get("error"):
            confidence += 0.1
        
        if characteristics.file_size > 1024:  # Has actual APK data
            confidence += 0.1
        
        if len(self.scan_history) > 10:  # Historical data available
            confidence += 0.1
        
        # Decrease confidence for edge cases
        if characteristics.obfuscation_level > 0.9:
            confidence -= 0.1
        
        if characteristics.file_size > 500 * 1024 * 1024:  # Very large APK
            confidence -= 0.1
        
        return max(0.5, min(1.0, confidence))
    
    def record_scan_results(self, apk_path: str, strategy_used: str, 
                          actual_duration: float, findings_count: int,
                          success: bool, performance_metrics: Dict[str, Any] = None):
        """Record scan results for learning and optimization."""
        scan_record = {
            "timestamp": datetime.now().isoformat(),
            "apk_path": apk_path,
            "apk_hash": self._get_file_hash(apk_path),
            "strategy_used": strategy_used,
            "actual_duration": actual_duration,
            "findings_count": findings_count,
            "success": success,
            "performance_metrics": performance_metrics or {}
        }
        
        self.scan_history.append(scan_record)
        
        # Keep only recent history
        if len(self.scan_history) > 1000:
            self.scan_history = self.scan_history[-1000:]
        
        self.logger.info(f"Recorded scan results: duration={actual_duration:.1f}s, findings={findings_count}")
    
    def get_performance_insights(self) -> Dict[str, Any]:
        """Get performance insights from historical data."""
        if not self.scan_history:
            return {"message": "No historical data available"}
        
        # Calculate statistics
        durations = [record["actual_duration"] for record in self.scan_history]
        findings = [record["findings_count"] for record in self.scan_history]
        successes = [record["success"] for record in self.scan_history]
        
        insights = {
            "total_scans": len(self.scan_history),
            "success_rate": sum(successes) / len(successes),
            "average_duration": np.mean(durations),
            "average_findings": np.mean(findings),
            "strategy_usage": Counter(record["strategy_used"] for record in self.scan_history)
        }
        
        # Strategy performance analysis
        strategy_performance = defaultdict(list)
        for record in self.scan_history:
            strategy_performance[record["strategy_used"]].append({
                "duration": record["actual_duration"],
                "findings": record["findings_count"],
                "success": record["success"]
            })
        
        insights["strategy_performance"] = {}
        for strategy, records in strategy_performance.items():
            insights["strategy_performance"][strategy] = {
                "avg_duration": np.mean([r["duration"] for r in records]),
                "avg_findings": np.mean([r["findings"] for r in records]),
                "success_rate": np.mean([r["success"] for r in records])
            }
        
        return insights
    
    def retrain_models(self) -> Dict[str, float]:
        """Retrain ML models with accumulated scan data."""
        if not ML_AVAILABLE or len(self.scan_history) < 50:
            self.logger.warning("Insufficient data for model retraining")
            return {}
        
        try:
            # Prepare training data
            X, y_duration, y_strategy = self._prepare_training_data()
            
            # Retrain duration estimator
            duration_score = 0.0
            if len(X) > 10:
                X_train, X_test, y_train, y_test = train_test_split(X, y_duration, test_size=0.2, random_state=42)
                self.ml_models["duration_estimator"].fit(X_train, y_train)
                y_pred = self.ml_models["duration_estimator"].predict(X_test)
                duration_score = 1.0 / (1.0 + mean_squared_error(y_test, y_pred))
            
            # Retrain strategy selector
            strategy_score = 0.0
            if len(set(y_strategy)) > 1:  # Multiple strategies
                X_train, X_test, y_train, y_test = train_test_split(X, y_strategy, test_size=0.2, random_state=42)
                self.ml_models["strategy_selector"].fit(X_train, y_train)
                y_pred = self.ml_models["strategy_selector"].predict(X_test)
                strategy_score = accuracy_score(y_test, y_pred)
            
            # Save models
            self._save_models()
            
            self.logger.info(f"Retrained models with {len(self.scan_history)} scan records")
            
            return {
                "duration_estimator_score": duration_score,
                "strategy_selector_score": strategy_score
            }
            
        except Exception as e:
            self.logger.error(f"Model retraining failed: {e}")
            return {}
    
    # Helper methods
    def _extract_apk_features(self, characteristics: APKCharacteristics, context: Dict[str, Any]) -> Dict[str, float]:
        """Extract features for ML models."""
        features = {
            "file_size_mb": characteristics.file_size / (1024 * 1024),
            "complexity_score": characteristics.complexity_score,
            "security_risk_score": characteristics.security_risk_score,
            "resource_count": characteristics.resource_count,
            "activity_count": characteristics.activity_count,
            "service_count": characteristics.service_count,
            "permission_count": characteristics.permission_count,
            "api_level": characteristics.api_level,
            "obfuscation_level": characteristics.obfuscation_level,
            "third_party_lib_count": len(characteristics.third_party_libraries),
            "encryption_indicator_count": len(characteristics.encryption_indicators),
            "network_indicator_count": len(characteristics.network_usage_indicators),
        }
        
        # Framework type encoding
        framework_encoding = {
            "native": 1.0,
            "hybrid": 0.5,
            "web": 0.3,
            "enterprise": 0.8,
            "game": 0.6
        }
        features["framework_type_score"] = framework_encoding.get(characteristics.framework_type, 0.5)
        
        return features
    
    def _predict_complexity(self, features: Dict[str, float]) -> float:
        """Predict APK complexity using ML model."""
        # Simplified heuristic-based prediction
        complexity = (
            min(features.get("file_size_mb", 0) / 100, 1.0) * 0.3 +
            features.get("resource_count", 0) / 1000 * 0.2 +
            features.get("permission_count", 0) / 30 * 0.2 +
            features.get("third_party_lib_count", 0) / 20 * 0.3
        )
        return min(complexity, 1.0)
    
    def _estimate_scan_duration(self, features: Dict[str, float]) -> float:
        """Estimate scan duration using ML model."""
        # Simplified heuristic-based estimation
        base_duration = 180  # 3 minutes base
        
        # Adjust based on features
        size_factor = features.get("file_size_mb", 10) / 10
        complexity_factor = features.get("complexity_score", 0.5) * 2
        obfuscation_factor = features.get("obfuscation_level", 0) * 3
        
        duration = base_duration * (1 + size_factor + complexity_factor + obfuscation_factor)
        return min(duration, 1800)  # Cap at 30 minutes
    
    def _assess_security_risk(self, features: Dict[str, float]) -> Dict[str, float]:
        """Assess security risk using ML model."""
        risk_score = (
            features.get("permission_count", 0) / 30 * 0.3 +
            features.get("network_indicator_count", 0) / 5 * 0.2 +
            (1.0 - features.get("api_level", 23) / 30) * 0.3 +
            features.get("obfuscation_level", 0) * 0.2
        )
        
        return {
            "overall_risk": min(risk_score, 1.0),
            "privacy_risk": min(features.get("permission_count", 0) / 25, 1.0),
            "security_risk": min(risk_score * 1.2, 1.0)
        }
    
    def _get_cluster_insights(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Get cluster-based insights for the APK."""
        # Simplified clustering insights
        feature_values = list(features.values())
        
        if len(feature_values) > 0:
            avg_feature = np.mean(feature_values)
            if avg_feature > 0.8:
                cluster = "high_complexity"
            elif avg_feature > 0.5:
                cluster = "medium_complexity"
            else:
                cluster = "low_complexity"
        else:
            cluster = "unknown"
        
        return {
            "cluster": cluster,
            "similarity_apps": [],  # Would contain similar apps in production
            "cluster_characteristics": f"Apps in {cluster} cluster typically require specialized analysis"
        }
    
    def _record_analysis(self, apk_path: str, characteristics: APKCharacteristics,
                        recommendation: AdaptiveRecommendation, context: Dict[str, Any]):
        """Record analysis for learning."""
        analysis_record = {
            "timestamp": datetime.now().isoformat(),
            "apk_path": apk_path,
            "apk_hash": self._get_file_hash(apk_path),
            "characteristics": asdict(characteristics),
            "recommendation": asdict(recommendation),
            "context": context
        }
        
        # Store APK profile
        apk_hash = self._get_file_hash(apk_path)
        self.apk_profiles[apk_hash] = analysis_record
    
    def _get_file_hash(self, file_path: str) -> str:
        """Get file hash for identification."""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return hashlib.md5(file_path.encode()).hexdigest()
    
    def _prepare_training_data(self) -> Tuple[List[List[float]], List[float], List[str]]:
        """Prepare training data from scan history."""
        X = []
        y_duration = []
        y_strategy = []
        
        for record in self.scan_history:
            # Create feature vector from available data
            feature_vector = [
                record.get("actual_duration", 300) / 600,  # Normalized duration
                record.get("findings_count", 5) / 20,  # Normalized findings
                1.0 if record.get("success", True) else 0.0,  # Success indicator
                len(record.get("strategy_used", "")) / 20  # Strategy name length as proxy
            ]
            
            X.append(feature_vector)
            y_duration.append(record["actual_duration"])
            y_strategy.append(record["strategy_used"])
        
        return X, y_duration, y_strategy
    
    def _load_or_create_models(self):
        """Load existing models or create new ones."""
        model_file = self.model_cache_dir / "adaptive_scanning_models.pkl"
        
        if model_file.exists():
            try:
                with open(model_file, 'rb') as f:
                    saved_data = pickle.load(f)
                    self.ml_models.update(saved_data.get("models", {}))
                    self.scan_history = saved_data.get("scan_history", [])
                    self.apk_profiles = saved_data.get("apk_profiles", {})
                    self.logger.info("Loaded existing adaptive scanning models")
            except Exception as e:
                self.logger.warning(f"Failed to load adaptive scanning models: {e}")
    
    def _save_models(self):
        """Save ML models to disk."""
        model_file = self.model_cache_dir / "adaptive_scanning_models.pkl"
        
        try:
            save_data = {
                "models": self.ml_models,
                "scan_history": self.scan_history[-500:],  # Keep recent history
                "apk_profiles": dict(list(self.apk_profiles.items())[-200:]),  # Keep recent profiles
                "timestamp": datetime.now().isoformat()
            }
            
            with open(model_file, 'wb') as f:
                pickle.dump(save_data, f)
                
            self.logger.info("Saved adaptive scanning models to disk")
            
        except Exception as e:
            self.logger.error(f"Failed to save adaptive scanning models: {e}")


class APKCharacteristicsAnalyzer:
    """Analyzes APK files to extract comprehensive characteristics."""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.APKCharacteristicsAnalyzer")
    
    def analyze_apk(self, apk_path: str) -> APKCharacteristics:
        """Analyze APK file and extract characteristics."""
        try:
            # Basic file info
            file_size = os.path.getsize(apk_path)
            
            # Extract APK contents
            apk_info = self._extract_apk_info(apk_path)
            
            # Calculate derived metrics
            complexity_score = self._calculate_complexity_score(apk_info)
            security_risk_score = self._calculate_security_risk_score(apk_info)
            obfuscation_level = self._detect_obfuscation_level(apk_info)
            
            return APKCharacteristics(
                file_size=file_size,
                package_name=apk_info.get("package_name", "unknown"),
                app_category=apk_info.get("category", "unknown"),
                complexity_score=complexity_score,
                security_risk_score=security_risk_score,
                resource_count=apk_info.get("resource_count", 0),
                activity_count=apk_info.get("activity_count", 0),
                service_count=apk_info.get("service_count", 0),
                permission_count=apk_info.get("permission_count", 0),
                api_level=apk_info.get("api_level", 23),
                framework_type=apk_info.get("framework_type", "native"),
                obfuscation_level=obfuscation_level,
                third_party_libraries=apk_info.get("third_party_libraries", []),
                encryption_indicators=apk_info.get("encryption_indicators", []),
                network_usage_indicators=apk_info.get("network_indicators", [])
            )
            
        except Exception as e:
            self.logger.error(f"APK analysis failed for {apk_path}: {e}")
            # Return default characteristics
            return APKCharacteristics(
                file_size=os.path.getsize(apk_path) if os.path.exists(apk_path) else 0,
                package_name="unknown",
                app_category="unknown",
                complexity_score=0.5,
                security_risk_score=0.5,
                resource_count=0,
                activity_count=0,
                service_count=0,
                permission_count=0,
                api_level=23,
                framework_type="unknown",
                obfuscation_level=0.0,
                third_party_libraries=[],
                encryption_indicators=[],
                network_usage_indicators=[]
            )
    
    def _extract_apk_info(self, apk_path: str) -> Dict[str, Any]:
        """Extract information from APK file."""
        info = {}
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Get file list
                file_list = apk_zip.namelist()
                info["resource_count"] = len(file_list)
                
                # Analyze manifest
                if "AndroidManifest.xml" in file_list:
                    manifest_info = self._analyze_manifest(apk_zip, "AndroidManifest.xml")
                    info.update(manifest_info)
                
                # Detect libraries
                info["third_party_libraries"] = self._detect_libraries(file_list)
                
                # Detect framework type
                info["framework_type"] = self._detect_framework_type(file_list)
                
                # Detect encryption indicators
                info["encryption_indicators"] = self._detect_encryption_indicators(file_list)
                
                # Detect network indicators
                info["network_indicators"] = self._detect_network_indicators(file_list)
                
        except Exception as e:
            self.logger.error(f"Failed to extract APK info: {e}")
        
        return info
    
    def _analyze_manifest(self, apk_zip: zipfile.ZipFile, manifest_path: str) -> Dict[str, Any]:
        """Analyze AndroidManifest.xml (simplified analysis)."""
        info = {}
        
        try:
            # This is a simplified version - real implementation would parse binary XML
            with apk_zip.open(manifest_path) as manifest_file:
                manifest_data = manifest_file.read()
                
                # Count approximate components (very rough estimation)
                info["activity_count"] = manifest_data.count(b'activity')
                info["service_count"] = manifest_data.count(b'service')
                info["permission_count"] = manifest_data.count(b'permission')
                
                # Estimate API level (rough)
                if b'android:targetSdkVersion' in manifest_data:
                    # Simplified extraction - would need proper XML parsing
                    info["api_level"] = 23  # Default
                else:
                    info["api_level"] = 23
                
        except Exception as e:
            self.logger.debug(f"Manifest analysis failed: {e}")
            info.update({
                "activity_count": 0,
                "service_count": 0,
                "permission_count": 0,
                "api_level": 23
            })
        
        return info
    
    def _detect_libraries(self, file_list: List[str]) -> List[str]:
        """Detect third-party libraries from file paths."""
        libraries = []
        
        # Common library indicators
        library_patterns = [
            r'.*com/google/.*',
            r'.*androidx/.*',
            r'.*org/apache/.*',
            r'.*com/facebook/.*',
            r'.*com/squareup/.*',
            r'.*retrofit.*',
            r'.*okhttp.*',
            r'.*gson.*',
            r'.*firebase.*'
        ]
        
        detected_libs = set()
        for file_path in file_list:
            for pattern in library_patterns:
                if re.match(pattern, file_path):
                    # Extract library name
                    parts = file_path.split('/')
                    if len(parts) > 2:
                        lib_name = '/'.join(parts[:3])
                        detected_libs.add(lib_name)
        
        return list(detected_libs)
    
    def _detect_framework_type(self, file_list: List[str]) -> str:
        """Detect application framework type."""
        # Check for common framework indicators
        if any('flutter' in f.lower() for f in file_list):
            return "flutter"
        elif any('react' in f.lower() or 'ionic' in f.lower() for f in file_list):
            return "hybrid"
        elif any('cordova' in f.lower() or 'phonegap' in f.lower() for f in file_list):
            return "web"
        elif any('unity' in f.lower() or 'unreal' in f.lower() for f in file_list):
            return "game"
        elif any('enterprise' in f.lower() or 'corp' in f.lower() for f in file_list):
            return "enterprise"
        else:
            return "native"
    
    def _detect_encryption_indicators(self, file_list: List[str]) -> List[str]:
        """Detect encryption-related files and indicators."""
        indicators = []
        
        crypto_patterns = [
            r'.*crypto.*',
            r'.*encrypt.*',
            r'.*cipher.*',
            r'.*\.keystore$',
            r'.*\.p12$',
            r'.*\.jks$'
        ]
        
        for file_path in file_list:
            for pattern in crypto_patterns:
                if re.match(pattern, file_path, re.IGNORECASE):
                    indicators.append(file_path)
                    break
        
        return indicators
    
    def _detect_network_indicators(self, file_list: List[str]) -> List[str]:
        """Detect network-related indicators."""
        indicators = []
        
        network_patterns = [
            r'.*network.*',
            r'.*http.*',
            r'.*socket.*',
            r'.*api.*',
            r'.*retrofit.*',
            r'.*okhttp.*'
        ]
        
        for file_path in file_list:
            for pattern in network_patterns:
                if re.match(pattern, file_path, re.IGNORECASE):
                    indicators.append(file_path)
                    break
        
        return indicators
    
    def _calculate_complexity_score(self, apk_info: Dict[str, Any]) -> float:
        """Calculate complexity score based on APK characteristics."""
        score = 0.0
        
        # Component count contribution
        activity_count = apk_info.get("activity_count", 0)
        service_count = apk_info.get("service_count", 0)
        component_score = min((activity_count + service_count) / 20, 1.0)
        score += component_score * 0.3
        
        # Resource count contribution
        resource_count = apk_info.get("resource_count", 0)
        resource_score = min(resource_count / 1000, 1.0)
        score += resource_score * 0.2
        
        # Library count contribution
        lib_count = len(apk_info.get("third_party_libraries", []))
        lib_score = min(lib_count / 15, 1.0)
        score += lib_score * 0.3
        
        # Permission count contribution
        perm_count = apk_info.get("permission_count", 0)
        perm_score = min(perm_count / 25, 1.0)
        score += perm_score * 0.2
        
        return min(score, 1.0)
    
    def _calculate_security_risk_score(self, apk_info: Dict[str, Any]) -> float:
        """Calculate security risk score."""
        score = 0.0
        
        # Permission risk
        perm_count = apk_info.get("permission_count", 0)
        if perm_count > 20:
            score += 0.3
        elif perm_count > 10:
            score += 0.2
        
        # Network indicators
        network_indicators = len(apk_info.get("network_indicators", []))
        if network_indicators > 5:
            score += 0.2
        
        # Encryption indicators (lack of encryption is risky)
        encryption_indicators = len(apk_info.get("encryption_indicators", []))
        if encryption_indicators == 0:
            score += 0.2
        
        # API level risk (older APIs are riskier)
        api_level = apk_info.get("api_level", 23)
        if api_level < 23:
            score += 0.3
        elif api_level < 26:
            score += 0.1
        
        return min(score, 1.0)
    
    def _detect_obfuscation_level(self, apk_info: Dict[str, Any]) -> float:
        """Detect level of code obfuscation."""
        # Simplified obfuscation detection
        obfuscation_score = 0.0
        
        # Check for common obfuscation indicators
        third_party_libs = apk_info.get("third_party_libraries", [])
        
        # ProGuard/R8 indicators
        if any('proguard' in lib.lower() or 'r8' in lib.lower() for lib in third_party_libs):
            obfuscation_score += 0.5
        
        # High library count might indicate obfuscation
        if len(third_party_libs) > 30:
            obfuscation_score += 0.3
        
        # Low resource names entropy might indicate obfuscation (simplified)
        resource_count = apk_info.get("resource_count", 0)
        if resource_count > 500:  # Threshold for potential obfuscation
            obfuscation_score += 0.2
        
        return min(obfuscation_score, 1.0)


class ScanningStrategyOptimizer:
    """Optimizes scanning strategies based on performance data."""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.ScanningStrategyOptimizer")
        self.optimization_history = []
    
    def optimize_strategy(self, base_strategy: ScanningStrategy, 
                         performance_data: Dict[str, Any]) -> ScanningStrategy:
        """Optimize scanning strategy based on performance data."""
        optimized = ScanningStrategy(
            strategy_id=f"{base_strategy.strategy_id}_optimized",
            execution_mode=base_strategy.execution_mode,
            plugin_selection=base_strategy.plugin_selection.copy(),
            timeout_multiplier=base_strategy.timeout_multiplier,
            resource_allocation=base_strategy.resource_allocation.copy(),
            priority_areas=base_strategy.priority_areas.copy(),
            confidence=base_strategy.confidence,
            estimated_duration=base_strategy.estimated_duration
        )
        
        # Optimize based on performance data
        if performance_data.get("avg_duration", 0) > base_strategy.estimated_duration * 1.5:
            optimized.timeout_multiplier *= 1.3
        
        if performance_data.get("success_rate", 1.0) < 0.8:
            optimized.execution_mode = "sequential"  # More stable
        
        if performance_data.get("avg_findings", 0) < 5:
            # Add more comprehensive plugins
            if "comprehensive_scanner" not in optimized.plugin_selection:
                optimized.plugin_selection.append("comprehensive_scanner")
        
        return optimized 
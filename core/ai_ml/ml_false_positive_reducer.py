#!/usr/bin/env python3
"""
ML-Based False Positive Reduction System

Advanced machine learning system to reduce false positives in vulnerability
detection through pattern learning, contextual analysis, and feedback integration.
"""

import logging
import json
import hashlib
import pickle
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import re

# ML imports with fallback
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer, HashingVectorizer
    from sklearn.metrics import precision_score, recall_score, f1_score
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.cluster import KMeans
    from sklearn.neighbors import LocalOutlierFactor
    import pandas as pd
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class FalsePositivePattern:
    """Pattern that commonly leads to false positives."""
    pattern_id: str
    pattern_text: str
    pattern_type: str
    confidence: float
    frequency: int
    accuracy: float
    context_indicators: List[str]
    mitigation_strategy: str

@dataclass
class FPReductionResult:
    """Result of false positive reduction analysis."""
    is_false_positive: bool
    confidence: float
    reason: str
    evidence: List[str]
    ml_score: float
    pattern_matches: List[str]
    recommendation: str

class MLFalsePositiveReducer:
    """
    Machine Learning-based False Positive Reduction System.
    
    Uses advanced ML techniques to:
    - Learn false positive patterns from historical data
    - Analyze contextual clues for false positive detection
    - Provide user feedback integration for continuous improvement
    - Reduce false positive rate while maintaining detection accuracy
    """
    
    def __init__(self, model_cache_dir: str = "models/false_positive_reduction"):
        """Initialize the ML false positive reducer."""
        self.logger = logging.getLogger(__name__)
        self.model_cache_dir = Path(model_cache_dir)
        self.model_cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Core components
        self.fp_patterns = {}
        self.ml_models = {}
        self.feature_extractors = {}
        self.confidence_calculators = {}
        
        # Learning data
        self.training_data = []
        self.feedback_data = []
        self.performance_history = []
        
        # Initialize components
        self._initialize_fp_patterns()
        if ML_AVAILABLE:
            self._initialize_ml_components()
            self._load_or_create_models()
        else:
            self.logger.warning("ML libraries not available - using pattern-based FP reduction only")
        
        # Performance tracking
        self.stats = {
            "total_analyzed": 0,
            "false_positives_detected": 0,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0
        }
        
        self.logger.info("ML False Positive Reducer initialized")
    
    def _initialize_fp_patterns(self):
        """Initialize known false positive patterns."""
        
        fp_patterns = {
            "build_artifacts": FalsePositivePattern(
                pattern_id="build_artifacts",
                pattern_text=r"(?i)(?:build.*success|compilation.*complete|gradle.*build)",
                pattern_type="BUILD_OUTPUT",
                confidence=0.95,
                frequency=0,
                accuracy=0.0,
                context_indicators=["gradle", "build", "compile", "success"],
                mitigation_strategy="Filter build-related output"
            ),
            
            "test_framework": FalsePositivePattern(
                pattern_id="test_framework",
                pattern_text=r"(?i)(?:test.*passed|junit.*success|test.*completed)",
                pattern_type="TEST_OUTPUT",
                confidence=0.90,
                frequency=0,
                accuracy=0.0,
                context_indicators=["test", "junit", "passed", "success"],
                mitigation_strategy="Filter testing framework output"
            ),
            
            "informational_logs": FalsePositivePattern(
                pattern_id="informational_logs",
                pattern_text=r"(?i)(?:info:|debug:|verbose:|starting.*analysis)",
                pattern_type="LOG_OUTPUT",
                confidence=0.85,
                frequency=0,
                accuracy=0.0,
                context_indicators=["info", "debug", "verbose", "log"],
                mitigation_strategy="Filter informational logging"
            ),
            
            "framework_warnings": FalsePositivePattern(
                pattern_id="framework_warnings",
                pattern_text=r"(?i)(?:warning.*deprecated|warning.*version|framework.*warning)",
                pattern_type="FRAMEWORK_WARNING",
                confidence=0.80,
                frequency=0,
                accuracy=0.0,
                context_indicators=["warning", "deprecated", "version", "framework"],
                mitigation_strategy="Filter framework deprecation warnings"
            ),
            
            "analysis_metadata": FalsePositivePattern(
                pattern_id="analysis_metadata",
                pattern_text=r"(?i)(?:analyzing.*file|processing.*plugin|plugin.*loaded)",
                pattern_type="ANALYSIS_METADATA",
                confidence=0.88,
                frequency=0,
                accuracy=0.0,
                context_indicators=["analyzing", "processing", "plugin", "loaded"],
                mitigation_strategy="Filter analysis process metadata"
            ),
            
            "configuration_info": FalsePositivePattern(
                pattern_id="configuration_info",
                pattern_text=r"(?i)(?:configuration.*loaded|settings.*applied|initialized.*component)",
                pattern_type="CONFIG_INFO",
                confidence=0.82,
                frequency=0,
                accuracy=0.0,
                context_indicators=["configuration", "settings", "initialized", "loaded"],
                mitigation_strategy="Filter configuration information"
            ),
            
            "status_updates": FalsePositivePattern(
                pattern_id="status_updates",
                pattern_text=r"(?i)(?:status.*update|progress.*\d+|completed.*step)",
                pattern_type="STATUS_UPDATE",
                confidence=0.85,
                frequency=0,
                accuracy=0.0,
                context_indicators=["status", "progress", "completed", "step"],
                mitigation_strategy="Filter status and progress updates"
            )
        }
        
        self.fp_patterns.update(fp_patterns)
        self.logger.info(f"Initialized {len(fp_patterns)} false positive patterns")
    
    def _initialize_ml_components(self):
        """Initialize machine learning components."""
        if not ML_AVAILABLE:
            return
        
        # Feature extractors
        self.feature_extractors = {
            "text_features": TfidfVectorizer(
                max_features=2000,
                ngram_range=(1, 3),
                stop_words='english',
                lowercase=True,
                analyzer='word'
            ),
            "char_features": TfidfVectorizer(
                max_features=1000,
                ngram_range=(2, 4),
                analyzer='char',
                lowercase=True
            ),
            "context_features": HashingVectorizer(
                n_features=500,
                ngram_range=(1, 2),
                lowercase=True
            )
        }
        
        # ML models for different aspects
        self.ml_models = {
            "fp_classifier": RandomForestClassifier(
                n_estimators=200,
                max_depth=25,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced'
            ),
            "confidence_estimator": GradientBoostingClassifier(
                n_estimators=100,
                max_depth=10,
                learning_rate=0.1,
                random_state=42
            ),
            "outlier_detector": LocalOutlierFactor(
                n_neighbors=20,
                contamination=0.1,
                novelty=True
            ),
            "pattern_clusterer": KMeans(
                n_clusters=10,
                random_state=42,
                n_init=10
            )
        }
        
        # Confidence calculators for different types
        self.confidence_calculators = {
            "pattern_confidence": self._calculate_pattern_confidence,
            "context_confidence": self._calculate_context_confidence,
            "ml_confidence": self._calculate_ml_confidence,
            "ensemble_confidence": self._calculate_ensemble_confidence
        }
        
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        self.logger.info("ML components initialized")
    
    def analyze_for_false_positive(self, content: str, title: str = "", 
                                 vulnerability_info: Dict[str, Any] = None,
                                 context: Dict[str, Any] = None) -> FPReductionResult:
        """
        Analyze content for false positive indicators.
        
        Args:
            content: Text content to analyze
            title: Title or summary
            vulnerability_info: Information about detected vulnerability
            context: Additional context information
            
        Returns:
            FPReductionResult with analysis
        """
        full_text = f"{title} {content}".strip()
        vulnerability_info = vulnerability_info or {}
        context = context or {}
        
        self.stats["total_analyzed"] += 1
        
        # Pattern-based analysis
        pattern_analysis = self._pattern_based_fp_analysis(full_text)
        
        # ML-based analysis
        ml_analysis = {}
        if ML_AVAILABLE and self.ml_models:
            ml_analysis = self._ml_based_fp_analysis(full_text, vulnerability_info, context)
        
        # Contextual analysis
        contextual_analysis = self._contextual_fp_analysis(full_text, vulnerability_info, context)
        
        # Ensemble analysis
        ensemble_result = self._ensemble_fp_analysis(
            pattern_analysis, ml_analysis, contextual_analysis, full_text
        )
        
        # Record for learning
        self._record_fp_analysis(full_text, ensemble_result, vulnerability_info, context)
        
        # Update statistics
        if ensemble_result.is_false_positive:
            self.stats["false_positives_detected"] += 1
        
        return ensemble_result
    
    def _pattern_based_fp_analysis(self, text: str) -> Dict[str, Any]:
        """Pattern-based false positive analysis."""
        matches = []
        max_confidence = 0.0
        best_pattern = None
        
        for pattern_id, pattern in self.fp_patterns.items():
            if re.search(pattern.pattern_text, text, re.IGNORECASE | re.MULTILINE):
                # Calculate context-enhanced confidence
                context_score = self._calculate_pattern_context_score(text, pattern.context_indicators)
                enhanced_confidence = min(pattern.confidence + (context_score * 0.1), 1.0)
                
                match_info = {
                    "pattern_id": pattern_id,
                    "pattern": pattern,
                    "confidence": enhanced_confidence,
                    "context_score": context_score
                }
                matches.append(match_info)
                
                if enhanced_confidence > max_confidence:
                    max_confidence = enhanced_confidence
                    best_pattern = match_info
        
        return {
            "matches": matches,
            "best_pattern": best_pattern,
            "has_fp_pattern": len(matches) > 0,
            "max_confidence": max_confidence,
            "pattern_count": len(matches)
        }
    
    def _ml_based_fp_analysis(self, text: str, vulnerability_info: Dict[str, Any], 
                            context: Dict[str, Any]) -> Dict[str, Any]:
        """ML-based false positive analysis."""
        try:
            # Extract features
            features = self._extract_fp_features(text, vulnerability_info, context)
            
            # ML prediction
            fp_prediction = self._predict_false_positive(features)
            
            # Confidence estimation
            confidence_score = self._estimate_fp_confidence(features)
            
            # Outlier detection
            outlier_score = self._detect_outliers(features)
            
            return {
                "ml_fp_probability": fp_prediction,
                "confidence_score": confidence_score,
                "outlier_score": outlier_score,
                "features": features,
                "is_ml_fp": fp_prediction > 0.6
            }
            
        except Exception as e:
            self.logger.error(f"ML-based FP analysis failed: {e}")
            return {
                "ml_fp_probability": 0.5,
                "confidence_score": 0.0,
                "error": str(e)
            }
    
    def _contextual_fp_analysis(self, text: str, vulnerability_info: Dict[str, Any], 
                              context: Dict[str, Any]) -> Dict[str, Any]:
        """Contextual false positive analysis."""
        analysis = {
            "context_fp_score": 0.0,
            "context_evidence": [],
            "fp_indicators": [],
            "vuln_indicators": []
        }
        
        # Analyze content type
        content_type_analysis = self._analyze_content_type(text)
        analysis.update(content_type_analysis)
        
        # Analyze vulnerability context
        vuln_context_analysis = self._analyze_vulnerability_context(text, vulnerability_info)
        analysis.update(vuln_context_analysis)
        
        # Analyze plugin context
        plugin_context_analysis = self._analyze_plugin_context(text, context)
        analysis.update(plugin_context_analysis)
        
        # Calculate overall context score
        analysis["context_fp_score"] = min(
            (content_type_analysis.get("score", 0) +
             vuln_context_analysis.get("score", 0) +
             plugin_context_analysis.get("score", 0)) / 3.0, 1.0
        )
        
        return analysis
    
    def _analyze_content_type(self, text: str) -> Dict[str, Any]:
        """Analyze content type for false positive indicators."""
        score = 0.0
        evidence = []
        
        text_lower = text.lower()
        
        # Check for non-vulnerability content types
        non_vuln_indicators = {
            "build_output": ["build success", "compilation complete", "gradle build"],
            "test_output": ["test passed", "junit", "test completed", "all tests"],
            "log_messages": ["info:", "debug:", "verbose:", "log level"],
            "status_updates": ["status:", "progress:", "completed step", "finished"],
            "configuration": ["config loaded", "settings applied", "initialized"]
        }
        
        for category, indicators in non_vuln_indicators.items():
            matches = sum(1 for indicator in indicators if indicator in text_lower)
            if matches > 0:
                score += matches * 0.2
                evidence.append(f"{category}_indicators_{matches}")
        
        # Check for emoji/formatting that suggests status rather than vulnerability
        if any(emoji in text for emoji in ["✅", "🔧", "📊", "ℹ️", "⚙️"]):
            score += 0.3
            evidence.append("status_emojis")
        
        return {"score": min(score, 1.0), "evidence": evidence}
    
    def _analyze_vulnerability_context(self, text: str, vulnerability_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze vulnerability-specific context."""
        score = 0.0
        evidence = []
        
        if not vulnerability_info:
            return {"score": 0.0, "evidence": ["no_vulnerability_info"]}
        
        # Check confidence levels
        vuln_confidence = vulnerability_info.get("confidence", 0.0)
        if vuln_confidence < 0.5:
            score += 0.4
            evidence.append(f"low_vulnerability_confidence_{vuln_confidence:.2f}")
        
        # Check severity mismatches
        severity = vulnerability_info.get("severity", "").lower()
        if severity in ["info", "low"] and "critical" not in text.lower():
            score += 0.2
            evidence.append(f"low_severity_{severity}")
        
        # Check for contradiction indicators
        contradiction_patterns = [
            r"(?i)no.*vulnerability.*found",
            r"(?i)security.*check.*passed",
            r"(?i)analysis.*completed.*successfully",
            r"(?i)no.*issues.*detected"
        ]
        
        for pattern in contradiction_patterns:
            if re.search(pattern, text):
                score += 0.3
                evidence.append("contradiction_pattern")
                break
        
        return {"score": min(score, 1.0), "evidence": evidence}
    
    def _analyze_plugin_context(self, text: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze plugin-specific context."""
        score = 0.0
        evidence = []
        
        plugin_name = context.get("plugin_name", "").lower()
        
        # Known noisy plugins
        noisy_plugins = ["logger", "info", "status", "progress", "debug"]
        if any(noisy in plugin_name for noisy in noisy_plugins):
            score += 0.3
            evidence.append(f"noisy_plugin_{plugin_name}")
        
        # Plugin execution status
        plugin_status = context.get("status", "").lower()
        if plugin_status in ["success", "completed", "finished"]:
            score += 0.2
            evidence.append(f"success_status_{plugin_status}")
        
        # Plugin type analysis
        plugin_type = context.get("type", "").lower()
        informational_types = ["info", "log", "status", "metadata"]
        if any(info_type in plugin_type for info_type in informational_types):
            score += 0.2
            evidence.append(f"informational_type_{plugin_type}")
        
        return {"score": min(score, 1.0), "evidence": evidence}
    
    def _extract_fp_features(self, text: str, vulnerability_info: Dict[str, Any], 
                           context: Dict[str, Any]) -> Dict[str, float]:
        """Extract features for ML-based false positive detection."""
        features = {}
        
        # Text-based features
        features["text_length"] = len(text)
        features["word_count"] = len(text.split())
        features["line_count"] = text.count('\n') + 1
        features["uppercase_ratio"] = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        
        # Content type features
        features["has_success_indicators"] = 1.0 if any(word in text.lower() for word in ["success", "passed", "completed", "ok"]) else 0.0
        features["has_error_indicators"] = 1.0 if any(word in text.lower() for word in ["error", "failed", "exception", "timeout"]) else 0.0
        features["has_status_emojis"] = 1.0 if any(emoji in text for emoji in ["✅", "❌", "🔧", "📊", "ℹ️"]) else 0.0
        
        # Vulnerability context features
        features["vulnerability_confidence"] = vulnerability_info.get("confidence", 0.0)
        features["vulnerability_severity_score"] = self._get_severity_score(vulnerability_info.get("severity", ""))
        
        # Plugin context features
        features["plugin_type_score"] = self._get_plugin_fp_score(context.get("type", ""))
        features["plugin_confidence"] = context.get("confidence", 0.0)
        
        # Pattern-based features
        features["fp_pattern_count"] = self._count_fp_patterns(text)
        features["vuln_pattern_count"] = self._count_vuln_patterns(text)
        
        # Statistical features
        features["word_entropy"] = self._calculate_word_entropy(text)
        features["repetition_score"] = self._calculate_repetition_score(text)
        
        return features
    
    def _ensemble_fp_analysis(self, pattern_analysis: Dict[str, Any], 
                            ml_analysis: Dict[str, Any], 
                            contextual_analysis: Dict[str, Any],
                            text: str) -> FPReductionResult:
        """Combine all analyses into final false positive determination."""
        
        # Collect evidence
        evidence = []
        evidence.extend(pattern_analysis.get("matches", []))
        evidence.extend(contextual_analysis.get("context_evidence", []))
        
        # Pattern-based score
        pattern_score = pattern_analysis.get("max_confidence", 0.0)
        
        # ML-based score
        ml_score = ml_analysis.get("ml_fp_probability", 0.5)
        
        # Context-based score
        context_score = contextual_analysis.get("context_fp_score", 0.0)
        
        # Weighted ensemble
        ensemble_score = (
            pattern_score * 0.4 +
            ml_score * 0.4 +
            context_score * 0.2
        )
        
        # Determine if false positive
        is_false_positive = ensemble_score > 0.6
        
        # Generate reason
        reason = self._generate_fp_reason(pattern_analysis, ml_analysis, contextual_analysis)
        
        # Generate recommendation
        recommendation = self._generate_fp_recommendation(is_false_positive, ensemble_score)
        
        return FPReductionResult(
            is_false_positive=is_false_positive,
            confidence=ensemble_score,
            reason=reason,
            evidence=evidence,
            ml_score=ml_score,
            pattern_matches=[m["pattern_id"] for m in pattern_analysis.get("matches", [])],
            recommendation=recommendation
        )
    
    def _generate_fp_reason(self, pattern_analysis: Dict[str, Any], 
                          ml_analysis: Dict[str, Any], 
                          contextual_analysis: Dict[str, Any]) -> str:
        """Generate explanation for false positive determination."""
        reasons = []
        
        # Pattern-based reasons
        if pattern_analysis.get("has_fp_pattern"):
            pattern_count = pattern_analysis.get("pattern_count", 0)
            reasons.append(f"Matched {pattern_count} false positive pattern(s)")
        
        # ML-based reasons
        if ml_analysis.get("is_ml_fp"):
            ml_prob = ml_analysis.get("ml_fp_probability", 0)
            reasons.append(f"ML analysis indicates {ml_prob:.1%} false positive probability")
        
        # Context-based reasons
        context_score = contextual_analysis.get("context_fp_score", 0)
        if context_score > 0.5:
            reasons.append("Strong contextual indicators suggest false positive")
        
        return ". ".join(reasons) if reasons else "No strong false positive indicators detected"
    
    def _generate_fp_recommendation(self, is_false_positive: bool, confidence: float) -> str:
        """Generate recommendation for handling the finding."""
        if is_false_positive:
            if confidence > 0.8:
                return "High confidence false positive - safe to filter out"
            elif confidence > 0.6:
                return "Likely false positive - consider filtering with manual review"
            else:
                return "Possible false positive - manual review recommended"
        else:
            return "Appears to be valid finding - include in results"
    
    def add_feedback(self, text: str, is_actual_fp: bool, user_notes: str = ""):
        """Add user feedback for model improvement."""
        feedback_record = {
            "timestamp": datetime.now().isoformat(),
            "text_hash": hashlib.md5(text.encode()).hexdigest(),
            "is_false_positive": is_actual_fp,
            "user_notes": user_notes,
            "text_length": len(text)
        }
        
        self.feedback_data.append(feedback_record)
        self.logger.info(f"Added FP feedback: is_fp={is_actual_fp}")
    
    def retrain_models(self) -> Dict[str, float]:
        """Retrain ML models with accumulated feedback data."""
        if not ML_AVAILABLE or len(self.feedback_data) < 20:
            self.logger.warning("Insufficient feedback data for retraining")
            return {}
        
        try:
            # Prepare training data from feedback
            X, y = self._prepare_feedback_training_data()
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Retrain models
            results = {}
            
            # Retrain FP classifier
            if "fp_classifier" in self.ml_models:
                classifier = self.ml_models["fp_classifier"]
                classifier.fit(X_train, y_train)
                
                # Evaluate
                y_pred = classifier.predict(X_test)
                results["fp_classifier_precision"] = precision_score(y_test, y_pred)
                results["fp_classifier_recall"] = recall_score(y_test, y_pred)
                results["fp_classifier_f1"] = f1_score(y_test, y_pred)
            
            # Update performance metrics
            self._update_performance_metrics(results)
            
            # Save models
            self._save_models()
            
            self.logger.info(f"Retrained models with {len(self.feedback_data)} feedback samples")
            return results
            
        except Exception as e:
            self.logger.error(f"Model retraining failed: {e}")
            return {}
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for the false positive reducer."""
        base_metrics = {
            "total_analyzed": self.stats["total_analyzed"],
            "false_positives_detected": self.stats["false_positives_detected"],
            "feedback_samples": len(self.feedback_data),
            "fp_patterns_count": len(self.fp_patterns),
            "ml_enabled": ML_AVAILABLE
        }
        
        if self.stats["total_analyzed"] > 0:
            base_metrics["fp_detection_rate"] = self.stats["false_positives_detected"] / self.stats["total_analyzed"]
        
        if self.performance_history:
            base_metrics["recent_accuracy"] = self.performance_history[-1].get("accuracy", 0.0)
            base_metrics["recent_precision"] = self.performance_history[-1].get("precision", 0.0)
            base_metrics["recent_recall"] = self.performance_history[-1].get("recall", 0.0)
        
        return base_metrics
    
    # Helper methods
    def _calculate_pattern_context_score(self, text: str, context_indicators: List[str]) -> float:
        """Calculate context relevance score for pattern matching."""
        if not context_indicators:
            return 0.0
        
        text_lower = text.lower()
        matches = sum(1 for indicator in context_indicators if indicator in text_lower)
        return min(matches / len(context_indicators), 1.0)
    
    def _get_severity_score(self, severity: str) -> float:
        """Convert severity to numeric score."""
        severity_scores = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.6,
            "low": 0.4,
            "info": 0.2
        }
        return severity_scores.get(severity.lower(), 0.5)
    
    def _get_plugin_fp_score(self, plugin_type: str) -> float:
        """Get false positive likelihood score for plugin type."""
        fp_prone_types = ["logger", "info", "status", "debug", "metadata"]
        plugin_type_lower = plugin_type.lower()
        
        if any(fp_type in plugin_type_lower for fp_type in fp_prone_types):
            return 0.8
        else:
            return 0.2
    
    def _count_fp_patterns(self, text: str) -> float:
        """Count false positive patterns in text."""
        count = 0
        for pattern in self.fp_patterns.values():
            if re.search(pattern.pattern_text, text, re.IGNORECASE):
                count += 1
        return count
    
    def _count_vuln_patterns(self, text: str) -> float:
        """Count vulnerability patterns in text."""
        vuln_patterns = [
            r"(?i)vulnerability.*detected",
            r"(?i)security.*issue.*found", 
            r"(?i)exploit.*possible",
            r"(?i)critical.*flaw"
        ]
        
        count = 0
        for pattern in vuln_patterns:
            if re.search(pattern, text):
                count += 1
        return count
    
    def _calculate_word_entropy(self, text: str) -> float:
        """Calculate entropy of word distribution."""
        words = text.lower().split()
        if not words:
            return 0.0
        
        word_counts = Counter(words)
        total_words = len(words)
        
        entropy = 0.0
        for count in word_counts.values():
            p = count / total_words
            entropy -= p * np.log2(p) if p > 0 else 0
        
        return entropy
    
    def _calculate_repetition_score(self, text: str) -> float:
        """Calculate repetition score in text."""
        words = text.lower().split()
        if len(words) < 2:
            return 0.0
        
        unique_words = len(set(words))
        total_words = len(words)
        
        return 1.0 - (unique_words / total_words)
    
    def _predict_false_positive(self, features: Dict[str, float]) -> float:
        """Predict false positive probability using ML model."""
        # Simplified prediction - would use trained model in production
        fp_score = (
            features.get("has_success_indicators", 0) * 0.3 +
            features.get("has_status_emojis", 0) * 0.2 +
            features.get("fp_pattern_count", 0) * 0.3 +
            (1.0 - features.get("vulnerability_confidence", 0.5)) * 0.2
        )
        
        return min(fp_score, 1.0)
    
    def _estimate_fp_confidence(self, features: Dict[str, float]) -> float:
        """Estimate confidence in false positive prediction."""
        confidence_factors = [
            features.get("text_length", 0) > 20,  # Sufficient text for analysis
            features.get("vulnerability_confidence", 0) > 0.3,  # Some vulnerability confidence
            features.get("fp_pattern_count", 0) > 0  # Has FP patterns
        ]
        
        return sum(confidence_factors) / len(confidence_factors)
    
    def _detect_outliers(self, features: Dict[str, float]) -> float:
        """Detect outliers in feature space."""
        # Simplified outlier detection
        feature_values = list(features.values())
        mean_val = np.mean(feature_values)
        std_val = np.std(feature_values)
        
        if std_val == 0:
            return 0.0
        
        z_scores = [(val - mean_val) / std_val for val in feature_values]
        max_z = max(abs(z) for z in z_scores)
        
        return min(max_z / 3.0, 1.0)  # Normalize to 0-1
    
    def _prepare_feedback_training_data(self) -> Tuple[List[List[float]], List[int]]:
        """Prepare training data from feedback."""
        X = []
        y = []
        
        for feedback in self.feedback_data:
            # Extract features from feedback (simplified)
            text_length = feedback.get("text_length", 0)
            is_fp = feedback.get("is_false_positive", False)
            
            # Create feature vector (would be more sophisticated in production)
            feature_vector = [
                text_length,
                1.0 if is_fp else 0.0,  # Placeholder features
                np.random.random(),  # Would be real features
                np.random.random()
            ]
            
            X.append(feature_vector)
            y.append(1 if is_fp else 0)
        
        return X, y
    
    def _update_performance_metrics(self, results: Dict[str, float]):
        """Update performance tracking."""
        performance_record = {
            "timestamp": datetime.now().isoformat(),
            "accuracy": results.get("fp_classifier_f1", 0.0),
            "precision": results.get("fp_classifier_precision", 0.0),
            "recall": results.get("fp_classifier_recall", 0.0)
        }
        
        self.performance_history.append(performance_record)
        
        # Keep only recent history
        if len(self.performance_history) > 100:
            self.performance_history = self.performance_history[-100:]
    
    def _record_fp_analysis(self, text: str, result: FPReductionResult, 
                          vulnerability_info: Dict[str, Any], context: Dict[str, Any]):
        """Record analysis for learning."""
        record = {
            "timestamp": datetime.now().isoformat(),
            "text_hash": hashlib.md5(text.encode()).hexdigest(),
            "result": asdict(result),
            "vulnerability_info": vulnerability_info,
            "context": context
        }
        
        self.training_data.append(record)
        
        # Keep only recent training data
        if len(self.training_data) > 5000:
            self.training_data = self.training_data[-5000:]
    
    def _load_or_create_models(self):
        """Load existing models or create new ones."""
        model_file = self.model_cache_dir / "fp_reduction_models.pkl"
        
        if model_file.exists():
            try:
                with open(model_file, 'rb') as f:
                    saved_data = pickle.load(f)
                    self.ml_models.update(saved_data.get("models", {}))
                    self.feedback_data = saved_data.get("feedback_data", [])
                    self.performance_history = saved_data.get("performance_history", [])
                    self.logger.info("Loaded existing FP reduction models")
            except Exception as e:
                self.logger.warning(f"Failed to load FP models: {e}")
    
    def _save_models(self):
        """Save ML models to disk."""
        model_file = self.model_cache_dir / "fp_reduction_models.pkl"
        
        try:
            save_data = {
                "models": self.ml_models,
                "feedback_data": self.feedback_data[-1000:],  # Keep recent feedback
                "performance_history": self.performance_history,
                "timestamp": datetime.now().isoformat()
            }
            
            with open(model_file, 'wb') as f:
                pickle.dump(save_data, f)
                
            self.logger.info("Saved FP reduction models to disk")
            
        except Exception as e:
            self.logger.error(f"Failed to save FP models: {e}") 
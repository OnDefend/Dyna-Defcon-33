#!/usr/bin/env python3
"""
Configurable Enhancement Engine for AODS

Advanced configuration intelligence system that provides dynamic enhancement
capabilities and intelligent configuration analysis.

Configuration Intelligence Framework - Dynamic Enhancement System

This module provides a configuration-driven rule engine that integrates entropy analysis
and context intelligence for comprehensive false positive reduction. Supports framework-specific
configurations, automatic threshold tuning, real-time updates, and performance monitoring.

Advanced Configuration Intelligence Framework
Target: <10ms per rule evaluation, intelligent rule weights, real-time configuration updates
"""

import copy
import hashlib
import json
import logging
import os
import threading
import time
import weakref
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

# Import our analysis engines
try:
    from .context_analyzer import ContextAnalyzer, ContextResult
    from .entropy_analyzer import EntropyAnalyzer, EntropyResult
except ImportError:
    # Fallback for testing
    import sys

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.context_analyzer import ContextAnalyzer, ContextResult
    from core.entropy_analyzer import EntropyAnalyzer, EntropyResult

@dataclass
class PerformanceMetrics:
    """Performance metrics for rule execution."""

    rule_name: str
    execution_time_ms: float
    memory_usage_mb: float
    accuracy: float
    timestamp: datetime = field(default_factory=datetime.now)
    framework_context: Optional[str] = None

@dataclass
class ConfigurationRule:
    """Definition of a configuration rule for analysis."""

    name: str
    rule_type: str  # 'entropy', 'context', 'combined'
    weight: float
    threshold: float
    enabled: bool = True
    framework_specific: Dict[str, Any] = field(default_factory=dict)
    performance_profile: str = "balanced"  # 'fast', 'balanced', 'accurate'
    description: str = ""

@dataclass
class FrameworkConfiguration:
    """Framework-specific configuration settings."""

    name: str
    enabled: bool
    entropy_adjustment: float
    confidence_multiplier: float
    whitelist_patterns: List[str]
    api_context_weight: float
    performance_profile: str
    custom_thresholds: Dict[str, float] = field(default_factory=dict)

@dataclass
class ValidationFeedback:
    """Feedback data for automatic threshold tuning."""

    rule_name: str
    finding_value: str
    expected_result: bool  # True if should be flagged, False if false positive
    actual_result: bool
    confidence: float
    framework_context: str
    timestamp: datetime = field(default_factory=datetime.now)

class ConfigurableEnhancementEngine:
    """
    Comprehensive configuration-driven enhancement engine for intelligent analysis.

    Features:
    - Framework-specific configuration loading from YAML
    - Automatic threshold tuning based on validation results
    - Real-time configuration updates without restart
    - Performance monitoring and optimization
    - Rule weights and confidence calculation system
    - Integration with entropy_analyzer and context_analyzer
    - Support for custom rule definitions
    - Configuration validation and error handling
    - Rollback capability for configuration changes
    """

    def __init__(
        self,
        config_path: str = "config/enhanced_detection_config.yaml",
        enable_auto_tune: bool = True,
        enable_real_time_updates: bool = True,
    ):
        """Initialize the configurable enhancement engine."""
        self.logger = logging.getLogger(__name__)
        self.config_path = Path(config_path)
        self.enable_auto_tune = enable_auto_tune
        self.enable_real_time_updates = enable_real_time_updates

        # Core configuration
        self.configuration = {}
        self.framework_configs: Dict[str, FrameworkConfiguration] = {}
        self.rules: Dict[str, ConfigurationRule] = {}
        self.rule_weights: Dict[str, float] = {}

        # Analysis engines
        self.entropy_analyzer = EntropyAnalyzer()
        self.context_analyzer = ContextAnalyzer()

        # Performance tracking
        self.performance_metrics: deque = deque(maxlen=1000)
        self.performance_targets = {
            "execution_time_ms": 10.0,
            "memory_usage_mb": 50.0,
            "accuracy": 0.85,
        }

        # Auto-tuning data
        self.validation_feedback: deque = deque(maxlen=500)
        self.tuning_history: List[Dict] = []

        # Configuration backup and rollback
        self.config_backup_stack: List[Dict] = []
        self.max_backup_stack_size = 10

        # Real-time updates
        self.config_lock = threading.RLock()
        self.config_file_watcher = None
        self.last_config_hash = None

        # Statistics
        self.stats = {
            "total_evaluations": 0,
            "rule_executions": defaultdict(int),
            "framework_usage": defaultdict(int),
            "performance_violations": 0,
            "auto_tune_adjustments": 0,
            "configuration_reloads": 0,
        }

        # Load initial configuration
        self.load_configuration()

        # Start real-time monitoring if enabled
        if self.enable_real_time_updates:
            self._start_config_monitoring()

    def load_configuration(self) -> bool:
        """Load configuration from YAML file with validation."""
        try:
            with self.config_lock:
                if not self.config_path.exists():
                    self.logger.error(
                        f"Configuration file not found: {self.config_path}"
                    )
                    return False

                # Calculate file hash for change detection
                with open(self.config_path, "rb") as f:
                    config_hash = hashlib.md5(f.read()).hexdigest()

                if config_hash == self.last_config_hash:
                    return True  # No changes

                # Backup current configuration
                if self.configuration:
                    self._backup_configuration()

                # Load new configuration
                with open(self.config_path, "r", encoding="utf-8") as f:
                    new_config = yaml.safe_load(f)

                # Validate configuration
                if not self._validate_configuration(new_config):
                    self.logger.error("Configuration validation failed")
                    return False

                # Apply new configuration
                self.configuration = new_config
                self.last_config_hash = config_hash

                # Parse framework configurations
                self._parse_framework_configurations()

                # Parse rules
                self._parse_rules()

                # Calculate rule weights
                self._calculate_rule_weights()

                self.stats["configuration_reloads"] += 1
                self.logger.info("Configuration loaded successfully")
                return True

        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            return False

    def _validate_configuration(self, config: Dict[str, Any]) -> bool:
        """Validate configuration structure and values."""
        required_sections = [
            "entropy_thresholds",
            "context_analysis",
            "framework_specific",
        ]

        for section in required_sections:
            if section not in config:
                self.logger.error(f"Missing required configuration section: {section}")
                return False

        # Validate entropy thresholds
        entropy_config = config["entropy_thresholds"]
        if "default" not in entropy_config:
            self.logger.error("Missing default entropy threshold")
            return False

        # Validate threshold values
        for key, value in entropy_config.items():
            if not isinstance(value, (int, float)) or value < 0:
                self.logger.error(f"Invalid entropy threshold for {key}: {value}")
                return False

        # Validate context analysis
        context_config = config["context_analysis"]
        if not isinstance(context_config.get("enabled", True), bool):
            self.logger.error("context_analysis.enabled must be boolean")
            return False

        # Validate framework configurations
        for framework_name, framework_config in config["framework_specific"].items():
            if not self._validate_framework_config(framework_name, framework_config):
                return False

        return True

    def _validate_framework_config(self, name: str, config: Dict[str, Any]) -> bool:
        """Validate a framework configuration."""
        required_fields = ["entropy_adjustment", "confidence_multiplier"]

        for field in required_fields:
            if field not in config:
                self.logger.error(f"Framework {name} missing required field: {field}")
                return False

        # Validate numeric values
        if not isinstance(config["entropy_adjustment"], (int, float)):
            self.logger.error(f"Framework {name} entropy_adjustment must be numeric")
            return False

        if not isinstance(config["confidence_multiplier"], (int, float)):
            self.logger.error(f"Framework {name} confidence_multiplier must be numeric")
            return False

        if config["confidence_multiplier"] <= 0:
            self.logger.error(
                f"Framework {name} confidence_multiplier must be positive"
            )
            return False

        return True

    def _parse_framework_configurations(self):
        """Parse framework-specific configurations."""
        self.framework_configs.clear()

        framework_section = self.configuration.get("framework_specific", {})

        for name, config in framework_section.items():
            framework_config = FrameworkConfiguration(
                name=name,
                enabled=config.get("enabled", True),
                entropy_adjustment=config.get("entropy_adjustment", 0.0),
                confidence_multiplier=config.get("confidence_multiplier", 1.0),
                whitelist_patterns=config.get("whitelist_patterns", []),
                api_context_weight=config.get("api_context_weight", 1.0),
                performance_profile=config.get("performance_profile", "balanced"),
                custom_thresholds=config.get("custom_thresholds", {}),
            )

            self.framework_configs[name] = framework_config

    def _parse_rules(self):
        """Parse and create configuration rules."""
        self.rules.clear()

        # Create entropy rules
        entropy_config = self.configuration.get("entropy_thresholds", {})
        for threshold_name, threshold_value in entropy_config.items():
            rule_name = f"entropy_{threshold_name}"
            rule = ConfigurationRule(
                name=rule_name,
                rule_type="entropy",
                weight=1.0,  # Will be normalized later
                threshold=threshold_value,
                description=f"Entropy threshold for {threshold_name}",
            )
            self.rules[rule_name] = rule

        # Create context analysis rule
        if self.configuration.get("context_analysis", {}).get("enabled", True):
            context_rule = ConfigurationRule(
                name="context_analysis",
                rule_type="context",
                weight=2.0,  # Higher weight for context analysis
                threshold=0.7,  # Default confidence threshold
                description="Context analysis with API proximity validation",
            )
            self.rules["context_analysis"] = context_rule

        # Create combined analysis rule
        combined_rule = ConfigurationRule(
            name="combined_analysis",
            rule_type="combined",
            weight=3.0,  # Highest weight for combined analysis
            threshold=0.8,
            description="Combined entropy and context analysis",
        )
        self.rules["combined_analysis"] = combined_rule

    def _calculate_rule_weights(self):
        """Calculate and normalize rule weights."""
        self.rule_weights.clear()

        if not self.rules:
            return

        # Calculate total weight
        total_weight = sum(rule.weight for rule in self.rules.values())

        if total_weight == 0:
            # Equal weights if all are zero
            equal_weight = 1.0 / len(self.rules)
            for rule_name in self.rules:
                self.rule_weights[rule_name] = equal_weight
        else:
            # Normalize weights
            for rule_name, rule in self.rules.items():
                self.rule_weights[rule_name] = rule.weight / total_weight

    def get_configuration(
        self, framework: str = "default", category: str = None
    ) -> Dict[str, Any]:
        """Get configuration for a specific framework or category."""
        with self.config_lock:
            if category:
                # Return category-specific configuration
                if category == "entropy_analysis" or category == "entropy_thresholds":
                    return self.configuration.get("entropy_thresholds", {})
                elif category == "context_analysis":
                    return self.configuration.get("context_analysis", {})
                elif category == "framework_specific":
                    return self.configuration.get("framework_specific", {})
                else:
                    return {}

            if framework == "default" or framework not in self.framework_configs:
                # For non-existent frameworks, return empty dict if explicitly requested
                if framework != "default" and framework not in self.framework_configs:
                    return {}
                return self.configuration.copy()

            # Merge base configuration with framework-specific config
            base_config = self.configuration.copy()
            framework_config = self.framework_configs[framework]

            # Apply framework-specific adjustments
            if "entropy_thresholds" in base_config:
                adjusted_thresholds = base_config["entropy_thresholds"].copy()

                # Apply entropy adjustment
                for key in adjusted_thresholds:
                    adjusted_thresholds[key] += framework_config.entropy_adjustment

                # Apply custom thresholds
                adjusted_thresholds.update(framework_config.custom_thresholds)

                base_config["entropy_thresholds"] = adjusted_thresholds

            # Add framework-specific configuration for easier access
            base_config["entropy_adjustment"] = framework_config.entropy_adjustment
            base_config["confidence_multiplier"] = (
                framework_config.confidence_multiplier
            )
            base_config["whitelist_patterns"] = framework_config.whitelist_patterns
            base_config["api_context_weight"] = framework_config.api_context_weight
            base_config["performance_profile"] = framework_config.performance_profile

            # Add framework-specific configuration object
            base_config["framework_config"] = asdict(framework_config)

            return base_config

    def get_rule_weight(self, rule_name: str) -> float:
        """Get the weight for a specific rule."""
        return self.rule_weights.get(rule_name, 0.0)

    def get_rule_threshold(self, rule_name: str, framework: str = "default") -> float:
        """Get threshold for a rule, adjusted for framework if applicable."""
        with self.config_lock:
            if rule_name not in self.rules:
                return 0.0

            base_threshold = self.rules[rule_name].threshold

            if framework == "default" or framework not in self.framework_configs:
                return base_threshold

            # Apply framework confidence multiplier
            framework_config = self.framework_configs[framework]
            return base_threshold * framework_config.confidence_multiplier

    def evaluate_rule_performance(
        self,
        rule_name: str,
        execution_time_ms: float,
        accuracy: float,
        memory_usage_mb: float,
    ) -> bool:
        """Evaluate if rule performance meets targets."""
        # Check against performance targets
        meets_time_target = (
            execution_time_ms <= self.performance_targets["execution_time_ms"]
        )
        meets_memory_target = (
            memory_usage_mb <= self.performance_targets["memory_usage_mb"]
        )
        meets_accuracy_target = accuracy >= self.performance_targets["accuracy"]

        performance_acceptable = (
            meets_time_target and meets_memory_target and meets_accuracy_target
        )

        # Record performance metrics
        metrics = PerformanceMetrics(
            rule_name=rule_name,
            execution_time_ms=execution_time_ms,
            memory_usage_mb=memory_usage_mb,
            accuracy=accuracy,
        )
        self.performance_metrics.append(metrics)

        if not performance_acceptable:
            self.stats["performance_violations"] += 1
            self.logger.warning(
                f"Rule {rule_name} performance below targets: "
                f"time={execution_time_ms}ms, memory={memory_usage_mb}MB, "
                f"accuracy={accuracy}"
            )

        return performance_acceptable

    def calculate_confidence_score(
        self, rule_scores: Dict[str, float], framework: str = "default"
    ) -> float:
        """Calculate weighted confidence score from individual rule scores."""
        if not rule_scores:
            return 0.0

        total_weighted_score = 0.0
        total_weights = 0.0

        for rule_name, score in rule_scores.items():
            weight = self.get_rule_weight(rule_name)
            total_weighted_score += score * weight
            total_weights += weight

        if total_weights == 0:
            return 0.0

        confidence = total_weighted_score / total_weights

        # Apply framework confidence multiplier if applicable
        if framework != "default" and framework in self.framework_configs:
            framework_config = self.framework_configs[framework]
            confidence *= framework_config.confidence_multiplier

        return min(1.0, max(0.0, confidence))

    def update_rule_configuration(self, rule_name: str, **kwargs) -> bool:
        """Update configuration for a specific rule at runtime."""
        try:
            with self.config_lock:
                if rule_name not in self.rules:
                    self.logger.error(f"Rule {rule_name} not found")
                    return False

                # Backup current configuration
                self._backup_configuration()

                rule = self.rules[rule_name]

                # Update rule properties
                if "threshold" in kwargs:
                    rule.threshold = float(kwargs["threshold"])
                if "weight" in kwargs:
                    rule.weight = float(kwargs["weight"])
                if "enabled" in kwargs:
                    rule.enabled = bool(kwargs["enabled"])
                if "performance_profile" in kwargs:
                    rule.performance_profile = kwargs["performance_profile"]

                # Recalculate weights if weight was changed
                if "weight" in kwargs:
                    self._calculate_rule_weights()

                self.logger.info(f"Rule {rule_name} configuration updated")
                return True

        except Exception as e:
            self.logger.error(f"Failed to update rule configuration: {e}")
            return False

    def provide_validation_feedback(self, rule_name: str, accuracy: float):
        """Provide validation feedback for a rule (simplified interface)."""
        # Create a validation feedback entry with minimal information
        feedback = ValidationFeedback(
            rule_name=rule_name,
            finding_value="validation_feedback",
            expected_result=True,
            actual_result=accuracy > 0.5,  # Simple threshold
            confidence=accuracy,
            framework_context="default",
        )

        self.validation_feedback.append(feedback)

        # Trigger auto-tuning if we have enough feedback
        if len(self.validation_feedback) >= 10:  # Lower threshold for testing
            self._auto_tune_thresholds()

    def add_validation_feedback(
        self,
        rule_name: str,
        finding_value: str,
        expected_result: bool,
        actual_result: bool,
        confidence: float,
        framework_context: str = "default",
    ):
        """Add validation feedback for automatic threshold tuning."""
        if not self.enable_auto_tune:
            return

        feedback = ValidationFeedback(
            rule_name=rule_name,
            finding_value=finding_value,
            expected_result=expected_result,
            actual_result=actual_result,
            confidence=confidence,
            framework_context=framework_context,
        )

        self.validation_feedback.append(feedback)

        # Trigger auto-tuning if we have enough feedback
        if (
            len(self.validation_feedback) >= 10
        ):  # Lower threshold for more responsive tuning
            self._auto_tune_thresholds()

    def _auto_tune_thresholds(self):
        """Automatically tune thresholds based on validation feedback."""
        if not self.enable_auto_tune:
            return

        try:
            with self.config_lock:
                # Group feedback by rule and framework
                feedback_groups = defaultdict(list)
                for feedback in self.validation_feedback:
                    key = (feedback.rule_name, feedback.framework_context)
                    feedback_groups[key].append(feedback)

                adjustments_made = 0

                for (rule_name, framework), feedback_list in feedback_groups.items():
                    if (
                        len(feedback_list) < 5
                    ):  # Lower minimum for more responsive tuning
                        continue

                    # Calculate accuracy metrics
                    correct_predictions = sum(
                        1 for f in feedback_list if f.expected_result == f.actual_result
                    )
                    accuracy = correct_predictions / len(feedback_list)

                    # Calculate false positive and false negative rates
                    false_positives = sum(
                        1
                        for f in feedback_list
                        if not f.expected_result and f.actual_result
                    )
                    false_negatives = sum(
                        1
                        for f in feedback_list
                        if f.expected_result and not f.actual_result
                    )

                    fp_rate = false_positives / len(feedback_list)
                    fn_rate = false_negatives / len(feedback_list)

                    # Determine threshold adjustment
                    adjustment = 0.0

                    if fp_rate > 0.2:  # Too many false positives
                        adjustment = 0.1  # Increase threshold (make more strict)
                    elif fn_rate > 0.2:  # Too many false negatives
                        adjustment = -0.1  # Decrease threshold (make less strict)
                    elif accuracy < 0.7:  # Poor overall accuracy
                        adjustment = 0.05  # Small increase to be more conservative

                    if adjustment != 0.0:
                        self._apply_threshold_adjustment(
                            rule_name, framework, adjustment
                        )
                        adjustments_made += 1

                if adjustments_made > 0:
                    self.stats["auto_tune_adjustments"] += adjustments_made
                    self.logger.info(
                        f"Auto-tuning applied {adjustments_made} threshold adjustments"
                    )

                    # Record tuning in history
                    tuning_record = {
                        "timestamp": datetime.now().isoformat(),
                        "adjustments_made": adjustments_made,
                        "feedback_samples": len(self.validation_feedback),
                    }
                    self.tuning_history.append(tuning_record)

        except Exception as e:
            self.logger.error(f"Auto-tuning failed: {e}")

    def _apply_threshold_adjustment(
        self, rule_name: str, framework: str, adjustment: float
    ):
        """Apply threshold adjustment for a specific rule and framework."""
        if rule_name not in self.rules:
            return

        if framework == "default":
            # Adjust base rule threshold
            old_threshold = self.rules[rule_name].threshold
            self.rules[rule_name].threshold += adjustment
            self.rules[rule_name].threshold = max(
                0.1, min(1.0, self.rules[rule_name].threshold)
            )
            self.logger.info(
                f"Adjusted {rule_name} threshold: {old_threshold} -> {self.rules[rule_name].threshold}"
            )
        else:
            # Adjust framework-specific multiplier
            if framework in self.framework_configs:
                config = self.framework_configs[framework]
                old_multiplier = config.confidence_multiplier
                config.confidence_multiplier += (
                    adjustment * 0.1
                )  # Smaller adjustment for multiplier
                config.confidence_multiplier = max(
                    0.1, min(2.0, config.confidence_multiplier)
                )
                self.logger.info(
                    f"Adjusted {framework} confidence multiplier: {old_multiplier} -> {config.confidence_multiplier}"
                )

    def evaluate_combined_analysis(
        self,
        finding_value: str,
        file_content: str,
        file_path: str,
        framework: str = "default",
    ) -> Dict[str, Any]:
        """
        Perform combined entropy and context analysis with configurable rules.

        Args:
            finding_value: The potential security finding
            file_content: Content of the file containing the finding
            file_path: Path to the file
            framework: Framework context for analysis

        Returns:
            Combined analysis result with weighted confidence
        """
        start_time = time.perf_counter()

        try:
            with self.config_lock:
                self.stats["total_evaluations"] += 1
                self.stats["framework_usage"][framework] += 1

                # Get framework configuration
                config = self.get_configuration(framework)

                # Perform entropy analysis
                entropy_result = self.entropy_analyzer.analyze(finding_value, framework)

                # Perform context analysis
                context_result = self.context_analyzer.analyze_api_context(
                    finding_value, file_content, file_path
                )

                # Calculate weighted confidence score
                confidence_score = self._calculate_weighted_confidence(
                    entropy_result, context_result, framework
                )

                # Determine if finding should be flagged
                threshold = self.get_rule_threshold("combined_analysis", framework)
                is_flagged = confidence_score >= threshold

                # Calculate performance metrics
                execution_time = (
                    time.perf_counter() - start_time
                ) * 1000  # Convert to ms

                # Update rule execution stats
                self.stats["rule_executions"]["combined_analysis"] += 1

                # Prepare result
                result = {
                    "finding_value": finding_value,
                    "file_path": file_path,
                    "framework_context": framework,
                    "entropy_analysis": {
                        "shannon_entropy": entropy_result.shannon_entropy,
                        "normalized_entropy": entropy_result.normalized_entropy,
                        "classification": entropy_result.classification,
                        "confidence": entropy_result.confidence,
                    },
                    "context_analysis": {
                        "api_contexts": [
                            api.name for api in context_result.api_contexts
                        ],
                        "proximity_score": context_result.proximity_score,
                        "data_flow_confidence": context_result.data_flow_confidence,
                        "risk_assessment": context_result.risk_assessment,
                        "confidence": context_result.confidence,
                    },
                    "combined_confidence": confidence_score,
                    "threshold": threshold,
                    "is_flagged": is_flagged,
                    "execution_time_ms": execution_time,
                    "rule_weights": self.rule_weights.copy(),
                    "configuration_version": (
                        self.last_config_hash[:8]
                        if self.last_config_hash
                        else "unknown"
                    ),
                }

                return result

        except Exception as e:
            self.logger.error(f"Combined analysis failed: {e}")
            return {
                "finding_value": finding_value,
                "file_path": file_path,
                "error": str(e),
                "is_flagged": False,
                "execution_time_ms": (time.perf_counter() - start_time) * 1000,
            }

    def _calculate_weighted_confidence(
        self,
        entropy_result: EntropyResult,
        context_result: ContextResult,
        framework: str,
    ) -> float:
        """Calculate weighted confidence score from entropy and context analysis."""
        # Get rule weights
        entropy_weight = self.get_rule_weight("entropy_default")
        context_weight = self.get_rule_weight("context_analysis")

        # Get framework configuration
        framework_config = self.framework_configs.get(framework)
        if framework_config:
            context_weight *= framework_config.api_context_weight

        # Normalize weights
        total_weight = entropy_weight + context_weight
        if total_weight > 0:
            entropy_weight /= total_weight
            context_weight /= total_weight
        else:
            entropy_weight = context_weight = 0.5

        # Calculate weighted confidence
        weighted_confidence = (
            entropy_result.confidence * entropy_weight
            + context_result.confidence * context_weight
        )

        # Apply framework confidence multiplier
        if framework_config:
            weighted_confidence *= framework_config.confidence_multiplier

        return min(1.0, max(0.0, weighted_confidence))

    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        if not self.performance_metrics:
            return {"status": "no_data"}

        # Calculate performance statistics
        execution_times = [m.execution_time_ms for m in self.performance_metrics]
        memory_usage = [m.memory_usage_mb for m in self.performance_metrics]
        accuracies = [m.accuracy for m in self.performance_metrics]

        # Performance summary
        avg_execution_time = sum(execution_times) / len(execution_times)
        max_execution_time = max(execution_times)
        avg_memory_usage = sum(memory_usage) / len(memory_usage)
        avg_accuracy = sum(accuracies) / len(accuracies)

        # Performance target compliance
        time_compliance = sum(1 for t in execution_times if t <= 10.0) / len(
            execution_times
        )
        memory_compliance = sum(1 for m in memory_usage if m <= 50.0) / len(
            memory_usage
        )
        accuracy_compliance = sum(1 for a in accuracies if a >= 0.85) / len(accuracies)

        # Group metrics by rule
        rules_performance = {}
        for metric in self.performance_metrics:
            rule_name = metric.rule_name
            if rule_name not in rules_performance:
                rules_performance[rule_name] = {
                    "execution_time_ms": metric.execution_time_ms,
                    "memory_usage_mb": metric.memory_usage_mb,
                    "accuracy": metric.accuracy,
                    "meets_target": (
                        metric.execution_time_ms <= 10.0
                        and metric.memory_usage_mb <= 50.0
                        and metric.accuracy >= 0.85
                    ),
                }

        # Framework performance data
        framework_performance = {}
        for framework_name in self.framework_configs:
            framework_performance[framework_name] = {
                "enabled": self.framework_configs[framework_name].enabled,
                "entropy_adjustment": self.framework_configs[
                    framework_name
                ].entropy_adjustment,
                "confidence_multiplier": self.framework_configs[
                    framework_name
                ].confidence_multiplier,
                "performance_profile": self.framework_configs[
                    framework_name
                ].performance_profile,
            }

        # Cache statistics
        cache_stats = {
            "entropy_cache_size": (
                len(self.entropy_analyzer.cache)
                if hasattr(self.entropy_analyzer, "cache")
                else 0
            ),
            "context_cache_size": (
                len(self.context_analyzer.api_pattern_cache)
                if hasattr(self.context_analyzer, "api_pattern_cache")
                else 0
            ),
        }

        return {
            "timestamp": datetime.now().isoformat(),
            "total_rules": len(self.rules),
            "active_rules": len([r for r in self.rules.values() if r.enabled]),
            "performance_target_ms": self.performance_targets["execution_time_ms"],
            "rules_performance": rules_performance,
            "framework_performance": framework_performance,
            "cache_stats": cache_stats,
            "summary": {
                "total_metrics": len(self.performance_metrics),
                "avg_execution_time_ms": avg_execution_time,
                "max_execution_time_ms": max_execution_time,
                "avg_memory_usage_mb": avg_memory_usage,
                "avg_accuracy": avg_accuracy,
                "performance_violations": self.stats["performance_violations"],
            },
            "compliance": {
                "time_target_compliance": time_compliance,
                "memory_target_compliance": memory_compliance,
                "accuracy_target_compliance": accuracy_compliance,
                "overall_compliance": (
                    time_compliance + memory_compliance + accuracy_compliance
                )
                / 3,
            },
            "targets": self.performance_targets.copy(),
            "stats": self.stats.copy(),
            "auto_tuning": {
                "enabled": self.enable_auto_tune,
                "adjustments_made": self.stats["auto_tune_adjustments"],
                "feedback_samples": len(self.validation_feedback),
                "tuning_history": self.tuning_history[-10:],  # Last 10 tuning events
            },
        }

    def _backup_configuration(self):
        """Backup current configuration for rollback capability."""
        backup = {
            "timestamp": datetime.now().isoformat(),
            "configuration": copy.deepcopy(self.configuration),
            "framework_configs": copy.deepcopy(
                {k: asdict(v) for k, v in self.framework_configs.items()}
            ),
            "rules": copy.deepcopy({k: asdict(v) for k, v in self.rules.items()}),
            "rule_weights": copy.deepcopy(self.rule_weights),
        }

        self.config_backup_stack.append(backup)

        # Maintain maximum stack size
        if len(self.config_backup_stack) > self.max_backup_stack_size:
            self.config_backup_stack.pop(0)

    def rollback_configuration(self) -> bool:
        """Rollback to the previous configuration."""
        if not self.config_backup_stack:
            self.logger.warning("No configuration backup available for rollback")
            return False

        try:
            with self.config_lock:
                backup = self.config_backup_stack.pop()

                # Restore configuration
                self.configuration = backup["configuration"]

                # Restore framework configs
                self.framework_configs.clear()
                for name, config_dict in backup["framework_configs"].items():
                    self.framework_configs[name] = FrameworkConfiguration(**config_dict)

                # Restore rules
                self.rules.clear()
                for name, rule_dict in backup["rules"].items():
                    self.rules[name] = ConfigurationRule(**rule_dict)

                # Restore rule weights
                self.rule_weights = backup["rule_weights"]

                self.logger.info(f"Configuration rolled back to {backup['timestamp']}")
                return True

        except Exception as e:
            self.logger.error(f"Configuration rollback failed: {e}")
            return False

    def _start_config_monitoring(self):
        """Start monitoring configuration file for real-time updates."""
        if not self.enable_real_time_updates:
            return

        def monitor_config():
            """Monitor configuration file for changes."""
            while self.enable_real_time_updates:
                try:
                    if self.config_path.exists():
                        # Check if file was modified
                        with open(self.config_path, "rb") as f:
                            current_hash = hashlib.md5(f.read()).hexdigest()

                        if current_hash != self.last_config_hash:
                            self.logger.info("Configuration file changed, reloading...")
                            if self.load_configuration():
                                self.logger.info("Configuration reloaded successfully")
                            else:
                                self.logger.error("Configuration reload failed")

                    time.sleep(5)  # Check every 5 seconds

                except Exception as e:
                    self.logger.error(f"Configuration monitoring error: {e}")
                    time.sleep(10)  # Wait longer on error

        # Start monitoring thread
        self.config_file_watcher = threading.Thread(target=monitor_config, daemon=True)
        self.config_file_watcher.start()

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive engine statistics."""
        return {
            "configuration": {
                "config_path": str(self.config_path),
                "last_reload": datetime.now().isoformat(),
                "frameworks_configured": len(self.framework_configs),
                "rules_configured": len(self.rules),
                "auto_tune_enabled": self.enable_auto_tune,
                "real_time_updates_enabled": self.enable_real_time_updates,
            },
            "performance": {
                "total_evaluations": self.stats["total_evaluations"],
                "performance_violations": self.stats["performance_violations"],
                "avg_execution_time_ms": (
                    (
                        sum(m.execution_time_ms for m in self.performance_metrics)
                        / len(self.performance_metrics)
                    )
                    if self.performance_metrics
                    else 0.0
                ),
            },
            "usage": {
                "framework_usage": dict(self.stats["framework_usage"]),
                "rule_executions": dict(self.stats["rule_executions"]),
            },
            "tuning": {
                "adjustments_made": self.stats["auto_tune_adjustments"],
                "feedback_samples": len(self.validation_feedback),
                "configuration_reloads": self.stats["configuration_reloads"],
            },
        }

    def shutdown(self):
        """Shutdown the enhancement engine and cleanup resources."""
        self.enable_real_time_updates = False

        if self.config_file_watcher and self.config_file_watcher.is_alive():
            self.config_file_watcher.join(timeout=1.0)

        # Clear caches
        self.entropy_analyzer.clear_cache()
        self.context_analyzer.clear_cache()

        self.logger.info("Configurable Enhancement Engine shut down")

    def validate_configuration(self) -> bool:
        """Public method to validate current configuration (for testing)."""
        return self._validate_configuration(self.configuration)

def create_enhancement_engine(
    config_path: str = "config/enhanced_detection_config.yaml",
    enable_auto_tune: bool = True,
    enable_real_time_updates: bool = True,
) -> ConfigurableEnhancementEngine:
    """
    Factory function to create a configured enhancement engine.

    Args:
        config_path: Path to configuration file
        enable_auto_tune: Enable automatic threshold tuning
        enable_real_time_updates: Enable real-time configuration updates

    Returns:
        Configured enhancement engine instance
    """
    return ConfigurableEnhancementEngine(
        config_path=config_path,
        enable_auto_tune=enable_auto_tune,
        enable_real_time_updates=enable_real_time_updates,
    )

# Example usage and testing
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Create engine
    engine = create_enhancement_engine()

    # Example analysis
    sample_finding = "fake_test_26YQlbZ6YQRaAGXH9Xam4rNx00vl3TQXH7"
    sample_file_content = """
    public class ApiManager {
        private static final String API_KEY = "fake_test_26YQlbZ6YQRaAGXH9Xam4rNx00vl3TQXH7";

        public void makeRequest() {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                .url("https://api.stripe.com/v1/charges")
                .header("Authorization", "Bearer " + API_KEY)
                .build();
        }
    }
    """

    # Perform analysis
    result = engine.evaluate_combined_analysis(
        finding_value=sample_finding,
        file_content=sample_file_content,
        file_path="ApiManager.java",
        framework="android_native",
    )

    print(f"Analysis Result: {json.dumps(result, indent=2)}")
    print(
        f"Performance Report: {json.dumps(engine.get_performance_report(), indent=2)}"
    )

    # Cleanup
    engine.shutdown()

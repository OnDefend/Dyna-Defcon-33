#!/usr/bin/env python3
"""
Enhanced False Positive Reduction - Secret Analyzer
===================================================

This module contains the main EnhancedSecretAnalyzer class that orchestrates
comprehensive secret detection using multiple specialized libraries and
advanced analysis techniques.

Features:
- Advanced entropy analysis with multiple algorithms
- Pattern matching and framework detection
- Integration with ML classifier and context analyzer
- Performance-optimized analysis pipeline
- Comprehensive secret validation

"""

import base64
import hashlib
import ipaddress
import json
import os
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import chardet
import filetype
import magic
import numpy as np
import pandas as pd
import regex
import textdistance
import tldextract
import validators
import yaml
from cachetools import TTLCache, cached
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    # Graceful fallback when pycryptodome is not available
    AES = None
    get_random_bytes = None
    CRYPTO_AVAILABLE = False
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Levenshtein import distance as levenshtein_distance
from loguru import logger
from publicsuffix2 import get_public_suffix
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.preprocessing import StandardScaler

from .context_analyzer import EnhancedContextAnalyzer
from .data_structures import (
    ContextAnalysisResult,
    EntropyAnalysisResult,
    FrameworkAnalysisResult,
    PatternMatchResult,
    SecretAnalysisResult
)
from .ml_classifier import MLEnhancedSecretClassifier

# Optional jellyfish import with fallback
try:
    import jellyfish
    JELLYFISH_AVAILABLE = True
except ImportError:
    JELLYFISH_AVAILABLE = False
    # Create fallback jellyfish functions
    class FallbackJellyfish:
        @staticmethod
        def jaro_winkler(s1, s2):
            """Fallback jaro_winkler using simple similarity."""
            # Simple character-based similarity fallback
            if not s1 or not s2:
                return 0.0
            s1_lower = s1.lower()
            s2_lower = s2.lower()
            if s1_lower == s2_lower:
                return 1.0
            # Simple character overlap similarity
            common_chars = set(s1_lower) & set(s2_lower)
            return len(common_chars) / max(len(set(s1_lower)), len(set(s2_lower)))
    
    jellyfish = FallbackJellyfish()

class EnhancedSecretAnalyzer:
    """
    Advanced secret analyzer using multiple specialized libraries for
    maximum accuracy and false positive reduction.
    """

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the enhanced secret analyzer."""
        self.logger = logger.bind(component="EnhancedSecretAnalyzer")

        # Initialize caches for performance
        self.analysis_cache = TTLCache(maxsize=10000, ttl=3600)  # 1 hour TTL
        self.domain_cache = TTLCache(maxsize=5000, ttl=7200)  # 2 hour TTL

        # Load configuration first
        self.config = self._load_config(config_path)

        # Initialize analyzers
        self._init_entropy_analyzers()
        self._init_ml_classifiers()
        self._init_pattern_matchers()
        self._init_domain_validators()
        self._init_file_analyzers()
        self._init_context_analyzer()
        self._init_framework_detector()
        self._init_rule_engine()

        self.logger.info("Enhanced Secret Analyzer v3.0 initialized successfully")

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "config",
                "enhanced_detection_config.yaml",
            )

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
            self.logger.info(f"Configuration loaded from {config_path}")
            return config
        except Exception as e:
            self.logger.warning(f"Failed to load config from {config_path}: {e}")
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "entropy_thresholds": {
                "default": 4.5,
                "unicode_text": 3.0,
                "api_keys": 5.0,
                "base64_encoded": 4.8,
                "jwt_tokens": 5.2,
                "uuids": 4.6,
                "hex_encoded": 4.0,
                "random_strings": 4.7,
            },
            "context_analysis": {
                "enabled": True,
                "api_proximity_radius": 7,
                "confidence_boost_for_context": 0.2,
                "confidence_penalty_for_isolation": -0.3,
            },
            "performance_limits": {
                "max_entropy_calculations_per_apk": 15000,
                "max_string_length_for_analysis": 10000,
                "max_context_analysis_time_seconds": 600,
                "memory_limit_mb": 1024,
            },
        }

    def _init_entropy_analyzers(self):
        """Initialize advanced entropy calculation methods."""
        self.entropy_methods = {
            "shannon": self._calculate_shannon_entropy,
            "base64": self._calculate_base64_entropy,
            "hex": self._calculate_hex_entropy,
            "ascii": self._calculate_ascii_entropy,
            "compressed": self._calculate_compressed_entropy,
        }

        # Load thresholds from config
        entropy_config = self.config.get("entropy_thresholds", {})
        self.entropy_thresholds = {
            "shannon_min": entropy_config.get("default", 4.5),
            "shannon_max": 6.0,
            "base64_min": entropy_config.get("base64_encoded", 4.8),
            "hex_min": entropy_config.get("hex_encoded", 4.0),
            "ascii_min": 4.2,
            "compressed_ratio": 0.85,
            "unicode_text": entropy_config.get("unicode_text", 3.0),
            "api_keys": entropy_config.get("api_keys", 5.0),
            "jwt_tokens": entropy_config.get("jwt_tokens", 5.2),
        }

    def _init_ml_classifiers(self):
        """Initialize machine learning classifiers for secret detection."""
        self.ml_classifier = MLEnhancedSecretClassifier(self.config)

    def _init_pattern_matchers(self):
        """Initialize comprehensive pattern matching systems."""
        # Secret patterns
        self.secret_patterns = [
            # AWS patterns
            r'AKIA[0-9A-Z]{16}',
            r'[0-9a-zA-Z/+]{40}',  # AWS secret key
            # GitHub patterns
            r'ghp_[a-zA-Z0-9]{36}',
            r'gho_[a-zA-Z0-9]{36}',
            r'ghu_[a-zA-Z0-9]{36}',
            # Stripe patterns
            r'sk_(test|live)_[0-9a-zA-Z]{99}',
            r'pk_(test|live)_[0-9a-zA-Z]{99}',
            # JWT patterns
            r'ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
            # Generic API key patterns
            r'[a-zA-Z0-9]{32,}',
            r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64
        ]
        
        # False positive patterns
        self.false_positive_patterns = [
            # Framework noise
            r'com\.android\.',
            r'androidx\.',
            r'ThemeData\.',
            r'MaterialApp',
            r'http://schemas\.',
            r'xmlns:',
            # Common placeholders
            r'YOUR_\w+_HERE',
            r'REPLACE_\w+',
            r'EXAMPLE_\w+',
            r'TEST_\w+',
            r'DEMO_\w+',
            # Version numbers
            r'\d+\.\d+\.\d+',
            # IP addresses
            r'127\.0\.0\.1',
            r'localhost',
            r'0\.0\.0\.0',
        ]
        
        # Compile patterns for performance
        self.compiled_secret_patterns = [re.compile(p) for p in self.secret_patterns]
        self.compiled_fp_patterns = [re.compile(p) for p in self.false_positive_patterns]

    def _init_domain_validators(self):
        """Initialize domain and URL validation systems."""
        self.domain_validators = {
            'tld': tldextract.extract,
            'public_suffix': get_public_suffix,
            'validators': validators,
        }

    def _init_file_analyzers(self):
        """Initialize file type and content analysis."""
        self.file_analyzers = {
            'magic': magic,
            'filetype': filetype,
            'chardet': chardet,
        }

    def _init_context_analyzer(self):
        """Initialize context analyzer."""
        self.context_analyzer = EnhancedContextAnalyzer(self.config)

    def _init_framework_detector(self):
        """Initialize framework-specific detection."""
        self.framework_config = self.config.get("framework_specific", {})

        # Compile framework patterns
        self.framework_patterns = {}
        for framework, config in self.framework_config.items():
            patterns = config.get("whitelist_patterns", [])
            self.framework_patterns[framework] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]

    def _init_rule_engine(self):
        """Initialize advanced rule engine."""
        rule_config = self.config.get("rule_engine", {})
        self.rule_engine_enabled = rule_config.get("enabled", True)
        self.confidence_threshold = rule_config.get("confidence_threshold", 0.7)
        self.rule_weights = rule_config.get(
            "rule_weights",
            {
                "entropy_analysis": 0.25,
                "context_analysis": 0.35,
                "pattern_matching": 0.20,
                "framework_specific": 0.10,
                "file_path_analysis": 0.10,
            },
        )

    def analyze_potential_secret(
        self, content: str, context: Optional[Dict[str, Any]] = None
    ) -> SecretAnalysisResult:
        """
        Comprehensive analysis of potential secret content.
        
        Args:
            content: The potential secret content to analyze
            context: Optional context information (file path, surrounding code, etc.)
            
        Returns:
            SecretAnalysisResult with comprehensive analysis details
        """
        # Create cache key for performance
        cache_key = hashlib.md5(f"{content}:{str(context)}".encode()).hexdigest()
        
        # Check cache first
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]

        # Initialize result
        result = SecretAnalysisResult(
            content=content,
            is_likely_secret=False,
            confidence_score=0.0,
            file_context=context.get("file_path") if context else None,
            line_number=context.get("line_number") if context else None,
        )

        try:
            # Framework classification
            framework = self._classify_framework(content, context)
            result.framework_classification = framework

            # Enhanced analysis pipeline
            analysis_scores = {}

            # 1. Entropy Analysis (25% weight)
            entropy_result = self._analyze_entropy_comprehensive(content, framework)
            analysis_scores["entropy"] = entropy_result.entropy_score
            result.analysis_details["entropy"] = entropy_result.__dict__

            # 2. Context Analysis (35% weight)
            context_result = self._analyze_context_comprehensive(content, context)
            analysis_scores["context"] = context_result.context_score
            result.analysis_details["context"] = context_result.__dict__
            result.context_analysis = context_result.__dict__

            # 3. Pattern Matching (20% weight)
            pattern_result = self._analyze_patterns_comprehensive(content, context, framework)
            analysis_scores["pattern"] = pattern_result.pattern_confidence
            result.analysis_details["pattern"] = pattern_result.__dict__

            # 4. Framework-Specific Analysis (10% weight)
            framework_result = self._analyze_framework_comprehensive(content, framework)
            analysis_scores["framework"] = 1.0 - framework_result.framework_specificity
            result.analysis_details["framework"] = framework_result.__dict__

            # 5. ML Enhancement (Advanced)
            if hasattr(self, 'ml_classifier') and self.ml_classifier:
                ml_is_secret, ml_confidence, ml_explanation = self.ml_classifier.predict_secret(content, context)
                result.ml_confidence = ml_confidence
                result.explainable_features = ml_explanation.get('feature_importance', {})
                result.usage_pattern = ml_explanation.get('usage_pattern')
                result.recommendation = ml_explanation.get('recommendation')
                
                # Include ML in weighted score
                analysis_scores["ml_enhanced"] = ml_confidence if ml_is_secret else (1.0 - ml_confidence)

            # Calculate weighted final score
            weights = self.rule_weights.copy()
            if "ml_enhanced" in analysis_scores:
                weights["ml_enhanced"] = 0.15  # Add ML weight
                # Normalize weights
                total_weight = sum(weights.values())
                weights = {k: v/total_weight for k, v in weights.items()}

            final_score = sum(
                analysis_scores.get(component, 0.0) * weight
                for component, weight in weights.items()
            )

            # Collect indicators
            result.false_positive_indicators = self._collect_false_positive_indicators(
                content, context, entropy_result, pattern_result, framework_result
            )
            result.true_positive_indicators = self._collect_true_positive_indicators(
                content, context, entropy_result, pattern_result
            )

            # Make final decision
            result.is_likely_secret = self._make_final_decision_enhanced(
                final_score, result.false_positive_indicators,
                result.true_positive_indicators, framework
            )

            # Set confidence score
            result.confidence_score = final_score

            # Apply context-based confidence adjustment
            if context_result:
                result.confidence_score = self.context_analyzer.enhance_confidence_with_context(
                    result.confidence_score, context_result
                )

        except Exception as e:
            self.logger.error(f"Error analyzing content '{content[:50]}...': {e}")
            result.is_likely_secret = False
            result.confidence_score = 0.0
            result.analysis_details["error"] = str(e)

        # Store in cache
        self.analysis_cache[cache_key] = result

        return result

    def _analyze_entropy_comprehensive(self, content: str, framework: Optional[str]) -> EntropyAnalysisResult:
        """Comprehensive entropy analysis with multiple algorithms."""
        result = EntropyAnalysisResult(
            shannon_entropy=self._calculate_shannon_entropy(content),
            base64_entropy=self._calculate_base64_entropy(content),
            hex_entropy=self._calculate_hex_entropy(content),
            ascii_entropy=self._calculate_ascii_entropy(content),
            compressed_entropy=self._calculate_compressed_entropy(content),
            entropy_score=0.0,
            entropy_confidence=0.0,
            is_high_entropy=False
        )

        # Calculate weighted entropy score
        entropy_weights = {
            'shannon': 0.4,
            'base64': 0.2,
            'hex': 0.2,
            'ascii': 0.1,
            'compressed': 0.1
        }

        weighted_entropy = (
            result.shannon_entropy * entropy_weights['shannon'] +
            result.base64_entropy * entropy_weights['base64'] +
            result.hex_entropy * entropy_weights['hex'] +
            result.ascii_entropy * entropy_weights['ascii'] +
            result.compressed_entropy * entropy_weights['compressed']
        )

        # Normalize to 0-1 scale
        result.entropy_score = min(weighted_entropy / 6.0, 1.0)
        
        # Determine if high entropy
        result.is_high_entropy = result.shannon_entropy > self.entropy_thresholds["shannon_min"]
        
        # Calculate confidence
        if result.is_high_entropy:
            result.entropy_confidence = min((result.shannon_entropy - 4.0) / 2.0, 1.0)
        else:
            result.entropy_confidence = max(1.0 - result.shannon_entropy / 4.0, 0.0)

        # Store detailed analysis
        result.entropy_details = {
            'weighted_entropy': weighted_entropy,
            'threshold_comparison': {
                'shannon_threshold': self.entropy_thresholds["shannon_min"],
                'exceeds_threshold': result.is_high_entropy
            }
        }

        return result

    def _analyze_context_comprehensive(self, content: str, context: Optional[Dict[str, Any]]) -> ContextAnalysisResult:
        """Comprehensive context analysis."""
        if not context:
            return ContextAnalysisResult()

        # Extract surrounding lines and file context
        surrounding_lines = context.get("surrounding_lines", [])
        file_context = context.get("file_path", "")

        return self.context_analyzer.analyze_context(content, surrounding_lines, file_context)

    def _analyze_patterns_comprehensive(self, content: str, context: Optional[Dict[str, Any]], 
                                      framework: Optional[str]) -> PatternMatchResult:
        """Comprehensive pattern matching analysis."""
        result = PatternMatchResult()

        # Check secret patterns
        for i, pattern in enumerate(self.compiled_secret_patterns):
            if pattern.search(content):
                result.matched_patterns.append(f"secret_pattern_{i}")
                result.is_known_pattern = True

        # Check false positive patterns
        fp_matches = 0
        for i, pattern in enumerate(self.compiled_fp_patterns):
            if pattern.search(content):
                result.matched_patterns.append(f"fp_pattern_{i}")
                fp_matches += 1

        # Calculate pattern confidence
        secret_matches = len([p for p in result.matched_patterns if p.startswith("secret_pattern")])
        
        if secret_matches > 0 and fp_matches == 0:
            result.pattern_confidence = 0.9
            result.pattern_type = "high_confidence_secret"
        elif secret_matches > 0 and fp_matches > 0:
            result.pattern_confidence = 0.5
            result.pattern_type = "ambiguous_pattern"
        elif fp_matches > 0:
            result.pattern_confidence = 0.1
            result.pattern_type = "likely_false_positive"
        else:
            result.pattern_confidence = 0.3
            result.pattern_type = "no_known_patterns"

        result.pattern_details = {
            'secret_matches': secret_matches,
            'fp_matches': fp_matches,
            'total_patterns_checked': len(self.compiled_secret_patterns) + len(self.compiled_fp_patterns)
        }

        return result

    def _analyze_framework_comprehensive(self, content: str, framework: Optional[str]) -> FrameworkAnalysisResult:
        """Comprehensive framework analysis."""
        result = FrameworkAnalysisResult()

        if not framework:
            return result

        result.detected_framework = framework
        
        # Check for framework noise indicators
        if framework in self.framework_patterns:
            for pattern in self.framework_patterns[framework]:
                if pattern.search(content):
                    result.framework_noise_indicators.append(pattern.pattern)

        # Calculate framework specificity
        noise_count = len(result.framework_noise_indicators)
        if noise_count > 0:
            result.framework_specificity = min(noise_count * 0.3, 1.0)
            result.is_framework_noise = result.framework_specificity > 0.7
            result.framework_confidence = 0.9
        else:
            result.framework_specificity = 0.0
            result.is_framework_noise = False
            result.framework_confidence = 0.1

        return result

    # Entropy calculation methods
    def _calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        length = len(data)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy

    def _calculate_base64_entropy(self, data: str) -> float:
        """Calculate entropy assuming base64 encoding."""
        try:
            if set(data) <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='):
                decoded = base64.b64decode(data + '==', validate=True)
                return self._calculate_shannon_entropy(decoded.decode('utf-8', errors='ignore'))
        except:
            pass
        return 0.0

    def _calculate_hex_entropy(self, data: str) -> float:
        """Calculate entropy assuming hex encoding."""
        if all(c in '0123456789abcdefABCDEF' for c in data):
            try:
                decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
                return self._calculate_shannon_entropy(decoded)
            except:
                pass
        return 0.0

    def _calculate_ascii_entropy(self, data: str) -> float:
        """Calculate ASCII-normalized entropy."""
        ascii_data = ''.join(c for c in data if ord(c) < 128)
        return self._calculate_shannon_entropy(ascii_data)

    def _calculate_compressed_entropy(self, data: str) -> float:
        """Calculate compression-based entropy."""
        try:
            import zlib
            compressed = zlib.compress(data.encode())
            compression_ratio = len(compressed) / len(data.encode())
            return min(compression_ratio * 6.0, 6.0)  # Scale to entropy range
        except:
            return 0.0

    def _classify_framework(self, content: str, context: Optional[Dict[str, Any]]) -> Optional[str]:
        """Classify the framework context."""
        if not context:
            return None

        file_path = context.get("file_path", "").lower()
        
        # File extension based classification
        if any(ext in file_path for ext in ['.java', '.kt']):
            return "android"
        elif any(ext in file_path for ext in ['.swift', '.m', '.mm']):
            return "ios"
        elif any(ext in file_path for ext in ['.dart']):
            return "flutter"
        elif any(ext in file_path for ext in ['.js', '.jsx', '.ts', '.tsx']):
            return "react_native"
        
        # Content-based classification
        content_lower = content.lower()
        if any(keyword in content_lower for keyword in ['android', 'androidx']):
            return "android"
        elif any(keyword in content_lower for keyword in ['flutter', 'dart']):
            return "flutter"
        elif any(keyword in content_lower for keyword in ['react', 'native']):
            return "react_native"
        
        return None

    def _collect_false_positive_indicators(self, content: str, context: Optional[Dict[str, Any]],
                                         entropy_result: EntropyAnalysisResult,
                                         pattern_result: PatternMatchResult,
                                         framework_result: FrameworkAnalysisResult) -> List[str]:
        """Collect false positive indicators."""
        indicators = []

        # Low entropy
        if not entropy_result.is_high_entropy:
            indicators.append("low_entropy")

        # Framework noise
        if framework_result.is_framework_noise:
            indicators.append("framework_noise")

        # False positive patterns
        if pattern_result.pattern_type == "likely_false_positive":
            indicators.append("false_positive_patterns")

        # Test context
        if context and any(keyword in str(context).lower() for keyword in ['test', 'mock', 'example']):
            indicators.append("test_context")

        return indicators

    def _collect_true_positive_indicators(self, content: str, context: Optional[Dict[str, Any]],
                                        entropy_result: EntropyAnalysisResult,
                                        pattern_result: PatternMatchResult) -> List[str]:
        """Collect true positive indicators."""
        indicators = []

        # High entropy
        if entropy_result.is_high_entropy:
            indicators.append("high_entropy")

        # Known secret patterns
        if pattern_result.is_known_pattern:
            indicators.append("known_secret_pattern")

        # API context
        if context and any(keyword in str(context).lower() for keyword in ['api', 'key', 'token', 'secret']):
            indicators.append("api_context")

        return indicators

    def _make_final_decision_enhanced(self, score: float, false_positive_indicators: List[str],
                                    true_positive_indicators: List[str], framework: Optional[str]) -> bool:
        """Enhanced final decision making with framework awareness."""
        
        # Use configured threshold
        threshold = self.confidence_threshold

        # Framework-specific threshold adjustments
        if framework and framework in self.framework_config:
            multiplier = self.framework_config[framework].get("confidence_multiplier", 1.0)
            threshold *= multiplier

        # Strong false positive indicators override score
        strong_fp_indicators = ["framework_noise", "test_context", "low_entropy", "false_positive_patterns"]
        
        for indicator in false_positive_indicators:
            if indicator in strong_fp_indicators:
                return False

        # Strong true positive indicators lower threshold
        strong_tp_indicators = ["high_entropy", "known_secret_pattern", "api_context"]
        
        strong_tp_count = sum(1 for indicator in true_positive_indicators if indicator in strong_tp_indicators)
        
        if strong_tp_count >= 2:
            threshold *= 0.8  # Lower threshold for strong indicators

        return score >= threshold 
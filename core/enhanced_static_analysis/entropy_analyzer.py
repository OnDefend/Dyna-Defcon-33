#!/usr/bin/env python3
"""
Entropy Analyzer for Enhanced Static Analysis

Advanced entropy analysis for secret detection with enhanced false positive filtering.
Provides sophisticated string analysis capabilities with context-aware detection.

Components:
- EntropyAnalyzer: Main entropy analysis engine with false positive reduction
- confidence calculation integration
- Context-aware exclusion patterns
- Pattern-based secret detection

"""

import logging
import math
import re
from collections import Counter
from typing import Optional

from .data_structures import SecretAnalysis

class EntropyAnalyzer:
    """Advanced entropy analysis for secret detection with enhanced false positive filtering."""

    def __init__(self):
        """Initialize the entropy analyzer with enhanced filtering."""
        # Initialize enhanced secret analyzer for advanced false positive reduction
        try:
            from core.enhanced_false_positive_reducer import EnhancedSecretAnalyzer
            self.enhanced_secret_analyzer = EnhancedSecretAnalyzer()
            self.use_enhanced_analyzer = True
        except Exception as e:
            logging.warning(f"Failed to initialize enhanced secret analyzer: {e}")
            self.enhanced_secret_analyzer = None
            self.use_enhanced_analyzer = False

        # Balanced entropy thresholds - reduced from initial values to improve detection
        self.min_entropy_threshold = 3.8  # Reduced from 4.0 to catch more legitimate secrets
        self.high_entropy_threshold = 4.5  # Reduced from 4.8 for better balance
        self.min_length = 8

        # Enhanced false positive patterns - framework noise detection
        self.false_positive_patterns = [
            re.compile(r"^[0-9]+$"),  # Pure numeric strings
            re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE),  # Hex strings
            re.compile(r"^[A-Z_]+$"),  # All caps constants
            re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),  # IP addresses
            # Framework-specific patterns (Flutter, React Native)
            re.compile(r"^(vertex|pointer|hover|change|stack|frame)\.", re.IGNORECASE),
            re.compile(r"^(flutter|react|native|framework|core)\.", re.IGNORECASE),
            re.compile(r"^[a-z]+[A-Z][a-zA-Z]*$"),  # CamelCase identifiers
            re.compile(r"^[a-z_]+[0-9]+$"),  # Variable names with numbers
            # Binary/asset noise patterns
            re.compile(r"corrup|dStack|IGSEGV|alloc|malloc", re.IGNORECASE),
            re.compile(r"^[0-9]+\*+.*", re.IGNORECASE),  # Memory dump patterns
            # Package/class names
            re.compile(r"^(com|org|net|io)\.[a-z0-9.]+$", re.IGNORECASE),
        ]

        # Context-aware exclusion patterns
        self.context_exclusions = [
            # File path exclusions - asset files (MAJOR FALSE POSITIVE SOURCE)
            re.compile(r"/assets/", re.IGNORECASE),
            re.compile(r"/res/raw/", re.IGNORECASE),
            re.compile(r"/lib/", re.IGNORECASE),
            re.compile(r"\.so$", re.IGNORECASE),
            re.compile(r"\.png$|\.jpg$|\.gif$|\.webp$", re.IGNORECASE),
            # Framework code exclusions
            re.compile(r"flutter/", re.IGNORECASE),
            re.compile(r"react-native/", re.IGNORECASE),
            re.compile(r"node_modules/", re.IGNORECASE),
            re.compile(r"framework/", re.IGNORECASE),
            # ENHANCED: Major false positive sources
            re.compile(r"/assets/flutter_assets/", re.IGNORECASE),
            re.compile(r"/assets/flutter_assets/fonts/", re.IGNORECASE),
            re.compile(r"MaterialIcons-Regular\.otf", re.IGNORECASE),
            re.compile(r"/NOTICES$", re.IGNORECASE),
        ]

        # ENHANCED: Secret exclusion contexts - content patterns that are NOT secrets
        self.secret_exclusion_contexts = [
            # Java bytecode signatures (major false positive source)
            re.compile(r"^Ljava/", re.IGNORECASE),
            re.compile(r"^Landroid/", re.IGNORECASE),
            re.compile(r"^Lcom/", re.IGNORECASE),
            re.compile(r"^Lorg/", re.IGNORECASE),
            # UI/Framework elements (major false positive source)
            re.compile(r"color(Primary|Secondary|Accent)", re.IGNORECASE),
            re.compile(r"translation(X|Y|Z)", re.IGNORECASE),
            re.compile(r"(Container|Parent|Data|Widget)", re.IGNORECASE),
            re.compile(r"(Resource|Format|Merge|Open)", re.IGNORECASE),
            # System/Framework function names
            re.compile(r"native(Create|Open|Format)", re.IGNORECASE),
            re.compile(r"(openRaw|mergeAes|format)", re.IGNORECASE),
            # Binary data patterns (not secrets)
            re.compile(r"^[A-F0-9]{32,}$", re.IGNORECASE),  # Pure hex
            re.compile(r"^\d+$"),  # Pure numbers
            re.compile(r"^[A-Z_]+$"),  # All caps constants
            # UI element names
            re.compile(r"(theme|widget|component|element)", re.IGNORECASE),
            re.compile(r"(button|input|text|view|layout)", re.IGNORECASE),
            # Flutter/Dart specific patterns
            re.compile(r"(ThemeData|PointerSignal|ImageRepeat)", re.IGNORECASE),
            re.compile(r"(FloatingCursor|MenuBuilder)", re.IGNORECASE),
            # Animation/UI framework patterns
            re.compile(r"(objectAnimator|pathData|iconFade)", re.IGNORECASE),
            re.compile(r"(translationZ|colorSeconda)", re.IGNORECASE),
        ]

        # Enhanced secret patterns with better confidence weights and lower thresholds
        self.secret_patterns = {
            "aws_access_key": {
                "pattern": re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
                "weight": 0.95,  # Increased weight for high confidence patterns
                "min_entropy": 2.5,  # Lowered threshold for known patterns
            },
            "aws_secret_key": {
                # FIXED: Much more restrictive pattern requiring context keywords
                "pattern": re.compile(
                    r"(?i)(?:aws[_-]?secret|secret[_-]?key|access[_-]?secret)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})",
                    re.MULTILINE,
                ),
                "weight": 0.9,  # Increased weight for context-aware pattern
                "min_entropy": 4.0,  # Increased threshold for better quality
            },
            "base64_encoded": {
                "pattern": re.compile(r"[A-Za-z0-9+/]{20,}={0,2}", re.MULTILINE),
                "weight": 0.5,  # Moderate weight due to false positive potential
                "min_entropy": 4.0,  # Reduced from 4.5
            },
            "jwt_token": {
                "pattern": re.compile(
                    r"eyJ[A-Za-z0-9+/=]+\.eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+",
                    re.MULTILINE,
                ),
                "weight": 0.95,  # High confidence for JWT pattern
                "min_entropy": 2.0,  # Low threshold for known pattern
            },
            "private_key": {
                "pattern": re.compile(
                    r"BEGIN (RSA )?PRIVATE KEY", re.IGNORECASE | re.MULTILINE
                ),
                "weight": 0.98,
                "min_entropy": 1.0,
            },
            "api_key_patterns": {
                "pattern": re.compile(
                    r"(sk_|pk_|xoxb-|ghp_|gho_)[A-Za-z0-9_-]{20,}", re.IGNORECASE
                ),
                "weight": 0.9,  # High confidence for known API key patterns
                "min_entropy": 3.0,
            },
            "generic_secret": {
                "pattern": re.compile(
                    r"(secret|password|key|token|auth)", re.IGNORECASE
                ),
                "weight": 0.3,  # Low weight for generic patterns
                "min_entropy": 4.2,  # Higher threshold for generic patterns
            },
        }

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string with enhanced accuracy."""
        if len(data) == 0:
            return 0.0

        # Character frequency analysis
        char_counts = Counter(data)
        data_len = len(data)

        # Calculate entropy with better precision
        entropy = 0.0
        for count in char_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)

        return entropy

    def is_context_excluded(self, file_path: str, context: str) -> bool:
        """Enhanced context exclusion with aggressive false positive filtering."""
        # FIXED: Add binary file exclusions to prevent massive false positives
        binary_file_exclusions = [
            "assets/meŉu",
            "assets/narnia.x86_64",
            "assets/narnia.arm64",
            "assets/narnia.aarch64",
            "lib/",
            "libs/",
            ".so",
            ".a",
            ".o",
        ]

        # Check binary file exclusions first
        for exclusion in binary_file_exclusions:
            if exclusion in file_path:
                return True

        # Check file path exclusions
        for pattern in self.context_exclusions:
            if pattern.search(file_path):
                return True

        # Check context for framework indicators
        framework_indicators = [
            "flutter", "react", "native", "framework", "assets", "resources",
            "vertex", "pointer", "hover", "stack", "frame", "alloc", "malloc",
            # FIXED: Add more binary/runtime indicators
            "GODEBUG", "GOROOT", "GOMAXPROCS", "LINUX_", "Armenian", "Balinese",
            "Cherokee", "Cyrillic", "Malayalam", "Mongolian", "Gujarati", "Gurmukhi",
            "nproc", "atomic", "goroutine", "interface", "runtime", "golang",
            "corrupted", "panic",
        ]
        context_lower = context.lower()
        if any(indicator.lower() in context_lower for indicator in framework_indicators):
            return True

        return False

    def is_likely_secret_content(self, value: str, context: str = "", file_path: str = "") -> bool:
        """Enhanced secret content detection using our new false positive reduction system."""
        # Check if enhanced analyzer is available and working
        if self.use_enhanced_analyzer and self.enhanced_secret_analyzer:
            try:
                # Use our enhanced analyzer instead of basic pattern matching
                analysis_context = {
                    "file_path": file_path,
                    "line_context": context,
                    "additional_context": {
                        "analyzer_type": "static_analysis",
                        "content_length": len(value),
                    },
                }

                result = self.enhanced_secret_analyzer.analyze_potential_secret(
                    content=value, context=analysis_context
                )

                return result.is_likely_secret

            except Exception as e:
                # Fallback to basic check if enhanced analyzer fails
                self._log_error(f"Enhanced analyzer failed for '{value[:50]}...': {e}")
                return self._basic_secret_check(value, context, file_path)
        else:
            # Use basic check if enhanced analyzer not available
            return self._basic_secret_check(value, context, file_path)

    def _basic_secret_check(self, value: str, context: str = "", file_path: str = "") -> bool:
        """Basic fallback secret detection (legacy)."""
        # Check against exclusion patterns first
        for pattern in self.secret_exclusion_contexts:
            if pattern.search(file_path):
                return False

        # Basic exclusions
        if len(value) < 8 or len(value) > 256:
            return False

        # Pure numeric or hex strings
        if re.match(r"^[0-9]+$", value) or re.match(r"^[A-F0-9]+$", value, re.IGNORECASE):
            return False

        # Framework patterns
        framework_patterns = [
            "ThemeData", "MaterialIcons", "flutter_assets", "StyleSheet",
            "Platform.OS", "xmlns:android", "http://schemas.android.com",
        ]

        for pattern in framework_patterns:
            if pattern in value:
                return False

        return True

    def is_likely_false_positive(self, value: str, context: str = "", file_path: str = "") -> bool:
        """Enhanced false positive detection - inverse of is_likely_secret_content."""
        return not self.is_likely_secret_content(value, context, file_path)

    def _log_error(self, message: str):
        """Log error message."""
        logging.error(message)

    def analyze_string(self, value: str, context: str = "", file_path: str = "") -> SecretAnalysis:
        """Analyze a string for potential secret content using professional confidence calculation."""
        if len(value) < self.min_length:
            return SecretAnalysis(
                value=value,
                entropy=0.0,
                pattern_type="too_short",
                confidence=0.0,
                context=context,
                file_path=file_path,
                risk_level="LOW",
            )

        entropy = self.calculate_entropy(value)

        # Check against secret patterns
        best_match = None
        highest_weight = 0.0

        for pattern_name, pattern_info in self.secret_patterns.items():
            if pattern_info["pattern"].search(f"{context} {value}"):
                if pattern_info["weight"] > highest_weight:
                    best_match = pattern_name
                    highest_weight = pattern_info["weight"]

        # Use professional confidence calculator for dynamic confidence scoring
        try:
            # Initialize confidence calculator if not already available
            if not hasattr(self, 'confidence_calculator'):
                from .confidence_calculator import StaticAnalysisConfidenceCalculator
                self.confidence_calculator = StaticAnalysisConfidenceCalculator()
            
            # Determine pattern type and severity for confidence calculation
            pattern_type = best_match or "entropy_based"
            severity = self._determine_severity_from_entropy_and_pattern(entropy, best_match, highest_weight)
            
            # Build evidence list for professional confidence calculation
            evidence = []
            if best_match:
                evidence.append(f"pattern_match:{best_match}")
                evidence.append(f"pattern_weight:{highest_weight}")
            evidence.append(f"entropy_score:{entropy:.3f}")
            evidence.append(f"value_length:{len(value)}")
            if context:
                evidence.append(f"context_available:true")
            
            # Calculate professional confidence using multi-factor analysis
            confidence = self.confidence_calculator.calculate_static_analysis_confidence(
                pattern_type=pattern_type,
                severity=severity,
                context=context,
                file_path=file_path,
                code_snippet=value[:100],  # First 100 chars for analysis
                evidence=evidence
            )
            
            # Apply entropy-specific adjustments
            confidence = self._apply_entropy_adjustments(
                confidence, entropy, best_match, highest_weight, value, context, file_path
            )
            
        except Exception as e:
            # Fallback to simplified calculation if professional calculator fails
            logging.warning(f"confidence calculation failed, using fallback: {e}")
            confidence = self._calculate_fallback_confidence(
                entropy, best_match, highest_weight, value, context, file_path
            )

        # Enhanced secret likelihood determination using dynamic thresholds
        confidence_threshold = self._get_dynamic_confidence_threshold(pattern_type, context)
        is_likely_secret = (
            confidence >= confidence_threshold
            or (best_match and confidence >= confidence_threshold * 0.7)
            or (entropy >= self.high_entropy_threshold and confidence >= confidence_threshold * 0.8)
        )

        # Determine risk level using dynamic thresholds
        risk_level = self._determine_risk_level(confidence, entropy, best_match)

        return SecretAnalysis(
            value=value,
            entropy=entropy,
            pattern_type=pattern_type,
            confidence=confidence,
            context=context,
            file_path=file_path,
            is_likely_secret=is_likely_secret,
            risk_level=risk_level,
        )

    def _determine_severity_from_entropy_and_pattern(self, entropy: float, pattern_match: Optional[str], pattern_weight: float) -> str:
        """Determine severity level based on entropy and pattern matching."""
        if pattern_match:
            if pattern_weight >= 0.9:
                return "CRITICAL"
            elif pattern_weight >= 0.8:
                return "HIGH"
            elif pattern_weight >= 0.6:
                return "MEDIUM"
            else:
                return "LOW"
        else:
            # Entropy-based severity determination
            if entropy >= self.high_entropy_threshold:
                return "MEDIUM"
            elif entropy >= self.min_entropy_threshold:
                return "LOW"
            else:
                return "INFO"

    def _apply_entropy_adjustments(self, base_confidence: float, entropy: float, pattern_match: Optional[str], 
                                 pattern_weight: float, value: str, context: str, file_path: str) -> float:
        """Apply entropy-specific adjustments to professional confidence score."""
        confidence = base_confidence
        
        if pattern_match:
            # Pattern-based adjustments
            pattern_info = self.secret_patterns.get(pattern_match, {})
            min_entropy = pattern_info.get("min_entropy", 3.0)
            
            if entropy >= min_entropy:
                # Entropy bonus for strong patterns
                entropy_bonus = min(0.15, (entropy - min_entropy) / 15.0)
                confidence = min(1.0, confidence + entropy_bonus)
            else:
                # Entropy penalty for weak patterns
                entropy_penalty = max(0.0, (min_entropy - entropy) / 10.0)
                confidence = max(0.1, confidence - entropy_penalty)
        else:
            # Entropy-only adjustments
            if entropy >= self.high_entropy_threshold:
                # Boost confidence for high entropy strings
                entropy_boost = min(0.2, (entropy - self.high_entropy_threshold) / 10.0)
                confidence = min(0.9, confidence + entropy_boost)  # Cap at 0.9 for entropy-only
            elif entropy < self.min_entropy_threshold:
                # Significant penalty for low entropy
                confidence *= 0.5

        # False positive reduction
        if self.is_likely_false_positive(value, context, file_path):
            if pattern_match:
                confidence *= 0.7  # Less aggressive reduction for pattern matches
            else:
                confidence *= 0.3  # More aggressive for entropy-only matches

        return max(0.0, min(1.0, confidence))

    def _calculate_fallback_confidence(self, entropy: float, pattern_match: Optional[str], pattern_weight: float,
                                     value: str, context: str, file_path: str) -> float:
        """Fallback confidence calculation if professional calculator fails."""
        confidence = 0.0

        if pattern_match:
            # Pattern-based confidence
            pattern_info = self.secret_patterns.get(pattern_match, {})
            base_confidence = pattern_weight
            
            if entropy >= pattern_info.get("min_entropy", 3.0):
                entropy_bonus = min(0.2, (entropy - pattern_info.get("min_entropy", 3.0)) / 10.0)
                confidence = min(0.95, base_confidence + entropy_bonus)
            else:
                confidence = max(0.4, base_confidence * 0.7)
        else:
            # Entropy-based confidence
            if entropy >= self.high_entropy_threshold:
                confidence = min(0.7, entropy / 6.0)
            elif entropy >= self.min_entropy_threshold:
                confidence = max(0.2, (entropy - self.min_entropy_threshold) / 4.0)

        # Apply false positive reduction
        if self.is_likely_false_positive(value, context, file_path):
            confidence *= 0.6 if pattern_match else 0.2

        return max(0.0, min(1.0, confidence))

    def _get_dynamic_confidence_threshold(self, pattern_type: str, context: str) -> float:
        """Get dynamic confidence threshold based on pattern type and context."""
        base_threshold = 0.5
        
        # Adjust based on pattern type
        if pattern_type in ['api_key', 'password', 'private_key']:
            base_threshold = 0.4  # Lower threshold for critical secrets
        elif pattern_type == 'entropy_based':
            base_threshold = 0.6  # Higher threshold for entropy-only detection
        
        # Adjust based on context
        if 'test' in context.lower() or 'example' in context.lower():
            base_threshold += 0.1  # Higher threshold for test contexts
        
        return base_threshold

    def _determine_risk_level(self, confidence: float, entropy: float, pattern_match: Optional[str]) -> str:
        """Determine risk level using dynamic thresholds."""
        if confidence >= 0.85:
            return "CRITICAL"
        elif confidence >= 0.7:
            return "HIGH"
        elif confidence >= 0.5:
            return "MEDIUM"
        elif confidence >= 0.3:
            return "LOW"
        else:
            return "INFO"

# Export the analyzer
__all__ = ['EntropyAnalyzer'] 
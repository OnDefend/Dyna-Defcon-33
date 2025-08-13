#!/usr/bin/env python3
"""
Entropy Analysis Engine for AODS

Enhanced entropy analysis for detecting patterns, secrets, and obfuscated content
in Android applications. Provides foundation enhancement capabilities for improved
security analysis.

Part of Foundation Enhancement - Advanced Pattern Detection Framework
"""

import logging
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

@dataclass
class EntropyResult:
    """Result of entropy analysis for a string."""

    value: str
    shannon_entropy: float
    character_distribution: Dict[str, int]
    character_count: int
    unique_chars: int
    normalized_entropy: float
    is_high_entropy: bool
    classification: str  # 'secret', 'ui_text', 'framework_noise', 'encoding', 'unknown'
    confidence: float
    language_detected: Optional[str] = None
    framework_context: Optional[str] = None

@dataclass
class FrameworkConfig:
    """Configuration for framework-specific entropy analysis."""

    name: str
    entropy_threshold: float
    min_length: int
    max_length: int
    exclude_patterns: List[str]
    noise_patterns: List[str]
    encoding_patterns: List[str]
    ui_text_indicators: List[str]

class EntropyAnalyzer:
    """
    Comprehensive entropy analyzer for intelligent string classification.

    Features:
    - Shannon entropy calculation with normalization
    - Framework-specific threshold configuration
    - Unicode/multi-byte text detection
    - API key vs UI text intelligent classification
    - Performance optimized for <1ms per string
    """

    # Default framework configurations
    DEFAULT_FRAMEWORKS = {
        "android_native": FrameworkConfig(
            name="Android Native",
            entropy_threshold=4.5,
            min_length=8,
            max_length=200,
            exclude_patterns=[
                r"^com\.android\.",
                r"^android\.",
                r"^androidx\.",
                r"^@drawable/",
                r"^@string/",
                r"^@layout/",
            ],
            noise_patterns=[
                r"^[A-Z_]+$",  # Constants
                r"^[a-z]+[A-Z][a-zA-Z]*$",  # CamelCase
                r"^\d{13}$",  # Timestamps
                r"^\d+\.\d+\.\d+",  # Version numbers
            ],
            encoding_patterns=[
                r"^[A-Za-z0-9+/]*={0,2}$",  # Base64
                r"^[a-fA-F0-9]+$",  # Hex
                r"^%[0-9A-Fa-f]{2}",  # URL encoded
            ],
            ui_text_indicators=[
                "button",
                "text",
                "label",
                "title",
                "hint",
                "description",
                "message",
                "dialog",
                "activity",
                "fragment",
                "layout",
            ],
        ),
        "react_native": FrameworkConfig(
            name="React Native",
            entropy_threshold=4.2,
            min_length=6,
            max_length=150,
            exclude_patterns=[
                r"^react-native",
                r"^@react-native",
                r"^metro-",
                r"^__",
                r"\.bundle$",
            ],
            noise_patterns=[
                r"^[a-zA-Z0-9_-]+\.js$",  # JS files
                r"^bundle_\d+",  # Bundle names
                r"^\w+Component$",  # React components
            ],
            encoding_patterns=[
                r"^data:image/",  # Data URLs
                r"^blob:",  # Blob URLs
                r"^[A-Za-z0-9+/]*={0,2}$",  # Base64
            ],
            ui_text_indicators=[
                "component",
                "screen",
                "navigation",
                "style",
                "theme",
                "props",
                "state",
                "render",
                "view",
                "text",
            ],
        ),
        "flutter": FrameworkConfig(
            name="Flutter",
            entropy_threshold=4.3,
            min_length=6,
            max_length=180,
            exclude_patterns=[r"^flutter/", r"^dart:", r"^package:", r"\.dart$"],
            noise_patterns=[
                r"^_[a-zA-Z0-9_]+$",  # Private Dart members
                r"^\$[a-zA-Z0-9_]+$",  # Generated identifiers
                r"^[A-Z][a-zA-Z0-9]*Widget$",  # Flutter widgets
            ],
            encoding_patterns=[
                r"^[A-Za-z0-9+/]*={0,2}$",  # Base64
                r"^[a-fA-F0-9]+$",  # Hex
            ],
            ui_text_indicators=[
                "widget",
                "build",
                "state",
                "theme",
                "style",
                "material",
                "cupertino",
                "scaffold",
                "appbar",
                "text",
            ],
        ),
        "unity": FrameworkConfig(
            name="Unity",
            entropy_threshold=4.4,
            min_length=8,
            max_length=200,
            exclude_patterns=[
                r"^UnityEngine\.",
                r"^UnityEditor\.",
                r"^System\.",
                r"\.unity$",
            ],
            noise_patterns=[
                r"^[A-Z][a-zA-Z0-9]*Behaviour$",  # Unity behaviors
                r"^[A-Z][a-zA-Z0-9]*Component$",  # Unity components
                r"^m_[a-zA-Z0-9_]+$",  # Unity serialized fields
            ],
            encoding_patterns=[
                r"^[A-Za-z0-9+/]*={0,2}$",  # Base64
                r"^[a-fA-F0-9-]{32,}$",  # GUIDs
            ],
            ui_text_indicators=[
                "gameobject",
                "component",
                "behaviour",
                "scene",
                "prefab",
                "material",
                "shader",
                "texture",
                "animation",
            ],
        ),
        "xamarin": FrameworkConfig(
            name="Xamarin",
            entropy_threshold=4.3,
            min_length=8,
            max_length=180,
            exclude_patterns=[r"^Xamarin\.", r"^System\.", r"^Microsoft\.", r"\.dll$"],
            noise_patterns=[
                r"^[A-Z][a-zA-Z0-9]*Activity$",  # Xamarin activities
                r"^[A-Z][a-zA-Z0-9]*Fragment$",  # Xamarin fragments
                r"^__[a-zA-Z0-9_]+$",  # Generated members
            ],
            encoding_patterns=[
                r"^[A-Za-z0-9+/]*={0,2}$",  # Base64
                r"^[a-fA-F0-9-]{32,}$",  # GUIDs
            ],
            ui_text_indicators=[
                "activity",
                "fragment",
                "adapter",
                "layout",
                "view",
                "resource",
                "drawable",
                "string",
                "style",
            ],
        ),
    }

    # Unicode ranges for language detection
    UNICODE_RANGES = {
        "chinese": [(0x4E00, 0x9FFF), (0x3400, 0x4DBF)],
        "japanese": [(0x3040, 0x309F), (0x30A0, 0x30FF), (0x31F0, 0x31FF)],
        "korean": [(0xAC00, 0xD7AF), (0x1100, 0x11FF), (0x3130, 0x318F)],
        "arabic": [(0x0600, 0x06FF), (0x0750, 0x077F), (0x08A0, 0x08FF)],
        "cyrillic": [(0x0400, 0x04FF), (0x0500, 0x052F)],
        "greek": [(0x0370, 0x03FF)],
        "hebrew": [(0x0590, 0x05FF)],
        "thai": [(0x0E00, 0x0E7F)],
        "devanagari": [(0x0900, 0x097F)],
        "latin_extended": [(0x0100, 0x017F), (0x0180, 0x024F)],
    }

    def __init__(self, framework_configs: Optional[Dict[str, FrameworkConfig]] = None):
        """Initialize the entropy analyzer with framework configurations."""
        self.logger = logging.getLogger(__name__)
        self.framework_configs = framework_configs or self.DEFAULT_FRAMEWORKS
        self.cache = {}  # Simple cache for performance
        self.stats = {
            "total_analyzed": 0,
            "cache_hits": 0,
            "classifications": Counter(),
        }

    def calculate_shannon_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy for a string.

        Args:
            text: Input string

        Returns:
            Shannon entropy value (0.0 to log2(len(unique_chars)))
        """
        if not text:
            return 0.0

        # Count character frequencies
        char_counts = Counter(text)
        length = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def normalize_entropy(self, entropy: float, unique_chars: int) -> float:
        """
        Normalize entropy based on character set size.

        Args:
            entropy: Raw Shannon entropy
            unique_chars: Number of unique characters

        Returns:
            Normalized entropy (0.0 to 1.0)
        """
        if unique_chars <= 1:
            return 0.0

        max_entropy = math.log2(unique_chars)
        return entropy / max_entropy if max_entropy > 0 else 0.0

    def detect_language(self, text: str) -> Optional[str]:
        """
        Detect the primary language/script of text based on Unicode ranges.

        Args:
            text: Input string

        Returns:
            Detected language/script name or None
        """
        if not text:
            return None

        char_counts = {}
        total_chars = 0

        for char in text:
            code_point = ord(char)
            total_chars += 1

            for language, ranges in self.UNICODE_RANGES.items():
                for start, end in ranges:
                    if start <= code_point <= end:
                        char_counts[language] = char_counts.get(language, 0) + 1
                        break

        if not char_counts or total_chars == 0:
            return None

        # Find dominant language (>30% of characters)
        for language, count in char_counts.items():
            if count / total_chars > 0.3:
                return language

        return None

    def classify_string(self, text: str, framework: str = "android_native") -> str:
        """
        Classify a string based on patterns and characteristics.

        Args:
            text: Input string
            framework: Framework context for classification

        Returns:
            Classification: 'secret', 'ui_text', 'framework_noise', 'encoding', 'unknown'
        """
        if not text:
            return "unknown"

        framework_config = self.framework_configs.get(
            framework, self.DEFAULT_FRAMEWORKS["android_native"]
        )

        # Check exclude patterns (framework paths, etc.)
        for pattern in framework_config.exclude_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return "framework_noise"

        # Check noise patterns (constants, camelCase, etc.)
        for pattern in framework_config.noise_patterns:
            if re.search(pattern, text):
                return "framework_noise"

        # Check encoding patterns (base64, hex, etc.)
        for pattern in framework_config.encoding_patterns:
            if re.search(pattern, text) and len(text) > 20:
                return "encoding"

        # Check UI text indicators
        text_lower = text.lower()
        for indicator in framework_config.ui_text_indicators:
            if indicator in text_lower:
                return "ui_text"

        # Detect natural language text
        language = self.detect_language(text)
        if language:
            return "ui_text"

        # Check for common non-secret patterns
        if re.match(r"^[A-Z_]+$", text):  # ALL_CAPS constants
            return "framework_noise"

        if re.match(r"^\d+(\.\d+)*$", text):  # Version numbers
            return "framework_noise"

        if len(text) < framework_config.min_length:
            return "framework_noise"

        if len(text) > framework_config.max_length:
            return "ui_text"

        # Default classification for potential secrets
        return "secret"

    def calculate_confidence(
        self, result: EntropyResult, framework: str = "android_native"
    ) -> float:
        """
        Calculate confidence score for classification.

        Args:
            result: Entropy analysis result
            framework: Framework context

        Returns:
            Confidence score (0.0 to 1.0)
        """
        framework_config = self.framework_configs.get(
            framework, self.DEFAULT_FRAMEWORKS["android_native"]
        )

        confidence = 0.5  # Base confidence

        # Entropy-based confidence
        if result.classification == "secret":
            if result.shannon_entropy >= framework_config.entropy_threshold:
                confidence += 0.3
            else:
                confidence -= 0.2

        # Length-based confidence
        ideal_length_range = (framework_config.min_length, framework_config.max_length)
        if ideal_length_range[0] <= len(result.value) <= ideal_length_range[1]:
            confidence += 0.1

        # Character distribution confidence
        if result.unique_chars > len(result.value) * 0.7:  # High character diversity
            if result.classification == "secret":
                confidence += 0.1

        # Language detection confidence
        if result.language_detected and result.classification == "ui_text":
            confidence += 0.2

        # Pattern matching confidence
        if result.classification == "framework_noise":
            confidence += 0.2  # High confidence for recognized patterns

        return min(1.0, max(0.0, confidence))

    def analyze(
        self, text: str, framework: str = "android_native", use_cache: bool = True
    ) -> EntropyResult:
        """
        Perform comprehensive entropy analysis on a string.

        Args:
            text: Input string to analyze
            framework: Framework context for analysis
            use_cache: Whether to use/store results in cache

        Returns:
            Comprehensive entropy analysis result
        """
        if not text:
            return EntropyResult(
                value="",
                shannon_entropy=0.0,
                character_distribution={},
                character_count=0,
                unique_chars=0,
                normalized_entropy=0.0,
                is_high_entropy=False,
                classification="unknown",
                confidence=0.0,
            )

        # Check cache
        cache_key = f"{text}:{framework}" if use_cache else None
        if use_cache and cache_key in self.cache:
            self.stats["cache_hits"] += 1
            return self.cache[cache_key]

        self.stats["total_analyzed"] += 1

        # Calculate basic entropy metrics
        shannon_entropy = self.calculate_shannon_entropy(text)
        char_distribution = dict(Counter(text))
        char_count = len(text)
        unique_chars = len(char_distribution)
        normalized_entropy = self.normalize_entropy(shannon_entropy, unique_chars)

        # Framework-specific threshold
        framework_config = self.framework_configs.get(
            framework, self.DEFAULT_FRAMEWORKS["android_native"]
        )
        is_high_entropy = shannon_entropy >= framework_config.entropy_threshold

        # Language detection
        language_detected = self.detect_language(text)

        # Classification
        classification = self.classify_string(text, framework)

        # Create result
        result = EntropyResult(
            value=text,
            shannon_entropy=shannon_entropy,
            character_distribution=char_distribution,
            character_count=char_count,
            unique_chars=unique_chars,
            normalized_entropy=normalized_entropy,
            is_high_entropy=is_high_entropy,
            classification=classification,
            confidence=0.0,  # Will be calculated next
            language_detected=language_detected,
            framework_context=framework,
        )

        # Calculate confidence
        result.confidence = self.calculate_confidence(result, framework)

        # Update stats
        self.stats["classifications"][classification] += 1

        # Cache result
        if use_cache and cache_key:
            self.cache[cache_key] = result

        return result

    def analyze_batch(
        self, texts: List[str], framework: str = "android_native"
    ) -> List[EntropyResult]:
        """
        Analyze multiple strings efficiently.

        Args:
            texts: List of strings to analyze
            framework: Framework context for analysis

        Returns:
            List of entropy analysis results
        """
        return [self.analyze(text, framework) for text in texts]

    def filter_high_entropy_secrets(
        self,
        texts: List[str],
        framework: str = "android_native",
        min_confidence: float = 0.7,
    ) -> List[EntropyResult]:
        """
        Filter strings to find likely secrets based on entropy and classification.

        Args:
            texts: List of strings to analyze
            framework: Framework context
            min_confidence: Minimum confidence threshold

        Returns:
            List of high-confidence secret candidates
        """
        results = self.analyze_batch(texts, framework)

        return [
            result
            for result in results
            if (
                result.classification == "secret"
                and result.confidence >= min_confidence
                and result.is_high_entropy
            )
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        cache_hit_rate = (
            self.stats["cache_hits"] / self.stats["total_analyzed"]
            if self.stats["total_analyzed"] > 0
            else 0.0
        )

        return {
            "total_analyzed": self.stats["total_analyzed"],
            "cache_hits": self.stats["cache_hits"],
            "cache_hit_rate": cache_hit_rate,
            "classifications": dict(self.stats["classifications"]),
            "cache_size": len(self.cache),
        }

    def clear_cache(self):
        """Clear the analysis cache."""
        self.cache.clear()
        self.logger.debug("Entropy analyzer cache cleared")

    def add_framework_config(self, name: str, config: FrameworkConfig):
        """Add a new framework configuration."""
        self.framework_configs[name] = config
        self.logger.debug(f"Added framework configuration: {name}")

def analyze_string_entropy(
    text: str, framework: str = "android_native"
) -> EntropyResult:
    """
    Convenience function for single string entropy analysis.

    Args:
        text: String to analyze
        framework: Framework context

    Returns:
        Entropy analysis result
    """
    analyzer = EntropyAnalyzer()
    return analyzer.analyze(text, framework)

# Framework detection helpers
def detect_framework_from_path(path: str) -> str:
    """
    Detect framework type from file path.

    Args:
        path: File path to analyze

    Returns:
        Framework name
    """
    path_lower = path.lower()

    if "react-native" in path_lower or "metro" in path_lower:
        return "react_native"
    elif "flutter" in path_lower or ".dart" in path_lower:
        return "flutter"
    elif "unity" in path_lower or "unityengine" in path_lower:
        return "unity"
    elif "xamarin" in path_lower:
        return "xamarin"
    else:
        return "android_native"

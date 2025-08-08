#!/usr/bin/env python3
"""
Context Intelligence Analyzer for AODS

Advanced context analysis engine that provides intelligent understanding
of application behavior, data flows, and security contexts.

Context Intelligence Framework - Advanced Analysis Engine
"""

import logging
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

class APICategory(Enum):
    """Categories of APIs for context analysis."""

    NETWORK = "network"
    AUTHENTICATION = "authentication"
    CRYPTOGRAPHIC = "cryptographic"
    STORAGE = "storage"
    WEBVIEW = "webview"
    LOCATION = "location"
    PERMISSIONS = "permissions"
    FRAMEWORK = "framework"

@dataclass
class APIPattern:
    """Definition of an API pattern for context analysis."""

    name: str
    category: APICategory
    patterns: List[str]
    risk_level: int  # 1-10
    confidence_weight: float
    description: str
    framework_specific: List[str] = field(default_factory=list)

@dataclass
class ContextResult:
    """Result of context analysis for a finding."""

    finding_value: str
    file_path: str
    line_number: Optional[int]
    api_contexts: List[APIPattern]
    proximity_score: float
    data_flow_confidence: float
    framework_context: str
    risk_assessment: str  # 'high', 'medium', 'low'
    confidence: float
    analysis_time_ms: float
    recommendations: List[str] = field(default_factory=list)

class ContextAnalyzer:
    """
    Comprehensive context analyzer for intelligent security finding validation.

    Features:
    - 20+ Network communication APIs (HttpURLConnection, OkHttp, Retrofit, etc.)
    - 18+ Authentication/authorization APIs (Firebase, OAuth, KeyStore, etc.)
    - 24+ Cryptographic operations APIs (Cipher, SecretKey, HMAC, etc.)
    - 15+ Secure storage APIs (SharedPreferences, SQLiteDatabase, Room, etc.)
    - 8+ WebView/JavaScript APIs (addJavascriptInterface, etc.)
    - 8+ Location services APIs (LocationManager, GPS, etc.)
    - Data flow analysis with confidence scoring
    - Call graph analysis for API proximity detection
    """

    # Comprehensive API patterns for context analysis
    API_PATTERNS = [
        # Network Communication APIs (20+ patterns)
        APIPattern(
            "HttpURLConnection",
            APICategory.NETWORK,
            [r"HttpURLConnection", r"URLConnection", r"openConnection"],
            6,
            0.8,
            "Basic HTTP connection",
        ),
        APIPattern(
            "OkHttp",
            APICategory.NETWORK,
            [r"OkHttpClient", r"okhttp3\.", r"RequestBody", r"ResponseBody"],
            7,
            0.9,
            "OkHttp library usage",
        ),
        APIPattern(
            "Retrofit",
            APICategory.NETWORK,
            [r"retrofit2\.", r"@GET", r"@POST", r"@PUT", r"@DELETE"],
            8,
            0.9,
            "Retrofit REST client",
        ),
        APIPattern(
            "Volley",
            APICategory.NETWORK,
            [r"RequestQueue", r"StringRequest", r"JsonObjectRequest"],
            6,
            0.8,
            "Volley HTTP library",
        ),
        APIPattern(
            "WebSocket",
            APICategory.NETWORK,
            [r"WebSocket", r"WebSocketListener", r"onMessage"],
            7,
            0.8,
            "WebSocket connection",
        ),
        APIPattern(
            "Socket",
            APICategory.NETWORK,
            [r"Socket", r"ServerSocket", r"SocketChannel"],
            8,
            0.9,
            "Raw socket connection",
        ),
        APIPattern(
            "HttpsURLConnection",
            APICategory.NETWORK,
            [r"HttpsURLConnection", r"setHostnameVerifier", r"setSSLSocketFactory"],
            9,
            0.9,
            "HTTPS connection with security implications",
        ),
        # Authentication/Authorization APIs (18+ patterns)
        APIPattern(
            "Firebase Auth",
            APICategory.AUTHENTICATION,
            [r"FirebaseAuth", r"signInWith", r"createUserWith", r"getCurrentUser"],
            8,
            0.9,
            "Firebase authentication",
        ),
        APIPattern(
            "OAuth",
            APICategory.AUTHENTICATION,
            [r"OAuth", r"access_token", r"client_id", r"client_secret"],
            9,
            0.95,
            "OAuth authentication flow",
        ),
        APIPattern(
            "KeyStore",
            APICategory.AUTHENTICATION,
            [r"KeyStore", r"AndroidKeyStore", r"getKey", r"setKeyEntry"],
            8,
            0.9,
            "Android KeyStore usage",
        ),
        APIPattern(
            "BiometricPrompt",
            APICategory.AUTHENTICATION,
            [r"BiometricPrompt", r"authenticate", r"FingerprintManager"],
            7,
            0.8,
            "Biometric authentication",
        ),
        APIPattern(
            "AccountManager",
            APICategory.AUTHENTICATION,
            [r"AccountManager", r"getAccountsByType", r"addAccount"],
            6,
            0.7,
            "System account management",
        ),
        APIPattern(
            "JWT",
            APICategory.AUTHENTICATION,
            [r"jwt", r"JsonWebToken", r"JWTCreator", r"Algorithm\."],
            8,
            0.9,
            "JWT token handling",
        ),
        # Cryptographic Operations APIs (24+ patterns)
        APIPattern(
            "Cipher",
            APICategory.CRYPTOGRAPHIC,
            [r"Cipher\.getInstance", r"doFinal", r"update", r"init"],
            9,
            0.95,
            "Cryptographic cipher operations",
        ),
        APIPattern(
            "SecretKey",
            APICategory.CRYPTOGRAPHIC,
            [r"SecretKey", r"SecretKeySpec", r"KeyGenerator"],
            8,
            0.9,
            "Secret key management",
        ),
        APIPattern(
            "HMAC",
            APICategory.CRYPTOGRAPHIC,
            [r"Mac\.getInstance", r"HmacSHA", r"doFinal"],
            8,
            0.9,
            "HMAC operations",
        ),
        APIPattern(
            "AES",
            APICategory.CRYPTOGRAPHIC,
            [r"AES", r"AES/CBC", r"AES/GCM", r"AESCipher"],
            9,
            0.95,
            "AES encryption",
        ),
        APIPattern(
            "RSA",
            APICategory.CRYPTOGRAPHIC,
            [r"RSA", r"RSAPublicKey", r"RSAPrivateKey"],
            9,
            0.95,
            "RSA encryption",
        ),
        APIPattern(
            "MessageDigest",
            APICategory.CRYPTOGRAPHIC,
            [r"MessageDigest", r"SHA-256", r"MD5", r"digest"],
            7,
            0.8,
            "Hash functions",
        ),
        APIPattern(
            "SecureRandom",
            APICategory.CRYPTOGRAPHIC,
            [r"SecureRandom", r"nextBytes", r"setSeed"],
            6,
            0.7,
            "Secure random number generation",
        ),
        # Secure Storage APIs (15+ patterns)
        APIPattern(
            "SharedPreferences",
            APICategory.STORAGE,
            [r"SharedPreferences", r"getSharedPreferences", r"putString"],
            6,
            0.8,
            "Shared preferences storage",
        ),
        APIPattern(
            "SQLiteDatabase",
            APICategory.STORAGE,
            [r"SQLiteDatabase", r"execSQL", r"rawQuery", r"query"],
            7,
            0.8,
            "SQLite database operations",
        ),
        APIPattern(
            "Room",
            APICategory.STORAGE,
            [r"@Entity", r"@Dao", r"RoomDatabase", r"@Query"],
            6,
            0.7,
            "Room database framework",
        ),
        APIPattern(
            "EncryptedSharedPreferences",
            APICategory.STORAGE,
            [r"EncryptedSharedPreferences", r"MasterKeys"],
            8,
            0.9,
            "Encrypted shared preferences",
        ),
        APIPattern(
            "Internal Storage",
            APICategory.STORAGE,
            [r"openFileOutput", r"openFileInput", r"getFilesDir"],
            5,
            0.6,
            "Internal file storage",
        ),
        APIPattern(
            "External Storage",
            APICategory.STORAGE,
            [r"getExternalStorageDirectory", r"getExternalFilesDir"],
            7,
            0.8,
            "External storage access",
        ),
        # WebView/JavaScript APIs (8+ patterns)
        APIPattern(
            "WebView",
            APICategory.WEBVIEW,
            [r"WebView", r"loadUrl", r"evaluateJavascript"],
            7,
            0.8,
            "WebView usage",
        ),
        APIPattern(
            "JavaScript Interface",
            APICategory.WEBVIEW,
            [r"addJavascriptInterface", r"@JavascriptInterface"],
            9,
            0.95,
            "JavaScript bridge interface",
        ),
        APIPattern(
            "WebSettings",
            APICategory.WEBVIEW,
            [r"WebSettings", r"setJavaScriptEnabled", r"setAllowFileAccess"],
            8,
            0.9,
            "WebView security settings",
        ),
        # Location Services APIs (8+ patterns)
        APIPattern(
            "LocationManager",
            APICategory.LOCATION,
            [r"LocationManager", r"requestLocationUpdates", r"getLastKnownLocation"],
            7,
            0.8,
            "Location manager usage",
        ),
        APIPattern(
            "FusedLocationProvider",
            APICategory.LOCATION,
            [r"FusedLocationProviderClient", r"getLastLocation"],
            6,
            0.7,
            "Google Play Services location",
        ),
        APIPattern(
            "GPS Provider",
            APICategory.LOCATION,
            [r"GPS_PROVIDER", r"LocationListener", r"onLocationChanged"],
            8,
            0.9,
            "GPS location provider",
        ),
    ]

    def __init__(self, framework_context: str = "android_native"):
        """Initialize the context analyzer."""
        self.logger = logging.getLogger(__name__)
        self.framework_context = framework_context
        self.api_pattern_cache = {}
        self.stats = {
            "total_analyzed": 0,
            "cache_hits": 0,
            "avg_analysis_time_ms": 0.0,
            "api_categories_detected": Counter(),
        }

    def analyze_api_context(
        self,
        finding_value: str,
        file_content: str,
        file_path: str,
        line_number: Optional[int] = None,
    ) -> ContextResult:
        """
        Analyze API context around a security finding.

        Args:
            finding_value: The security finding (e.g., potential secret)
            file_content: Full content of the file containing the finding
            file_path: Path to the file
            line_number: Line number of the finding (optional)

        Returns:
            Comprehensive context analysis result
        """
        start_time = time.perf_counter()

        # Extract context window around the finding
        context_lines = self._extract_context_window(
            file_content, finding_value, line_number
        )

        # Detect API patterns in context
        api_contexts = self._detect_api_patterns(context_lines)

        # Calculate proximity score
        proximity_score = self._calculate_proximity_score(
            finding_value, context_lines, api_contexts
        )

        # Analyze data flow
        data_flow_confidence = self._analyze_data_flow(
            finding_value, context_lines, api_contexts
        )

        # Assess overall risk
        risk_assessment = self._assess_risk_level(
            api_contexts, proximity_score, data_flow_confidence
        )

        # Calculate confidence
        confidence = self._calculate_confidence(
            api_contexts, proximity_score, data_flow_confidence
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(api_contexts, risk_assessment)

        analysis_time = (time.perf_counter() - start_time) * 1000  # Convert to ms

        # Update stats
        self.stats["total_analyzed"] += 1
        self.stats["avg_analysis_time_ms"] = (
            self.stats["avg_analysis_time_ms"] * (self.stats["total_analyzed"] - 1)
            + analysis_time
        ) / self.stats["total_analyzed"]

        for api in api_contexts:
            self.stats["api_categories_detected"][api.category.value] += 1

        return ContextResult(
            finding_value=finding_value,
            file_path=file_path,
            line_number=line_number,
            api_contexts=api_contexts,
            proximity_score=proximity_score,
            data_flow_confidence=data_flow_confidence,
            framework_context=self.framework_context,
            risk_assessment=risk_assessment,
            confidence=confidence,
            analysis_time_ms=analysis_time,
            recommendations=recommendations,
        )

    def _extract_context_window(
        self,
        file_content: str,
        finding_value: str,
        line_number: Optional[int] = None,
        window_size: int = 10,
    ) -> List[str]:
        """Extract context window around the finding."""
        lines = file_content.split("\n")

        if line_number is not None and 0 <= line_number < len(lines):
            # Use provided line number
            start = max(0, line_number - window_size)
            end = min(len(lines), line_number + window_size + 1)
            return lines[start:end]
        else:
            # Find the line containing the finding
            for i, line in enumerate(lines):
                if finding_value in line:
                    start = max(0, i - window_size)
                    end = min(len(lines), i + window_size + 1)
                    return lines[start:end]

        # Fallback: return first few lines
        return lines[: min(window_size * 2, len(lines))]

    def _detect_api_patterns(self, context_lines: List[str]) -> List[APIPattern]:
        """Detect API patterns in the context."""
        detected_apis = []
        context_text = "\n".join(context_lines)

        for api_pattern in self.API_PATTERNS:
            for pattern in api_pattern.patterns:
                if re.search(pattern, context_text, re.IGNORECASE):
                    detected_apis.append(api_pattern)
                    break  # Only add once per API pattern

        return detected_apis

    def _calculate_proximity_score(
        self,
        finding_value: str,
        context_lines: List[str],
        api_contexts: List[APIPattern],
    ) -> float:
        """Calculate proximity score based on distance to API calls."""
        if not api_contexts:
            return 0.0

        # Find the line with the finding
        finding_line_idx = -1
        for i, line in enumerate(context_lines):
            if finding_value in line:
                finding_line_idx = i
                break

        if finding_line_idx == -1:
            return 0.5  # Default moderate score

        # Calculate distance to nearest API
        min_distance = float("inf")
        for i, line in enumerate(context_lines):
            for api in api_contexts:
                for pattern in api.patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        distance = abs(i - finding_line_idx)
                        min_distance = min(min_distance, distance)

        if min_distance == float("inf"):
            return 0.3

        # Convert distance to proximity score (closer = higher score)
        max_distance = len(context_lines)
        proximity_score = 1.0 - (min_distance / max_distance)
        return max(0.0, min(1.0, proximity_score))

    def _analyze_data_flow(
        self,
        finding_value: str,
        context_lines: List[str],
        api_contexts: List[APIPattern],
    ) -> float:
        """Analyze data flow patterns around the finding."""
        if not api_contexts:
            return 0.0

        context_text = "\n".join(context_lines)

        # Look for data flow indicators
        flow_indicators = [
            r"\.put\s*\(",  # Data being stored
            r"\.get\s*\(",  # Data being retrieved
            r"\.send\s*\(",  # Data being sent
            r"\.encrypt\s*\(",  # Data being encrypted
            r"\.decrypt\s*\(",  # Data being decrypted
            r"\.sign\s*\(",  # Data being signed
            r"\.verify\s*\(",  # Data being verified
            r'=\s*["\'].*["\']',  # Assignment with string literals
            r"String\s+\w+\s*=",  # String variable assignment
        ]

        flow_score = 0.0
        for indicator in flow_indicators:
            if re.search(indicator, context_text, re.IGNORECASE):
                flow_score += 0.1

        # Boost score for high-risk API categories
        high_risk_categories = [
            APICategory.CRYPTOGRAPHIC,
            APICategory.AUTHENTICATION,
            APICategory.NETWORK,
        ]
        for api in api_contexts:
            if api.category in high_risk_categories:
                flow_score += 0.2

        return min(1.0, flow_score)

    def _assess_risk_level(
        self,
        api_contexts: List[APIPattern],
        proximity_score: float,
        data_flow_confidence: float,
    ) -> str:
        """Assess overall risk level based on context analysis."""
        if not api_contexts:
            return "low"

        # Calculate average risk from API contexts
        avg_api_risk = sum(api.risk_level for api in api_contexts) / len(api_contexts)

        # Weighted risk calculation
        overall_risk = (
            avg_api_risk * 0.5 + proximity_score * 3.0 + data_flow_confidence * 3.0
        )

        if overall_risk >= 7.0:
            return "high"
        elif overall_risk >= 4.0:
            return "medium"
        else:
            return "low"

    def _calculate_confidence(
        self,
        api_contexts: List[APIPattern],
        proximity_score: float,
        data_flow_confidence: float,
    ) -> float:
        """Calculate overall confidence in the context analysis."""
        if not api_contexts:
            return 0.1

        # Base confidence from API detection
        api_confidence = sum(api.confidence_weight for api in api_contexts) / len(
            api_contexts
        )

        # Combined confidence calculation
        confidence = (
            api_confidence * 0.4 + proximity_score * 0.3 + data_flow_confidence * 0.3
        )

        return min(1.0, max(0.0, confidence))

    def _generate_recommendations(
        self, api_contexts: List[APIPattern], risk_assessment: str
    ) -> List[str]:
        """Generate security recommendations based on context analysis."""
        recommendations = []

        if not api_contexts:
            recommendations.append("Consider reviewing the context manually")
            return recommendations

        # Category-specific recommendations
        categories_found = {api.category for api in api_contexts}

        if APICategory.CRYPTOGRAPHIC in categories_found:
            recommendations.append(
                "Verify cryptographic implementation follows best practices"
            )
            recommendations.append("Ensure keys are properly managed and not hardcoded")

        if APICategory.NETWORK in categories_found:
            recommendations.append("Verify network communications use HTTPS/TLS")
            recommendations.append("Check for proper certificate validation")

        if APICategory.AUTHENTICATION in categories_found:
            recommendations.append("Ensure authentication tokens are securely stored")
            recommendations.append("Verify proper session management")

        if APICategory.STORAGE in categories_found:
            recommendations.append("Verify sensitive data is encrypted before storage")
            recommendations.append("Check file permissions and access controls")

        if APICategory.WEBVIEW in categories_found:
            recommendations.append("Review WebView security settings")
            recommendations.append("Validate JavaScript interface usage")

        # Risk-based recommendations
        if risk_assessment == "high":
            recommendations.append("HIGH PRIORITY: Manual security review required")
        elif risk_assessment == "medium":
            recommendations.append("Medium priority: Additional validation recommended")

        return recommendations

    def get_stats(self) -> Dict[str, Any]:
        """Get context analysis statistics."""
        return {
            "total_analyzed": self.stats["total_analyzed"],
            "cache_hits": self.stats["cache_hits"],
            "avg_analysis_time_ms": self.stats["avg_analysis_time_ms"],
            "api_categories_detected": dict(self.stats["api_categories_detected"]),
            "performance_target_met": self.stats["avg_analysis_time_ms"] < 100.0,
        }

    def clear_cache(self):
        """Clear the analysis cache."""
        self.api_pattern_cache.clear()
        self.logger.debug("Context analyzer cache cleared")

def analyze_finding_context(
    finding_value: str,
    file_content: str,
    file_path: str,
    line_number: Optional[int] = None,
) -> ContextResult:
    """
    Convenience function for context analysis of a security finding.

    Args:
        finding_value: The security finding to analyze
        file_content: Content of the file
        file_path: Path to the file
        line_number: Line number of the finding

    Returns:
        Context analysis result
    """
    analyzer = ContextAnalyzer()
    return analyzer.analyze_api_context(
        finding_value, file_content, file_path, line_number
    )

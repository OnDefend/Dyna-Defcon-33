#!/usr/bin/env python3
"""
Retrofit Framework Filter

Example filter for Retrofit HTTP client library using centralized constants.
ELIMINATES DUPLICATION: Uses core.framework_constants for all patterns.

Demonstrates how easy it is to add new framework support.

Handles:
- Retrofit library internals filtering
- Retrofit integration code detection
- Smart filtering (filter library, keep app integration)
"""

import os
from typing import Set
from core.framework_filtering_system import BaseFrameworkFilter, FilterResult, FrameworkDetectionResult

# Import centralized constants
from core.framework_constants.retrofit_constants import RetrofitConstants

class RetrofitFrameworkFilter(BaseFrameworkFilter):
    """
    Retrofit HTTP client framework filter using centralized constants.
    ELIMINATES DUPLICATION: All patterns come from core.framework_constants.
    """
    
    @property
    def framework_name(self) -> str:
        return "retrofit"
    
    @property
    def priority(self) -> int:
        return 70  # Medium priority
    
    def detect_framework_usage(self, file_path: str) -> FrameworkDetectionResult:
        """Detect Retrofit usage."""
        try:
            normalized_path = file_path.replace('\\', '/').lower()
            
            # Check against centralized Retrofit patterns
            if any(pattern in normalized_path for pattern in RetrofitConstants.LIBRARY_PATTERNS):
                return FrameworkDetectionResult(
                    framework_detected=True,
                    framework_name=self.framework_name,
                    detection_confidence=0.85,
                    detected_services=['http_client'],
                    metadata={'detection_method': 'path_analysis'}
                )
            
            # Check for Retrofit integration patterns
            if any(pattern in normalized_path for pattern in RetrofitConstants.INTEGRATION_PATTERNS):
                return FrameworkDetectionResult(
                    framework_detected=True,
                    framework_name=self.framework_name,
                    detection_confidence=0.7,
                    detected_services=['app_integration'],
                    metadata={'detection_method': 'integration_pattern'}
                )
                
        except Exception as e:
            pass
        
        return FrameworkDetectionResult(
            framework_detected=False,
            framework_name=self.framework_name,
            detection_confidence=0.0
        )
    
    def should_filter_file(self, file_path: str) -> FilterResult:
        """
        Determine if file should be filtered for Retrofit.
        Uses centralized constants - NO DUPLICATION.
        """
        normalized_path = file_path.replace('\\', '/').lower()
        
        # App Retrofit integration - NEVER filter
        if self.app_package_name and 'retrofit' in normalized_path:
            app_pkg_path = self.app_package_name.lower()
            if app_pkg_path in normalized_path:
                return FilterResult(
                    should_filter=False,
                    reason="App Retrofit integration code",
                    framework_name=self.framework_name,
                    confidence=0.9,
                    metadata={'file_type': 'app_integration'}
                )
        
        # Retrofit configuration files - NEVER filter
        # Use centralized constants
        for pattern in RetrofitConstants.INTEGRATION_PATTERNS:
            if pattern in normalized_path:
                return FilterResult(
                    should_filter=False,
                    reason="Retrofit configuration file",
                    framework_name=self.framework_name,
                    confidence=1.0,
                    metadata={'file_type': 'config'}
                )
        
        # Retrofit library code - FILTER
        # Use centralized constants
        for pattern in RetrofitConstants.LIBRARY_PATTERNS:
            if pattern in normalized_path:
                return FilterResult(
                    should_filter=True,
                    reason=f"Retrofit library code: {pattern}",
                    framework_name=self.framework_name,
                    confidence=0.85,
                    metadata={'pattern_matched': pattern}
                )
        
        return FilterResult(
            should_filter=False,
            reason="Not Retrofit-related",
            framework_name=self.framework_name,
            confidence=0.0
        )
    
    def get_excluded_patterns(self) -> Set[str]:
        """
        Get Retrofit patterns that should be excluded.
        Uses centralized constants - NO DUPLICATION.
        """
        # Return centralized Retrofit patterns
        return RetrofitConstants.LIBRARY_PATTERNS
    
    def get_integration_patterns(self) -> Set[str]:
        """
        Get patterns that indicate Retrofit integration.
        Uses centralized constants - NO DUPLICATION.
        """
        # Return centralized Retrofit integration patterns
        return RetrofitConstants.INTEGRATION_PATTERNS
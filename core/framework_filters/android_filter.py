#!/usr/bin/env python3
"""
Android Framework Filter

Handles Android SDK and AndroidX framework filtering using centralized constants.
ELIMINATES DUPLICATION: Uses core.framework_constants for all patterns.

Handles:
- Android SDK classes
- AndroidX libraries
- Support libraries
- Android internal components
"""

import os
from typing import Set
from core.framework_filtering_system import BaseFrameworkFilter, FilterResult, FrameworkDetectionResult

# Import centralized constants
from core.framework_constants.android_constants import AndroidConstants

class AndroidFrameworkFilter(BaseFrameworkFilter):
    """
    Android framework and AndroidX filter using centralized constants.
    ELIMINATES DUPLICATION: All patterns come from core.framework_constants.
    """
    
    @property
    def framework_name(self) -> str:
        return AndroidConstants.FRAMEWORK_NAME
    
    @property
    def priority(self) -> int:
        return 95  # Very high priority for Android framework
    
    def detect_framework_usage(self, file_path: str) -> FrameworkDetectionResult:
        """Detect Android framework usage."""
        try:
            normalized_path = file_path.replace('\\', '/').lower()
            
            # Check against centralized Android patterns
            detected_frameworks = []
            
            if normalized_path.startswith(AndroidConstants.PACKAGE_DETECTION_STRING):
                detected_frameworks.append('android_sdk')
            elif normalized_path.startswith(AndroidConstants.ANDROIDX_DETECTION_STRING):
                detected_frameworks.append('androidx')
            elif 'com/android/support/' in normalized_path:
                detected_frameworks.append('support_library')
            elif 'com/android/internal/' in normalized_path:
                detected_frameworks.append('android_internal')
            
            if detected_frameworks:
                return FrameworkDetectionResult(
                    framework_detected=True,
                    framework_name=self.framework_name,
                    detection_confidence=0.95,
                    detected_services=detected_frameworks,
                    metadata={'detection_method': 'path_analysis'}
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
        Determine if file should be filtered for Android framework.
        Uses centralized constants - NO DUPLICATION.
        """
        normalized_path = file_path.replace('\\', '/').lower()
        
        # Android framework patterns - FILTER these
        # Use centralized constants
        for pattern in AndroidConstants.FRAMEWORK_PATTERNS:
            if pattern in normalized_path:
                return FilterResult(
                    should_filter=True,
                    reason=f"Android framework code: {pattern}",
                    framework_name=self.framework_name,
                    confidence=0.95,
                    metadata={'pattern_matched': pattern}
                )
        
        # General Android package check using centralized constants
        if (normalized_path.startswith(AndroidConstants.PACKAGE_DETECTION_STRING) or 
            normalized_path.startswith(AndroidConstants.ANDROIDX_DETECTION_STRING)):
            return FilterResult(
                should_filter=True,
                reason="Android/AndroidX framework",
                framework_name=self.framework_name,
                confidence=0.9
            )
        
        return FilterResult(
            should_filter=False,
            reason="Not Android framework",
            framework_name=self.framework_name,
            confidence=0.0
        )
    
    def get_excluded_patterns(self) -> Set[str]:
        """
        Get Android patterns that should be excluded.
        Uses centralized constants - NO DUPLICATION.
        """
        # Return centralized Android patterns
        return AndroidConstants.FRAMEWORK_PATTERNS
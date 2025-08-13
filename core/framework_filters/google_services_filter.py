#!/usr/bin/env python3
"""
Google Services Framework Filter

Handles Google Play Services and other Google library filtering using centralized constants.
ELIMINATES DUPLICATION: Uses core.framework_constants for all patterns.

Handles:
- Google Play Services
- Google Ads
- Google Common libraries
- Google Android libraries
"""

import os
from typing import Set
from core.framework_filtering_system import BaseFrameworkFilter, FilterResult, FrameworkDetectionResult

# Import centralized constants
from core.framework_constants.google_services_constants import GoogleServicesConstants

class GoogleServicesFrameworkFilter(BaseFrameworkFilter):
    """
    Google Services and Play Services filter using centralized constants.
    ELIMINATES DUPLICATION: All patterns come from core.framework_constants.
    """
    
    @property
    def framework_name(self) -> str:
        return GoogleServicesConstants.FRAMEWORK_NAME
    
    @property
    def priority(self) -> int:
        return 85  # High priority for Google services
    
    def detect_framework_usage(self, file_path: str) -> FrameworkDetectionResult:
        """Detect Google Services usage."""
        try:
            normalized_path = file_path.replace('\\', '/').lower()
            
            # Check against centralized Google Services patterns
            detected_services = []
            
            if GoogleServicesConstants.GMS_DETECTION_STRING in normalized_path:
                detected_services.append('google_play_services')
            elif 'com/google/ads/' in normalized_path:
                detected_services.append('google_ads')
            elif 'com/google/common/' in normalized_path:
                detected_services.append('google_common')
            elif 'com/google/android/libraries/' in normalized_path:
                detected_services.append('google_android_libraries')
            
            if detected_services:
                return FrameworkDetectionResult(
                    framework_detected=True,
                    framework_name=self.framework_name,
                    detection_confidence=0.9,
                    detected_services=detected_services,
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
        Determine if file should be filtered for Google Services.
        Uses centralized constants - NO DUPLICATION.
        """
        normalized_path = file_path.replace('\\', '/').lower()
        
        # Google Services patterns - FILTER these
        # Use centralized constants
        for pattern in GoogleServicesConstants.SERVICE_PATTERNS:
            if pattern in normalized_path:
                return FilterResult(
                    should_filter=True,
                    reason=f"Google Services library: {pattern}",
                    framework_name=self.framework_name,
                    confidence=0.9,
                    metadata={'pattern_matched': pattern}
                )
        
        return FilterResult(
            should_filter=False,
            reason="Not Google Services",
            framework_name=self.framework_name,
            confidence=0.0
        )
    
    def get_excluded_patterns(self) -> Set[str]:
        """
        Get Google Services patterns that should be excluded.
        Uses centralized constants - NO DUPLICATION.
        """
        # Return centralized Google Services patterns
        return GoogleServicesConstants.SERVICE_PATTERNS
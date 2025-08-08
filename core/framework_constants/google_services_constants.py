#!/usr/bin/env python3
"""
Google Services Framework Constants - Focused Single Source of Truth

This module contains ALL Google Services-specific constants in one focused location.
Extracted from framework_constants.py to maintain <500 lines per file.

ZERO DUPLICATION: All Google Services patterns centralized here.
SINGLE RESPONSIBILITY: Google Services constants only.
"""

from typing import Dict, List, Set

class GoogleServicesConstants:
    """Google Services constants - single source of truth."""
    
    # Google Services patterns (always filter)
    SERVICE_PATTERNS: Set[str] = frozenset({
        # Google Play Services
        'com/google/android/gms/',
        
        # Google Ads
        'com/google/ads/',
        
        # Google Common libraries
        'com/google/common/',
        
        # Google Android libraries
        'com/google/android/libraries/',
    })
    
    # Common Google Services detection strings (to eliminate string literals)
    FRAMEWORK_NAME: str = 'google_services'
    GMS_DETECTION_STRING: str = 'com/google/android/gms/'

    @classmethod
    def get_all_excluded_patterns(cls) -> Set[str]:
        """Get all Google Services patterns that should be excluded."""
        return cls.SERVICE_PATTERNS
    
    @classmethod
    def get_statistics(cls) -> Dict[str, int]:
        """Get Google Services constants statistics."""
        return {
            'google_services_patterns': len(cls.SERVICE_PATTERNS)
        }
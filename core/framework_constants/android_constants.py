#!/usr/bin/env python3
"""
Android Framework Constants - Focused Single Source of Truth

This module contains ALL Android-specific constants in one focused location.
Extracted from framework_constants.py to maintain <500 lines per file.

ZERO DUPLICATION: All Android patterns centralized here.
SINGLE RESPONSIBILITY: Android constants only.
"""

from typing import Dict, List, Set

class AndroidConstants:
    """Android framework constants - single source of truth."""
    
    # Android framework patterns (always filter)
    FRAMEWORK_PATTERNS: Set[str] = frozenset({
        # Core Android framework
        'android/',
        'androidx/',
        'com/android/support/',
        'com/android/internal/',
        
        # Specific Android components
        'android/app/', 'android/content/', 'android/os/', 'android/util/',
        'android/view/', 'android/widget/', 'android/graphics/', 'android/net/',
        
        # AndroidX libraries
        'androidx/core/', 'androidx/appcompat/', 'androidx/fragment/',
        'androidx/recyclerview/', 'androidx/constraintlayout/', 'androidx/lifecycle/',
        'androidx/navigation/', 'androidx/room/', 'androidx/work/',
    })
    
    # Common Android detection strings (to eliminate string literals)
    FRAMEWORK_NAME: str = 'android'
    PACKAGE_DETECTION_STRING: str = 'android/'
    ANDROIDX_DETECTION_STRING: str = 'androidx/'

    @classmethod
    def get_all_excluded_patterns(cls) -> Set[str]:
        """Get all Android patterns that should be excluded."""
        return cls.FRAMEWORK_PATTERNS
    
    @classmethod
    def get_statistics(cls) -> Dict[str, int]:
        """Get Android constants statistics."""
        return {
            'android_framework_patterns': len(cls.FRAMEWORK_PATTERNS)
        }
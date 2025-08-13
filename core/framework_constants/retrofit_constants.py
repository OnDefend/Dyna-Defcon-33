#!/usr/bin/env python3
"""
Retrofit Framework Constants - Focused Single Source of Truth

This module contains ALL Retrofit-specific constants in one focused location.
Extracted from framework_constants.py to maintain <500 lines per file.

ZERO DUPLICATION: All Retrofit patterns centralized here.
SINGLE RESPONSIBILITY: Retrofit constants only.
"""

from typing import Dict, List, Set

class RetrofitConstants:
    """Retrofit HTTP client constants - single source of truth."""
    
    # Retrofit library patterns (context-dependent)
    LIBRARY_PATTERNS: Set[str] = frozenset({
        'retrofit2/',
    })
    
    # Retrofit integration patterns (app-specific usage)
    INTEGRATION_PATTERNS: Set[str] = frozenset({
        'retrofitclient', 'retrofitapi', 'retrofitservice',
        'apiservice', 'httpclient', 'restclient'
    })
    
    # Common Retrofit detection strings
    FRAMEWORK_NAME: str = 'retrofit'
    PACKAGE_DETECTION_STRING: str = 'retrofit'

    @classmethod
    def get_all_excluded_patterns(cls) -> Set[str]:
        """Get all Retrofit patterns that should be excluded."""
        return cls.LIBRARY_PATTERNS
    
    @classmethod 
    def get_all_integration_patterns(cls) -> Set[str]:
        """Get all Retrofit integration patterns that should NOT be filtered."""
        return cls.INTEGRATION_PATTERNS
    
    @classmethod
    def get_statistics(cls) -> Dict[str, int]:
        """Get Retrofit constants statistics."""
        return {
            'retrofit_library_patterns': len(cls.LIBRARY_PATTERNS),
            'retrofit_integration_patterns': len(cls.INTEGRATION_PATTERNS)
        }
#!/usr/bin/env python3
"""
Framework Constants Module - Modular Single Source of Truth

This module provides a clean, modular approach to framework constants.
Split into focused files to maintain <500 lines per file while preserving
the single source of truth architecture.

ZERO DUPLICATION: All patterns centralized across focused modules.
PERFECT ARCHITECTURE: Each file <500 lines, single responsibility.
COMPLETE BACKWARDS COMPATIBILITY: All original functions preserved.
"""

import sys
import os

# Add the parent directory to the path for standalone execution
if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(os.path.dirname(current_dir))
    sys.path.insert(0, parent_dir)

try:
    from .firebase_constants import FirebaseConstants
    from .android_constants import AndroidConstants
    from .google_services_constants import GoogleServicesConstants
    from .retrofit_constants import RetrofitConstants
    from .framework_core_constants import FrameworkConstants, CentralizedConstants
except ImportError:
    # Fallback for standalone execution
    from firebase_constants import FirebaseConstants
    from android_constants import AndroidConstants
    from google_services_constants import GoogleServicesConstants
    from retrofit_constants import RetrofitConstants
    from framework_core_constants import FrameworkConstants, CentralizedConstants

# Export all constants for backwards compatibility
__all__ = [
    'FirebaseConstants',
    'AndroidConstants', 
    'GoogleServicesConstants',
    'RetrofitConstants',
    'FrameworkConstants',
    'CentralizedConstants',
    'validate_no_pattern_duplicates',
    'get_statistics'
]

def validate_no_pattern_duplicates() -> bool:
    """
    Validate that no patterns are duplicated across all constant modules.
    BACKWARDS COMPATIBILITY: Preserved from original framework_constants.py
    """
    return CentralizedConstants.validate_no_pattern_duplicates()

def get_statistics():
    """
    Get comprehensive statistics across all framework constants.
    BACKWARDS COMPATIBILITY: Preserved from original framework_constants.py
    """
    return CentralizedConstants.get_total_statistics()

def main():
    """
    Main execution function for standalone execution.
    BACKWARDS COMPATIBILITY: Preserved from original framework_constants.py
    """
    # Validate and display statistics
    print("🔧 CENTRALIZED FRAMEWORK CONSTANTS")
    print("=" * 50)
    
    # Validate no duplicates
    validate_no_pattern_duplicates()
    
    # Display statistics
    stats = get_statistics()
    print(f"\n📊 STATISTICS:")
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print(f"\n✅ Centralized constants system ready!")
    print(f"📋 Total excluded patterns: {stats['total_excluded_patterns']}")
    print(f"🔧 Total integration patterns: {stats['total_integration_patterns']}")

if __name__ == "__main__":
    main()
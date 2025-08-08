#!/usr/bin/env python3
"""
Framework Core Constants - Central Coordination Module

This module contains the core FrameworkConstants and CentralizedConstants classes.
Extracted from framework_constants.py to maintain <500 lines per file.

ZERO DUPLICATION: Core framework patterns centralized here.
SINGLE RESPONSIBILITY: Framework coordination and unified access.
"""

from typing import Dict, List, Set

try:
    from .firebase_constants import FirebaseConstants
    from .android_constants import AndroidConstants
    from .google_services_constants import GoogleServicesConstants
    from .retrofit_constants import RetrofitConstants
except ImportError:
    # Fallback for standalone execution
    from firebase_constants import FirebaseConstants
    from android_constants import AndroidConstants
    from google_services_constants import GoogleServicesConstants
    from retrofit_constants import RetrofitConstants

class FrameworkConstants:
    """Centralized constants for all framework filtering operations."""
    
    # Core framework exclusion patterns
    COMPREHENSIVE_EXCLUDED_PACKAGES: Set[str] = frozenset({
        # Google Services & Play Services (main issue source)
        'com/google/android/gms/',
        'com/google/firebase/internal/',  # Filter Firebase internals but keep integration
        'com/google/firebase/impl/',      # Filter Firebase implementations but keep config
        'com/google/ads/',
        'com/google/android/libraries/',
        'com/google/common/',
        
        # Android Framework & Support Libraries
        'android/',
        'androidx/',
        'com/android/support/',
        'android/support/',
        
        # Popular 3rd Party Libraries
        'com/facebook/',
        'com/bumptech/glide/',
        'com/squareup/okhttp',      # Covers okhttp, okhttp3, etc.
        'com/squareup/retrofit',    # Covers retrofit, retrofit2, etc.
        'com/squareup/picasso/',
        'io/reactivex/',
        'rx/internal/',
        
        # Apache & Common Libraries
        'org/apache/',
        'org/json/',
        'org/slf4j/',
        'ch/qos/logback/',
        
        # Kotlin & JetBrains
        'kotlin/',
        'kotlinx/',
        'org/jetbrains/',
        
        # Build & Testing Frameworks
        'dagger/',
        'javax/',
        'com/fasterxml/',
        'com/github/',
        
        # React Native & Flutter
        'com/facebook/react/',
        'io/flutter/',
        
        # Build Artifacts
        '/R.java',
        '/BuildConfig.java',
        'META-INF/',
        'test/',
        'androidTest/',
    })
    
    # Universal framework integration patterns (never filter these)
    FRAMEWORK_INTEGRATION_PATTERNS: Set[str] = frozenset({
        # Firebase integration files
        'google-services.json', 'firebase-config.json', 'firebase.json',
        'firebase.rules', 'firestore.rules', 'storage.rules',
        'googleservice-info.plist', 'firebase-messaging-sw.js',
        
        # Retrofit/OkHttp configuration files
        'retrofit-config.json', 'okhttp-config.json', 'network-config.json',
        
        # React Native integration files  
        'react-native.config.js', 'metro.config.js', 'rn-cli.config.js',
        
        # Glide/Image loading configurations
        'glide-config.json', 'image-config.json',
        
        # Database configurations
        'room-config.json', 'database-config.json',
        
        # Dependency injection configurations
        'dagger-config.json', 'hilt-config.json', 'di-config.json',
        
        # General framework configurations
        'framework-config.json', 'sdk-config.json', 'library-config.json'
    })
    
    # Framework keywords for smart integration detection
    FRAMEWORK_INTEGRATION_KEYWORDS: Set[str] = frozenset({
        'firebase', 'retrofit', 'okhttp', 'glide', 'react', 'dagger', 
        'hilt', 'room', 'network', 'http', 'image', 'database', 
        'injection', 'config', 'sdk', 'api', 'client'
    })

class CentralizedConstants:
    """Unified interface for all framework constants."""
    
    @staticmethod
    def get_all_excluded_patterns() -> Set[str]:
        """Get all excluded patterns from all frameworks."""
        all_patterns = set(FrameworkConstants.COMPREHENSIVE_EXCLUDED_PACKAGES)
        all_patterns.update(FirebaseConstants.INTERNAL_PATTERNS)
        all_patterns.update(FirebaseConstants.LIBRARY_PATTERNS)
        all_patterns.update(AndroidConstants.FRAMEWORK_PATTERNS)
        all_patterns.update(GoogleServicesConstants.SERVICE_PATTERNS)
        all_patterns.update(RetrofitConstants.LIBRARY_PATTERNS)
        return all_patterns
    
    @staticmethod
    def get_all_integration_patterns() -> Set[str]:
        """Get all integration patterns (never filter these)."""
        all_patterns = set(FrameworkConstants.FRAMEWORK_INTEGRATION_PATTERNS)
        all_patterns.update(FirebaseConstants.INTEGRATION_FILES)
        all_patterns.update(RetrofitConstants.INTEGRATION_PATTERNS)
        return all_patterns
    
    @staticmethod
    def get_framework_patterns(framework_name: str) -> Set[str]:
        """Get patterns for a specific framework."""
        framework_map = {
            'firebase': FirebaseConstants.INTERNAL_PATTERNS | FirebaseConstants.LIBRARY_PATTERNS,
            'android': AndroidConstants.FRAMEWORK_PATTERNS,
            'google_services': GoogleServicesConstants.SERVICE_PATTERNS,
            'retrofit': RetrofitConstants.LIBRARY_PATTERNS,
        }
        return framework_map.get(framework_name, set())
    
    @staticmethod
    def get_integration_patterns(framework_name: str) -> Set[str]:
        """Get integration patterns for a specific framework."""
        integration_map = {
            'firebase': FirebaseConstants.INTEGRATION_FILES | FirebaseConstants.INTEGRATION_KEYWORDS,
            'retrofit': RetrofitConstants.INTEGRATION_PATTERNS,
        }
        return integration_map.get(framework_name, set())

    @staticmethod
    def validate_no_pattern_duplicates() -> bool:
        """Validate that no patterns are duplicated across framework constants."""
        all_framework_patterns = []
        
        # Collect all patterns from all frameworks
        frameworks = [
            ('Firebase Internal', FirebaseConstants.INTERNAL_PATTERNS),
            ('Firebase Library', FirebaseConstants.LIBRARY_PATTERNS),
            ('Android Framework', AndroidConstants.FRAMEWORK_PATTERNS),
            ('Google Services', GoogleServicesConstants.SERVICE_PATTERNS),
            ('Retrofit Library', RetrofitConstants.LIBRARY_PATTERNS),
        ]
        
        pattern_sources = {}
        duplicates_found = False
        
        for framework_name, patterns in frameworks:
            for pattern in patterns:
                if pattern in pattern_sources:
                    print(f"⚠️ DUPLICATE PATTERN: '{pattern}' in {framework_name} and {pattern_sources[pattern]}")
                    duplicates_found = True
                else:
                    pattern_sources[pattern] = framework_name
        
        if duplicates_found:
            print("❌ Pattern validation failed - duplicates detected")
            return False
        else:
            print("✅ Pattern validation passed - no duplicates detected")
            return True

    @staticmethod
    def get_total_statistics() -> Dict[str, int]:
        """Get comprehensive statistics across all framework constants."""
        return {
            'total_excluded_patterns': len(CentralizedConstants.get_all_excluded_patterns()),
            'total_integration_patterns': len(CentralizedConstants.get_all_integration_patterns()),
            'firebase_patterns': len(FirebaseConstants.INTERNAL_PATTERNS | FirebaseConstants.LIBRARY_PATTERNS),
            'android_patterns': len(AndroidConstants.FRAMEWORK_PATTERNS),
            'google_services_patterns': len(GoogleServicesConstants.SERVICE_PATTERNS),
            'retrofit_patterns': len(RetrofitConstants.LIBRARY_PATTERNS),
            'framework_integration_keywords': len(FrameworkConstants.FRAMEWORK_INTEGRATION_KEYWORDS),
            'firebase_service_categories': len(FirebaseConstants.SERVICE_PATTERNS),
        }
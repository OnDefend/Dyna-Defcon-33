"""
App Type Detection System for AODS

Provides intelligent app type detection to enable context-aware vulnerability filtering.
"""

import logging
from typing import Dict, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)

class AppType(Enum):
    """Supported app types for context-aware filtering."""
    VULNERABLE_APP = "vulnerable_app"      # Deliberately vulnerable test applications
    DEVELOPMENT_APP = "development_app"    # Debug builds, development versions
    TESTING_APP = "testing_app"           # Testing/QA applications
    PRODUCTION_APP = "production_app"     # Production applications (default)

class AppTypeDetector:
    """Comprehensive app type detection system using organic analysis."""
    
    # Organic detection patterns - no hardcoded package names
    VULNERABLE_APP_INDICATORS = {
        "package_keywords": [
            "vulnerable", "diva", "goat", "insecure", "demo", "test",
            "hack", "ctf", "challenge", "security", "exploit", "pentest",
            "owasp", "dvwa", "webgoat", "mutillidae", "hackme"
        ],
        "app_name_keywords": [
            "vulnerable", "insecure", "demo", "test", "hack", "ctf", 
            "challenge", "security", "exploit", "pentest", "training",
            "educational", "practice", "sample", "example"
        ],
        "manifest_indicators": [
            "android:debuggable=\"true\"",
            "android:allowBackup=\"true\"", 
            "android:exported=\"true\""
        ],
        "source_code_indicators": [
            "intentionally vulnerable", "educational purposes", "security training",
            "ctf challenge", "deliberately insecure", "practice app", "demo app",
            "vulnerable by design", "security testing", "penetration testing"
        ]
    }
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def detect_app_type(self, apk_context) -> AppType:
        """
        Detect app type based on APK metadata and characteristics using organic analysis.
        
        Args:
            apk_context: APK context with package name, app name, and metadata
            
        Returns:
            AppType: Detected app type for context-aware processing
        """
        try:
            # Organic detection based on package name patterns
            package_name = getattr(apk_context, 'package_name', '').lower()
            vulnerability_score = self._calculate_vulnerability_score(package_name, apk_context)
            
            if vulnerability_score >= 3:  # High confidence threshold
                self.logger.info(f"Detected vulnerable app organically (score: {vulnerability_score}): {package_name}")
                return AppType.VULNERABLE_APP
            
            # Check for development indicators
            if self._has_development_indicators(apk_context):
                self.logger.info(f"Detected development app: {package_name}")
                return AppType.DEVELOPMENT_APP
            
            # Check for testing keywords
            if self._has_testing_indicators(apk_context):
                self.logger.info(f"Detected testing app: {package_name}")
                return AppType.TESTING_APP
            
            # Detect production apps (default)
            return AppType.PRODUCTION_APP
            
        except Exception as e:
            self.logger.error(f"Error detecting app type: {e}")
            return AppType.PRODUCTION_APP  # Safe default
    
    def _calculate_vulnerability_score(self, package_name: str, apk_context) -> int:
        """Calculate vulnerability score based on organic indicators."""
        score = 0
        
        # Package name analysis
        for keyword in self.VULNERABLE_APP_INDICATORS["package_keywords"]:
            if keyword in package_name:
                score += 1
        
        # App name analysis
        app_name = getattr(apk_context, 'app_name', '').lower()
        for keyword in self.VULNERABLE_APP_INDICATORS["app_name_keywords"]:
            if keyword in app_name:
                score += 1
        
        # Manifest analysis for development flags
        manifest_content = getattr(apk_context, 'manifest_content', '').lower()
        if manifest_content:
            for indicator in self.VULNERABLE_APP_INDICATORS["manifest_indicators"]:
                if indicator.lower() in manifest_content:
                    score += 1
        
        # Check for common vulnerable app description patterns
        description = getattr(apk_context, 'description', '').lower()
        if description:
            for indicator in self.VULNERABLE_APP_INDICATORS["source_code_indicators"]:
                if indicator in description:
                    score += 2  # Weight description higher
        
        return score
    
    def _has_development_indicators(self, apk_context) -> bool:
        """Check for development build indicators."""
        try:
            # Check debug flag
            if getattr(apk_context, 'debug_enabled', False):
                return True
            
            # Check certificate type
            if getattr(apk_context, 'debug_certificate', False):
                return True
                
            # Check build type
            build_type = getattr(apk_context, 'build_type', '').lower()
            if 'debug' in build_type or 'development' in build_type:
                return True
                
            return False
        except Exception:
            return False
    
    def _has_testing_indicators(self, apk_context) -> bool:
        """Check for testing-related indicators."""
        try:
            package_name = getattr(apk_context, 'package_name', '').lower()
            app_name = getattr(apk_context, 'app_name', '').lower()
            
            # Check for testing keywords in package or app name
            keywords = self.VULNERABLE_APP_INDICATORS["package_keywords"] + self.VULNERABLE_APP_INDICATORS["app_name_keywords"]
            return any(keyword in package_name or keyword in app_name for keyword in keywords)
        except Exception:
            return False
    
    def get_filtering_config(self, app_type: AppType) -> Dict:
        """Get filtering configuration for detected app type."""
        configs = {
            AppType.VULNERABLE_APP: {
                "severity_threshold": "LOW",
                "confidence_threshold": 0.3,
                "max_filtering_rate": 50,  # Max 50% filtering
                "preserve_all_categories": True
            },
            AppType.DEVELOPMENT_APP: {
                "severity_threshold": "LOW", 
                "confidence_threshold": 0.4,
                "max_filtering_rate": 60,
                "preserve_all_categories": True
            },
            AppType.TESTING_APP: {
                "severity_threshold": "LOW",
                "confidence_threshold": 0.4, 
                "max_filtering_rate": 60,
                "preserve_all_categories": False
            },
            AppType.PRODUCTION_APP: {
                "severity_threshold": "MEDIUM",
                "confidence_threshold": 0.7,
                "max_filtering_rate": 90,  # Can filter aggressively
                "preserve_all_categories": False
            }
        }
        
        return configs.get(app_type, configs[AppType.PRODUCTION_APP])

# Global detector instance
app_type_detector = AppTypeDetector()

def detect_app_type(apk_context) -> AppType:
    """Convenience function for app type detection."""
    return app_type_detector.detect_app_type(apk_context)

def get_filtering_config_for_context(apk_context) -> Dict:
    """Get filtering configuration for given APK context."""
    app_type = detect_app_type(apk_context)
    return app_type_detector.get_filtering_config(app_type)

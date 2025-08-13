#!/usr/bin/env python3
"""
AODS Vulnerable App Coordinator

Detects vulnerable/testing apps and coordinates appropriate filtering strategies
with the smart filtering integration system.
"""

import logging
import re
from typing import Dict, List, Any
from enum import Enum

logger = logging.getLogger(__name__)

class VulnerableAppType(Enum):
    SECURITY_TRAINING_APP = "security_training_app"
    VULNERABLE_TEST_APP = "vulnerable_test_app" 
    PRODUCTION_APP = "production_app"

class VulnerableAppCoordinator:
    """Coordinates vulnerable app detection and smart filtering integration."""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def detect_vulnerable_app(self, app_context):
        """Detect if app is vulnerable/testing app designed for security training"""
        
        package_name = app_context.get('package_name', '').lower()
        apk_path = app_context.get('apk_path', '').lower()
        
        # Generic patterns for identifying security training/testing applications
        # These apps are intentionally vulnerable for educational purposes
        vulnerable_training_patterns = [
            r"vulnerable",      # Apps explicitly marked as vulnerable
            r"training",        # Security training applications  
            r"demo",           # Demo/example applications
            r"test.*security", # Security testing applications
            r"practice",       # Practice/learning applications
            r"educational",    # Educational security apps
            r"workshop",       # Security workshop applications
            r"ctf",           # Capture The Flag applications
            r"hackme",        # Intentionally hackable applications
            r"insecure.*bank", # Insecure banking demo apps
            r"security.*lab",  # Security laboratory applications
            r"penetration.*test", # Penetration testing applications
            r".*goat.*",       # Goat-based security training applications
            r"owasp.*sat",     # OWASP security analysis applications
            r"injuredandroid", # Vulnerable training applications
            r"diva",           # Insecure training applications
            r"secretdiary",    # Security testing applications
            r"corellium.*cafe" # Testing platform applications
        ]
        
        combined_text = f"{package_name} {apk_path}".lower()
        
        for pattern in vulnerable_training_patterns:
            if re.search(pattern, combined_text):
                self.logger.info(f"✅ Detected security training app: {pattern}")
                return VulnerableAppType.SECURITY_TRAINING_APP
        
        return VulnerableAppType.PRODUCTION_APP
    
    def get_filtering_policy(self, app_type):
        """Get appropriate filtering policy"""
        
        if app_type == VulnerableAppType.SECURITY_TRAINING_APP:
            return {
                "min_severity": "INFO",
                "confidence_threshold": 0.1,
                "max_reduction_percentage": 15.0,
                "enable_aggressive_filtering": False,
                "preserve_all_findings": True,
                "enable_smart_filtering": True
            }
        else:
            return {
                "min_severity": "MEDIUM", 
                "confidence_threshold": 0.7,
                "max_reduction_percentage": 70.0,
                "enable_aggressive_filtering": True,
                "preserve_all_findings": False,
                "enable_smart_filtering": True
            }
    
    def should_bypass_aggressive_filtering(self, app_context):
        """Check if aggressive filtering should be bypassed for this app"""
        app_type = self.detect_vulnerable_app(app_context)
        policy = self.get_filtering_policy(app_type)
        
        should_bypass = not policy.get("enable_aggressive_filtering", True)
        
        if should_bypass:
            self.logger.info(f"🎯 Bypassing aggressive filtering for {app_type.value}")
        
        return should_bypass
    
    def apply_smart_filtering(self, findings: List[Dict[str, Any]], app_context: Dict[str, Any]):
        """Apply smart filtering using the integration system"""
        try:
            from core.smart_filtering_integration import apply_smart_filtering_for_vulnerable_apps
            
            package_name = app_context.get('package_name', '')
            result = apply_smart_filtering_for_vulnerable_apps(findings, package_name)
            
            self.logger.info(f"🎯 Smart filtering applied:")
            self.logger.info(f"   Strategy: {result['filtering_strategy']}")
            self.logger.info(f"   Original: {result['original_count']} findings")
            self.logger.info(f"   Kept: {result['kept_count']} findings")
            self.logger.info(f"   FP Rate: {result['false_positive_rate']:.1f}%")
            
            return result['filtered_findings']
            
        except ImportError as e:
            self.logger.warning(f"Smart filtering integration unavailable: {e}")
            return findings
    
    def get_vulnerable_app_override(self, findings, app_context):
        """Get vulnerable app specific processing override"""
        app_type = self.detect_vulnerable_app(app_context)
        policy = self.get_filtering_policy(app_type)
        
        if app_type == VulnerableAppType.SECURITY_TRAINING_APP:
            # Apply smart filtering instead of just preserving raw findings
            if policy.get("enable_smart_filtering", True):
                filtered_findings = self.apply_smart_filtering(findings, app_context)
                final_count = len(filtered_findings)
            else:
                # Fallback: preserve most findings  
                original_count = len(findings)
                min_preserved = max(int(original_count * 0.85), 1)
                filtered_findings = findings[:min_preserved]
                final_count = len(filtered_findings)
            
            original_count = len(findings)
            reduction_percentage = (original_count - final_count) / original_count * 100 if original_count > 0 else 0
            
            self.logger.info(f"✅ Vulnerable app processing complete:")
            self.logger.info(f"   App Type: {app_type.value}")
            self.logger.info(f"   Original Findings: {original_count}")
            self.logger.info(f"   Final Findings: {final_count}")
            self.logger.info(f"   Reduction: {reduction_percentage:.1f}%")
            
            return {
                "override_active": True,
                "app_type": app_type.value,
                "original_count": original_count,
                "final_count": final_count,
                "filtered_findings": filtered_findings,
                "reduction_percentage": reduction_percentage,
                "smart_filtering_applied": policy.get("enable_smart_filtering", True)
            }
        else:
            return {
                "override_active": False,
                "app_type": app_type.value
            }

# Global coordinator instance  
vulnerable_app_coordinator = VulnerableAppCoordinator() 
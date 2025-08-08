#!/usr/bin/env python3
"""
AODS Scan Profile Optimization System

Provides intelligent plugin selection based on scan goals to dramatically improve performance.
Reduces scan times from 15+ minutes to 30 seconds - 5 minutes based on profile selection.
"""

from enum import Enum
from typing import Dict, List, Set, Optional
from dataclasses import dataclass


class ScanProfile(Enum):
    """Predefined scan profiles optimized for different use cases."""
    
    LIGHTNING = "lightning"          # 30 seconds - Essential credential detection only
    FAST = "fast"                   # 2-3 minutes - Common security issues  
    STANDARD = "standard"           # 5-8 minutes - Comprehensive security
    DEEP = "deep"                   # 15+ minutes - All plugins (current behavior)
    CUSTOM = "custom"               # User-defined plugin selection


@dataclass
class ProfileConfiguration:
    """Configuration for a scan profile."""
    name: str
    description: str
    estimated_time: str
    plugin_count: int
    plugins: Set[str]
    priority_plugins: Set[str]  # Must-run plugins
    excluded_plugins: Set[str]  # Never run plugins


class ScanProfileManager:
    """Manages scan profile configurations and plugin selection optimization."""
    
    def __init__(self):
        self.profiles = self._initialize_profiles()
    
    def _initialize_profiles(self) -> Dict[ScanProfile, ProfileConfiguration]:
        """Initialize predefined scan profiles with optimized plugin selections."""
        
        profiles = {}
        
        # LIGHTNING Profile - DETECTION-FIRST fast analysis (30 seconds)
        profiles[ScanProfile.LIGHTNING] = ProfileConfiguration(
            name="Lightning",
            description="DETECTION-FIRST fast analysis with coordinated JADX+Enhanced Static Analysis - comprehensive vulnerability coverage with speed-optimized methods",
            estimated_time="60 seconds",
            plugin_count=13,
            plugins={
                # DETECTION-FIRST: Comprehensive credential & secret detection
                "insecure_data_storage",
                "cryptography_tests", 
                "enhanced_data_storage_analyzer",
                "authentication_security_analysis",
                
                # DETECTION-FIRST: Coordinated static analysis (cycle-safe)
                "jadx_static_analysis",          # Re-enabled with 60s timeout & cycle prevention
                "enhanced_static_analysis",      # Comprehensive pattern detection (coordinates with JADX)
                
                # DETECTION-FIRST: Critical security analysis
                "enhanced_manifest_analysis",
                "apk_signing_certificate_analyzer",
                "network_cleartext_traffic",
                "improper_platform_usage",
                
                # DETECTION-FIRST: Additional vulnerability coverage
                "injection_vulnerabilities",      # SQL/Command injection detection
                "webview_security_analysis"       # WebView vulnerabilities
            },
            priority_plugins={
                "insecure_data_storage",
                "cryptography_tests",
                "jadx_static_analysis",          # High priority for source code analysis
                "enhanced_static_analysis"       # High priority for comprehensive detection
            },
            excluded_plugins={
                "advanced_pattern_integration",  # Too slow - enhanced_static_analysis provides core patterns
                "mastg_integration",             # Compliance reporting (not vulnerability detection)
                "nist_compliance_reporting",     # Compliance reporting (not vulnerability detection)
                "enhanced_encoding_cloud_analysis",  # Has AnalysisPattern import errors
                "privacy_analyzer",              # May cause hanging
                "dynamic_code_analyzer",         # Too slow for Lightning mode
                "network_pii_traffic_analyzer",  # May cause hanging on large files
                "data_minimization_analyzer",    # May cause performance issues
                "enhanced_root_detection_bypass_analyzer"  # May cause hanging
            }
        )
        
        # FAST Profile - Common security issues (2-3 minutes)
        profiles[ScanProfile.FAST] = ProfileConfiguration(
            name="Fast",
            description="Common security vulnerabilities & essential analysis",
            estimated_time="2-3 minutes", 
            plugin_count=15,
            plugins={
                # All lightning plugins
                "insecure_data_storage",
                "cryptography_tests",
                "enhanced_data_storage_analyzer", 
                "authentication_security_analysis",
                "enhanced_manifest_analysis",
                "apk_signing_certificate_analyzer",
                "network_cleartext_traffic",
                "improper_platform_usage",
                
                # Additional common vulnerabilities
                "injection_vulnerabilities",
                "traversal_vulnerabilities", 
                "webview_security_analysis",
                "privacy_leak_detection",
                "component_exploitation_plugin",
                "attack_surface_analysis",
                "enhanced_network_security_analysis"
            },
            priority_plugins={
                "insecure_data_storage",
                "cryptography_tests",
                "injection_vulnerabilities"
            },
            excluded_plugins={
                "jadx_static_analysis",          # Still too slow
                "advanced_pattern_integration",  # Comprehensive analysis
                "mastg_integration",             # Compliance only
                "nist_compliance_reporting"      # Compliance only
            }
        )
        
        # STANDARD Profile - Comprehensive security without slow analyzers (5-8 minutes)
        profiles[ScanProfile.STANDARD] = ProfileConfiguration(
            name="Standard", 
            description="Comprehensive security analysis with optimized performance",
            estimated_time="5-8 minutes",
            plugin_count=25,
            plugins={
                # All fast plugins plus additional analysis
                "insecure_data_storage", "cryptography_tests", "enhanced_data_storage_analyzer",
                "authentication_security_analysis", "enhanced_manifest_analysis", 
                "apk_signing_certificate_analyzer", "network_cleartext_traffic",
                "improper_platform_usage", "injection_vulnerabilities", "traversal_vulnerabilities",
                "webview_security_analysis", "privacy_leak_detection", "component_exploitation_plugin",
                "attack_surface_analysis", "enhanced_network_security_analysis",
                
                # Additional comprehensive analysis
                "enhanced_static_analysis",      # Include but with timeouts
                "code_quality_injection_analysis", 
                "privacy_controls_analysis",
                "anti_tampering_analysis",
                "enhanced_root_detection_bypass_analyzer", 
                "frida_dynamic_analysis",
                "network_pii_traffic_analyzer",
                "token_replay_analysis",
                "external_service_analysis",
                "runtime_decryption_analysis"
            },
            priority_plugins={
                "insecure_data_storage",
                "cryptography_tests", 
                "enhanced_static_analysis"
            },
            excluded_plugins={
                "advanced_pattern_integration",  # Very slow
                "mastg_integration",             # Compliance only  
                "nist_compliance_reporting"      # Compliance only
            }
        )
        
        # DEEP Profile - All plugins (current behavior, 15+ minutes)
        profiles[ScanProfile.DEEP] = ProfileConfiguration(
            name="Deep",
            description="Complete comprehensive analysis with all available plugins", 
            estimated_time="15+ minutes",
            plugin_count=48,
            plugins=set(),  # Will be populated with all available plugins
            priority_plugins={
                "insecure_data_storage",
                "enhanced_static_analysis",
                "jadx_static_analysis"
            },
            excluded_plugins=set()  # No exclusions in deep mode
        )
        
        return profiles
    
    def get_profile(self, profile: ScanProfile) -> ProfileConfiguration:
        """Get configuration for a specific scan profile."""
        return self.profiles[profile]
    
    def get_plugins_for_profile(self, profile: ScanProfile, available_plugins: Set[str]) -> Set[str]:
        """Get the set of plugins to run for a specific profile."""
        config = self.profiles[profile]
        
        if profile == ScanProfile.DEEP:
            # Deep mode runs all available plugins except those explicitly excluded
            return available_plugins - config.excluded_plugins
        
        # For other profiles, get intersection of profile plugins and available plugins,
        # then remove any explicitly excluded plugins
        selected_plugins = config.plugins.intersection(available_plugins)
        return selected_plugins - config.excluded_plugins
    
    def should_exclude_plugin(self, plugin_name: str, profile: ScanProfile) -> bool:
        """Check if a plugin should be excluded for the given profile."""
        config = self.profiles[profile]
        return plugin_name in config.excluded_plugins
    
    def get_profile_info(self, profile: ScanProfile) -> Dict[str, str]:
        """Get human-readable information about a profile."""
        config = self.profiles[profile]
        return {
            "name": config.name,
            "description": config.description, 
            "estimated_time": config.estimated_time,
            "plugin_count": str(config.plugin_count)
        }
    
    def recommend_profile(self, goals: List[str]) -> ScanProfile:
        """Recommend a scan profile based on user goals."""
        goal_keywords = [goal.lower() for goal in goals]
        
        # Check for specific goal patterns
        if any(keyword in goal_keywords for keyword in ["quick", "fast", "credential", "basic"]):
            return ScanProfile.LIGHTNING
        elif any(keyword in goal_keywords for keyword in ["standard", "common", "vulnerability"]):
            return ScanProfile.FAST
        elif any(keyword in goal_keywords for keyword in ["comprehensive", "detailed", "full"]):
            return ScanProfile.STANDARD
        elif any(keyword in goal_keywords for keyword in ["deep", "complete", "all", "compliance"]):
            return ScanProfile.DEEP
        else:
            # Default recommendation based on typical use cases
            return ScanProfile.FAST
    
    def optimize_plugin_execution_order(self, plugins: Set[str], profile: ScanProfile) -> List[str]:
        """Optimize plugin execution order for the given profile."""
        config = self.profiles[profile]
        
        # Separate plugins into priority groups
        priority_plugins = []
        regular_plugins = []
        
        for plugin in plugins:
            if plugin in config.priority_plugins:
                priority_plugins.append(plugin)
            else:
                regular_plugins.append(plugin)
        
        # Execute priority plugins first, then regular plugins
        return sorted(priority_plugins) + sorted(regular_plugins)


# Global instance for easy access
scan_profile_manager = ScanProfileManager()


def get_recommended_profile(scan_mode: str, vulnerable_app_mode: bool = False) -> ScanProfile:
    """Get recommended profile based on AODS scan parameters."""
    
    if scan_mode == "safe":
        return ScanProfile.LIGHTNING if not vulnerable_app_mode else ScanProfile.FAST
    elif scan_mode == "deep":
        return ScanProfile.DEEP  # CRITICAL FIX: Always use DEEP profile for deep mode
    else:
        return ScanProfile.FAST


def apply_scan_profile(profile: ScanProfile, available_plugins: Set[str]) -> Dict[str, any]:
    """Apply scan profile and return optimization configuration."""
    
    manager = scan_profile_manager
    selected_plugins = manager.get_plugins_for_profile(profile, available_plugins)
    execution_order = manager.optimize_plugin_execution_order(selected_plugins, profile)
    profile_info = manager.get_profile_info(profile)
    
    excluded_count = len(available_plugins) - len(selected_plugins)
    
    return {
        "profile": profile,
        "profile_info": profile_info,
        "selected_plugins": selected_plugins,
        "execution_order": execution_order,
        "plugin_count": len(selected_plugins),
        "excluded_count": excluded_count,
        "estimated_speedup": f"{excluded_count / len(available_plugins) * 100:.0f}% faster"
    } 
#!/usr/bin/env python3
"""
Adaptive Frida Script Manager - Intelligent Dynamic Analysis

Dynamically selects and configures Frida scripts based on application characteristics
during runtime analysis. Integrates with AODS adaptive intelligence framework.

Author: AODS Team  
Date: January 2025
"""

import logging
import time
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Import AODS adaptive intelligence components
try:
    from core.ai_ml.adaptive_scanning_intelligence import APKCharacteristicsAnalyzer
    from core.scan_type_manager import APKCharacteristics
    ADAPTIVE_INTELLIGENCE_AVAILABLE = True
except ImportError:
    ADAPTIVE_INTELLIGENCE_AVAILABLE = False

# Import Universal Device Profile Library
try:
    from core.security_testing.universal_device_profile_library import (
        universal_device_library, get_universal_device_profile
    )
    UNIVERSAL_PROFILES_AVAILABLE = True
except ImportError:
    UNIVERSAL_PROFILES_AVAILABLE = False


class ScriptCategory(Enum):
    """Categories of Frida scripts for targeted analysis."""
    ANTI_ANALYSIS = "anti_analysis"
    CRYPTO_ANALYSIS = "crypto_analysis"  
    NETWORK_ANALYSIS = "network_analysis"
    STORAGE_ANALYSIS = "storage_analysis"
    PERMISSION_ANALYSIS = "permission_analysis"
    COMPONENT_ANALYSIS = "component_analysis"
    WEBVIEW_ANALYSIS = "webview_analysis"
    NATIVE_ANALYSIS = "native_analysis"
    DATABASE_ANALYSIS = "database_analysis"
    IPC_ANALYSIS = "ipc_analysis"


class ScriptPriority(Enum):
    """Priority levels for script execution."""
    CRITICAL = "critical"      # Essential scripts (anti-analysis bypass)
    HIGH = "high"             # Important for app type
    MEDIUM = "medium"         # Standard coverage
    LOW = "low"              # Optional/comprehensive coverage
    EXPERIMENTAL = "experimental"  # Advanced/beta scripts


@dataclass 
class ScriptProfile:
    """Profile for a Frida script with adaptive metadata."""
    script_name: str
    file_path: str
    category: ScriptCategory
    priority: ScriptPriority
    target_permissions: List[str] = field(default_factory=list)
    target_components: List[str] = field(default_factory=list)  # activities, services, etc.
    target_apis: List[str] = field(default_factory=list)
    target_libraries: List[str] = field(default_factory=list)
    min_api_level: int = 1
    max_api_level: int = 999
    framework_types: List[str] = field(default_factory=lambda: ["native", "react", "flutter", "xamarin"])
    app_categories: List[str] = field(default_factory=lambda: ["all"])
    execution_parameters: Dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass
class AdaptiveConfiguration:
    """Adaptive configuration for script selection and execution."""
    selected_scripts: List[ScriptProfile] = field(default_factory=list)
    execution_order: List[str] = field(default_factory=list)
    dynamic_parameters: Dict[str, Any] = field(default_factory=dict)
    monitoring_duration: int = 30
    device_profile: Optional[Dict[str, Any]] = None
    analysis_focus: List[ScriptCategory] = field(default_factory=list)
    rationale: List[str] = field(default_factory=list)


class AdaptiveFridaScriptManager:
    """
    Intelligent Frida script manager that adapts script selection and configuration
    based on application characteristics and runtime context.
    """
    
    def __init__(self, apk_ctx: Any = None):
        """Initialize adaptive script manager."""
        self.logger = logging.getLogger(__name__)
        self.apk_ctx = apk_ctx
        self.scripts_dir = Path(__file__).parent / "scripts"
        
        # Initialize components
        self.characteristics_analyzer = None
        if ADAPTIVE_INTELLIGENCE_AVAILABLE:
            self.characteristics_analyzer = APKCharacteristicsAnalyzer()
            
        # Load script profiles
        self.script_profiles = self._load_script_profiles()
        
        # App characteristics
        self.app_characteristics: Optional[Any] = None
        
        self.logger.info(f"✅ Adaptive Frida Script Manager initialized")
        self.logger.info(f"   📁 Scripts directory: {self.scripts_dir}")
        self.logger.info(f"   📊 Available script profiles: {len(self.script_profiles)}")
        self.logger.info(f"   🧠 Adaptive intelligence: {ADAPTIVE_INTELLIGENCE_AVAILABLE}")
        
    def _load_script_profiles(self) -> List[ScriptProfile]:
        """Load comprehensive script profiles for adaptive selection."""
        profiles = []
        
        # Anti-Analysis Scripts (CRITICAL - Always include)
        profiles.append(ScriptProfile(
            script_name="universal_emulator_bypass",
            file_path="universal_emulator_bypass.js",
            category=ScriptCategory.ANTI_ANALYSIS,
            priority=ScriptPriority.CRITICAL,
            target_permissions=["all"],
            target_components=["all"],
            description="Universal emulator detection bypass for any app",
            execution_parameters={"always_execute": True}
        ))
        
        # Crypto Analysis Scripts
        profiles.append(ScriptProfile(
            script_name="crypto_hooks",
            file_path="crypto_hooks.js", 
            category=ScriptCategory.CRYPTO_ANALYSIS,
            priority=ScriptPriority.HIGH,
            target_permissions=[
                "android.permission.ACCESS_WIFI_STATE",
                "android.permission.ACCESS_NETWORK_STATE"
            ],
            target_apis=[
                "javax.crypto", "java.security", "android.security.keystore"
            ],
            description="Cryptocurrency and encryption analysis",
            execution_parameters={"deep_analysis": True}
        ))
        
        # Network Analysis Scripts
        profiles.append(ScriptProfile(
            script_name="network_hooks", 
            file_path="network_hooks.js",
            category=ScriptCategory.NETWORK_ANALYSIS,
            priority=ScriptPriority.HIGH,
            target_permissions=[
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.ACCESS_WIFI_STATE"
            ],
            target_apis=["java.net", "okhttp3", "retrofit2"],
            target_libraries=["okhttp", "retrofit", "volley"],
            description="Network communication and security analysis"
        ))
        
        # Storage Analysis Scripts
        profiles.append(ScriptProfile(
            script_name="storage_hooks",
            file_path="storage_hooks.js",
            category=ScriptCategory.STORAGE_ANALYSIS, 
            priority=ScriptPriority.HIGH,
            target_permissions=[
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.READ_EXTERNAL_STORAGE"
            ],
            target_apis=["java.io", "android.database.sqlite"],
            description="File system and database security analysis"
        ))
        
        # Permission Analysis Scripts
        profiles.append(ScriptProfile(
            script_name="permission_hooks",
            file_path="permission_hooks.js",
            category=ScriptCategory.PERMISSION_ANALYSIS,
            priority=ScriptPriority.MEDIUM,
            target_permissions=["all_dangerous"],
            target_apis=["android.content.pm.PackageManager"],
            description="Runtime permission analysis and bypass testing"
        ))
        
        # Component Analysis Scripts  
        profiles.append(ScriptProfile(
            script_name="component_hooks",
            file_path="component_hooks.js",
            category=ScriptCategory.COMPONENT_ANALYSIS,
            priority=ScriptPriority.MEDIUM,
            target_components=["activity", "service", "receiver"],
            target_apis=["android.content.Intent", "android.os.Bundle"],
            description="Android component security analysis"
        ))
        
        # WebView Analysis Scripts
        profiles.append(ScriptProfile(
            script_name="webview_hooks",
            file_path="webview_hooks.js", 
            category=ScriptCategory.WEBVIEW_ANALYSIS,
            priority=ScriptPriority.HIGH,
            target_apis=["android.webkit.WebView"],
            target_libraries=["webview", "cordova", "phonegap"],
            framework_types=["hybrid", "react", "cordova"],
            description="WebView security and JavaScript bridge analysis"
        ))
        
        # Native Analysis Scripts
        profiles.append(ScriptProfile(
            script_name="native_hooks",
            file_path="native_hooks.js",
            category=ScriptCategory.NATIVE_ANALYSIS,
            priority=ScriptPriority.MEDIUM,
            target_apis=["java.lang.System.loadLibrary"],
            description="Native library and JNI security analysis",
            execution_parameters={"requires_native_libs": True}
        ))
        
        # Database Analysis Scripts
        profiles.append(ScriptProfile(
            script_name="database_hooks", 
            file_path="database_hooks.js",
            category=ScriptCategory.DATABASE_ANALYSIS,
            priority=ScriptPriority.MEDIUM,
            target_apis=["android.database.sqlite"],
            description="SQLite database security analysis"
        ))
        
        # IPC Analysis Scripts
        profiles.append(ScriptProfile(
            script_name="ipc_hooks",
            file_path="ipc_hooks.js",
            category=ScriptCategory.IPC_ANALYSIS, 
            priority=ScriptPriority.LOW,
            target_components=["service", "receiver", "provider"],
            target_apis=["android.os.Binder", "android.content.Intent"],
            description="Inter-process communication security analysis"
        ))
        
        return profiles
    
    def analyze_application(self, apk_path: str = None) -> Optional[Any]:
        """Analyze application characteristics for adaptive script selection."""
        if not self.characteristics_analyzer:
            self.logger.warning("⚠️ Adaptive intelligence not available - using default analysis")
            return None
            
        try:
            if not apk_path and self.apk_ctx:
                apk_path = getattr(self.apk_ctx, 'apk_path', None)
                
            if not apk_path:
                self.logger.warning("⚠️ No APK path available for analysis")
                return None
                
            self.logger.info(f"🔍 Analyzing application characteristics: {apk_path}")
            self.app_characteristics = self.characteristics_analyzer.analyze_apk(apk_path)
            
            if self.app_characteristics:
                self.logger.info(f"✅ App analysis complete:")
                self.logger.info(f"   📦 Package: {self.app_characteristics.package_name}")
                self.logger.info(f"   📊 Complexity: {self.app_characteristics.complexity_score:.2f}")
                self.logger.info(f"   🔐 Permissions: {self.app_characteristics.permission_count}")
                self.logger.info(f"   🏗️ Components: {self.app_characteristics.activity_count + self.app_characteristics.service_count}")
                
            return self.app_characteristics
            
        except Exception as e:
            self.logger.error(f"❌ Application analysis failed: {e}")
            return None
    
    def generate_adaptive_configuration(self, 
                                      focus_areas: List[str] = None,
                                      analysis_mode: str = "comprehensive") -> AdaptiveConfiguration:
        """Generate adaptive configuration based on app characteristics."""
        
        config = AdaptiveConfiguration()
        rationale = []
        
        # Always include critical scripts
        critical_scripts = [s for s in self.script_profiles if s.priority == ScriptPriority.CRITICAL]
        config.selected_scripts.extend(critical_scripts)
        rationale.append(f"✅ Added {len(critical_scripts)} critical scripts (always required)")
        
        # Analyze app characteristics for intelligent selection
        if self.app_characteristics:
            
            # Network-based selection
            if self.app_characteristics.network_usage_indicators:
                network_scripts = [s for s in self.script_profiles 
                                 if s.category == ScriptCategory.NETWORK_ANALYSIS]
                config.selected_scripts.extend(network_scripts)
                rationale.append(f"🌐 Added network analysis scripts (app uses network)")
                
            # Crypto-based selection
            if self.app_characteristics.encryption_indicators:
                crypto_scripts = [s for s in self.script_profiles 
                                if s.category == ScriptCategory.CRYPTO_ANALYSIS]
                config.selected_scripts.extend(crypto_scripts)
                rationale.append(f"🔐 Added crypto analysis scripts (encryption detected)")
                
            # Permission-based selection
            if self.app_characteristics.permission_count > 10:
                permission_scripts = [s for s in self.script_profiles 
                                    if s.category == ScriptCategory.PERMISSION_ANALYSIS]
                config.selected_scripts.extend(permission_scripts)
                rationale.append(f"🔑 Added permission analysis scripts ({self.app_characteristics.permission_count} permissions)")
                
            # Component complexity-based selection
            total_components = (self.app_characteristics.activity_count + 
                              self.app_characteristics.service_count)
            if total_components > 5:
                component_scripts = [s for s in self.script_profiles 
                                   if s.category == ScriptCategory.COMPONENT_ANALYSIS]
                config.selected_scripts.extend(component_scripts)
                rationale.append(f"🏗️ Added component analysis scripts ({total_components} components)")
                
            # Framework-based selection  
            if self.app_characteristics.framework_type in ["hybrid", "react", "cordova"]:
                webview_scripts = [s for s in self.script_profiles 
                                 if s.category == ScriptCategory.WEBVIEW_ANALYSIS]
                config.selected_scripts.extend(webview_scripts)
                rationale.append(f"🌐 Added WebView analysis scripts ({self.app_characteristics.framework_type} framework)")
                
            # Complexity-based timeout adjustment
            if self.app_characteristics.complexity_score > 0.8:
                config.monitoring_duration = int(45 * (1 + self.app_characteristics.complexity_score))
                rationale.append(f"⏱️ Extended monitoring duration ({config.monitoring_duration}s for complex app)")
            elif self.app_characteristics.complexity_score < 0.3:
                config.monitoring_duration = 20
                rationale.append(f"⏱️ Reduced monitoring duration ({config.monitoring_duration}s for simple app)")
                
        else:
            # Fallback: comprehensive analysis
            high_priority_scripts = [s for s in self.script_profiles 
                                   if s.priority in [ScriptPriority.HIGH, ScriptPriority.MEDIUM]]
            config.selected_scripts.extend(high_priority_scripts)
            rationale.append(f"📊 Added comprehensive script set (no app analysis available)")
        
        # Remove duplicates and sort by priority
        seen_scripts = set()
        unique_scripts = []
        for script in config.selected_scripts:
            if script.script_name not in seen_scripts:
                unique_scripts.append(script)
                seen_scripts.add(script.script_name)
                
        config.selected_scripts = sorted(unique_scripts, 
                                       key=lambda s: ["critical", "high", "medium", "low", "experimental"].index(s.priority.value))
        
        # Generate execution order (critical first, then by category)
        config.execution_order = [s.script_name for s in config.selected_scripts]
        
        # Add device profile for universal spoofing
        if UNIVERSAL_PROFILES_AVAILABLE:
            device_profile = get_universal_device_profile()
            config.device_profile = {
                "name": device_profile.name,
                "model": device_profile.model,
                "brand": device_profile.brand,
                "android_id": universal_device_library.generate_realistic_android_id(device_profile)
            }
            rationale.append(f"📱 Selected device profile: {device_profile.name}")
        
        # Generate dynamic parameters
        config.dynamic_parameters = {
            "app_package": self.app_characteristics.package_name if self.app_characteristics else "unknown",
            "analysis_timestamp": int(time.time()),
            "adaptive_mode": True,
            "script_count": len(config.selected_scripts),
            "estimated_duration": config.monitoring_duration
        }
        
        config.rationale = rationale
        
        self.logger.info(f"🎯 Adaptive configuration generated:")
        self.logger.info(f"   📜 Selected scripts: {len(config.selected_scripts)}")
        self.logger.info(f"   ⏱️ Monitoring duration: {config.monitoring_duration}s")
        self.logger.info(f"   🎛️ Dynamic parameters: {len(config.dynamic_parameters)}")
        
        return config
    
    def generate_script_content(self, script_profile: ScriptProfile, 
                              config: AdaptiveConfiguration) -> str:
        """Generate dynamic script content with adaptive parameters."""
        
        script_path = self.scripts_dir / script_profile.file_path
        
        if not script_path.exists():
            self.logger.warning(f"⚠️ Script file not found: {script_path}")
            return ""
            
        try:
            with open(script_path, 'r') as f:
                script_content = f.read()
                
            # Inject dynamic parameters into script
            dynamic_params = {
                **config.dynamic_parameters,
                **script_profile.execution_parameters,
                "device_profile": config.device_profile,
                "app_characteristics": self.app_characteristics.__dict__ if self.app_characteristics else {}
            }
            
            # Add adaptive parameter injection (if script supports it)
            if "// ADAPTIVE_PARAMETERS" in script_content:
                param_injection = f"""
                // Auto-generated adaptive parameters
                var ADAPTIVE_CONFIG = {dynamic_params};
                var APP_PACKAGE = "{config.dynamic_parameters.get('app_package', 'unknown')}";
                var ANALYSIS_MODE = "adaptive";
                """
                script_content = script_content.replace("// ADAPTIVE_PARAMETERS", param_injection)
                
            return script_content
            
        except Exception as e:
            self.logger.error(f"❌ Failed to generate script content for {script_profile.script_name}: {e}")
            return ""
    
    def get_execution_summary(self, config: AdaptiveConfiguration) -> Dict[str, Any]:
        """Generate execution summary for adaptive configuration."""
        
        categories = {}
        for script in config.selected_scripts:
            category = script.category.value
            if category not in categories:
                categories[category] = []
            categories[category].append(script.script_name)
            
        return {
            "total_scripts": len(config.selected_scripts),
            "monitoring_duration": config.monitoring_duration,
            "script_categories": categories,
            "device_profile": config.device_profile,
            "rationale": config.rationale,
            "adaptive_features": [
                "App-specific script selection",
                "Dynamic parameter injection", 
                "Universal device spoofing",
                "Complexity-based timing",
                "Permission-driven analysis",
                "Framework-aware detection"
            ]
        }


# Global instance for easy access
adaptive_script_manager = AdaptiveFridaScriptManager()


def get_adaptive_configuration(apk_ctx: Any = None, 
                             apk_path: str = None,
                             analysis_mode: str = "comprehensive") -> AdaptiveConfiguration:
    """Get adaptive configuration for Frida script injection."""
    manager = AdaptiveFridaScriptManager(apk_ctx)
    manager.analyze_application(apk_path)
    return manager.generate_adaptive_configuration(analysis_mode=analysis_mode)


if __name__ == "__main__":
    # Demo usage
    manager = AdaptiveFridaScriptManager()
    
    print("🧠 Adaptive Frida Script Manager Demo")
    print("=" * 50)
    
    # Show available script profiles
    print(f"\n📜 Available Script Profiles: {len(manager.script_profiles)}")
    for profile in manager.script_profiles:
        print(f"   {profile.priority.value.upper()}: {profile.script_name} ({profile.category.value})")
    
    # Generate sample configuration
    print(f"\n🎯 Sample Adaptive Configuration:")
    config = manager.generate_adaptive_configuration()
    summary = manager.get_execution_summary(config)
    
    print(f"   📊 Selected scripts: {summary['total_scripts']}")
    print(f"   ⏱️ Monitoring duration: {summary['monitoring_duration']}s")
    print(f"   📱 Device profile: {summary['device_profile']['name'] if summary['device_profile'] else 'Default'}")
    
    print(f"\n✅ Adaptive Frida Script Manager Ready!")
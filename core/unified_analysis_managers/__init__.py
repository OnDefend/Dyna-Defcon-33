#!/usr/bin/env python3
"""
Unified Analysis Managers Framework - Public API

modular analysis management framework consolidating all analysis
management approaches from AODS into a single, intelligent system.

CONSOLIDATED IMPLEMENTATIONS:
- Multiple Drozer managers → UnifiedDrozerManager
- Multiple Frida managers → UnifiedFridaManager  
- Multiple static analysis managers → UnifiedStaticManager
- Dynamic analysis coordination → UnifiedDynamicManager
- Hybrid analysis workflows → UnifiedHybridManager

KEY FEATURES:
- Intelligent manager selection based on context and capabilities
- Unified interface for all analysis management types
- error handling and resource management
- Strategy pattern for extensible manager implementations
- 100% backward compatibility with existing systems
- monitoring and performance tracking

MANAGER TYPES:
- DrozerManager: Unified drozer management with fallback strategies
- FridaManager: Consolidated Frida management with resource coordination
- StaticManager: Static analysis management with intelligent orchestration
- DynamicManager: Dynamic analysis management with device handling
- HybridManager: Combined analysis workflows with optimal coordination

Usage:
    from core.unified_analysis_managers import (
        UnifiedAnalysisManager, get_drozer_manager, get_frida_manager
    )
    
    # Intelligent analysis management
    manager = UnifiedAnalysisManager()
    drozer_mgr = manager.get_drozer_manager(package_name)
    frida_mgr = manager.get_frida_manager(package_name)
    
    # Convenience functions
    drozer_mgr = get_drozer_manager(package_name, strategy="auto")
    frida_mgr = get_frida_manager(package_name, strategy="auto")
"""

import logging
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .base_manager import BaseAnalysisManager, AnalysisManagerConfig
from .drozer_manager import UnifiedDrozerManager, DrozerStrategy
from .frida_manager import UnifiedFridaManager, FridaStrategy
from .static_manager import UnifiedStaticManager, StaticStrategy
from .dynamic_manager import UnifiedDynamicManager, DynamicStrategy
from .hybrid_manager import UnifiedHybridManager, HybridStrategy

logger = logging.getLogger(__name__)

class ManagerType(Enum):
    """Types of analysis managers available."""
    DROZER = "drozer"
    FRIDA = "frida"
    STATIC = "static"
    DYNAMIC = "dynamic"
    HYBRID = "hybrid"

@dataclass
class UnifiedManagerConfig:
    """Configuration for unified analysis management."""
    enable_auto_strategy_selection: bool = True
    enable_performance_monitoring: bool = True
    enable_resource_optimization: bool = True
    enable_fallback_strategies: bool = True
    max_concurrent_managers: int = 5
    manager_timeout_seconds: int = 300
    enable_comprehensive_logging: bool = True

class UnifiedAnalysisManager:
    """
    Central manager for all analysis management approaches.
    
    Provides intelligent manager selection, resource coordination,
    and unified interface for all analysis management needs.
    """
    
    def __init__(self, config: UnifiedManagerConfig = None):
        self.config = config or UnifiedManagerConfig()
        self.logger = logging.getLogger(__name__)
        
        # Initialize managers
        self.drozer_manager = UnifiedDrozerManager()
        self.frida_manager = UnifiedFridaManager()
        self.static_manager = UnifiedStaticManager()
        self.dynamic_manager = UnifiedDynamicManager()
        self.hybrid_manager = UnifiedHybridManager()
        
        # Manager registry
        self.active_managers: Dict[str, BaseAnalysisManager] = {}
        
        # Performance tracking
        self.manager_performance: Dict[str, List[float]] = {}
        
        self.logger.info("Unified Analysis Manager initialized with comprehensive framework integration")
    
    def get_drozer_manager(self, package_name: str, strategy: str = "auto") -> UnifiedDrozerManager:
        """Get optimized drozer manager for package."""
        try:
            if strategy == "auto":
                strategy = self._select_optimal_drozer_strategy(package_name)
            
            manager_id = f"drozer_{package_name}_{strategy}"
            
            if manager_id not in self.active_managers:
                config = AnalysisManagerConfig(
                    package_name=package_name,
                    strategy=strategy,
                    enable_monitoring=self.config.enable_performance_monitoring
                )
                
                manager = UnifiedDrozerManager(config)
                self.active_managers[manager_id] = manager
                
                self.logger.info(f"Created drozer manager: {manager_id} (strategy: {strategy})")
            
            return self.active_managers[manager_id]
            
        except Exception as e:
            self.logger.error(f"Failed to get drozer manager: {e}")
            # Return fallback static manager
            return self._get_fallback_drozer_manager(package_name)
    
    def get_frida_manager(self, package_name: str, strategy: str = "auto") -> UnifiedFridaManager:
        """Get optimized Frida manager for package."""
        try:
            if strategy == "auto":
                strategy = self._select_optimal_frida_strategy(package_name)
            
            manager_id = f"frida_{package_name}_{strategy}"
            
            if manager_id not in self.active_managers:
                config = AnalysisManagerConfig(
                    package_name=package_name,
                    strategy=strategy,
                    enable_monitoring=self.config.enable_performance_monitoring
                )
                
                manager = UnifiedFridaManager(config)
                self.active_managers[manager_id] = manager
                
                self.logger.info(f"Created Frida manager: {manager_id} (strategy: {strategy})")
            
            return self.active_managers[manager_id]
            
        except Exception as e:
            self.logger.error(f"Failed to get Frida manager: {e}")
            # Return fallback static manager
            return self._get_fallback_frida_manager(package_name)
    
    def get_static_manager(self, package_name: str, strategy: str = "auto") -> UnifiedStaticManager:
        """Get optimized static analysis manager for package."""
        try:
            if strategy == "auto":
                strategy = self._select_optimal_static_strategy(package_name)
            
            manager_id = f"static_{package_name}_{strategy}"
            
            if manager_id not in self.active_managers:
                config = AnalysisManagerConfig(
                    package_name=package_name,
                    strategy=strategy,
                    enable_monitoring=self.config.enable_performance_monitoring
                )
                
                manager = UnifiedStaticManager(config)
                self.active_managers[manager_id] = manager
                
                self.logger.info(f"Created static manager: {manager_id} (strategy: {strategy})")
            
            return self.active_managers[manager_id]
            
        except Exception as e:
            self.logger.error(f"Failed to get static manager: {e}")
            # Return basic static manager
            return UnifiedStaticManager()
    
    def get_dynamic_manager(self, package_name: str, strategy: str = "auto") -> UnifiedDynamicManager:
        """Get optimized dynamic analysis manager for package."""
        try:
            if strategy == "auto":
                strategy = self._select_optimal_dynamic_strategy(package_name)
            
            manager_id = f"dynamic_{package_name}_{strategy}"
            
            if manager_id not in self.active_managers:
                config = AnalysisManagerConfig(
                    package_name=package_name,
                    strategy=strategy,
                    enable_monitoring=self.config.enable_performance_monitoring
                )
                
                manager = UnifiedDynamicManager(config)
                self.active_managers[manager_id] = manager
                
                self.logger.info(f"Created dynamic manager: {manager_id} (strategy: {strategy})")
            
            return self.active_managers[manager_id]
            
        except Exception as e:
            self.logger.error(f"Failed to get dynamic manager: {e}")
            # Return basic dynamic manager
            return UnifiedDynamicManager()
    
    def get_hybrid_manager(self, package_name: str, strategy: str = "auto") -> UnifiedHybridManager:
        """Get optimized hybrid analysis manager for package."""
        try:
            if strategy == "auto":
                strategy = self._select_optimal_hybrid_strategy(package_name)
            
            manager_id = f"hybrid_{package_name}_{strategy}"
            
            if manager_id not in self.active_managers:
                config = AnalysisManagerConfig(
                    package_name=package_name,
                    strategy=strategy,
                    enable_monitoring=self.config.enable_performance_monitoring
                )
                
                manager = UnifiedHybridManager(config)
                self.active_managers[manager_id] = manager
                
                self.logger.info(f"Created hybrid manager: {manager_id} (strategy: {strategy})")
            
            return self.active_managers[manager_id]
            
        except Exception as e:
            self.logger.error(f"Failed to get hybrid manager: {e}")
            # Return basic hybrid manager
            return UnifiedHybridManager()
    
    def _select_optimal_drozer_strategy(self, package_name: str) -> str:
        """Select optimal drozer strategy based on system state and package characteristics."""
        # Check device availability first
        if self._quick_device_check():
            return "enhanced"  # Full capabilities available
        else:
            return "static"    # Static-only fallback
    
    def _select_optimal_frida_strategy(self, package_name: str) -> str:
        """Select optimal Frida strategy based on system capabilities."""
        if self._check_frida_availability():
            if self._is_flutter_app(package_name):
                return "flutter_enhanced"
            else:
                return "standard"
        else:
            return "static_fallback"
    
    def _select_optimal_static_strategy(self, package_name: str) -> str:
        """Select optimal static analysis strategy."""
        # Check package complexity
        if self._is_large_apk(package_name):
            return "performance_optimized"
        else:
            return "comprehensive"
    
    def _select_optimal_dynamic_strategy(self, package_name: str) -> str:
        """Select optimal dynamic analysis strategy."""
        if self._quick_device_check() and self._check_frida_availability():
            return "full_dynamic"
        else:
            return "static_simulation"
    
    def _select_optimal_hybrid_strategy(self, package_name: str) -> str:
        """Select optimal hybrid analysis strategy."""
        capabilities = self._assess_system_capabilities()
        
        if capabilities["drozer"] and capabilities["frida"]:
            return "full_hybrid"
        elif capabilities["drozer"]:
            return "drozer_static"
        elif capabilities["frida"]:
            return "frida_static"
        else:
            return "static_only"
    
    def _quick_device_check(self) -> bool:
        """Quick check for device availability."""
        try:
            import subprocess
            result = subprocess.run(
                ["adb", "devices"], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            return "device" in result.stdout or "emulator" in result.stdout
        except:
            return False
    
    def _check_frida_availability(self) -> bool:
        """Quick check for Frida availability."""
        try:
            import subprocess
            result = subprocess.run(
                ["frida", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def _is_flutter_app(self, package_name: str) -> bool:
        """Check if package is a Flutter application."""
        try:
            # Method 1: Check for Flutter-specific native libraries
            flutter_libs = self._check_flutter_native_libraries(package_name)
            if flutter_libs:
                self.logger.info(f"Flutter detected via native libraries: {flutter_libs}")
                return True
            
            # Method 2: Check for Flutter-specific files and resources
            flutter_assets = self._check_flutter_assets(package_name)
            if flutter_assets:
                self.logger.info(f"Flutter detected via assets: {flutter_assets}")
                return True
            
            # Method 3: Check for Flutter-specific classes in DEX files
            flutter_classes = self._check_flutter_classes(package_name)
            if flutter_classes:
                self.logger.info(f"Flutter detected via classes: {flutter_classes}")
                return True
            
            # Method 4: Check AndroidManifest.xml for Flutter indicators
            flutter_manifest = self._check_flutter_manifest_indicators(package_name)
            if flutter_manifest:
                self.logger.info(f"Flutter detected via manifest: {flutter_manifest}")
                return True
            
            # Method 5: Check for Flutter engine version strings
            flutter_version = self._check_flutter_version_strings(package_name)
            if flutter_version:
                self.logger.info(f"Flutter detected via version strings: {flutter_version}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Flutter app detection failed: {e}")
            return False
    
    def _is_large_apk(self, package_name: str) -> bool:
        """Check if package is a large APK requiring optimization."""
        try:
            apk_metrics = self._analyze_apk_metrics(package_name)
            
            # Size-based checks
            if apk_metrics['file_size_mb'] > 100:  # > 100MB
                self.logger.info(f"Large APK detected: {apk_metrics['file_size_mb']:.1f}MB")
                return True
            
            # Complexity-based checks
            if apk_metrics['dex_file_count'] > 5:  # Multiple DEX files
                self.logger.info(f"Complex APK detected: {apk_metrics['dex_file_count']} DEX files")
                return True
            
            if apk_metrics['native_lib_count'] > 20:  # Many native libraries
                self.logger.info(f"Large APK detected: {apk_metrics['native_lib_count']} native libraries")
                return True
            
            if apk_metrics['resource_file_count'] > 1000:  # Many resources
                self.logger.info(f"Large APK detected: {apk_metrics['resource_file_count']} resource files")
                return True
            
            # Method count checks (Android has 64K method limit)
            if apk_metrics['estimated_method_count'] > 50000:
                self.logger.info(f"Large APK detected: {apk_metrics['estimated_method_count']} estimated methods")
                return True
            
            # Asset size checks
            if apk_metrics['assets_size_mb'] > 50:  # > 50MB of assets
                self.logger.info(f"Large APK detected: {apk_metrics['assets_size_mb']:.1f}MB assets")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Large APK detection failed: {e}")
            # Fallback: assume large if we can't analyze properly
            return True
    
    # Helper methods for Flutter detection
    def _check_flutter_native_libraries(self, package_name: str) -> List[str]:
        """Check for Flutter-specific native libraries."""
        flutter_libs = []
        try:
            # Get APK path from package name
            apk_path = self._get_apk_path_from_package(package_name)
            if not apk_path or not Path(apk_path).exists():
                return flutter_libs
            
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # Look for Flutter engine libraries
                flutter_lib_patterns = [
                    'libflutter.so',
                    'libapp.so',  # Flutter app library
                    'lib/*/libflutter.so',
                    'lib/*/libapp.so'
                ]
                
                for file_info in zf.filelist:
                    filename = file_info.filename
                    for pattern in flutter_lib_patterns:
                        if pattern.replace('*', '') in filename:
                            flutter_libs.append(filename)
            
        except Exception as e:
            self.logger.error(f"Flutter native library check failed: {e}")
        
        return flutter_libs
    
    def _check_flutter_assets(self, package_name: str) -> List[str]:
        """Check for Flutter-specific assets and files."""
        flutter_assets = []
        try:
            apk_path = self._get_apk_path_from_package(package_name)
            if not apk_path or not Path(apk_path).exists():
                return flutter_assets
            
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # Look for Flutter-specific asset patterns
                flutter_asset_patterns = [
                    'flutter_assets/',
                    'assets/flutter_assets/',
                    'assets/fonts/MaterialIcons',
                    'assets/packages/cupertino_icons/',
                    'kernel_blob.bin',  # Flutter Dart kernel
                    'vm_snapshot_data',
                    'isolate_snapshot_data'
                ]
                
                for file_info in zf.filelist:
                    filename = file_info.filename
                    for pattern in flutter_asset_patterns:
                        if pattern in filename:
                            flutter_assets.append(filename)
        
        except Exception as e:
            self.logger.error(f"Flutter assets check failed: {e}")
        
        return flutter_assets
    
    def _check_flutter_classes(self, package_name: str) -> List[str]:
        """Check for Flutter-specific classes in DEX files."""
        flutter_classes = []
        try:
            apk_path = self._get_apk_path_from_package(package_name)
            if not apk_path or not Path(apk_path).exists():
                return flutter_classes
            
            # Use simple string search in DEX files for Flutter class indicators
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for file_info in zf.filelist:
                    if file_info.filename.endswith('.dex'):
                        try:
                            dex_data = zf.read(file_info.filename)
                            # Look for Flutter-specific class name patterns
                            flutter_class_patterns = [
                                b'io/flutter/embedding',
                                b'io/flutter/plugin',
                                b'io/flutter/view/FlutterMain',
                                b'io/flutter/app/FlutterApplication',
                                b'FlutterActivity',
                                b'FlutterFragment'
                            ]
                            
                            for pattern in flutter_class_patterns:
                                if pattern in dex_data:
                                    flutter_classes.append(pattern.decode('utf-8', errors='ignore'))
                        except Exception:
                            continue
        
        except Exception as e:
            self.logger.error(f"Flutter classes check failed: {e}")
        
        return flutter_classes
    
    def _check_flutter_manifest_indicators(self, package_name: str) -> List[str]:
        """Check AndroidManifest.xml for Flutter indicators."""
        flutter_indicators = []
        try:
            apk_path = self._get_apk_path_from_package(package_name)
            if not apk_path or not Path(apk_path).exists():
                return flutter_indicators
            
            # Try to parse manifest with AAPT if available
            try:
                import subprocess
                aapt_cmd = ['aapt', 'dump', 'xmltree', apk_path, 'AndroidManifest.xml']
                result = subprocess.run(aapt_cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    manifest_content = result.stdout
                    
                    # Look for Flutter-specific activities and metadata
                    flutter_manifest_patterns = [
                        'io.flutter.embedding.android.FlutterActivity',
                        'io.flutter.app.FlutterApplication',
                        'io.flutter.embedding.android.FlutterFragmentActivity',
                        'flutterEmbedding',
                        'io.flutter.embedding.engine.dart.DartExecutor'
                    ]
                    
                    for pattern in flutter_manifest_patterns:
                        if pattern in manifest_content:
                            flutter_indicators.append(pattern)
            except Exception:
                # Fallback: simple binary search in AndroidManifest.xml
                import zipfile
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    try:
                        manifest_data = zf.read('AndroidManifest.xml')
                        for pattern in [b'flutter', b'Flutter']:
                            if pattern in manifest_data:
                                flutter_indicators.append(pattern.decode('utf-8', errors='ignore'))
                    except Exception:
                        pass
        
        except Exception as e:
            self.logger.error(f"Flutter manifest check failed: {e}")
        
        return flutter_indicators
    
    def _check_flutter_version_strings(self, package_name: str) -> List[str]:
        """Check for Flutter engine version strings."""
        flutter_versions = []
        try:
            apk_path = self._get_apk_path_from_package(package_name)
            if not apk_path or not Path(apk_path).exists():
                return flutter_versions
            
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # Check for version information in native libraries
                for file_info in zf.filelist:
                    if 'libflutter.so' in file_info.filename:
                        try:
                            lib_data = zf.read(file_info.filename)
                            # Look for version strings (simple pattern matching)
                            if b'Flutter' in lib_data and b'Engine' in lib_data:
                                flutter_versions.append('Flutter Engine detected in native library')
                        except Exception:
                            continue
        
        except Exception as e:
            self.logger.error(f"Flutter version check failed: {e}")
        
        return flutter_versions
    
    def _analyze_apk_metrics(self, package_name: str) -> Dict[str, Any]:
        """Analyze APK metrics for size and complexity assessment."""
        metrics = {
            'file_size_mb': 0.0,
            'dex_file_count': 0,
            'native_lib_count': 0,
            'resource_file_count': 0,
            'assets_size_mb': 0.0,
            'estimated_method_count': 0
        }
        
        try:
            apk_path = self._get_apk_path_from_package(package_name)
            if not apk_path or not Path(apk_path).exists():
                return metrics
            
            # Get file size
            file_size = Path(apk_path).stat().st_size
            metrics['file_size_mb'] = file_size / (1024 * 1024)
            
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as zf:
                assets_size = 0
                
                for file_info in zf.filelist:
                    filename = file_info.filename
                    file_size = file_info.file_size
                    
                    # Count DEX files
                    if filename.endswith('.dex'):
                        metrics['dex_file_count'] += 1
                        # Estimate method count (rough approximation)
                        metrics['estimated_method_count'] += file_size // 100  # Very rough estimate
                    
                    # Count native libraries
                    elif '/lib/' in filename and filename.endswith('.so'):
                        metrics['native_lib_count'] += 1
                    
                    # Count resource files
                    elif filename.startswith('res/') or filename.startswith('resources.'):
                        metrics['resource_file_count'] += 1
                    
                    # Calculate assets size
                    elif filename.startswith('assets/'):
                        assets_size += file_size
                
                metrics['assets_size_mb'] = assets_size / (1024 * 1024)
        
        except Exception as e:
            self.logger.error(f"APK metrics analysis failed: {e}")
        
        return metrics
    
    def _get_apk_path_from_package(self, package_name: str) -> Optional[str]:
        """Get APK file path from package name."""
        try:
            # Try to get APK path from the analysis context
            if hasattr(self, 'apk_ctx') and hasattr(self.apk_ctx, 'apk_path'):
                return str(self.apk_ctx.apk_path)
            
            # Try to find APK file in common locations
            common_paths = [
                f"apks/{package_name}.apk",
                f"samples/{package_name}.apk",
                f"{package_name}.apk"
            ]
            
            for path in common_paths:
                if Path(path).exists():
                    return path
            
            # If package_name is already a path
            if Path(package_name).exists() and package_name.endswith('.apk'):
                return package_name
            
            return None
            
        except Exception as e:
            self.logger.error(f"APK path resolution failed: {e}")
            return None
    
    def _assess_system_capabilities(self) -> Dict[str, bool]:
        """Assess available system capabilities."""
        return {
            "drozer": self._quick_device_check(),
            "frida": self._check_frida_availability(),
            "devices": self._quick_device_check()
        }
    
    def _get_fallback_drozer_manager(self, package_name: str) -> UnifiedDrozerManager:
        """Get fallback drozer manager for error cases."""
        config = AnalysisManagerConfig(
            package_name=package_name,
            strategy="static",
            enable_monitoring=False
        )
        return UnifiedDrozerManager(config)
    
    def _get_fallback_frida_manager(self, package_name: str) -> UnifiedFridaManager:
        """Get fallback Frida manager for error cases."""
        config = AnalysisManagerConfig(
            package_name=package_name,
            strategy="static_fallback",
            enable_monitoring=False
        )
        return UnifiedFridaManager(config)
    
    def cleanup_managers(self) -> None:
        """Clean up all active managers."""
        for manager_id, manager in self.active_managers.items():
            try:
                if hasattr(manager, 'cleanup'):
                    manager.cleanup()
                self.logger.info(f"Cleaned up manager: {manager_id}")
            except Exception as e:
                self.logger.warning(f"Failed to cleanup manager {manager_id}: {e}")
        
        self.active_managers.clear()
        self.logger.info("All managers cleaned up")

# Global instance
_unified_analysis_manager = None

def get_unified_analysis_manager() -> UnifiedAnalysisManager:
    """Get global unified analysis manager instance."""
    global _unified_analysis_manager
    if _unified_analysis_manager is None:
        _unified_analysis_manager = UnifiedAnalysisManager()
    return _unified_analysis_manager

# Convenience functions for common use cases
def get_drozer_manager(package_name: str, strategy: str = "auto") -> UnifiedDrozerManager:
    """Get optimized drozer manager for package."""
    manager = get_unified_analysis_manager()
    return manager.get_drozer_manager(package_name, strategy)

def get_frida_manager(package_name: str, strategy: str = "auto") -> UnifiedFridaManager:
    """Get optimized Frida manager for package."""
    manager = get_unified_analysis_manager()
    return manager.get_frida_manager(package_name, strategy)

def get_static_manager(package_name: str, strategy: str = "auto") -> UnifiedStaticManager:
    """Get optimized static analysis manager for package."""
    manager = get_unified_analysis_manager()
    return manager.get_static_manager(package_name, strategy)

def get_dynamic_manager(package_name: str, strategy: str = "auto") -> UnifiedDynamicManager:
    """Get optimized dynamic analysis manager for package."""
    manager = get_unified_analysis_manager()
    return manager.get_dynamic_manager(package_name, strategy)

def get_hybrid_manager(package_name: str, strategy: str = "auto") -> UnifiedHybridManager:
    """Get optimized hybrid analysis manager for package."""
    manager = get_unified_analysis_manager()
    return manager.get_hybrid_manager(package_name, strategy)

# Export public interface
__all__ = [
    "UnifiedAnalysisManager",
    "ManagerType",
    "UnifiedManagerConfig",
    "get_unified_analysis_manager",
    "get_drozer_manager",
    "get_frida_manager", 
    "get_static_manager",
    "get_dynamic_manager",
    "get_hybrid_manager"
] 
#!/usr/bin/env python3
"""
MASTG Plugin Integration Manager Module

Manages integration with existing AODS plugins for MASTG test execution.
Provides dynamic plugin discovery, mapping, and execution orchestration.

Features:
- Dynamic plugin discovery and loading
- Plugin availability checking and validation
- Timeout-protected plugin execution
- Error handling and fallback mechanisms
- Plugin performance monitoring
- Configuration-based plugin selection
"""

import importlib
import logging
import threading
import time
from typing import Dict, List, Optional, Any, Callable, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from rich.text import Text

from .data_structures import MASTGConfiguration, PluginAvailabilityInfo

class PluginIntegrationManager:
    """
    Manages integration with existing AODS plugins for MASTG testing.
    
    Provides dynamic plugin discovery, availability checking, and execution
    orchestration with comprehensive error handling and performance monitoring.
    """
    
    def __init__(self, config: MASTGConfiguration):
        """Initialize the plugin integration manager."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Plugin registry
        self._available_plugins: Dict[str, Any] = {}
        self._plugin_info: Dict[str, PluginAvailabilityInfo] = {}
        self._import_errors: List[str] = []
        
        # Performance tracking
        self._execution_times: Dict[str, List[float]] = {}
        self._plugin_lock = threading.RLock()
        
        # Initialize plugin discovery
        self._discover_plugins()
        self._build_plugin_mapping()
        
        self.logger.info(f"Plugin Integration Manager initialized with {len(self._available_plugins)} plugins")
    
    def _discover_plugins(self):
        """Discover and load available AODS plugins."""
        plugin_modules = [
            # Cryptography plugins
            ("cryptography_tests", "plugins.cryptography_tests"),
            ("advanced_cryptography_tests", "plugins.advanced_cryptography_tests"),
            
            # Authentication plugins
            ("authentication_security_analysis", "plugins.authentication_security_analysis"),
            
            # Network security plugins
            ("enhanced_network_security_analysis", "plugins.enhanced_network_security_analysis"),
            ("advanced_ssl_tls_analyzer", "plugins.advanced_ssl_tls_analyzer"),
            ("apk_signing_certificate_analyzer", "plugins.apk_signing_certificate_analyzer"),
            
            # Platform security plugins
            ("improper_platform_usage", "plugins.improper_platform_usage"),
            
            # Storage security plugins
            ("insecure_data_storage", "plugins.insecure_data_storage"),
            ("enhanced_data_storage_analyzer", "plugins.enhanced_data_storage_analyzer"),
            
            # Code analysis plugins
            ("native_binary_analysis", "plugins.native_binary_analysis"),
            
            # Anti-tampering plugins
            ("anti_tampering_analysis", "plugins.anti_tampering_analysis"),
            ("enhanced_root_detection_bypass_analyzer", "plugins.enhanced_root_detection_bypass_analyzer"),
            
            # Dynamic analysis plugins
            ("frida_dynamic_analysis", "plugins.frida_dynamic_analysis"),
            
            # Additional security plugins
            ("attack_surface_analysis", "plugins.attack_surface_analysis"),
            ("traversal_vulnerabilities", "plugins.traversal_vulnerabilities"),
            ("webview_security_analysis", "plugins.webview_security_analysis"),
            ("external_service_analysis", "plugins.external_service_analysis"),
        ]
        
        for plugin_name, module_path in plugin_modules:
            self._load_plugin(plugin_name, module_path)
        
        self.logger.info(f"Plugin discovery completed: {len(self._available_plugins)} available, "
                        f"{len(self._import_errors)} errors")
    
    def _load_plugin(self, plugin_name: str, module_path: str):
        """Load a single plugin with error handling."""
        try:
            # Import the plugin module
            plugin_module = importlib.import_module(module_path)
            
            # Validate plugin interface
            if not hasattr(plugin_module, 'run'):
                self.logger.warning(f"Plugin {plugin_name} missing 'run' function")
                return
            
            # Store plugin reference
            self._available_plugins[plugin_name] = plugin_module
            
            # Create plugin info
            plugin_info = PluginAvailabilityInfo(
                plugin_name=plugin_name,
                is_available=True,
                version=getattr(plugin_module, '__version__', 'unknown'),
                capabilities=self._detect_plugin_capabilities(plugin_module)
            )
            self._plugin_info[plugin_name] = plugin_info
            
            self.logger.debug(f"Successfully loaded plugin: {plugin_name}")
            
        except ImportError as e:
            error_msg = f"Failed to import {plugin_name}: {e}"
            self._import_errors.append(error_msg)
            
            # Create unavailable plugin info
            plugin_info = PluginAvailabilityInfo(
                plugin_name=plugin_name,
                is_available=False,
                load_error=str(e)
            )
            self._plugin_info[plugin_name] = plugin_info
            
            self.logger.debug(f"Plugin {plugin_name} not available: {e}")
            
        except Exception as e:
            error_msg = f"Error loading {plugin_name}: {e}"
            self._import_errors.append(error_msg)
            self.logger.error(error_msg, exc_info=True)
    
    def _detect_plugin_capabilities(self, plugin_module: Any) -> List[str]:
        """Detect capabilities of a plugin module."""
        capabilities = []
        
        # Check for common plugin functions
        if hasattr(plugin_module, 'run'):
            capabilities.append('basic_analysis')
        if hasattr(plugin_module, 'run_plugin'):
            capabilities.append('enhanced_analysis')
        if hasattr(plugin_module, 'analyze'):
            capabilities.append('direct_analysis')
        if hasattr(plugin_module, 'get_vulnerabilities'):
            capabilities.append('vulnerability_detection')
        if hasattr(plugin_module, 'generate_report'):
            capabilities.append('report_generation')
        
        # Check for specific analysis types based on module attributes
        module_str = str(plugin_module)
        if 'crypto' in module_str.lower():
            capabilities.append('cryptography_analysis')
        if 'network' in module_str.lower():
            capabilities.append('network_analysis')
        if 'auth' in module_str.lower():
            capabilities.append('authentication_analysis')
        if 'storage' in module_str.lower():
            capabilities.append('storage_analysis')
        if 'platform' in module_str.lower():
            capabilities.append('platform_analysis')
        if 'frida' in module_str.lower():
            capabilities.append('dynamic_analysis')
        
        return capabilities
    
    def _build_plugin_mapping(self):
        """Build comprehensive plugin mapping for MASTG tests."""
        self._plugin_mapping = {
            # Cryptography analysis
            "cryptography_tests": self._available_plugins.get("cryptography_tests"),
            "advanced_cryptography_tests": self._available_plugins.get("advanced_cryptography_tests"),
            
            # Authentication analysis
            "authentication_security_analysis": self._available_plugins.get("authentication_security_analysis"),
            
            # Network security analysis
            "enhanced_network_security_analysis": self._available_plugins.get("enhanced_network_security_analysis"),
            "advanced_ssl_tls_analyzer": self._available_plugins.get("advanced_ssl_tls_analyzer"),
            "apk_signing_certificate_analyzer": self._available_plugins.get("apk_signing_certificate_analyzer"),
            
            # Platform security analysis
            "improper_platform_usage": self._available_plugins.get("improper_platform_usage"),
            
            # Storage security analysis
            "insecure_data_storage": self._available_plugins.get("insecure_data_storage"),
            "enhanced_data_storage_analyzer": self._available_plugins.get("enhanced_data_storage_analyzer"),
            
            # Code analysis
            "native_binary_analysis": self._available_plugins.get("native_binary_analysis"),
            
            # Anti-tampering analysis
            "anti_tampering_analysis": self._available_plugins.get("anti_tampering_analysis"),
            "enhanced_root_detection_bypass_analyzer": self._available_plugins.get("enhanced_root_detection_bypass_analyzer"),
            
            # Dynamic analysis
            "frida_dynamic_analysis": self._available_plugins.get("frida_dynamic_analysis"),
            
            # Additional analysis
            "attack_surface_analysis": self._available_plugins.get("attack_surface_analysis"),
            "traversal_vulnerabilities": self._available_plugins.get("traversal_vulnerabilities"),
            "webview_security_analysis": self._available_plugins.get("webview_security_analysis"),
            "external_service_analysis": self._available_plugins.get("external_service_analysis"),
        }
        
        # Remove None entries
        self._plugin_mapping = {k: v for k, v in self._plugin_mapping.items() if v is not None}
    
    def is_plugin_available(self, plugin_name: str) -> bool:
        """Check if a specific plugin is available."""
        return plugin_name in self._available_plugins
    
    def get_plugin_availability(self) -> Dict[str, bool]:
        """Get availability status of all tracked plugins."""
        return {name: info.is_available for name, info in self._plugin_info.items()}
    
    def get_plugin_info(self, plugin_name: str) -> Optional[PluginAvailabilityInfo]:
        """Get detailed information about a specific plugin."""
        return self._plugin_info.get(plugin_name)
    
    def get_available_plugins(self) -> List[str]:
        """Get list of available plugin names."""
        return list(self._available_plugins.keys())
    
    def execute_plugin(self, plugin_name: str, apk_ctx: Any, timeout: int = 30) -> Tuple[str, Union[str, Text]]:
        """
        Execute a plugin with timeout protection and error handling.
        
        Args:
            plugin_name: Name of the plugin to execute
            apk_ctx: APK analysis context
            timeout: Execution timeout in seconds
            
        Returns:
            Tuple of (analysis_type, result)
            
        Raises:
            RuntimeError: If plugin is not available
            TimeoutError: If execution times out
        """
        if not self.is_plugin_available(plugin_name):
            raise RuntimeError(f"Plugin {plugin_name} is not available")
        
        plugin_module = self._available_plugins[plugin_name]
        start_time = time.time()
        
        try:
            # Execute plugin with timeout protection
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._execute_plugin_function, plugin_module, apk_ctx)
                
                try:
                    result = future.result(timeout=timeout)
                    execution_time = time.time() - start_time
                    
                    # Record performance metrics
                    self._record_execution_time(plugin_name, execution_time)
                    
                    self.logger.debug(f"Plugin {plugin_name} executed successfully in {execution_time:.2f}s")
                    return result
                    
                except FutureTimeoutError:
                    self.logger.error(f"Plugin {plugin_name} execution timed out after {timeout}s")
                    raise TimeoutError(f"Plugin {plugin_name} execution timed out")
        
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Plugin {plugin_name} execution failed after {execution_time:.2f}s: {e}")
            raise
    
    def _execute_plugin_function(self, plugin_module: Any, apk_ctx: Any) -> Tuple[str, Union[str, Text]]:
        """Execute the plugin's main function."""
        # Try different plugin entry points in order of preference
        entry_points = ['run_plugin', 'run', 'analyze']
        
        for entry_point in entry_points:
            if hasattr(plugin_module, entry_point):
                plugin_func = getattr(plugin_module, entry_point)
                
                try:
                    result = plugin_func(apk_ctx)
                    
                    # Ensure result is in expected format
                    if isinstance(result, tuple) and len(result) == 2:
                        return result
                    else:
                        # Wrap single result in tuple
                        plugin_name = getattr(plugin_module, '__name__', 'Unknown Plugin')
                        return (plugin_name, result)
                        
                except Exception as e:
                    self.logger.error(f"Plugin function {entry_point} failed: {e}")
                    continue
        
        raise RuntimeError(f"No valid entry point found in plugin {plugin_module}")
    
    def _record_execution_time(self, plugin_name: str, execution_time: float):
        """Record execution time for performance monitoring."""
        with self._plugin_lock:
            if plugin_name not in self._execution_times:
                self._execution_times[plugin_name] = []
            
            self._execution_times[plugin_name].append(execution_time)
            
            # Keep only last 10 execution times
            if len(self._execution_times[plugin_name]) > 10:
                self._execution_times[plugin_name] = self._execution_times[plugin_name][-10:]
            
            # Update plugin performance rating
            self._update_plugin_performance_rating(plugin_name)
    
    def _update_plugin_performance_rating(self, plugin_name: str):
        """Update plugin performance rating based on execution times."""
        if plugin_name not in self._execution_times:
            return
        
        times = self._execution_times[plugin_name]
        avg_time = sum(times) / len(times)
        
        # Rate performance based on average execution time
        if avg_time < 5:
            rating = "EXCELLENT"
        elif avg_time < 15:
            rating = "GOOD"
        elif avg_time < 30:
            rating = "FAIR"
        else:
            rating = "POOR"
        
        # Update plugin info
        if plugin_name in self._plugin_info:
            self._plugin_info[plugin_name].performance_rating = rating
    
    def get_plugin_performance_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get performance metrics for all plugins."""
        metrics = {}
        
        with self._plugin_lock:
            for plugin_name, times in self._execution_times.items():
                if times:
                    metrics[plugin_name] = {
                        "average_time": sum(times) / len(times),
                        "min_time": min(times),
                        "max_time": max(times),
                        "execution_count": len(times),
                        "performance_rating": self._plugin_info.get(plugin_name, PluginAvailabilityInfo(plugin_name, False)).performance_rating
                    }
        
        return metrics
    
    def validate_plugin_compatibility(self, plugin_name: str) -> List[str]:
        """Validate plugin compatibility and return list of issues."""
        issues = []
        
        if not self.is_plugin_available(plugin_name):
            issues.append(f"Plugin {plugin_name} is not available")
            return issues
        
        plugin_module = self._available_plugins[plugin_name]
        
        # Check for required functions
        required_functions = ['run']
        for func_name in required_functions:
            if not hasattr(plugin_module, func_name):
                issues.append(f"Plugin {plugin_name} missing required function: {func_name}")
        
        # Check plugin info
        plugin_info = self._plugin_info.get(plugin_name)
        if plugin_info and plugin_info.load_error:
            issues.append(f"Plugin {plugin_name} has load error: {plugin_info.load_error}")
        
        return issues
    
    def get_plugin_mapping_suggestions(self, test_category: str) -> List[str]:
        """Get plugin suggestions based on test category."""
        category_mappings = {
            "CRYPTO": ["cryptography_tests", "advanced_cryptography_tests"],
            "AUTH": ["authentication_security_analysis"],
            "NETWORK": ["enhanced_network_security_analysis", "advanced_ssl_tls_analyzer", "apk_signing_certificate_analyzer"],
            "PLATFORM": ["improper_platform_usage", "attack_surface_analysis"],
            "CODE": ["native_binary_analysis"],
            "RESILIENCE": ["anti_tampering_analysis", "enhanced_root_detection_bypass_analyzer"],
            "STORAGE": ["insecure_data_storage", "enhanced_data_storage_analyzer"],
            "GENERAL": ["frida_dynamic_analysis", "webview_security_analysis"]
        }
        
        suggested_plugins = category_mappings.get(test_category, [])
        
        # Filter to only available plugins
        available_suggestions = [plugin for plugin in suggested_plugins 
                               if self.is_plugin_available(plugin)]
        
        return available_suggestions
    
    def execute_plugin_batch(self, plugin_requests: List[Tuple[str, Any]], 
                           max_concurrent: int = 3) -> Dict[str, Tuple[str, Union[str, Text]]]:
        """
        Execute multiple plugins concurrently.
        
        Args:
            plugin_requests: List of (plugin_name, apk_ctx) tuples
            max_concurrent: Maximum concurrent plugin executions
            
        Returns:
            Dictionary mapping plugin names to results
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            # Submit all plugin executions
            future_to_plugin = {}
            for plugin_name, apk_ctx in plugin_requests:
                if self.is_plugin_available(plugin_name):
                    future = executor.submit(self.execute_plugin, plugin_name, apk_ctx, self.config.plugin_timeout)
                    future_to_plugin[future] = plugin_name
                else:
                    # Record unavailable plugins
                    results[plugin_name] = (plugin_name, f"Plugin {plugin_name} not available")
            
            # Collect results
            for future in future_to_plugin:
                plugin_name = future_to_plugin[future]
                try:
                    result = future.result(timeout=1)  # Quick result retrieval
                    results[plugin_name] = result
                except Exception as e:
                    self.logger.error(f"Batch plugin execution failed for {plugin_name}: {e}")
                    results[plugin_name] = (plugin_name, f"Execution failed: {str(e)}")
        
        return results
    
    def cleanup_plugins(self):
        """Cleanup plugin resources and clear caches."""
        with self._plugin_lock:
            self._execution_times.clear()
            
        self.logger.info("Plugin resources cleaned up")
    
    def get_import_errors(self) -> List[str]:
        """Get list of plugin import errors."""
        return self._import_errors.copy()
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a specific plugin module."""
        try:
            if plugin_name in self._available_plugins:
                # Get original module path
                plugin_module = self._available_plugins[plugin_name]
                module_path = plugin_module.__name__
                
                # Reload the module
                importlib.reload(plugin_module)
                
                # Update capabilities
                plugin_info = self._plugin_info.get(plugin_name)
                if plugin_info:
                    plugin_info.capabilities = self._detect_plugin_capabilities(plugin_module)
                
                self.logger.info(f"Successfully reloaded plugin: {plugin_name}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to reload plugin {plugin_name}: {e}")
            
        return False
    
    def get_plugin_statistics(self) -> Dict[str, Any]:
        """Get comprehensive plugin statistics."""
        available_count = len(self._available_plugins)
        total_tracked = len(self._plugin_info)
        error_count = len(self._import_errors)
        
        return {
            "total_plugins_tracked": total_tracked,
            "available_plugins": available_count,
            "unavailable_plugins": total_tracked - available_count,
            "import_errors": error_count,
            "plugins_with_performance_data": len(self._execution_times),
            "average_plugin_capabilities": sum(len(info.capabilities) for info in self._plugin_info.values()) / total_tracked if total_tracked > 0 else 0
        } 
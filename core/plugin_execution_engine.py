#!/usr/bin/env python3
"""
Plugin Execution Engine with MASVS Integration

This engine ensures that all plugin executions automatically apply MASVS controls
to vulnerability findings and maintain compliance tracking throughout execution.
"""

import logging
import time
import asyncio
from typing import Dict, List, Any, Optional, Callable, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from core.enhanced_vulnerability_processor import process_vulnerabilities_with_masvs
from core.masvs_tagging_service import MASVSTaggingService

logger = logging.getLogger(__name__)

class MASVSIntegratedPluginEngine:
    """
    Plugin execution engine with automatic MASVS integration.
    
    This engine ensures that every plugin execution results in properly
    MASVS-tagged vulnerabilities for compliance tracking.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the MASVS-integrated plugin engine."""
        self.config = config or {}
        self.masvs_service = MASVSTaggingService()
        
        # Plugin registry
        self.registered_plugins = {}
        
        # Execution statistics
        self.execution_stats = {
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "masvs_integrations": 0,
            "total_vulnerabilities_processed": 0
        }
        
        # Plugin-to-MASVS mapping for automatic tagging
        self.plugin_masvs_mapping = {
            # Storage & Data
            "secret_extractor": ["MASVS-STORAGE-1", "MASVS-STORAGE-2"],
            "data_storage_analyzer": ["MASVS-STORAGE-1"],
            "database_security_analyzer": ["MASVS-STORAGE-2"],
            "enhanced_data_storage_analyzer": ["MASVS-STORAGE-1", "MASVS-STORAGE-2"],
            
            # Cryptography
            "cryptographic_security_analyzer": ["MASVS-CRYPTO-1", "MASVS-CRYPTO-2"],
            "key_management_analyzer": ["MASVS-CRYPTO-2"],
            "ssl_security_analyzer": ["MASVS-CRYPTO-1"],
            "runtime_decryption_analysis": ["MASVS-CRYPTO-1", "MASVS-CRYPTO-2", "MASVS-RESILIENCE-2"],
            
            # Authentication
            "authentication_analyzer": ["MASVS-AUTH-1", "MASVS-AUTH-2"],
            "authentication_security_analysis": ["MASVS-AUTH-1", "MASVS-AUTH-2"],
            "session_management_analyzer": ["MASVS-AUTH-3"],
            "biometric_security_analyzer": ["MASVS-AUTH-2"],
            
            # Network
            "network_security_analyzer": ["MASVS-NETWORK-1", "MASVS-NETWORK-2"],
            "network_cleartext_traffic_analyzer": ["MASVS-NETWORK-1"],
            "certificate_pinning_analyzer": ["MASVS-NETWORK-2"],
            "network_pii_traffic_analyzer": ["MASVS-NETWORK-1"],
            
            # Platform
            "permissions_analyzer": ["MASVS-PLATFORM-1"],
            "intent_security_analyzer": ["MASVS-PLATFORM-1"],
            "webview_security_analyzer": ["MASVS-PLATFORM-2"],
            "enhanced_manifest_analysis": ["MASVS-PLATFORM-1", "MASVS-PLATFORM-2"],
            "deep_link_analyzer": ["MASVS-PLATFORM-3"],
            
            # Code Quality
            "code_quality_analyzer": ["MASVS-CODE-1", "MASVS-CODE-2"],
            "code_quality_injection_analysis": ["MASVS-CODE-1"],
            "anti_debugging_analyzer": ["MASVS-CODE-3"],
            "obfuscation_analyzer": ["MASVS-CODE-4"],
            "dynamic_code_analyzer": ["MASVS-CODE-4"],
            
            # Resilience
            "anti_tampering_analyzer": ["MASVS-RESILIENCE-1"],
            "root_detection_analyzer": ["MASVS-RESILIENCE-2"],
            "emulator_detection_analyzer": ["MASVS-RESILIENCE-2"],
            
            # Privacy
            "privacy_analyzer": ["MASVS-PRIVACY-1", "MASVS-PRIVACY-2"],
            "data_minimization_analyzer": ["MASVS-PRIVACY-2"],
            "consent_analyzer": ["MASVS-PRIVACY-3"],
            "tracking_analyzer": ["MASVS-PRIVACY-4"]
        }
        
        logger.info("MASVS-integrated plugin engine initialized")
    
    def register_plugin(self, plugin_name: str, plugin_function: Callable, 
                       masvs_controls: Optional[List[str]] = None):
        """Register a plugin with optional MASVS control override."""
        self.registered_plugins[plugin_name] = {
            "function": plugin_function,
            "masvs_controls": masvs_controls or self.plugin_masvs_mapping.get(plugin_name, []),
            "registered_at": datetime.now().isoformat()
        }
        
        logger.info(f"Registered plugin: {plugin_name} with MASVS controls: {masvs_controls}")
    
    def execute_plugin_with_masvs(self, plugin_name: str, *args, **kwargs) -> Dict[str, Any]:
        """Execute a plugin with automatic MASVS integration."""
        start_time = time.time()
        
        logger.info(f"🔌 Executing plugin: {plugin_name} with MASVS integration")
        
        try:
            # **MANIFEST ANALYSIS FIX**: Force re-registration for enhanced_manifest_analysis to use structured data
            if plugin_name == "enhanced_manifest_analysis" and plugin_name in self.registered_plugins:
                logger.info(f"🔄 Forcing re-registration of {plugin_name} for structured data")
                del self.registered_plugins[plugin_name]
            
            # Get plugin information
            plugin_info = self.registered_plugins.get(plugin_name)
            if not plugin_info:
                # Try to auto-register common plugins
                plugin_info = self._auto_register_plugin(plugin_name)
            
            if not plugin_info:
                raise ValueError(f"Plugin {plugin_name} not registered and cannot be auto-registered")
            
            # Execute the plugin
            plugin_result = plugin_info["function"](*args, **kwargs)
            
            # Process the result with MASVS integration
            enhanced_result = self._integrate_masvs_with_result(
                plugin_name, plugin_result, plugin_info["masvs_controls"]
            )
            
            # Update statistics
            self.execution_stats["total_executions"] += 1
            self.execution_stats["successful_executions"] += 1
            self.execution_stats["masvs_integrations"] += 1
            
            execution_time = time.time() - start_time
            
            logger.info(f"✅ Plugin {plugin_name} executed successfully in {execution_time:.2f}s with MASVS integration")
            
            return {
                "plugin_name": plugin_name,
                "execution_status": "success",
                "execution_time": execution_time,
                "masvs_integrated": True,
                "masvs_controls_applied": plugin_info["masvs_controls"],
                "result": enhanced_result
            }
            
        except Exception as e:
            self.execution_stats["total_executions"] += 1
            self.execution_stats["failed_executions"] += 1
            
            logger.error(f"❌ Plugin {plugin_name} execution failed: {e}")
            
            return {
                "plugin_name": plugin_name,
                "execution_status": "failed",
                "execution_time": time.time() - start_time,
                "masvs_integrated": False,
                "error": str(e),
                "result": None
            }
    
    def _auto_register_plugin(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Attempt to auto-register a plugin by importing it."""
        try:
            # Try to import the plugin
            module_path = f"plugins.{plugin_name}"
            
            # Import and get the main function
            import importlib
            module = importlib.import_module(module_path)
            
            # Look for common function names
            plugin_function = None
            
            # **MANIFEST ANALYSIS FIX**: Use structured data method for enhanced_manifest_analysis
            if plugin_name == "enhanced_manifest_analysis" and hasattr(module, "run_with_structured_data"):
                plugin_function = getattr(module, "run_with_structured_data")
                logger.info(f"🔧 Using structured data method for {plugin_name}")
            else:
                for func_name in ["run", "analyze", "execute", "main"]:
                    if hasattr(module, func_name):
                        plugin_function = getattr(module, func_name)
                        break
            
            if plugin_function:
                masvs_controls = self.plugin_masvs_mapping.get(plugin_name, [])
                self.register_plugin(plugin_name, plugin_function, masvs_controls)
                return self.registered_plugins[plugin_name]
            
        except Exception as e:
            logger.debug(f"Failed to auto-register plugin {plugin_name}: {e}")
        
        return None
    
    def _integrate_masvs_with_result(self, plugin_name: str, plugin_result: Any, 
                                   masvs_controls: List[str]) -> Dict[str, Any]:
        """Integrate MASVS controls with plugin result."""
        
        # Normalize plugin result to standard format
        normalized_result = self._normalize_plugin_result(plugin_name, plugin_result)
        
        # Extract vulnerabilities from result
        vulnerabilities = self._extract_vulnerabilities_from_result(normalized_result)
        
        # Apply MASVS controls to vulnerabilities
        if vulnerabilities:
            enhanced_vulnerabilities = self._apply_masvs_to_vulnerabilities(
                vulnerabilities, plugin_name, masvs_controls
            )
            
            # Update the result with enhanced vulnerabilities
            normalized_result["vulnerabilities"] = enhanced_vulnerabilities
            normalized_result["masvs_integration"] = {
                "controls_applied": masvs_controls,
                "vulnerabilities_enhanced": len(enhanced_vulnerabilities),
                "plugin_name": plugin_name
            }
            
            self.execution_stats["total_vulnerabilities_processed"] += len(enhanced_vulnerabilities)
        
        return normalized_result
    
    def _normalize_plugin_result(self, plugin_name: str, plugin_result: Any) -> Dict[str, Any]:
        """Normalize plugin result to standard format."""
        
        if isinstance(plugin_result, dict):
            return plugin_result
        elif isinstance(plugin_result, list):
            return {
                "plugin_name": plugin_name,
                "vulnerabilities": plugin_result,
                "status": "completed"
            }
        elif isinstance(plugin_result, tuple) and len(plugin_result) == 2:
            title, content = plugin_result
            return {
                "plugin_name": plugin_name,
                "title": title,
                "content": content,
                "status": "completed"
            }
        else:
            return {
                "plugin_name": plugin_name,
                "raw_result": str(plugin_result),
                "status": "completed"
            }
    
    def _extract_vulnerabilities_from_result(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from normalized plugin result."""
        
        vulnerabilities = []
        
        # Direct vulnerabilities list
        if "vulnerabilities" in result and isinstance(result["vulnerabilities"], list):
            vulnerabilities.extend(result["vulnerabilities"])
        
        # Findings list (alternative naming)
        if "findings" in result and isinstance(result["findings"], list):
            vulnerabilities.extend(result["findings"])
        
        # Convert raw content to vulnerability if needed
        if not vulnerabilities and ("content" in result or "raw_result" in result):
            content = result.get("content") or result.get("raw_result", "")
            if content and len(str(content)) > 10:  # Minimum content threshold
                vulnerabilities.append({
                    "title": result.get("title", f"{result.get('plugin_name', 'Unknown')} Finding"),
                    "description": str(content)[:500],  # Limit description length
                    "severity": "INFO",
                    "confidence": 0.7,
                    "plugin_name": result.get("plugin_name", "unknown")
                })
        
        return vulnerabilities
    
    def _apply_masvs_to_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]], 
                                      plugin_name: str, masvs_controls: List[str]) -> List[Dict[str, Any]]:
        """Apply MASVS controls to vulnerabilities."""
        
        enhanced_vulnerabilities = []
        
        for vuln in vulnerabilities:
            enhanced_vuln = vuln.copy()
            
            # Add plugin information
            enhanced_vuln["plugin_name"] = plugin_name
            
            # Apply MASVS controls from plugin mapping
            if masvs_controls:
                existing_controls = enhanced_vuln.get("masvs_controls", [])
                all_controls = list(set(existing_controls + masvs_controls))
                enhanced_vuln["masvs_controls"] = all_controls
                
                # Set MASVS category based on controls
                if all_controls:
                    primary_category = self._determine_primary_masvs_category(all_controls)
                    enhanced_vuln["masvs_category"] = primary_category
            
            # Apply automatic MASVS tagging based on content
            tagged_vuln = self.masvs_service._apply_masvs_tags_to_vulnerability(enhanced_vuln)
            
            enhanced_vulnerabilities.append(tagged_vuln)
        
        return enhanced_vulnerabilities
    
    def _determine_primary_masvs_category(self, controls: List[str]) -> str:
        """Determine primary MASVS category from controls."""
        if not controls:
            return "GENERAL"
        
        # Count categories
        category_counts = {}
        for control in controls:
            if "-" in control:
                category = control.split("-")[1]
                category_counts[category] = category_counts.get(category, 0) + 1
        
        # Return most frequent category
        if category_counts:
            return max(category_counts, key=category_counts.get)
        
        return "GENERAL"
    
    async def execute_plugins_parallel(self, plugin_tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute multiple plugins in parallel with MASVS integration."""
        
        logger.info(f"🚀 Executing {len(plugin_tasks)} plugins in parallel with MASVS integration")
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.config.get("max_workers", 4)) as executor:
            # Submit all plugin tasks
            futures = {}
            for task in plugin_tasks:
                plugin_name = task["plugin_name"]
                args = task.get("args", [])
                kwargs = task.get("kwargs", {})
                
                future = executor.submit(self.execute_plugin_with_masvs, plugin_name, *args, **kwargs)
                futures[future] = plugin_name
            
            # Collect results as they complete
            for future in as_completed(futures):
                plugin_name = futures[future]
                try:
                    result = future.result(timeout=self.config.get("plugin_timeout", 300))
                    results.append(result)
                    
                except Exception as e:
                    logger.error(f"Parallel execution failed for {plugin_name}: {e}")
                    results.append({
                        "plugin_name": plugin_name,
                        "execution_status": "failed",
                        "error": str(e),
                        "masvs_integrated": False
                    })
        
        logger.info(f"✅ Parallel plugin execution completed: {len(results)} results")
        return results
    
    def generate_execution_report(self) -> Dict[str, Any]:
        """Generate comprehensive execution report with MASVS integration status."""
        
        return {
            "execution_statistics": self.execution_stats.copy(),
            "registered_plugins": len(self.registered_plugins),
            "masvs_mappings": len(self.plugin_masvs_mapping),
            "plugin_registry": {
                name: {
                    "masvs_controls": info["masvs_controls"],
                    "registered_at": info["registered_at"]
                }
                for name, info in self.registered_plugins.items()
            },
            "success_rate": (
                self.execution_stats["successful_executions"] / 
                max(1, self.execution_stats["total_executions"])
            ) * 100,
            "masvs_integration_rate": (
                self.execution_stats["masvs_integrations"] / 
                max(1, self.execution_stats["total_executions"])
            ) * 100,
            "report_generated_at": datetime.now().isoformat()
        }
    
    def get_plugin_masvs_mapping(self, plugin_name: str) -> List[str]:
        """Get MASVS controls for a specific plugin."""
        return self.plugin_masvs_mapping.get(plugin_name, [])
    
    def update_plugin_masvs_mapping(self, plugin_name: str, masvs_controls: List[str]):
        """Update MASVS controls for a plugin."""
        self.plugin_masvs_mapping[plugin_name] = masvs_controls
        
        # Update registered plugin if it exists
        if plugin_name in self.registered_plugins:
            self.registered_plugins[plugin_name]["masvs_controls"] = masvs_controls
        
        logger.info(f"Updated MASVS mapping for {plugin_name}: {masvs_controls}")

# Global plugin engine instance
_plugin_engine = None

def get_plugin_engine(config: Dict[str, Any] = None) -> MASVSIntegratedPluginEngine:
    """Get global plugin engine instance."""
    global _plugin_engine
    if _plugin_engine is None:
        _plugin_engine = MASVSIntegratedPluginEngine(config)
    return _plugin_engine

def execute_plugin_with_masvs_integration(plugin_name: str, *args, **kwargs) -> Dict[str, Any]:
    """Convenience function for executing plugins with MASVS integration."""
    engine = get_plugin_engine()
    return engine.execute_plugin_with_masvs(plugin_name, *args, **kwargs) 
    return engine.execute_plugin_with_masvs(plugin_name, *args, **kwargs) 
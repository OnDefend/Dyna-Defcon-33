#!/usr/bin/env python3
"""
AODS Frida-First Dynamic Analysis Integration

This module integrates the Frida-first approach directly into AODS,
replacing unreliable Drozer dependencies with comprehensive Frida-based testing.

Features:
- Direct Frida integration with AODS plugin manager
- Comprehensive security analysis modules
- Real-time vulnerability detection
- Professional confidence calculation
- Evidence-based reporting
"""

import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class FridaDynamicIntegration:
    """Integrates Frida-first dynamic analysis with AODS."""
    
    def __init__(self, config_path: str = "frida_testing_config.json"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.device_id = self.config.get("frida_dynamic_testing", {}).get("device_config", {}).get("target_device")
        self.frida_available = False
        self._check_frida_availability()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load Frida testing configuration."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file not found: {self.config_path}")
                return self._get_default_config()
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default Frida configuration."""
        return {
            "frida_dynamic_testing": {
                "enabled": True,
                "primary_method": True,
                "drozer_fallback": False,
                "analysis_modules": {
                    "ssl_tls_analysis": True,
                    "webview_security": True,
                    "anti_tampering": True,
                    "icc_security": True,
                    "runtime_manipulation": True,
                    "crypto_implementation": True,
                    "network_security": True
                }
            }
        }
    
    def _check_frida_availability(self) -> bool:
        """Check if Frida is available and device is connected."""
        try:
            import frida
            
            if self.device_id:
                device = frida.get_device(self.device_id)
                processes = device.enumerate_processes()
                logger.info(f"✅ Frida available, connected to {device.name} with {len(processes)} processes")
                self.frida_available = True
                return True
            else:
                # **FRIDA RECOVERY FIX**: Provide graceful fallback when no device configured
                logger.info("ℹ️ No target device configured - Frida dynamic analysis will be skipped")
                logger.info("💡 To enable Frida dynamic analysis:")
                logger.info("   1. Install Frida: pip install frida-tools")
                logger.info("   2. Configure target device in frida_testing_config.json")
                logger.info("   3. Ensure Android device/emulator is connected")
                self.frida_available = False
                return False
                
        except ImportError as e:
            # **FRIDA RECOVERY FIX**: Graceful handling when Frida module not installed
            logger.info("ℹ️ Frida module not installed - dynamic analysis will use static analysis only")
            logger.debug("💡 To enable Frida dynamic analysis: pip install frida-tools")
            self.frida_available = False
            return False
        except Exception as e:
            # **FRIDA RECOVERY FIX**: Handle other errors gracefully
            logger.info(f"ℹ️ Frida not available: {str(e)}")
            logger.debug("💡 Check device connection and Frida server status")
            self.frida_available = False
            return False
    
    def create_frida_plugin_config(self, apk_ctx) -> Dict[str, Any]:
        """Create plugin configuration for Frida analysis."""
        if not self.frida_available:
            return {"error": "Frida not available"}
        
        # Get package name with improved fallback logic
        package_name = getattr(apk_ctx, 'package_name', None)
        if not package_name or package_name in ["", "None", "null"]:
            package_name = 'unknown.package'
            self.logger.warning(f"No valid package name found in APK context, using fallback: {package_name}")
        
        config = {
            "package_name": package_name,
            "device_id": self.device_id,
            "comprehensive_analysis": True,
            "timeout_seconds": 300,
            "enable_all_modules": True,
            "analysis_modules": self.config.get("frida_dynamic_testing", {}).get("analysis_modules", {}),
            "real_time_monitoring": True,
            "evidence_collection": True,
            "bypass_detection": True
        }
        
        return config
    
    def run_frida_dynamic_analysis(self, apk_ctx) -> Dict[str, Any]:
        """Run comprehensive Frida dynamic analysis."""
        
        logger.info("🚀 Starting Frida-first dynamic analysis...")
        
        start_time = time.time()
        
        if not self.frida_available:
            return {
                "success": False,
                "error": "Frida not available or device not connected",
                "findings": [],
                "execution_time": 0,
                "frida_first": True
            }
        
        try:
            # Import and run enhanced Frida analyzer
            from plugins.frida_dynamic_analysis.enhanced_frida_analyzer import EnhancedFridaDynamicAnalyzer
            
            # Create configuration
            config = self.create_frida_plugin_config(apk_ctx)
            package_name = config["package_name"]
            
            logger.info(f"📱 Analyzing package: {package_name}")
            
            # Initialize enhanced analyzer
            analyzer = EnhancedFridaDynamicAnalyzer(package_name, config)
            
            # Run comprehensive analysis
            results = analyzer.analyze()
            
            execution_time = time.time() - start_time
            
            # Process results
            findings = self._process_frida_results(results)
            
            logger.info(f"✅ Frida analysis completed in {execution_time:.2f}s with {len(findings)} findings")
            
            return {
                "success": True,
                "findings": findings,
                "execution_time": execution_time,
                "frida_first": True,
                "raw_results": results,
                "device_info": {
                    "device_id": self.device_id,
                    "analysis_modules": list(config["analysis_modules"].keys())
                }
            }
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"❌ Frida analysis failed: {e}")
            
            return {
                "success": False,
                "error": str(e),
                "findings": [],
                "execution_time": execution_time,
                "frida_first": True
            }
    
    def _process_frida_results(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process Frida analysis results into standardized findings."""
        findings = []
        
        if not isinstance(results, dict):
            return findings
        
        # Extract vulnerabilities from results
        vulnerabilities = results.get('vulnerabilities', [])
        if isinstance(vulnerabilities, list):
            for vuln in vulnerabilities:
                if isinstance(vuln, dict):
                    finding = {
                        "type": "dynamic_vulnerability",
                        "title": vuln.get('title', 'Unknown Vulnerability'),
                        "description": vuln.get('description', 'No description available'),
                        "severity": vuln.get('severity', 'MEDIUM'),
                        "confidence": vuln.get('confidence', 0.5),
                        "source": "frida_dynamic_analysis",
                        "category": vuln.get('category', 'security'),
                        "evidence": vuln.get('evidence', {}),
                        "remediation": vuln.get('remediation', 'Review and fix identified issue')
                    }
                    findings.append(finding)
        
        # Extract analysis results
        for analysis_type, analysis_results in results.items():
            if analysis_type != 'vulnerabilities' and isinstance(analysis_results, dict):
                if analysis_results.get('findings'):
                    for finding_data in analysis_results['findings']:
                        finding = {
                            "type": f"dynamic_{analysis_type}",
                            "title": finding_data.get('title', f'{analysis_type} Finding'),
                            "description": finding_data.get('description', ''),
                            "severity": finding_data.get('severity', 'INFO'),
                            "confidence": finding_data.get('confidence', 0.3),
                            "source": "frida_dynamic_analysis",
                            "category": analysis_type,
                            "evidence": finding_data.get('evidence', {})
                        }
                        findings.append(finding)
        
        return findings
    
    def integrate_with_plugin_manager(self, plugin_manager):
        """Integrate Frida-first analysis with AODS plugin manager."""
        
        logger.info("🔧 Integrating Frida-first dynamic analysis with AODS...")
        
        # Add custom Frida plugin runner
        def frida_dynamic_plugin_runner(apk_ctx):
            """Custom plugin runner for Frida dynamic analysis."""
            results = self.run_frida_dynamic_analysis(apk_ctx)
            
            if results["success"]:
                return ("🚀 Frida Dynamic Analysis", {
                    "vulnerabilities": results["findings"],
                    "execution_time": results["execution_time"],
                    "frida_enabled": True,
                    "device_info": results.get("device_info", {}),
                    "total_findings": len(results["findings"])
                })
            else:
                return ("❌ Frida Dynamic Analysis Failed", {
                    "error": results.get("error", "Unknown error"),
                    "execution_time": results["execution_time"],
                    "frida_enabled": False
                })
        
        # Register as priority dynamic analysis plugin
        if hasattr(plugin_manager, 'register_priority_plugin'):
            plugin_manager.register_priority_plugin(
                'frida_dynamic_analysis', 
                frida_dynamic_plugin_runner,
                priority=1  # Highest priority
            )
        
        logger.info("✅ Frida-first integration completed")
        
        return True

def enable_frida_first_analysis(plugin_manager) -> bool:
    """Enable Frida-first dynamic analysis in AODS."""
    
    try:
        # Create integration instance
        frida_integration = FridaDynamicIntegration()
        
        # Check if Frida is available
        if not frida_integration.frida_available:
            logger.warning("❌ Frida not available - cannot enable Frida-first analysis")
            return False
        
        # Integrate with plugin manager
        success = frida_integration.integrate_with_plugin_manager(plugin_manager)
        
        if success:
            logger.info("🎉 Frida-first dynamic analysis enabled successfully!")
            return True
        else:
            logger.error("❌ Failed to enable Frida-first analysis")
            return False
            
    except Exception as e:
        logger.error(f"❌ Frida-first integration failed: {e}")
        return False

# Export main functions
__all__ = [
    'FridaDynamicIntegration',
    'enable_frida_first_analysis'
]
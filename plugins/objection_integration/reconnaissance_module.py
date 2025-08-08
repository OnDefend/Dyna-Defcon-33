#!/usr/bin/env python3
"""
Objection Reconnaissance Module

Uses objection for rapid app exploration and reconnaissance before AODS
comprehensive analysis. Provides intelligent hints for AODS configuration.

Author: AODS Team
Date: January 2025
"""

import json
import logging
import subprocess
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ReconnaissanceResult:
    """Results from objection reconnaissance."""
    package_name: str
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    key_methods: List[str] = field(default_factory=list)
    interesting_strings: List[str] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    crypto_indicators: List[str] = field(default_factory=list)
    network_indicators: List[str] = field(default_factory=list)
    storage_indicators: List[str] = field(default_factory=list)
    aods_hints: Dict[str, Any] = field(default_factory=dict)


class ObjectionReconnaissanceModule:
    """
    Rapid app reconnaissance using objection before AODS analysis.
    
    Provides quick discovery of app structure, components, and potential
    security-relevant areas to optimize AODS configuration and focus.
    """
    
    def __init__(self):
        """Initialize reconnaissance module."""
        self.logger = logging.getLogger(__name__)
        self.objection_available = self._check_objection_availability()
        
        if self.objection_available:
            self.logger.info("✅ Objection Reconnaissance Module initialized")
        else:
            self.logger.warning("⚠️ Objection not available - reconnaissance disabled")
    
    def _check_objection_availability(self) -> bool:
        """Check if objection is available in the system."""
        try:
            result = subprocess.run(['objection', '--version'], 
                                   capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version = result.stdout.strip()
                self.logger.info(f"✅ Objection available: {version}")
                return True
            else:
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    def quick_reconnaissance(self, package_name: str, 
                           timeout: int = 60) -> ReconnaissanceResult:
        """
        Perform rapid reconnaissance of target application.
        
        Args:
            package_name: Target Android application package name
            timeout: Maximum time for reconnaissance in seconds
            
        Returns:
            ReconnaissanceResult: Comprehensive reconnaissance data
        """
        if not self.objection_available:
            self.logger.warning("⚠️ Objection not available - skipping reconnaissance")
            return ReconnaissanceResult(package_name=package_name)
        
        self.logger.info(f"🔍 Starting objection reconnaissance for {package_name}")
        start_time = time.time()
        
        result = ReconnaissanceResult(package_name=package_name)
        
        try:
            # Quick component discovery
            result.activities = self._discover_activities(package_name, timeout//4)
            result.services = self._discover_services(package_name, timeout//4)
            result.receivers = self._discover_receivers(package_name, timeout//4)
            
            # Method and string analysis
            result.key_methods = self._discover_key_methods(package_name, timeout//4)
            result.interesting_strings = self._discover_strings(package_name, timeout//4)
            
            # Security-relevant indicators
            result.crypto_indicators = self._find_crypto_indicators(result)
            result.network_indicators = self._find_network_indicators(result)
            result.storage_indicators = self._find_storage_indicators(result)
            
            # Generate AODS configuration hints
            result.aods_hints = self._generate_aods_hints(result)
            
            elapsed = time.time() - start_time
            self.logger.info(f"✅ Reconnaissance completed in {elapsed:.1f}s")
            
        except Exception as e:
            self.logger.error(f"❌ Reconnaissance failed: {e}")
        
        return result
    
    def _discover_activities(self, package_name: str, timeout: int) -> List[str]:
        """Discover application activities using objection."""
        try:
            cmd = ['objection', '-g', package_name, 'explore', '-c', 
                   'android hooking list activities']
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                   timeout=timeout)
            
            if result.returncode == 0:
                activities = []
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('[') and '.' in line:
                        activities.append(line)
                
                self.logger.info(f"   📱 Found {len(activities)} activities")
                return activities[:20]  # Limit results
            
        except subprocess.TimeoutExpired:
            self.logger.warning("⏱️ Activity discovery timeout")
        except Exception as e:
            self.logger.error(f"❌ Activity discovery failed: {e}")
        
        return []
    
    def _discover_services(self, package_name: str, timeout: int) -> List[str]:
        """Discover application services using objection."""
        try:
            cmd = ['objection', '-g', package_name, 'explore', '-c',
                   'android hooking list services']
            
            result = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=timeout)
            
            if result.returncode == 0:
                services = []
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('[') and '.' in line:
                        services.append(line)
                
                self.logger.info(f"   🔧 Found {len(services)} services")
                return services[:20]
                
        except subprocess.TimeoutExpired:
            self.logger.warning("⏱️ Service discovery timeout")
        except Exception as e:
            self.logger.error(f"❌ Service discovery failed: {e}")
        
        return []
    
    def _discover_receivers(self, package_name: str, timeout: int) -> List[str]:
        """Discover broadcast receivers using objection."""
        try:
            cmd = ['objection', '-g', package_name, 'explore', '-c',
                   'android hooking list receivers']
            
            result = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=timeout)
            
            if result.returncode == 0:
                receivers = []
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('[') and '.' in line:
                        receivers.append(line)
                
                self.logger.info(f"   📡 Found {len(receivers)} receivers")
                return receivers[:20]
                
        except subprocess.TimeoutExpired:
            self.logger.warning("⏱️ Receiver discovery timeout")
        except Exception as e:
            self.logger.error(f"❌ Receiver discovery failed: {e}")
        
        return []
    
    def _discover_key_methods(self, package_name: str, timeout: int) -> List[str]:
        """Discover key security-relevant methods using objection."""
        try:
            # Look for common security-related classes
            security_classes = [
                'java.security',
                'javax.crypto',
                'android.security',
                'java.net.URL',
                'java.io.File'
            ]
            
            key_methods = []
            
            for class_pattern in security_classes:
                try:
                    cmd = ['objection', '-g', package_name, 'explore', '-c',
                           f'android hooking list class_methods "{class_pattern}"']
                    
                    result = subprocess.run(cmd, capture_output=True, text=True,
                                           timeout=timeout//len(security_classes))
                    
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            line = line.strip()
                            if line and '(' in line and ')' in line:
                                key_methods.append(line)
                                
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    continue
            
            self.logger.info(f"   🔍 Found {len(key_methods)} key methods")
            return key_methods[:50]
            
        except Exception as e:
            self.logger.error(f"❌ Key method discovery failed: {e}")
        
        return []
    
    def _discover_strings(self, package_name: str, timeout: int) -> List[str]:
        """Discover interesting strings using objection."""
        try:
            # Search for security-relevant strings
            search_patterns = ['password', 'key', 'token', 'secret', 'api', 'url']
            interesting_strings = []
            
            for pattern in search_patterns:
                try:
                    cmd = ['objection', '-g', package_name, 'explore', '-c',
                           f'memory search --string "{pattern}"']
                    
                    result = subprocess.run(cmd, capture_output=True, text=True,
                                           timeout=timeout//len(search_patterns))
                    
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            line = line.strip()
                            if line and pattern.lower() in line.lower():
                                interesting_strings.append(line)
                                
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    continue
            
            self.logger.info(f"   🔤 Found {len(interesting_strings)} interesting strings")
            return interesting_strings[:30]
            
        except Exception as e:
            self.logger.error(f"❌ String discovery failed: {e}")
        
        return []
    
    def _find_crypto_indicators(self, result: ReconnaissanceResult) -> List[str]:
        """Identify cryptographic indicators from reconnaissance data."""
        crypto_indicators = []
        
        # Check methods for crypto patterns
        crypto_patterns = [
            'MessageDigest', 'Cipher', 'KeyGenerator', 'SecretKey',
            'encrypt', 'decrypt', 'hash', 'digest'
        ]
        
        for method in result.key_methods:
            for pattern in crypto_patterns:
                if pattern.lower() in method.lower():
                    crypto_indicators.append(method)
                    break
        
        # Check strings for crypto indicators
        for string in result.interesting_strings:
            for pattern in crypto_patterns:
                if pattern.lower() in string.lower():
                    crypto_indicators.append(string)
                    break
        
        return list(set(crypto_indicators))
    
    def _find_network_indicators(self, result: ReconnaissanceResult) -> List[str]:
        """Identify network indicators from reconnaissance data."""
        network_indicators = []
        
        # Check methods for network patterns
        network_patterns = [
            'URL', 'HttpClient', 'URLConnection', 'Socket',
            'OkHttp', 'Retrofit', 'network', 'http'
        ]
        
        for method in result.key_methods:
            for pattern in network_patterns:
                if pattern.lower() in method.lower():
                    network_indicators.append(method)
                    break
        
        # Check strings for URLs and network indicators
        for string in result.interesting_strings:
            if any(proto in string.lower() for proto in ['http://', 'https://', 'ftp://']):
                network_indicators.append(string)
            elif any(pattern.lower() in string.lower() for pattern in network_patterns):
                network_indicators.append(string)
        
        return list(set(network_indicators))
    
    def _find_storage_indicators(self, result: ReconnaissanceResult) -> List[str]:
        """Identify storage indicators from reconnaissance data."""
        storage_indicators = []
        
        # Check methods for storage patterns
        storage_patterns = [
            'FileOutputStream', 'FileInputStream', 'SharedPreferences',
            'SQLiteDatabase', 'file', 'storage', 'database'
        ]
        
        for method in result.key_methods:
            for pattern in storage_patterns:
                if pattern.lower() in method.lower():
                    storage_indicators.append(method)
                    break
        
        # Check strings for file paths
        for string in result.interesting_strings:
            if any(path in string.lower() for path in ['/data/', '/sdcard/', '.db', '.json']):
                storage_indicators.append(string)
        
        return list(set(storage_indicators))
    
    def _generate_aods_hints(self, result: ReconnaissanceResult) -> Dict[str, Any]:
        """Generate AODS configuration hints based on reconnaissance."""
        
        hints = {
            "suggested_scripts": [],
            "priority_areas": [],
            "monitoring_duration": 30,
            "analysis_mode": "comprehensive",
            "custom_focus": []
        }
        
        # Suggest scripts based on discovered indicators
        if result.crypto_indicators:
            hints["suggested_scripts"].append("crypto_hooks")
            hints["priority_areas"].append("cryptographic_analysis")
            
        if result.network_indicators:
            hints["suggested_scripts"].append("network_hooks")
            hints["priority_areas"].append("network_security")
            
        if result.storage_indicators:
            hints["suggested_scripts"].append("storage_hooks")
            hints["priority_areas"].append("data_storage")
            
        if result.activities:
            hints["suggested_scripts"].append("component_hooks")
            hints["priority_areas"].append("component_analysis")
        
        # Adjust monitoring duration based on app complexity
        component_count = len(result.activities) + len(result.services) + len(result.receivers)
        
        if component_count > 20:
            hints["monitoring_duration"] = 60
            hints["analysis_mode"] = "comprehensive"
        elif component_count > 10:
            hints["monitoring_duration"] = 45
        elif component_count < 5:
            hints["monitoring_duration"] = 20
            hints["analysis_mode"] = "targeted"
        
        # Custom focus areas
        if len(result.crypto_indicators) > 5:
            hints["custom_focus"].append("intensive_crypto_analysis")
            
        if len(result.network_indicators) > 5:
            hints["custom_focus"].append("comprehensive_network_analysis")
        
        return hints
    
    def generate_objection_session_script(self, result: ReconnaissanceResult) -> str:
        """Generate objection session script for manual exploration."""
        
        script_lines = [
            f"# Objection Manual Exploration Script",
            f"# Package: {result.package_name}",
            f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"objection -g {result.package_name} explore",
            "",
            "# Component Discovery",
            "android hooking list activities",
            "android hooking list services", 
            "android hooking list receivers",
            "",
            "# Security Analysis"
        ]
        
        if result.crypto_indicators:
            script_lines.extend([
                "# Crypto Analysis",
                "android hooking watch class java.security.MessageDigest",
                "android hooking watch class javax.crypto.Cipher",
                ""
            ])
        
        if result.network_indicators:
            script_lines.extend([
                "# Network Analysis", 
                "android hooking watch class java.net.URL",
                "android hooking watch class okhttp3.OkHttpClient",
                ""
            ])
        
        if result.storage_indicators:
            script_lines.extend([
                "# Storage Analysis",
                "android hooking watch class java.io.FileOutputStream",
                "android hooking watch class android.content.SharedPreferences",
                ""
            ])
        
        script_lines.extend([
            "# Memory Analysis",
            "memory list modules",
            "memory search --string password",
            "memory search --string token",
            "",
            "# Exit",
            "exit"
        ])
        
        return "\n".join(script_lines)
    
    def export_reconnaissance_report(self, result: ReconnaissanceResult, 
                                   output_path: str) -> bool:
        """Export reconnaissance results to JSON report."""
        
        try:
            report_data = {
                "reconnaissance_report": {
                    "package_name": result.package_name,
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "discovered_components": {
                        "activities": result.activities,
                        "services": result.services,
                        "receivers": result.receivers
                    },
                    "security_indicators": {
                        "crypto_indicators": result.crypto_indicators,
                        "network_indicators": result.network_indicators,
                        "storage_indicators": result.storage_indicators
                    },
                    "aods_configuration_hints": result.aods_hints,
                    "manual_exploration": {
                        "objection_session_script": self.generate_objection_session_script(result)
                    }
                }
            }
            
            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            self.logger.info(f"✅ Reconnaissance report exported: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to export reconnaissance report: {e}")
            return False


def quick_recon(package_name: str, timeout: int = 60) -> ReconnaissanceResult:
    """Convenience function for quick reconnaissance."""
    recon_module = ObjectionReconnaissanceModule()
    return recon_module.quick_reconnaissance(package_name, timeout)


if __name__ == "__main__":
    # Demo usage
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python reconnaissance_module.py <package_name>")
        sys.exit(1)
    
    package_name = sys.argv[1]
    
    print(f"🔍 Objection Reconnaissance Demo: {package_name}")
    print("=" * 60)
    
    recon_module = ObjectionReconnaissanceModule()
    
    if not recon_module.objection_available:
        print("❌ Objection not available - install with: pip install objection")
        sys.exit(1)
    
    # Perform reconnaissance
    result = recon_module.quick_reconnaissance(package_name)
    
    # Display results
    print(f"\n📊 Reconnaissance Results:")
    print(f"   📱 Activities: {len(result.activities)}")
    print(f"   🔧 Services: {len(result.services)}")
    print(f"   📡 Receivers: {len(result.receivers)}")
    print(f"   🔍 Key Methods: {len(result.key_methods)}")
    print(f"   🔤 Interesting Strings: {len(result.interesting_strings)}")
    
    print(f"\n🎯 Security Indicators:")
    print(f"   🔐 Crypto: {len(result.crypto_indicators)}")
    print(f"   🌐 Network: {len(result.network_indicators)}")
    print(f"   📁 Storage: {len(result.storage_indicators)}")
    
    print(f"\n🧠 AODS Hints:")
    print(f"   📜 Suggested scripts: {result.aods_hints.get('suggested_scripts', [])}")
    print(f"   ⏱️ Monitoring duration: {result.aods_hints.get('monitoring_duration', 30)}s")
    print(f"   📊 Analysis mode: {result.aods_hints.get('analysis_mode', 'comprehensive')}")
    
    # Export report
    output_file = f"reconnaissance_{package_name}_{int(time.time())}.json"
    recon_module.export_reconnaissance_report(result, output_file)
    
    print(f"\n✅ Reconnaissance completed!")
    print(f"📄 Report saved: {output_file}")
    print(f"🔧 Use hints to optimize AODS configuration")
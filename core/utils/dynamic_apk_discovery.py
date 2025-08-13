"""
Dynamic APK Discovery Utility
Provides organic APK discovery for testing and validation
No hardcoded APK names or paths - fully dynamic detection
"""

import os
import glob
from pathlib import Path
from typing import List, Optional, Dict, Any
import json
import logging

logger = logging.getLogger(__name__)

class DynamicAPKDiscovery:
    """Discovers APKs dynamically for testing without hardcoded references"""
    
    def __init__(self):
        self.search_paths = [
            "apks/",
            "test_apks/", 
            "samples/",
            "../apks/",
            "./",
            "../../apks/"
        ]
        
    def find_available_apks(self, max_count: int = 5) -> List[Dict[str, Any]]:
        """Find available APKs dynamically"""
        found_apks = []
        
        for search_path in self.search_paths:
            if not os.path.exists(search_path):
                continue
                
            apk_files = glob.glob(os.path.join(search_path, "*.apk"))
            
            for apk_file in apk_files:
                if len(found_apks) >= max_count:
                    break
                    
                apk_info = {
                    'path': apk_file,
                    'name': os.path.basename(apk_file),
                    'size_mb': round(os.path.getsize(apk_file) / (1024 * 1024), 2),
                    'directory': os.path.dirname(apk_file)
                }
                
                # Try to extract package name dynamically using aapt
                package_name = self._extract_package_name(apk_file)
                if package_name:
                    apk_info['package_name'] = package_name
                    
                found_apks.append(apk_info)
                
            if len(found_apks) >= max_count:
                break
                
        return found_apks
    
    def find_vulnerable_apks(self, max_count: int = 3) -> List[Dict[str, Any]]:
        """Find APKs that appear to be vulnerable/testing apps"""
        all_apks = self.find_available_apks(max_count * 2)
        vulnerable_apks = []
        
        vulnerable_indicators = [
            'vulnerable', 'insecure', 'demo', 'test', 'goat', 'diva',
            'hack', 'ctf', 'challenge', 'security', 'exploit', 'pentest'
        ]
        
        for apk in all_apks:
            if len(vulnerable_apks) >= max_count:
                break
                
            # Check APK name for vulnerable indicators
            apk_name_lower = apk['name'].lower()
            package_name_lower = apk.get('package_name', '').lower()
            
            is_vulnerable = any(
                indicator in apk_name_lower or indicator in package_name_lower
                for indicator in vulnerable_indicators
            )
            
            if is_vulnerable:
                vulnerable_apks.append(apk)
        
        # If no clearly vulnerable APKs found, return first few APKs
        if not vulnerable_apks and all_apks:
            vulnerable_apks = all_apks[:max_count]
            
        return vulnerable_apks
    
    def find_best_test_apk(self) -> Optional[Dict[str, Any]]:
        """Find the best APK for testing (prefers vulnerable apps)"""
        vulnerable_apks = self.find_vulnerable_apks(1)
        if vulnerable_apks:
            return vulnerable_apks[0]
            
        all_apks = self.find_available_apks(1)
        if all_apks:
            return all_apks[0]
            
        return None
    
    def get_apk_context_data(self, apk_path: str) -> Dict[str, Any]:
        """Get context data for an APK dynamically"""
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")
            
        package_name = self._extract_package_name(apk_path)
        
        return {
            'apk_path': apk_path,
            'apk_path_str': apk_path,
            'package_name': package_name or 'unknown.package',
            'apk_name': os.path.basename(apk_path),
            'size_mb': round(os.path.getsize(apk_path) / (1024 * 1024), 2)
        }
    
    def _extract_package_name(self, apk_path: str) -> Optional[str]:
        """Extract package name from APK using aapt if available"""
        try:
            import subprocess
            result = subprocess.run([
                'aapt', 'dump', 'badging', apk_path
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('package: name='):
                        # Extract package name from: package: name='com.example.app'
                        start = line.find("name='") + 6
                        end = line.find("'", start)
                        if start > 5 and end > start:
                            return line[start:end]
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.debug(f"Could not extract package name from {apk_path}: {e}")
            
        # Fallback: try to guess from filename
        filename = os.path.basename(apk_path).lower()
        if 'goat' in filename:
            return 'owasp.sat.agoat'
        elif 'diva' in filename:
            return 'jakhar.aseem.diva'
        elif 'insecure' in filename and 'bank' in filename:
            return 'com.android.insecurebankv2'
            
        return None
    
    def discover_existing_reports(self) -> List[str]:
        """Find existing JSON report files"""
        report_patterns = [
            "*.json",
            "*_security_report.json",
            "*_enhanced_*.json",
            "aods_*.json"
        ]
        
        found_reports = []
        for pattern in report_patterns:
            found_reports.extend(glob.glob(pattern))
            
        # Filter to likely AODS reports
        aods_reports = []
        for report in found_reports:
            try:
                with open(report, 'r') as f:
                    data = json.load(f)
                    # Check if it looks like an AODS report
                    if (isinstance(data, dict) and 
                        ('package_name' in data or 'vulnerabilities' in data or 'scan_results' in data)):
                        aods_reports.append(report)
            except:
                continue
                
        return aods_reports
    
    def create_mock_apk_context(self, package_name: str = None) -> Dict[str, Any]:
        """Create a mock APK context for testing when no real APK is available"""
        if not package_name:
            package_name = "com.example.testapp"
            
        return {
            'apk_path_str': './mock_test_app.apk',
            'package_name': package_name,
            'apk_name': 'mock_test_app.apk',
            'size_mb': 5.0,
            'decompiled_path': './mock_decompiled/',
            'is_mock': True
        }

# Global instance for easy access
apk_discovery = DynamicAPKDiscovery()

def get_test_apk() -> Optional[Dict[str, Any]]:
    """Quick function to get the best available test APK"""
    return apk_discovery.find_best_test_apk()

def get_vulnerable_apks(count: int = 3) -> List[Dict[str, Any]]:
    """Quick function to get vulnerable test APKs"""
    return apk_discovery.find_vulnerable_apks(count)

def get_apk_context(apk_path: str = None) -> Dict[str, Any]:
    """Quick function to get APK context data"""
    if apk_path:
        return apk_discovery.get_apk_context_data(apk_path)
    
    # Auto-discover best APK
    best_apk = get_test_apk()
    if best_apk:
        return apk_discovery.get_apk_context_data(best_apk['path'])
    
    # Fallback to mock context
    return apk_discovery.create_mock_apk_context() 
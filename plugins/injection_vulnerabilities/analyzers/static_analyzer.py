"""
Static Injection Vulnerability Analyzer

This module handles static analysis of injection vulnerabilities through
code analysis and manifest inspection.
"""

import logging
import os
import re
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
import xml.etree.ElementTree as ET

from core.apk_ctx import APKContext

logger = logging.getLogger(__name__)

class StaticInjectionAnalyzer:
    """
    Static analyzer for injection vulnerabilities.
    
    Provides static analysis capabilities for detecting injection vulnerabilities
    through code analysis and manifest inspection.
    """
    
    def __init__(self):
        """Initialize the static analyzer."""
        self.max_files_to_analyze = 1000
        self.sql_injection_patterns = [
            (r'query\([^)]*\+[^)]*\)', "String concatenation in SQL query"),
            (r'rawQuery\([^)]*\+[^)]*\)', "String concatenation in raw query"),
            (r'execSQL\([^)]*\+[^)]*\)', "String concatenation in execSQL"),
            (r'delete\([^)]*\+[^)]*\)', "String concatenation in delete query"),
            (r'update\([^)]*\+[^)]*\)', "String concatenation in update query"),
            (r'insert\([^)]*\+[^)]*\)', "String concatenation in insert query"),
            (r'\"SELECT[^\"]*\"\s*\+', "String concatenation in SELECT statement"),
            (r'\"INSERT[^\"]*\"\s*\+', "String concatenation in INSERT statement"),
            (r'\"UPDATE[^\"]*\"\s*\+', "String concatenation in UPDATE statement"),
            (r'\"DELETE[^\"]*\"\s*\+', "String concatenation in DELETE statement"),
        ]
        
        self.content_provider_patterns = [
            (r'extends\s+ContentProvider', "ContentProvider implementation"),
            (r'query\s*\([^)]*Uri[^)]*\)', "ContentProvider query method"),
            (r'insert\s*\([^)]*Uri[^)]*\)', "ContentProvider insert method"),
            (r'update\s*\([^)]*Uri[^)]*\)', "ContentProvider update method"),
            (r'delete\s*\([^)]*Uri[^)]*\)', "ContentProvider delete method"),
        ]
        
    def analyze_injection_vulnerabilities(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Analyze injection vulnerabilities using static analysis.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Static analysis results
        """
        logger.info("Starting static injection vulnerability analysis")
        
        results = {
            "enabled": True,
            "manifest_analysis": {},
            "code_analysis": {},
            "vulnerabilities": [],
            "analysis_time": 0.0,
            "status": "pending"
        }
        
        try:
            start_time = time.time()
            
            # Analyze AndroidManifest.xml
            logger.info("Analyzing AndroidManifest.xml for content providers")
            manifest_results = self._analyze_manifest(apk_ctx)
            results["manifest_analysis"] = manifest_results
            
            # Check for shutdown
            if self._check_shutdown():
                results["status"] = "cancelled"
                return results
            
            # Analyze code for injection patterns
            logger.info("Analyzing code for injection patterns")
            code_results = self._analyze_code(apk_ctx)
            results["code_analysis"] = code_results
            
            # Consolidate vulnerabilities
            results["vulnerabilities"] = self._consolidate_vulnerabilities(manifest_results, code_results)
            
            results["analysis_time"] = time.time() - start_time
            results["status"] = "completed"
            
            logger.info(f"Static analysis completed in {results['analysis_time']:.2f}s")
            
        except Exception as e:
            logger.error(f"Static analysis failed: {str(e)}")
            results["status"] = "failed"
            results["error"] = str(e)
        
        return results
    
    def _analyze_manifest(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Analyze AndroidManifest.xml for content provider vulnerabilities.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Manifest analysis results
        """
        results = {
            "enabled": True,
            "manifest_path": "",
            "content_providers": [],
            "exported_providers": [],
            "vulnerable_providers": [],
            "analysis_time": 0.0
        }
        
        try:
            start_time = time.time()
            
            # Determine manifest path
            manifest_path = self._get_manifest_path(apk_ctx)
            results["manifest_path"] = str(manifest_path) if manifest_path else ""
            
            if not manifest_path or not manifest_path.exists():
                results["enabled"] = False
                results["error"] = "AndroidManifest.xml not found"
                return results
            
            # Parse manifest
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Find all content providers
            providers = root.findall(".//provider")
            results["content_providers"] = self._analyze_providers(providers)
            
            # Find exported providers
            exported = [p for p in results["content_providers"] if p.get("exported", False)]
            results["exported_providers"] = exported
            
            # Identify vulnerable providers
            vulnerable = self._identify_vulnerable_providers(exported)
            results["vulnerable_providers"] = vulnerable
            
            results["analysis_time"] = time.time() - start_time
            
        except Exception as e:
            logger.error(f"Manifest analysis failed: {str(e)}")
            results["enabled"] = False
            results["error"] = str(e)
        
        return results
    
    def _analyze_code(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """
        Analyze code for injection vulnerability patterns.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            Dict[str, Any]: Code analysis results
        """
        results = {
            "enabled": True,
            "jadx_path": "",
            "files_analyzed": 0,
            "sql_injection_patterns": [],
            "content_provider_implementations": [],
            "vulnerable_code_patterns": [],
            "analysis_time": 0.0
        }
        
        try:
            start_time = time.time()
            
            # Check if JADX output is available
            jadx_path = self._get_jadx_path(apk_ctx)
            results["jadx_path"] = str(jadx_path) if jadx_path else ""
            
            if not jadx_path or not jadx_path.exists():
                results["enabled"] = False
                results["error"] = "JADX output not available"
                return results
            
            # Analyze Java files
            file_count = 0
            for root, dirs, files in os.walk(jadx_path):
                for file in files:
                    if file.endswith('.java'):
                        # Check for shutdown periodically
                        if file_count % 50 == 0 and self._check_shutdown():
                            results["status"] = "cancelled"
                            return results
                        
                        file_count += 1
                        if file_count > self.max_files_to_analyze:
                            logger.info(f"Limiting analysis to {self.max_files_to_analyze} files")
                            break
                        
                        file_path = os.path.join(root, file)
                        self._analyze_java_file(file_path, results)
            
            results["files_analyzed"] = file_count
            results["analysis_time"] = time.time() - start_time
            
        except Exception as e:
            logger.error(f"Code analysis failed: {str(e)}")
            results["enabled"] = False
            results["error"] = str(e)
        
        return results
    
    def _analyze_providers(self, providers: List[Any]) -> List[Dict[str, Any]]:
        """
        Analyze content provider elements from manifest.
        
        Args:
            providers: List of provider XML elements
            
        Returns:
            List[Dict[str, Any]]: Analyzed provider information
        """
        analyzed_providers = []
        
        for provider in providers:
            provider_info = {
                "name": provider.get("android:name", ""),
                "authorities": provider.get("android:authorities", ""),
                "exported": provider.get("android:exported", "false").lower() == "true",
                "enabled": provider.get("android:enabled", "true").lower() == "true",
                "grant_uri_permissions": provider.get("android:grantUriPermissions", "false").lower() == "true",
                "multiprocess": provider.get("android:multiprocess", "false").lower() == "true",
                "read_permission": provider.get("android:readPermission", ""),
                "write_permission": provider.get("android:writePermission", ""),
                "permission": provider.get("android:permission", ""),
                "path_permissions": [],
                "grant_uri_permissions_patterns": []
            }
            
            # Find path permissions
            path_permissions = provider.findall("path-permission")
            for path_perm in path_permissions:
                provider_info["path_permissions"].append({
                    "path": path_perm.get("android:path", ""),
                    "pathPrefix": path_perm.get("android:pathPrefix", ""),
                    "pathPattern": path_perm.get("android:pathPattern", ""),
                    "readPermission": path_perm.get("android:readPermission", ""),
                    "writePermission": path_perm.get("android:writePermission", "")
                })
            
            # Find grant-uri-permission patterns
            grant_patterns = provider.findall("grant-uri-permission")
            for pattern in grant_patterns:
                provider_info["grant_uri_permissions_patterns"].append({
                    "path": pattern.get("android:path", ""),
                    "pathPrefix": pattern.get("android:pathPrefix", ""),
                    "pathPattern": pattern.get("android:pathPattern", "")
                })
            
            analyzed_providers.append(provider_info)
        
        return analyzed_providers
    
    def _identify_vulnerable_providers(self, exported_providers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identify vulnerable content providers.
        
        Args:
            exported_providers: List of exported providers
            
        Returns:
            List[Dict[str, Any]]: Vulnerable providers with risk assessment
        """
        vulnerable = []
        
        for provider in exported_providers:
            risk_factors = []
            risk_level = "LOW"
            
            # Check for missing permissions
            if not provider.get("read_permission") and not provider.get("write_permission") and not provider.get("permission"):
                risk_factors.append("No permissions required")
                risk_level = "HIGH"
            
            # Check for grant URI permissions
            if provider.get("grant_uri_permissions", False):
                risk_factors.append("Grant URI permissions enabled")
                risk_level = "MEDIUM" if risk_level == "LOW" else risk_level
            
            # Check for path permissions
            if not provider.get("path_permissions"):
                risk_factors.append("No path-specific permissions")
                risk_level = "MEDIUM" if risk_level == "LOW" else risk_level
            
            if risk_factors:
                vulnerable.append({
                    "provider": provider,
                    "risk_level": risk_level,
                    "risk_factors": risk_factors,
                    "description": f"Exported provider {provider.get('authorities', 'unknown')} has security issues"
                })
        
        return vulnerable
    
    def _analyze_java_file(self, file_path: str, results: Dict[str, Any]):
        """
        Analyze a single Java file for injection patterns.
        
        Args:
            file_path: Path to the Java file
            results: Results dictionary to update
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for SQL injection patterns
            for pattern, description in self.sql_injection_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    results["sql_injection_patterns"].append({
                        "file": os.path.basename(file_path),
                        "line": line_num,
                        "pattern": description,
                        "code": match.group(0),
                        "full_path": file_path
                    })
            
            # Check for ContentProvider implementations
            for pattern, description in self.content_provider_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    results["content_provider_implementations"].append({
                        "file": os.path.basename(file_path),
                        "line": line_num,
                        "pattern": description,
                        "code": match.group(0),
                        "full_path": file_path
                    })
            
        except Exception as e:
            logger.warning(f"Failed to analyze file {file_path}: {str(e)}")
    
    def _consolidate_vulnerabilities(self, manifest_results: Dict[str, Any], code_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Consolidate vulnerabilities from manifest and code analysis.
        
        Args:
            manifest_results: Manifest analysis results
            code_results: Code analysis results
            
        Returns:
            List[Dict[str, Any]]: Consolidated vulnerability list
        """
        vulnerabilities = []
        
        # Add manifest vulnerabilities
        for vuln_provider in manifest_results.get("vulnerable_providers", []):
            vulnerabilities.append({
                "type": "content_provider_exposure",
                "severity": self._map_risk_to_severity(vuln_provider.get("risk_level", "LOW")),
                "confidence": 0.8,
                "description": vuln_provider.get("description", ""),
                "location": vuln_provider.get("provider", {}).get("authorities", "unknown"),
                "source": "manifest_analysis",
                "risk_factors": vuln_provider.get("risk_factors", []),
                "remediation": [
                    "Add proper permission requirements",
                    "Implement access control checks",
                    "Use signature-level permissions",
                    "Validate all URI requests"
                ]
            })
        
        # Add code vulnerabilities
        for sql_pattern in code_results.get("sql_injection_patterns", []):
            vulnerabilities.append({
                "type": "sql_injection",
                "severity": "HIGH",
                "confidence": 0.7,
                "description": f"SQL injection vulnerability: {sql_pattern.get('pattern', '')}",
                "location": f"{sql_pattern.get('file', '')}:{sql_pattern.get('line', 0)}",
                "source": "code_analysis",
                "code_snippet": sql_pattern.get("code", ""),
                "remediation": [
                    "Use parameterized queries",
                    "Implement input validation",
                    "Use prepared statements",
                    "Sanitize user input"
                ]
            })
        
        # Add ContentProvider implementation findings
        for cp_impl in code_results.get("content_provider_implementations", []):
            vulnerabilities.append({
                "type": "content_provider_implementation",
                "severity": "MEDIUM",
                "confidence": 0.6,
                "description": f"ContentProvider implementation found: {cp_impl.get('pattern', '')}",
                "location": f"{cp_impl.get('file', '')}:{cp_impl.get('line', 0)}",
                "source": "code_analysis",
                "code_snippet": cp_impl.get("code", ""),
                "remediation": [
                    "Implement proper access controls",
                    "Validate all input parameters",
                    "Use least privilege principle",
                    "Add security checks"
                ]
            })
        
        return vulnerabilities
    
    def _get_manifest_path(self, apk_ctx: APKContext) -> Optional[Path]:
        """Get path to AndroidManifest.xml file."""
        if hasattr(apk_ctx, 'apktool_output_dir') and apk_ctx.apktool_output_dir:
            return Path(apk_ctx.apktool_output_dir) / "AndroidManifest.xml"
        return None
    
    def _get_jadx_path(self, apk_ctx: APKContext) -> Optional[Path]:
        """Get path to JADX output directory."""
        if hasattr(apk_ctx, 'jadx_output_dir') and apk_ctx.jadx_output_dir:
            return Path(apk_ctx.jadx_output_dir)
        return None
    
    def _map_risk_to_severity(self, risk_level: str) -> str:
        """Map risk level to severity."""
        mapping = {
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW"
        }
        return mapping.get(risk_level, "LOW")
    
    def _check_shutdown(self) -> bool:
        """Check if graceful shutdown has been requested."""
        try:
            from core.graceful_shutdown_manager import is_shutdown_requested
            return is_shutdown_requested()
        except ImportError:
            return False
    
    def analyze_manifest_providers(self, apk_ctx: APKContext) -> List[str]:
        """
        Legacy compatibility method for analyzing manifest providers.
        
        Args:
            apk_ctx: The APKContext instance
            
        Returns:
            List[str]: List of vulnerability descriptions
        """
        try:
            results = self._analyze_manifest(apk_ctx)
            vulnerabilities = []
            
            for vuln_provider in results.get("vulnerable_providers", []):
                provider = vuln_provider.get("provider", {})
                authorities = provider.get("authorities", "unknown")
                risk_factors = vuln_provider.get("risk_factors", [])
                
                vuln_desc = f"⚠️ Exported Content Provider: {authorities}"
                if risk_factors:
                    vuln_desc += f" ({', '.join(risk_factors)})"
                
                vulnerabilities.append(vuln_desc)
            
            return vulnerabilities
            
        except Exception as e:
            return [f"Error analyzing manifest: {e}"]
    
    def analyze_code_patterns(self, jadx_dir: str) -> List[str]:
        """
        Legacy compatibility method for analyzing code patterns.
        
        Args:
            jadx_dir: Path to JADX output directory
            
        Returns:
            List[str]: List of vulnerability descriptions
        """
        try:
            # Create a mock APK context
            class MockAPKContext:
                def __init__(self, jadx_dir):
                    self.jadx_output_dir = jadx_dir
            
            mock_ctx = MockAPKContext(jadx_dir)
            results = self._analyze_code(mock_ctx)
            vulnerabilities = []
            
            for sql_pattern in results.get("sql_injection_patterns", []):
                rel_path = os.path.relpath(sql_pattern.get("full_path", ""), jadx_dir)
                vulnerabilities.append(f"⚠️ {sql_pattern.get('pattern', '')} in {rel_path}")
            
            return vulnerabilities
            
        except Exception as e:
            return [f"Error analyzing code: {e}"] 
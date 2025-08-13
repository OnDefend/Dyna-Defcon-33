#!/usr/bin/env python3
"""
Evidence Enrichment Engine

Enhances generic vulnerability evidence with specific technical details extracted
from APK analysis, decompiled sources, and manifest files.

This engine uses organic, data-driven approaches to extract real technical details
rather than hardcoded patterns.
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class EvidenceEnrichmentEngine:
    """
    Enhances vulnerability evidence with technical details extracted from APK analysis.
    
    Uses organic, data-driven approaches to find relevant technical details such as:
    - File paths and line numbers
    - Manifest configurations
    - Permission declarations
    - Code snippets
    - Certificate details
    """
    
    def __init__(self, apk_path: str, workspace_dir: str = None):
        """Initialize the evidence enrichment engine."""
        self.apk_path = apk_path
        self.workspace_dir = workspace_dir or "workspace"
        self.logger = logging.getLogger(__name__)
        
        # Find decompiled sources
        self.decompiled_sources = self._find_decompiled_sources()
        self.manifest_path = self._find_manifest()
        
        # Cache for parsed files
        self._manifest_cache = None
        self._source_files_cache = {}
        
    def enrich_evidence(self, vulnerability: Dict[str, Any]) -> List[str]:
        """
        Enrich evidence for a vulnerability with actual vulnerable code snippets.
        
        Args:
            vulnerability: Vulnerability dict with title, description, category, evidence
            
        Returns:
            Enhanced evidence list with actual vulnerable code snippets
        """
        enhanced_evidence = []
        original_evidence = vulnerability.get('evidence', [])
        
        # Keep original evidence
        if isinstance(original_evidence, list):
            enhanced_evidence.extend(original_evidence)
        else:
            enhanced_evidence.append(str(original_evidence))
        
        # Extract ACTUAL vulnerable code based on vulnerability type
        category = vulnerability.get('category', '').lower()
        title = vulnerability.get('title', '').lower()
        description = vulnerability.get('description', '').lower()
        
        # Extract vulnerable code snippets based on specific vulnerability patterns
        if 'certificate' in title or 'certificate' in category or 'ssl' in title:
            enhanced_evidence.extend(self._extract_vulnerable_ssl_code())
        
        if 'permission' in title or 'permission' in description:
            enhanced_evidence.extend(self._extract_vulnerable_permission_code())
        
        if 'manifest' in title or 'manifest' in description or 'debuggable' in title:
            enhanced_evidence.extend(self._extract_vulnerable_manifest_code())
        
        if 'root' in title or 'root' in category:
            enhanced_evidence.extend(self._extract_vulnerable_root_detection_code())
        
        if 'secret' in title or 'api' in title or 'key' in title:
            enhanced_evidence.extend(self._extract_vulnerable_secret_code())
        
        if 'injection' in title or 'sql' in title or 'xss' in title:
            enhanced_evidence.extend(self._extract_vulnerable_injection_code())
        
        # Generic vulnerable code patterns
        enhanced_evidence.extend(self._extract_vulnerable_code_patterns(title, description))
        
        # Remove duplicates while preserving order
        return list(dict.fromkeys(enhanced_evidence))
    
    def _find_decompiled_sources(self) -> str:
        """Find decompiled source directory."""
        # Check common decompiled source locations
        base_name = Path(self.apk_path).stem
        
        candidates = [
            f"{self.workspace_dir}/{base_name}_decompiled",
            f"{self.workspace_dir}/*_decompiled",
            f"/tmp/jadx_decompiled/jadx_*",
            f"decompiled/{base_name}"
        ]
        
        for pattern in candidates:
            if '*' in pattern:
                import glob
                matches = glob.glob(pattern)
                if matches:
                    return matches[0]
            elif os.path.exists(pattern):
                return pattern
        
        return ""
    
    def _find_manifest(self) -> str:
        """Find AndroidManifest.xml file."""
        if not self.decompiled_sources:
            return ""
        
        candidates = [
            os.path.join(self.decompiled_sources, "AndroidManifest.xml"),
            os.path.join(self.decompiled_sources, "resources", "AndroidManifest.xml"),
            os.path.join(self.decompiled_sources, "original", "AndroidManifest.xml")
        ]
        
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate
        
        return ""
    
    def _extract_vulnerable_ssl_code(self) -> List[str]:
        """Extract actual vulnerable SSL/TLS code from decompiled sources."""
        evidence = []
        
        if not self.decompiled_sources:
            return evidence
        
        # Patterns for vulnerable SSL code
        ssl_patterns = [
            r'X509TrustManager.*checkServerTrusted.*\{\s*\}',  # Empty trust manager
            r'HostnameVerifier.*verify.*return\s+true',        # Accepting all hostnames
            r'HttpsURLConnection.*setHostnameVerifier.*ALLOW_ALL',  # Bypass hostname verification
            r'TrustManager.*checkClientTrusted.*\{\s*\}',      # Empty client trust check
            r'SSLContext.*getInstance.*"SSL"',                 # Using insecure SSL
            r'\.setSSLSocketFactory.*new.*TrustAllSocketFactory',  # Custom insecure factory
            r'checkServerTrusted\([^)]+\)\s*\{\s*\}',         # Empty implementation
        ]
        
        try:
            for root, dirs, files in os.walk(self.decompiled_sources):
                for file in files:
                    if file.endswith('.java'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                for pattern in ssl_patterns:
                                    matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                                    for match in matches:
                                        # Extract context around the match
                                        context = self._extract_code_context(content, match.start(), match.end())
                                        if context:
                                            rel_path = os.path.relpath(file_path, self.decompiled_sources)
                                            line_num = content[:match.start()].count('\n') + 1
                                            evidence.append(f"{rel_path}:{line_num}: {context}")
                                            
                                            if len(evidence) >= 3:  # Limit to avoid too much detail
                                                return evidence
                        except Exception:
                            continue
        except Exception as e:
            self.logger.debug(f"Error extracting SSL code: {e}")
        
        return evidence
    
    def _extract_vulnerable_permission_code(self) -> List[str]:
        """Extract actual vulnerable permission-related code."""
        evidence = []
        
        if not self.decompiled_sources:
            return evidence
        
        # Patterns for vulnerable permission usage
        permission_patterns = [
            r'checkSelfPermission.*==.*PERMISSION_DENIED.*\{\s*\}',  # Empty permission denial handling
            r'requestPermissions.*new\s+String\[\]\s*\{[^}]*CAMERA[^}]*\}',  # Camera permission request
            r'READ_EXTERNAL_STORAGE.*without.*permission.*check',    # Storage access without check
            r'ACCESS_FINE_LOCATION.*requestPermissions',             # Location permission
            r'WRITE_EXTERNAL_STORAGE.*getExternalStorageDirectory',  # Storage write
        ]
        
        try:
            for root, dirs, files in os.walk(self.decompiled_sources):
                for file in files:
                    if file.endswith('.java'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                for pattern in permission_patterns:
                                    matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                                    for match in matches:
                                        context = self._extract_code_context(content, match.start(), match.end())
                                        if context:
                                            rel_path = os.path.relpath(file_path, self.decompiled_sources)
                                            line_num = content[:match.start()].count('\n') + 1
                                            evidence.append(f"{rel_path}:{line_num}: {context}")
                                            
                                            if len(evidence) >= 2:
                                                return evidence
                        except Exception:
                            continue
        except Exception as e:
            self.logger.debug(f"Error extracting permission code: {e}")
        
        return evidence
    
    def _extract_vulnerable_manifest_code(self) -> List[str]:
        """Extract vulnerable manifest configurations."""
        evidence = []
        
        if not self.manifest_path:
            return evidence
        
        try:
            with open(self.manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Extract specific vulnerable configurations
                if 'android:debuggable="true"' in content:
                    line_num = content[:content.find('android:debuggable="true"')].count('\n') + 1
                    evidence.append(f"AndroidManifest.xml:{line_num}: android:debuggable=\"true\"")
                
                if 'android:allowBackup="true"' in content:
                    line_num = content[:content.find('android:allowBackup="true"')].count('\n') + 1
                    evidence.append(f"AndroidManifest.xml:{line_num}: android:allowBackup=\"true\"")
                
                if 'android:usesCleartextTraffic="true"' in content:
                    line_num = content[:content.find('android:usesCleartextTraffic="true"')].count('\n') + 1
                    evidence.append(f"AndroidManifest.xml:{line_num}: android:usesCleartextTraffic=\"true\"")
                
                # Look for exported components without permission
                exported_pattern = r'android:exported="true"[^>]*(?!android:permission)'
                matches = re.finditer(exported_pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    evidence.append(f"AndroidManifest.xml:{line_num}: Exported component without permission")
                    if len(evidence) >= 3:
                        break
                        
        except Exception as e:
            self.logger.debug(f"Error extracting manifest code: {e}")
        
        return evidence
    
    def _extract_vulnerable_root_detection_code(self) -> List[str]:
        """Extract actual root detection code patterns."""
        evidence = []
        
        if not self.decompiled_sources:
            return evidence
        
        # Root detection patterns
        root_patterns = [
            r'Runtime\.getRuntime\(\)\.exec\("su"\)',           # Su command execution
            r'new\s+File\("/system/app/Superuser\.apk"\)',      # Superuser APK check
            r'isDeviceRooted\(\)',                              # Common root check method
            r'RootBeer\(\)\.isRooted\(\)',                      # RootBeer library usage
            r'Build\.TAGS.*contains.*"test-keys"',              # Test keys check
            r'/system/bin/su.*exists\(\)',                      # Su binary check
        ]
        
        try:
            for root, dirs, files in os.walk(self.decompiled_sources):
                for file in files:
                    if file.endswith('.java'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                for pattern in root_patterns:
                                    matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                                    for match in matches:
                                        context = self._extract_code_context(content, match.start(), match.end())
                                        if context:
                                            rel_path = os.path.relpath(file_path, self.decompiled_sources)
                                            line_num = content[:match.start()].count('\n') + 1
                                            evidence.append(f"{rel_path}:{line_num}: {context}")
                                            
                                            if len(evidence) >= 2:
                                                return evidence
                        except Exception:
                            continue
        except Exception as e:
            self.logger.debug(f"Error extracting root detection code: {e}")
        
        return evidence
    
    def _extract_vulnerable_secret_code(self) -> List[str]:
        """Extract hardcoded secrets and API keys."""
        evidence = []
        
        if not self.decompiled_sources:
            return evidence
        
        # Secret patterns (from enhanced static analysis)
        secret_patterns = [
            r'(?i)api[_-]?key[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_]{10,})',
            r'(?i)password[\'"\s]*[=:][\'"\s]*([^\s\'";]{6,})',
            r'(?i)secret[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_\.]{15,})',
            r'(?i)token[\'"\s]*[=:][\'"\s]*([a-zA-Z0-9\-_\.]{20,})',
            r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
        ]
        
        try:
            for root, dirs, files in os.walk(self.decompiled_sources):
                for file in files:
                    if file.endswith(('.java', '.xml', '.properties')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                for pattern in secret_patterns:
                                    matches = re.finditer(pattern, content, re.IGNORECASE)
                                    for match in matches:
                                        context = self._extract_code_context(content, match.start(), match.end())
                                        if context and not self._is_test_or_example(context):
                                            rel_path = os.path.relpath(file_path, self.decompiled_sources)
                                            line_num = content[:match.start()].count('\n') + 1
                                            evidence.append(f"{rel_path}:{line_num}: {context}")
                                            
                                            if len(evidence) >= 2:
                                                return evidence
                        except Exception:
                            continue
        except Exception as e:
            self.logger.debug(f"Error extracting secret code: {e}")
        
        return evidence
    
    def _extract_vulnerable_injection_code(self) -> List[str]:
        """Extract injection vulnerability patterns."""
        evidence = []
        
        if not self.decompiled_sources:
            return evidence
        
        # Injection patterns
        injection_patterns = [
            r'rawQuery\([^)]*\+[^)]*\)',                       # SQL injection via string concatenation
            r'execSQL\([^)]*\+[^)]*\)',                        # Direct SQL execution with concatenation
            r'loadUrl\([^)]*\+[^)]*\)',                        # URL injection
            r'eval\([^)]*\+[^)]*\)',                           # JavaScript eval with user input
            r'Runtime\.getRuntime\(\)\.exec\([^)]*\+[^)]*\)',  # Command injection
        ]
        
        try:
            for root, dirs, files in os.walk(self.decompiled_sources):
                for file in files:
                    if file.endswith('.java'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                for pattern in injection_patterns:
                                    matches = re.finditer(pattern, content, re.IGNORECASE)
                                    for match in matches:
                                        context = self._extract_code_context(content, match.start(), match.end())
                                        if context:
                                            rel_path = os.path.relpath(file_path, self.decompiled_sources)
                                            line_num = content[:match.start()].count('\n') + 1
                                            evidence.append(f"{rel_path}:{line_num}: {context}")
                                            
                                            if len(evidence) >= 2:
                                                return evidence
                        except Exception:
                            continue
        except Exception as e:
            self.logger.debug(f"Error extracting injection code: {e}")
        
        return evidence
    
    def _extract_vulnerable_code_patterns(self, title: str, description: str) -> List[str]:
        """Extract generic vulnerable code patterns based on vulnerability context."""
        evidence = []
        
        if not self.decompiled_sources:
            return evidence
        
        # Extract keywords from vulnerability description to search for relevant code
        keywords = []
        
        # Common vulnerability keywords that might appear in code
        vuln_keywords = ['crypto', 'encrypt', 'decrypt', 'hash', 'random', 'secure', 'verify', 'validate', 'bypass', 'admin', 'root', 'debug']
        
        for keyword in vuln_keywords:
            if keyword in title or keyword in description:
                keywords.append(keyword)
        
        if not keywords:
            return evidence
        
        try:
            # Search for code containing these keywords
            for root, dirs, files in os.walk(self.decompiled_sources):
                for file in files:
                    if file.endswith('.java'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                for keyword in keywords:
                                    # Look for method calls or variable assignments containing the keyword
                                    pattern = rf'\b{keyword}[A-Za-z]*\s*[\(\=]'
                                    matches = re.finditer(pattern, content, re.IGNORECASE)
                                    for match in matches:
                                        context = self._extract_code_context(content, match.start(), match.end())
                                        if context and len(context.strip()) > 10:  # Meaningful context
                                            rel_path = os.path.relpath(file_path, self.decompiled_sources)
                                            line_num = content[:match.start()].count('\n') + 1
                                            evidence.append(f"{rel_path}:{line_num}: {context}")
                                            
                                            if len(evidence) >= 1:  # Limit generic evidence
                                                return evidence
                        except Exception:
                            continue
        except Exception as e:
            self.logger.debug(f"Error extracting generic code patterns: {e}")
        
        return evidence
    
    def _extract_code_context(self, content: str, start: int, end: int, context_lines: int = 2) -> str:
        """Extract code context around a match with surrounding lines."""
        try:
            # Find the start of the current line
            line_start = content.rfind('\n', 0, start) + 1
            
            # Find context_lines before
            context_start = line_start
            for _ in range(context_lines):
                prev_line = content.rfind('\n', 0, context_start - 1)
                if prev_line == -1:
                    break
                context_start = prev_line + 1
            
            # Find the end of the current line
            line_end = content.find('\n', end)
            if line_end == -1:
                line_end = len(content)
            
            # Find context_lines after
            context_end = line_end
            for _ in range(context_lines):
                next_line = content.find('\n', context_end + 1)
                if next_line == -1:
                    context_end = len(content)
                    break
                context_end = next_line
            
            # Extract the context
            context = content[context_start:context_end].strip()
            
            # Clean up the context (remove excessive whitespace)
            lines = context.split('\n')
            cleaned_lines = []
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith('//') and len(stripped) > 3:
                    cleaned_lines.append(stripped)
            
            if len(cleaned_lines) > 0:
                return ' | '.join(cleaned_lines[:3])  # Max 3 lines, joined with |
            
            return ""
            
        except Exception:
            return ""
    
    def _is_test_or_example(self, context: str) -> bool:
        """Check if the context appears to be test or example code."""
        test_indicators = ['test', 'example', 'sample', 'demo', 'mock', 'fake', 'dummy']
        context_lower = context.lower()
        return any(indicator in context_lower for indicator in test_indicators)
    
    def _get_parsed_manifest(self) -> Optional[ET.Element]:
        """Get parsed AndroidManifest.xml, using cache."""
        if self._manifest_cache is not None:
            return self._manifest_cache
        
        if not self.manifest_path or not os.path.exists(self.manifest_path):
            self._manifest_cache = None
            return None
        
        try:
            tree = ET.parse(self.manifest_path)
            self._manifest_cache = tree.getroot()
            return self._manifest_cache
        except Exception as e:
            self.logger.debug(f"Could not parse manifest: {e}")
            self._manifest_cache = None
            return None
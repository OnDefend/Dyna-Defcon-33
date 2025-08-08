#!/usr/bin/env python3
"""
Dynamic Code Attribution System
==============================

Maps dynamic vulnerabilities to source code locations, providing file paths
and line numbers for runtime-detected issues by correlating with static analysis
and decompiled code.
"""

import os
import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import json


class CodeLocationMapper:
    """Maps vulnerability descriptions to actual code locations."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Common file patterns for different vulnerability types
        self.location_patterns = {
            'sql_injection': [
                r'.*SQLite.*Activity.*\.java',
                r'.*SQL.*Activity.*\.java', 
                r'.*Database.*\.java',
                r'.*injection.*\.java'
            ],
            'xss': [
                r'.*XSS.*Activity.*\.java',
                r'.*WebView.*\.java',
                r'.*Web.*Activity.*\.java'
            ],
            'insecure_storage': [
                r'.*Storage.*Activity.*\.java',
                r'.*SharedPreferences.*\.java',
                r'.*File.*Activity.*\.java',
                r'.*Data.*Activity.*\.java'
            ],
            'insecure_logging': [
                r'.*Logging.*Activity.*\.java',
                r'.*Log.*Activity.*\.java'
            ],
            'crypto': [
                r'.*Crypto.*\.java',
                r'.*Hash.*Activity.*\.java',
                r'.*Cipher.*\.java'
            ],
            'exported_component': [
                'AndroidManifest.xml'
            ],
            'network': [
                r'.*Network.*\.java',
                r'.*Http.*\.java',
                r'.*SSL.*\.java'
            ]
        }
        
        # Code snippet patterns for extraction
        self.code_snippet_patterns = {
            'sql_injection': [
                r'rawQuery\([^)]+\)',
                r'execSQL\([^)]+\)', 
                r'query\([^)]+\)',
                r'\.append\([^)]+\)'
            ],
            'xss': [
                r'loadUrl\([^)]+\)',
                r'loadData\([^)]+\)',
                r'setJavaScriptEnabled\(true\)'
            ],
            'insecure_storage': [
                r'getExternalStorageDirectory\(\)',
                r'openFileOutput\([^)]+\)',
                r'getSharedPreferences\([^)]+\)'
            ],
            'crypto': [
                r'MessageDigest\.getInstance\([^)]+\)',
                r'getInstance\("MD5"\)',
                r'getInstance\("SHA1"\)'
            ],
            'insecure_logging': [
                r'Log\.[weid]\([^)]+\)',
                r'System\.out\.print[ln]*\([^)]+\)'
            ]
        }
    
    def map_vulnerability_to_code(
        self, 
        vulnerability_title: str,
        vulnerability_description: str,
        plugin_name: str,
        apk_context = None
    ) -> Tuple[Optional[str], Optional[int], Optional[str]]:
        """
        Map a vulnerability to its source code location.
        
        Returns:
            Tuple of (file_path, line_number, code_snippet)
        """
        
        try:
            # Determine vulnerability category
            vuln_category = self._categorize_vulnerability(vulnerability_title, plugin_name)
            
            # Get decompiled source paths
            source_paths = self._get_source_paths(apk_context)
            
            if not source_paths:
                return None, None, None
            
            # Find matching file
            target_file = self._find_target_file(vuln_category, source_paths)
            
            if not target_file:
                return None, None, None
            
            # Extract line number and code snippet
            line_number, code_snippet = self._extract_code_details(
                target_file, vuln_category, vulnerability_description
            )
            
            # Make file path relative for better presentation
            relative_path = self._make_relative_path(target_file, source_paths[0])
            
            return relative_path, line_number, code_snippet
            
        except Exception as e:
            self.logger.debug(f"Code attribution failed for {vulnerability_title}: {e}")
            return None, None, None
    
    def _categorize_vulnerability(self, title: str, plugin_name: str) -> str:
        """Categorize vulnerability to determine search strategy."""
        
        title_lower = title.lower()
        plugin_lower = plugin_name.lower() if plugin_name else ""
        
        category_keywords = {
            'sql_injection': ['sql', 'injection', 'database'],
            'xss': ['xss', 'cross-site', 'script', 'webview'],
            'insecure_storage': ['storage', 'data', 'file', 'shared', 'external'],
            'insecure_logging': ['logging', 'log'],
            'crypto': ['crypto', 'hash', 'cipher', 'md5', 'sha1'],
            'exported_component': ['exported', 'component', 'activity', 'service', 'receiver'],
            'network': ['network', 'http', 'ssl', 'tls', 'cleartext']
        }
        
        for category, keywords in category_keywords.items():
            if any(keyword in title_lower or keyword in plugin_lower for keyword in keywords):
                return category
        
        return 'generic'
    
    def _get_source_paths(self, apk_context) -> List[str]:
        """Get decompiled source paths from APK context."""
        
        source_paths = []
        
        if not apk_context:
            return source_paths
        
        # Primary: Use decompiled_apk_dir from APK context
        if hasattr(apk_context, 'decompiled_apk_dir') and apk_context.decompiled_apk_dir:
            decompiled_path = str(apk_context.decompiled_apk_dir)
            if os.path.exists(decompiled_path):
                source_paths.append(decompiled_path)
        
        # Secondary: Check for JADX output directories
        jadx_base_dirs = [
            "/tmp/jadx_decompiled",
            "/tmp/jadx_output", 
            "/tmp/aods_jadx"
        ]
        
        for base_dir in jadx_base_dirs:
            if os.path.exists(base_dir):
                # Find the most recent directory
                for item in sorted(os.listdir(base_dir), reverse=True):
                    item_path = os.path.join(base_dir, item)
                    if os.path.isdir(item_path):
                        source_paths.append(item_path)
                        break
        
        # Tertiary: Check for extraction directories 
        extraction_dirs = [
            "/tmp/apk_extraction",
            "/tmp/static_analysis"
        ]
        
        for ext_dir in extraction_dirs:
            if os.path.exists(ext_dir):
                source_paths.append(ext_dir)
        
        return source_paths
    
    def _find_target_file(self, vuln_category: str, source_paths: List[str]) -> Optional[str]:
        """Find the target file based on vulnerability category."""
        
        patterns = self.location_patterns.get(vuln_category, [])
        
        if not patterns:
            return None
        
        for source_path in source_paths:
            for pattern in patterns:
                matches = self._find_files_matching_pattern(source_path, pattern)
                if matches:
                    # Return the first match
                    return matches[0]
        
        return None
    
    def _find_files_matching_pattern(self, root_path: str, pattern: str) -> List[str]:
        """Find files matching a pattern in the directory tree."""
        
        matches = []
        
        try:
            for root, dirs, files in os.walk(root_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Use regex matching for patterns
                    if re.search(pattern, file_path, re.IGNORECASE):
                        matches.append(file_path)
        
        except Exception as e:
            self.logger.debug(f"Error walking directory {root_path}: {e}")
        
        return matches
    
    def _extract_code_details(
        self, 
        file_path: str, 
        vuln_category: str, 
        description: str
    ) -> Tuple[Optional[int], Optional[str]]:
        """Extract line number and code snippet from the target file."""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Get code patterns for this vulnerability category
            patterns = self.code_snippet_patterns.get(vuln_category, [])
            
            # Look for specific patterns mentioned in the description
            description_patterns = self._extract_patterns_from_description(description)
            patterns.extend(description_patterns)
            
            # Search for matching lines
            for line_num, line in enumerate(lines, 1):
                line_clean = line.strip()
                
                for pattern in patterns:
                    if re.search(pattern, line_clean, re.IGNORECASE):
                        return line_num, line_clean
            
            # Fallback: Find first meaningful code line
            for line_num, line in enumerate(lines, 1):
                line_clean = line.strip()
                if (len(line_clean) > 10 and 
                    any(indicator in line_clean for indicator in ['.', '(', ')', '{', '}', ';']) and
                    not line_clean.startswith('//')):
                    return line_num, line_clean
            
            return None, None
            
        except Exception as e:
            self.logger.debug(f"Error extracting code details from {file_path}: {e}")
            return None, None
    
    def _extract_patterns_from_description(self, description: str) -> List[str]:
        """Extract code patterns mentioned in the vulnerability description."""
        
        patterns = []
        
        # Look for method calls or code fragments in the description
        method_pattern = r'(\w+\.\w+\([^)]*\))'
        method_matches = re.findall(method_pattern, description)
        
        for match in method_matches:
            # Escape special regex characters
            escaped_match = re.escape(match)
            patterns.append(escaped_match)
        
        # Look for quoted code fragments
        quoted_pattern = r'"([^"]+)"'
        quoted_matches = re.findall(quoted_pattern, description)
        
        for match in quoted_matches:
            if len(match) > 5 and any(c in match for c in ['.', '(', ')']):
                escaped_match = re.escape(match)
                patterns.append(escaped_match)
        
        return patterns
    
    def _make_relative_path(self, file_path: str, base_path: str) -> str:
        """Make file path relative to base path for better presentation."""
        
        try:
            # Convert to Path objects for better handling
            file_path_obj = Path(file_path)
            base_path_obj = Path(base_path)
            
            # Get relative path
            relative_path = file_path_obj.relative_to(base_path_obj)
            
            return str(relative_path)
            
        except Exception:
            # If relative path creation fails, return the filename
            return os.path.basename(file_path)


class DynamicCodeAttribution:
    """Main system for attributing dynamic vulnerabilities to source code."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.location_mapper = CodeLocationMapper()
    
    def enhance_vulnerabilities_with_code_attribution(
        self, 
        vulnerabilities: List[Any], 
        apk_context = None
    ) -> List[Any]:
        """Enhance vulnerabilities with proper code attribution."""
        
        enhanced_vulnerabilities = []
        
        for vuln in vulnerabilities:
            try:
                enhanced_vuln = self._enhance_single_vulnerability(vuln, apk_context)
                enhanced_vulnerabilities.append(enhanced_vuln)
            except Exception as e:
                self.logger.warning(f"Code attribution failed for vulnerability {getattr(vuln, 'id', 'unknown')}: {e}")
                enhanced_vulnerabilities.append(vuln)
        
        return enhanced_vulnerabilities
    
    def _enhance_single_vulnerability(self, vuln: Any, apk_context = None) -> Any:
        """Enhance a single vulnerability with code attribution."""
        
        # Map vulnerability to code location
        file_path, line_number, code_snippet = self.location_mapper.map_vulnerability_to_code(
            vuln.title,
            vuln.description, 
            getattr(vuln, 'plugin_name', ''),
            apk_context
        )
        
        # Update vulnerability with code attribution if found
        if file_path:
            vuln.context.file_path = file_path
            
        if line_number:
            vuln.context.line_number = line_number
            
        if code_snippet:
            # Enhance existing code snippet or replace placeholder
            current_snippet = vuln.context.code_snippet or ""
            if (not current_snippet or 
                current_snippet in ["Runtime analysis - no direct code snippet available", 
                                  "Runtime analysis - detailed code attribution pending"]):
                vuln.context.code_snippet = code_snippet
        
        return vuln
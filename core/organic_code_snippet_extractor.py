#!/usr/bin/env python3
"""
AODS Organic Code Snippet Extractor

Extracts REAL code snippets from decompiled APK source files without hardcoding.
Integrates with AODS's existing ContextualLocationEnhancer and source code analysis.

This replaces hardcoded code examples with actual code from the analyzed APK.
"""

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class OrganicCodeSnippetExtractor:
    """
    Extracts real code snippets from AODS decompiled sources organically.
    
    No hardcoded examples - only actual code from the analyzed APK.
    """
    
    def __init__(self, decompiled_path: Optional[str] = None):
        """
        Initialize the organic code snippet extractor.
        
        Args:
            decompiled_path: Path to decompiled APK sources (usually from JADX)
        """
        self.decompiled_path = decompiled_path
        self.logger = logger
        
        # Common source paths where AODS/JADX decompiles APKs
        self.source_search_paths = [
            decompiled_path,
            "sources",
            "jadx_output", 
            "decompiled",
            "apk_decompiled",
            "/tmp/jadx",
            "/tmp/aods_decompiled"
        ] if decompiled_path else []
        
        # File extensions to search for code
        self.code_extensions = ['.java', '.kt', '.xml']
        
    def extract_organic_snippet(self, vulnerability: Dict[str, Any]) -> Optional[str]:
        """
        Extract actual code snippet from decompiled sources for a vulnerability.
        
        Args:
            vulnerability: Vulnerability data from AODS
            
        Returns:
            Real code snippet from the APK, or None if not found
        """
        try:
            # Try multiple extraction strategies in order of preference
            
            # Strategy 1: Use existing code snippet if it looks real
            existing_snippet = self._get_existing_snippet(vulnerability)
            if existing_snippet and self._is_real_code(existing_snippet):
                return existing_snippet
            
            # Strategy 2: Extract from file_path and line_number if available  
            file_snippet = self._extract_from_file_location(vulnerability)
            if file_snippet:
                return file_snippet
                
            # Strategy 3: Search decompiled sources for relevant patterns
            pattern_snippet = self._search_for_vulnerability_pattern(vulnerability)
            if pattern_snippet:
                return pattern_snippet
                
            # Strategy 4: Use contextual location enhancer if available
            contextual_snippet = self._extract_with_contextual_enhancer(vulnerability)
            if contextual_snippet:
                return contextual_snippet
                
            return None
            
        except Exception as e:
            self.logger.debug(f"Organic snippet extraction failed: {e}")
            return None
    
    def _get_existing_snippet(self, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Check if vulnerability already has a real code snippet."""
        existing = vulnerability.get('code_snippet', '')
        
        # Check various fields where code might be stored
        if not existing:
            existing = vulnerability.get('source_code', '')
        if not existing:
            existing = vulnerability.get('matched_code', '')
        if not existing:
            # Check in evidence or context
            evidence = vulnerability.get('evidence', {})
            if isinstance(evidence, dict):
                existing = evidence.get('code_snippet', '') or evidence.get('source_code', '')
                
        return existing if existing else None
    
    def _is_real_code(self, snippet: str) -> bool:
        """
        Determine if a code snippet is real (from APK) vs hardcoded example.
        
        Args:
            snippet: Code snippet to analyze
            
        Returns:
            True if snippet appears to be real code from the APK
        """
        if not snippet or len(snippet.strip()) < 10:
            return False
            
        # Indicators of hardcoded examples (avoid these)
        hardcoded_indicators = [
            '// BEFORE (Vulnerable)',
            '// AFTER (Secure)',
            '// <- SECURITY ISSUE',
            '// <- WEAK ALGORITHM',
            '// Issue:',
            'BiometricPrompt.PromptInfo.Builder()',
            'MessageDigest.getInstance("MD5")',
            'android:debuggable="true"',
            'VulnerableActivity',
            'WEAK ALGORITHM',
            'SQL INJECTION'
        ]
        
        for indicator in hardcoded_indicators:
            if indicator in snippet:
                return False
        
        # Indicators of real code from APK
        real_code_indicators = [
            # Real package names (not generic examples)
            'import ',
            'package ',
            # Real Android API usage patterns
            'android.',
            'androidx.',
            'com.google.',
            # Actual method implementations
            '@Override',
            'public class',
            'private void',
            'protected ',
            # Real variable names (not generic)
            'this.',
            'super.',
            # Real resource references
            'R.',
            '@+id/',
            '@string/',
        ]
        
        real_indicators_found = sum(1 for indicator in real_code_indicators if indicator in snippet)
        
        # Must have at least 2 real code indicators and no hardcoded ones
        return real_indicators_found >= 2
    
    def _extract_from_file_location(self, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Extract code snippet from specific file and line number."""
        file_path = vulnerability.get('file_path', '')
        line_number = vulnerability.get('line_number', 0)
        
        if not file_path or not line_number:
            return None
            
        # Find the actual source file
        source_file = self._find_source_file(file_path)
        if not source_file:
            return None
            
        try:
            with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            # Extract snippet with context (5 lines before and after)
            start_line = max(0, line_number - 6)  # 5 lines before
            end_line = min(len(lines), line_number + 5)  # 5 lines after
            
            snippet_lines = lines[start_line:end_line]
            snippet = ''.join(snippet_lines).strip()
            
            # Add line numbers for context
            numbered_lines = []
            for i, line in enumerate(snippet_lines, start=start_line + 1):
                marker = " -> " if i == line_number else "    "
                numbered_lines.append(f"{i:3d}{marker}{line.rstrip()}")
            
            return '\n'.join(numbered_lines)
            
        except Exception as e:
            self.logger.debug(f"Failed to read source file {source_file}: {e}")
            return None
    
    def _find_source_file(self, file_path: str) -> Optional[str]:
        """Find the actual source file in decompiled directories."""
        if not file_path:
            return None
            
        # Try multiple search strategies
        search_locations = []
        
        # Add all configured search paths
        for search_path in self.source_search_paths:
            if search_path and os.path.exists(search_path):
                search_locations.extend([
                    os.path.join(search_path, file_path),
                    os.path.join(search_path, 'sources', file_path),
                    os.path.join(search_path, 'src', file_path),
                ])
        
        # Search in common AODS/JADX output locations
        common_paths = [
            f"sources/{file_path}",
            f"jadx_output/sources/{file_path}",
            f"decompiled/sources/{file_path}",
            f"/tmp/jadx/{file_path}",
            file_path  # Direct path
        ]
        search_locations.extend(common_paths)
        
        # Find first existing file
        for location in search_locations:
            if location and os.path.isfile(location):
                return location
                
        return None
    
    def _search_for_vulnerability_pattern(self, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Search decompiled sources for code patterns related to the vulnerability."""
        title = vulnerability.get('title', '').lower()
        description = vulnerability.get('description', '').lower()
        
        # Define search patterns based on vulnerability type
        search_patterns = []
        
        if 'biometric' in title:
            search_patterns.extend([
                r'FingerprintManager',
                r'BiometricPrompt',
                r'fingerprint',
                r'biometric'
            ])
        elif 'crypto' in title or 'md5' in description:
            search_patterns.extend([
                r'MessageDigest\.getInstance',
                r'Cipher\.getInstance',
                r'crypto',
                r'encrypt',
                r'hash'
            ])
        elif 'sql' in title and 'injection' in title:
            search_patterns.extend([
                r'rawQuery',
                r'execSQL',
                r'SELECT.*WHERE',
                r'database\.'
            ])
        elif 'network' in title or 'cleartext' in title:
            search_patterns.extend([
                r'HttpURLConnection',
                r'http://',
                r'cleartext',
                r'network_security_config'
            ])
        elif 'exported' in title or 'component' in title:
            search_patterns.extend([
                r'android:exported',
                r'<activity',
                r'<service',
                r'<receiver'
            ])
        elif 'debuggable' in title:
            search_patterns.extend([
                r'android:debuggable',
                r'<application',
                r'BuildConfig\.DEBUG'
            ])
        
        if not search_patterns:
            return None
            
        # Search all source files for these patterns
        return self._search_source_files_for_patterns(search_patterns)
    
    def _search_source_files_for_patterns(self, patterns: List[str]) -> Optional[str]:
        """Search all source files for given patterns."""
        if not self.source_search_paths:
            return None
            
        for search_path in self.source_search_paths:
            if not search_path or not os.path.exists(search_path):
                continue
                
            try:
                # Walk through all source files
                for root, dirs, files in os.walk(search_path):
                    for file in files:
                        if any(file.endswith(ext) for ext in self.code_extensions):
                            file_path = os.path.join(root, file)
                            snippet = self._search_file_for_patterns(file_path, patterns)
                            if snippet:
                                return snippet
                                
            except Exception as e:
                self.logger.debug(f"Error searching {search_path}: {e}")
                continue
                
        return None
    
    def _search_file_for_patterns(self, file_path: str, patterns: List[str]) -> Optional[str]:
        """Search a single file for vulnerability patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Check if any pattern matches
            for pattern in patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    # Extract snippet around first match
                    match = matches[0]
                    lines = content.split('\n')
                    
                    # Find line number of match
                    char_pos = match.start()
                    line_num = content[:char_pos].count('\n')
                    
                    # Extract context around the match
                    start_line = max(0, line_num - 3)
                    end_line = min(len(lines), line_num + 4)
                    
                    snippet_lines = lines[start_line:end_line]
                    
                    # Add line numbers and highlight the match
                    numbered_lines = []
                    for i, line in enumerate(snippet_lines, start=start_line + 1):
                        marker = " -> " if i == line_num + 1 else "    "
                        numbered_lines.append(f"{i:3d}{marker}{line}")
                    
                    return '\n'.join(numbered_lines)
                    
        except Exception as e:
            self.logger.debug(f"Error reading {file_path}: {e}")
            
        return None
    
    def _extract_with_contextual_enhancer(self, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Use AODS's ContextualLocationEnhancer if available."""
        try:
            from core.contextual_location_enhancer import ContextualLocationEnhancer
            
            # Get location info
            location = {
                'file_path': vulnerability.get('file_path', ''),
                'line_number': vulnerability.get('line_number', 1)
            }
            
            # Try to find source code
            file_path = self._find_source_file(location['file_path'])
            if not file_path:
                return None
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
                
            # Use AODS's contextual enhancer
            enhancer = ContextualLocationEnhancer()
            contextual_info = enhancer.enhance_location_with_context(location, source_code)
            
            return contextual_info.code_snippet if contextual_info else None
            
        except ImportError:
            self.logger.debug("ContextualLocationEnhancer not available")
            return None
        except Exception as e:
            self.logger.debug(f"Contextual enhancement failed: {e}")
            return None

def get_organic_code_snippet(vulnerability: Dict[str, Any], 
                           decompiled_path: Optional[str] = None) -> Optional[str]:
    """
    Convenience function to extract organic code snippet for a vulnerability.
    
    Args:
        vulnerability: AODS vulnerability data
        decompiled_path: Path to decompiled APK sources
        
    Returns:
        Real code snippet from APK, or None if not available
    """
    extractor = OrganicCodeSnippetExtractor(decompiled_path)
    return extractor.extract_organic_snippet(vulnerability)

def enhance_vulnerabilities_with_organic_code(vulnerabilities: List[Dict[str, Any]], 
                                           decompiled_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Enhance multiple vulnerabilities with organic code snippets.
    
    Args:
        vulnerabilities: List of AODS vulnerabilities
        decompiled_path: Path to decompiled APK sources
        
    Returns:
        Enhanced vulnerabilities with organic code snippets
    """
    extractor = OrganicCodeSnippetExtractor(decompiled_path)
    enhanced = []
    
    for vuln in vulnerabilities:
        enhanced_vuln = vuln.copy()
        
        # Only replace if no real code snippet exists
        existing_snippet = enhanced_vuln.get('code_snippet', '')
        if not existing_snippet or not extractor._is_real_code(existing_snippet):
            organic_snippet = extractor.extract_organic_snippet(vuln)
            if organic_snippet:
                enhanced_vuln['code_snippet'] = organic_snippet
                enhanced_vuln['code_snippet_source'] = 'organic_extraction'
                
        enhanced.append(enhanced_vuln)
    
    return enhanced



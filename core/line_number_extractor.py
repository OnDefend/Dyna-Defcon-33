#!/usr/bin/env python3
"""
Line Number Extractor
=====================

This module provides enhanced line number extraction capabilities for vulnerability reporting.
It addresses the issue of vulnerabilities defaulting to line_number: 1 by implementing 
sophisticated line number detection and context extraction.

CRITICAL: This replaces hardcoded line number defaults with actual extracted line numbers.
"""

import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

class LineNumberExtractor:
    """
    Enhanced line number extraction and context analysis for vulnerability reporting.
    
    This class provides:
    1. Accurate line number extraction from pattern matches
    2. Context-aware fallback when direct extraction fails
    3. Code snippet extraction around vulnerable lines
    4. Validation of extracted line numbers
    """
    
    def __init__(self):
        """Initialize the line number extractor."""
        self.logger = logging.getLogger(__name__)
        self._cache = {}  # Cache for file content analysis
        
        # Common patterns for finding code context
        self.method_patterns = [
            re.compile(r'^\s*(public|private|protected|static).*?\s+(\w+)\s*\(', re.MULTILINE),
            re.compile(r'^\s*def\s+(\w+)\s*\(', re.MULTILINE),  # Python
            re.compile(r'^\s*function\s+(\w+)\s*\(', re.MULTILINE),  # JavaScript
        ]
        
        self.class_patterns = [
            re.compile(r'^\s*(public\s+)?class\s+(\w+)', re.MULTILINE),
            re.compile(r'^\s*class\s+(\w+)', re.MULTILINE),  # Python/other
        ]
        
        self.logger.info("🔍 **LINE NUMBER EXTRACTOR INITIALIZED**")
    
    def extract_line_number_and_context(self, 
                                      content: str, 
                                      pattern_match: Any, 
                                      file_path: str = None) -> Dict[str, Any]:
        """
        Extract accurate line number and surrounding context from a pattern match.
        
        Args:
            content: Full file content
            pattern_match: Regex match object or start position
            file_path: Path to the file (for logging)
            
        Returns:
            Dictionary with line_number, method_name, class_name, vulnerable_code, surrounding_context
        """
        try:
            # Handle different input types
            if hasattr(pattern_match, 'start'):
                # Regex match object
                match_start = pattern_match.start()
                match_end = pattern_match.end()
                matched_text = pattern_match.group(0)
            elif isinstance(pattern_match, int):
                # Integer position
                match_start = pattern_match
                match_end = pattern_match
                matched_text = ""
            else:
                # Fallback
                match_start = 0
                match_end = 0
                matched_text = str(pattern_match)
            
            # **ACCURATE LINE NUMBER CALCULATION**
            line_number = content[:match_start].count('\n') + 1
            
            # Split content into lines for context extraction
            lines = content.split('\n')
            
            # Validate line number
            if line_number < 1:
                line_number = 1
            elif line_number > len(lines):
                line_number = len(lines)
            
            # **CONTEXT EXTRACTION**
            context_result = self._extract_context_info(lines, line_number, match_start, match_end)
            
            # **VULNERABLE CODE EXTRACTION**
            vulnerable_code = self._extract_vulnerable_code(lines, line_number, matched_text)
            
            # **SURROUNDING CONTEXT**
            surrounding_context = self._extract_surrounding_context(lines, line_number)
            
            result = {
                'line_number': line_number,
                'method_name': context_result.get('method_name', ''),
                'class_name': context_result.get('class_name', ''),
                'vulnerable_code': vulnerable_code,
                'surrounding_context': surrounding_context,
                'pattern_matches': [matched_text] if matched_text else [],
                'extraction_confidence': self._calculate_extraction_confidence(line_number, context_result)
            }
            
            self.logger.debug(f"🔍 Extracted line {line_number} from {file_path or 'content'}")
            
            return result
            
        except Exception as e:
            self.logger.warning(f"Line number extraction failed: {e}")
            return self._create_fallback_result(content, file_path)
    
    def extract_line_number_from_content_position(self, content: str, position: int) -> int:
        """
        Extract line number from a specific position in content.
        
        Args:
            content: Full file content
            position: Character position in content
            
        Returns:
            Line number (1-based)
        """
        if position < 0:
            return 1
        
        try:
            line_number = content[:position].count('\n') + 1
            
            # Validate against total lines
            total_lines = content.count('\n') + 1
            if line_number > total_lines:
                line_number = total_lines
            
            return max(1, line_number)
            
        except Exception:
            return 1
    
    def enhance_vulnerability_location(self, vulnerability: Dict[str, Any], 
                                     source_content: str = None) -> Dict[str, Any]:
        """
        Enhance a vulnerability's location information with accurate line numbers.
        
        Args:
            vulnerability: Vulnerability dictionary
            source_content: Source file content (if available)
            
        Returns:
            Enhanced vulnerability with accurate line numbers
        """
        original_line = vulnerability.get('line_number', 1)
        
        # If we have source content and evidence, try to find accurate line number
        if source_content and vulnerability.get('evidence'):
            evidence = vulnerability['evidence']
            
            # Try to find the evidence in the source content
            if evidence in source_content:
                position = source_content.find(evidence)
                accurate_line = self.extract_line_number_from_content_position(source_content, position)
                
                if accurate_line != original_line:
                    vulnerability['line_number'] = accurate_line
                    vulnerability['line_number_enhanced'] = True
                    vulnerability['original_line_number'] = original_line
                    
                    self.logger.info(f"🔍 **LINE NUMBER ENHANCED**: {original_line} → {accurate_line}")
                    
                    # Extract additional context
                    context = self.extract_line_number_and_context(source_content, position)
                    
                    if context.get('method_name'):
                        vulnerability['method_name'] = context['method_name']
                    if context.get('class_name'):
                        vulnerability['class_name'] = context['class_name']
                    if context.get('vulnerable_code'):
                        vulnerability['vulnerable_code'] = context['vulnerable_code']
        
        return vulnerability
    
    def _extract_context_info(self, lines: List[str], line_number: int, 
                            match_start: int, match_end: int) -> Dict[str, str]:
        """Extract method and class context for the line."""
        context = {'method_name': '', 'class_name': ''}
        
        # Search backwards from the current line to find method and class
        search_start = max(0, line_number - 50)  # Look up to 50 lines back
        search_content = '\n'.join(lines[search_start:line_number])
        
        # Find method name
        for pattern in self.method_patterns:
            matches = list(pattern.finditer(search_content))
            if matches:
                last_match = matches[-1]  # Get the closest method
                context['method_name'] = last_match.group(2) if last_match.lastindex >= 2 else last_match.group(1)
                break
        
        # Find class name
        for pattern in self.class_patterns:
            matches = list(pattern.finditer(search_content))
            if matches:
                last_match = matches[-1]  # Get the closest class
                context['class_name'] = last_match.group(2) if last_match.lastindex >= 2 else last_match.group(1)
                break
        
        return context
    
    def _extract_vulnerable_code(self, lines: List[str], line_number: int, matched_text: str) -> str:
        """Extract the vulnerable code snippet."""
        if line_number <= len(lines):
            line_index = line_number - 1
            current_line = lines[line_index].strip()
            
            # If we have matched text and it's in the current line, return that line
            if matched_text and matched_text in current_line:
                return current_line
            
            # Otherwise return the current line
            return current_line
        
        return matched_text if matched_text else ""
    
    def _extract_surrounding_context(self, lines: List[str], line_number: int, context_lines: int = 3) -> str:
        """Extract surrounding context around the vulnerable line."""
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(lines), line_number + context_lines)
        
        context_lines_list = lines[start_line:end_line]
        
        # Add line numbers for clarity
        numbered_lines = []
        for i, line in enumerate(context_lines_list):
            actual_line_num = start_line + i + 1
            marker = " --> " if actual_line_num == line_number else "     "
            numbered_lines.append(f"{actual_line_num:4d}{marker}{line}")
        
        return '\n'.join(numbered_lines)
    
    def _calculate_extraction_confidence(self, line_number: int, context: Dict[str, str]) -> float:
        """Calculate confidence score for the extraction."""
        confidence = 0.5  # Base confidence
        
        if line_number > 1:
            confidence += 0.2  # Not defaulted to line 1
        
        if context.get('method_name'):
            confidence += 0.15  # Found method context
        
        if context.get('class_name'):
            confidence += 0.15  # Found class context
        
        return min(1.0, confidence)
    
    def _create_fallback_result(self, content: str, file_path: str = None) -> Dict[str, Any]:
        """Create fallback result when extraction fails."""
        lines = content.split('\n')
        
        return {
            'line_number': 1,
            'method_name': '',
            'class_name': '',
            'vulnerable_code': lines[0] if lines else '',
            'surrounding_context': '\n'.join(lines[:5]) if lines else '',
            'pattern_matches': [],
            'extraction_confidence': 0.1
        }


def extract_line_number_from_match(content: str, match: Any) -> int:
    """
    **CONVENIENCE FUNCTION**: Extract line number from a regex match.
    
    This should replace all instances of hardcoded line_number=1.
    
    Args:
        content: Full file content
        match: Regex match object or position
        
    Returns:
        Accurate line number (1-based)
    """
    extractor = LineNumberExtractor()
    result = extractor.extract_line_number_and_context(content, match)
    return result['line_number']

def enhance_vulnerability_with_line_context(vulnerability: Dict[str, Any], 
                                           source_content: str = None) -> Dict[str, Any]:
    """
    **CONVENIENCE FUNCTION**: Enhance vulnerability with accurate line context.
    
    This should be used to replace hardcoded defaults throughout the pipeline.
    """
    extractor = LineNumberExtractor()
    return extractor.enhance_vulnerability_location(vulnerability, source_content)
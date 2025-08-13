#!/usr/bin/env python3
"""
Base Security Analyzer Framework for AODS

Core security analysis framework providing foundational capabilities
for Android application security assessment and vulnerability detection.
"""

import logging
import re
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path
import hashlib
import mimetypes
from core.enhanced_config_manager import EnhancedConfigManager

class BaseSecurityAnalyzer(ABC):
    """
    Abstract base class for all AODS security analyzers.
    
    Provides:
    - Standardized finding format
    - Common utility functions
    - Error handling patterns
    - Performance monitoring
    - Edge case management
    """
    
    def __init__(self, config_manager: Optional[EnhancedConfigManager] = None):
        """
        Initialize base analyzer
        
        Args:
            config_manager: Configuration manager instance (creates new if None)
        """
        self.config_manager = config_manager or EnhancedConfigManager()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.findings = []
        
        # Performance tracking
        self.analysis_stats = {
            'files_analyzed': 0,
            'patterns_matched': 0,
            'errors_encountered': 0,
            'analysis_time': 0.0,
            'start_time': None
        }
        
        # Edge case handling settings
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        self.max_line_length = 50000  # 50K characters
        self.context_lines = 3
        self.binary_threshold = 0.3  # 30% non-text characters
        
        self.logger.debug(f"Initialized {self.__class__.__name__}")
    
    @abstractmethod
    def analyze(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """
        Main analysis method - must be implemented by subclasses
        
        Returns:
            List of security findings
        """
        # Default implementation - should be overridden by subclasses
        self.start_analysis()
        try:
            # Perform basic analysis
            findings = self._perform_basic_analysis()
            self.findings.extend(findings)
            
            # Update analysis stats
            self.analysis_stats['findings_count'] = len(self.findings)
            self.analysis_stats['analysis_completed'] = True
            
            return self.findings
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            self.analysis_stats['analysis_failed'] = True
            return []
        finally:
            self.end_analysis()
    
    def _perform_basic_analysis(self):
        """Perform basic security analysis - should be overridden by subclasses."""
        return []
    
    def start_analysis(self):
        """Start timing analysis performance"""
        self.analysis_stats['start_time'] = time.time()
        self.findings.clear()
    
    def end_analysis(self) -> Dict[str, Any]:
        """End timing and return performance statistics"""
        if self.analysis_stats['start_time']:
            self.analysis_stats['analysis_time'] = time.time() - self.analysis_stats['start_time']
        
        return {
            'findings_count': len(self.findings),
            'performance_stats': self.analysis_stats.copy(),
            'analyzer_name': self.__class__.__name__
        }
    
    def _create_finding(self, **kwargs) -> Dict[str, Any]:
        """
        Create standardized finding dictionary with comprehensive metadata
        
        Args:
            **kwargs: Finding attributes
            
        Returns:
            Standardized finding dictionary
        """
        # Generate unique finding ID
        finding_id = self._generate_finding_id(kwargs)
        
        # Create base finding structure
        finding = {
            # Core identification
            'id': finding_id,
            'analyzer': self.__class__.__name__,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': '1.0',
            
            # Finding classification
            'type': kwargs.get('type', 'SECURITY_ISSUE'),
            'severity': self._validate_severity(kwargs.get('severity', 'MEDIUM')),
            'confidence': self._validate_confidence(kwargs.get('confidence', self._calculate_default_confidence(kwargs))),
            'category': kwargs.get('category', 'GENERAL'),
            
            # Finding details
            'title': kwargs.get('title', 'Security Issue Detected'),
            'description': kwargs.get('description', ''),
            'reason': kwargs.get('reason', ''),
            'recommendation': kwargs.get('recommendation', ''),
            
            # Location information
            'location': kwargs.get('location', ''),
            'file_path': kwargs.get('file_path', ''),
            'line_number': kwargs.get('line_number', 0),
            'column_number': kwargs.get('column_number', 0),
            
            # Evidence
            'evidence': kwargs.get('evidence', ''),
            'context': kwargs.get('context', ''),
            'pattern_matched': kwargs.get('pattern_matched', ''),
            
            # References
            'cwe_id': kwargs.get('cwe_id', ''),
            'owasp_category': kwargs.get('owasp_category', ''),
            'references': kwargs.get('references', []),
            
            # Risk assessment
            'exploitability': kwargs.get('exploitability', 'UNKNOWN'),
            'impact': kwargs.get('impact', 'UNKNOWN'),
            'false_positive_risk': kwargs.get('false_positive_risk', 'MEDIUM'),
            
            # Additional metadata
            'tags': kwargs.get('tags', []),
            'custom_fields': kwargs.get('custom_fields', {})
        }
        
        # Add analyzer-specific fields
        for key, value in kwargs.items():
            if key not in finding and not key.startswith('_'):
                finding[key] = value
        
        return finding
    
    def _generate_finding_id(self, finding_data: Dict[str, Any]) -> str:
        """Generate unique finding ID based on content"""
        # Create deterministic hash from key finding attributes
        key_data = {
            'analyzer': self.__class__.__name__,
            'type': finding_data.get('type', ''),
            'location': finding_data.get('location', ''),
            'evidence': finding_data.get('evidence', ''),
            'pattern': finding_data.get('pattern_matched', '')
        }
        
        hash_input = str(sorted(key_data.items()))
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    
    def _validate_severity(self, severity: str) -> str:
        """Validate and normalize severity level"""
        valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO']
        severity_upper = str(severity).upper()
        
        if severity_upper in valid_severities:
            return severity_upper
        
        # Map common alternatives
        severity_mapping = {
            'INFORMATIONAL': 'INFO',
            'WARN': 'MEDIUM',
            'WARNING': 'MEDIUM',
            'ERROR': 'HIGH',
            'SEVERE': 'CRITICAL',
            'MINOR': 'LOW',
            'MAJOR': 'HIGH'
        }
        
        return severity_mapping.get(severity_upper, 'MEDIUM')
    
    def _calculate_default_confidence(self, finding_data: Dict[str, Any]) -> float:
        """Calculate dynamic default confidence based on finding characteristics"""
        base_confidence = 0.6
        
        # Adjust based on evidence quality
        evidence = str(finding_data.get('evidence', ''))
        if len(evidence) > 100:  # Detailed evidence
            base_confidence += 0.15
        elif len(evidence) > 50:  # Moderate evidence
            base_confidence += 0.1
        
        # Adjust based on severity
        severity = finding_data.get('severity', 'MEDIUM')
        if severity == 'CRITICAL':
            base_confidence += 0.2
        elif severity == 'HIGH':
            base_confidence += 0.15
        elif severity == 'MEDIUM':
            base_confidence += 0.1
        
        # Adjust based on analyzer type
        analyzer_name = self.__class__.__name__.lower()
        if 'crypto' in analyzer_name or 'security' in analyzer_name:
            base_confidence += 0.1
        
        # Adjust based on pattern specificity
        pattern = str(finding_data.get('pattern_matched', ''))
        if len(pattern) > 20:  # Specific pattern
            base_confidence += 0.1
        
        return max(0.3, min(0.95, base_confidence))
    
    def _validate_confidence(self, confidence: Union[str, float, int]) -> float:
        """Validate and normalize confidence score"""
        try:
            conf_float = float(confidence)
            return max(0.0, min(1.0, conf_float))
        except (ValueError, TypeError):
            return 0.7  # Dynamic default confidence
    
    def _get_line_number(self, content: str, position: int) -> int:
        """
        Get line number for a position in content with error handling
        
        Args:
            content: Text content
            position: Character position
            
        Returns:
            Line number (1-indexed)
        """
        try:
            if position < 0 or position > len(content):
                return 1
            
            return content[:position].count('\n') + 1
        except Exception:
            return 1
    
    def _get_column_number(self, content: str, position: int) -> int:
        """
        Get column number for a position in content
        
        Args:
            content: Text content
            position: Character position
            
        Returns:
            Column number (1-indexed)
        """
        try:
            if position < 0 or position > len(content):
                return 1
            
            last_newline = content.rfind('\n', 0, position)
            return position - last_newline
        except Exception:
            return 1
    
    def _extract_context(self, content: str, start: int, end: int, 
                        context_lines: int = None) -> str:
        """
        Extract code context around a match with comprehensive error handling
        
        Args:
            content: Source content
            start: Start position of match
            end: End position of match
            context_lines: Number of context lines (uses default if None)
            
        Returns:
            Formatted context string with line numbers
        """
        try:
            if not content or start < 0 or end > len(content) or start > end:
                return ""
            
            lines = content.split('\n')
            if not lines:
                return ""
            
            context_lines = context_lines or self.context_lines
            
            # Get line numbers for match
            start_line = self._get_line_number(content, start) - 1  # 0-indexed
            end_line = self._get_line_number(content, end) - 1
            
            # Calculate context boundaries
            context_start = max(0, start_line - context_lines)
            context_end = min(len(lines), end_line + context_lines + 1)
            
            # Build context with line numbers
            context_lines_formatted = []
            for i in range(context_start, context_end):
                if i >= len(lines):
                    break
                    
                # Mark the actual match lines
                marker = ">>> " if start_line <= i <= end_line else "    "
                line_content = lines[i]
                
                # Truncate extremely long lines
                if len(line_content) > self.max_line_length:
                    line_content = line_content[:self.max_line_length] + "... [TRUNCATED]"
                
                context_lines_formatted.append(f"{marker}{i+1:4}: {line_content}")
            
            return '\n'.join(context_lines_formatted)
            
        except Exception as e:
            self.logger.debug(f"Error extracting context: {e}")
            return f"[Context extraction failed: {str(e)}]"
    
    def _is_binary_content(self, content: Union[str, bytes]) -> bool:
        """
        Check if content is binary (not suitable for text analysis)
        
        Args:
            content: Content to check
            
        Returns:
            True if content appears to be binary
        """
        try:
            if isinstance(content, bytes):
                # Check for null bytes and high ratio of non-printable chars
                if b'\x00' in content:
                    return True
                
                # Sample first 8KB for performance
                sample = content[:8192]
                if not sample:
                    return False
                
                # Count printable characters
                printable_count = sum(1 for byte in sample if 32 <= byte <= 126 or byte in [9, 10, 13])
                ratio = printable_count / len(sample)
                
                return ratio < (1 - self.binary_threshold)
            
            elif isinstance(content, str):
                # Check for unusual Unicode characters that might indicate binary
                if '\x00' in content:
                    return True
                
                # Check ratio of printable characters
                sample = content[:8192]
                if not sample:
                    return False
                
                printable_count = sum(1 for char in sample if char.isprintable() or char in ['\t', '\n', '\r'])
                ratio = printable_count / len(sample)
                
                return ratio < (1 - self.binary_threshold)
            
            return False
            
        except Exception:
            # If we can't determine, assume it's text
            return False
    
    def _safe_file_read(self, file_path: Union[str, Path]) -> Tuple[Optional[str], bool]:
        """
        Safely read file content with comprehensive error handling
        
        Args:
            file_path: Path to file
            
        Returns:
            Tuple of (content, success_flag)
        """
        try:
            path_obj = Path(file_path)
            
            # Check if file exists and is readable
            if not path_obj.exists():
                self.logger.debug(f"File does not exist: {file_path}")
                return None, False
            
            if not path_obj.is_file():
                self.logger.debug(f"Path is not a file: {file_path}")
                return None, False
            
            # Check file size
            file_size = path_obj.stat().st_size
            if file_size > self.max_file_size:
                self.logger.warning(f"File too large ({file_size} bytes): {file_path}")
                return None, False
            
            if file_size == 0:
                self.logger.debug(f"Empty file: {file_path}")
                return "", True
            
            # Try to detect file type
            mime_type, _ = mimetypes.guess_type(str(path_obj))
            if mime_type and mime_type.startswith('image/'):
                self.logger.debug(f"Skipping image file: {file_path}")
                return None, False
            
            # Read file with multiple encoding attempts
            encodings = ['utf-8', 'utf-16', 'latin-1', 'cp1252']
            
            for encoding in encodings:
                try:
                    with open(path_obj, 'r', encoding=encoding, errors='replace') as f:
                        content = f.read()
                    
                    # Check if content is binary
                    if self._is_binary_content(content):
                        self.logger.debug(f"Binary content detected: {file_path}")
                        return None, False
                    
                    self.logger.debug(f"Successfully read file with {encoding}: {file_path}")
                    return content, True
                    
                except UnicodeDecodeError:
                    continue
                except Exception as e:
                    self.logger.debug(f"Error reading with {encoding}: {e}")
                    continue
            
            # If all encodings fail, try binary mode and check
            try:
                with open(path_obj, 'rb') as f:
                    raw_content = f.read()
                
                if self._is_binary_content(raw_content):
                    self.logger.debug(f"Binary file confirmed: {file_path}")
                    return None, False
                
                # Try to decode as UTF-8 with error replacement
                content = raw_content.decode('utf-8', errors='replace')
                return content, True
                
            except Exception as e:
                self.logger.error(f"Failed to read file {file_path}: {e}")
                return None, False
                
        except Exception as e:
            self.logger.error(f"Unexpected error reading file {file_path}: {e}")
            self.analysis_stats['errors_encountered'] += 1
            return None, False
    
    def _normalize_file_path(self, file_path: Union[str, Path]) -> str:
        """
        Normalize file path for consistent reporting
        
        Args:
            file_path: File path to normalize
            
        Returns:
            Normalized path string
        """
        try:
            path_obj = Path(file_path)
            return str(path_obj.resolve())
        except Exception:
            return str(file_path)
    
    def _should_analyze_file(self, file_path: Union[str, Path]) -> bool:
        """
        Determine if file should be analyzed based on type and characteristics
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file should be analyzed
        """
        try:
            path_obj = Path(file_path)
            
            # Skip non-existent files
            if not path_obj.exists() or not path_obj.is_file():
                return False
            
            # Skip empty files
            if path_obj.stat().st_size == 0:
                return False
            
            # Skip files that are too large
            if path_obj.stat().st_size > self.max_file_size:
                return False
            
            # Check file extension
            suffix = path_obj.suffix.lower()
            
            # Skip obviously binary file types
            binary_extensions = {
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
                '.mp3', '.mp4', '.avi', '.mov', '.wav',
                '.zip', '.rar', '.7z', '.tar', '.gz',
                '.exe', '.dll', '.so', '.dylib',
                '.pdf', '.doc', '.docx', '.xls', '.xlsx'
            }
            
            if suffix in binary_extensions:
                return False
            
            # Prefer text-based files
            text_extensions = {
                '.java', '.kt', '.xml', '.json', '.js', '.ts',
                '.html', '.htm', '.css', '.txt', '.md',
                '.properties', '.yml', '.yaml', '.sql',
                '.sh', '.py', '.rb', '.php', '.c', '.cpp', '.h'
            }
            
            # If it's a known text extension, analyze it
            if suffix in text_extensions:
                return True
            
            # For unknown extensions, try to detect content type
            mime_type, _ = mimetypes.guess_type(str(path_obj))
            if mime_type:
                return mime_type.startswith('text/') or 'xml' in mime_type or 'json' in mime_type
            
            # Default to analyzing if we can't determine
            return True
            
        except Exception as e:
            self.logger.debug(f"Error checking file {file_path}: {e}")
            return False
    
    def add_finding(self, finding: Dict[str, Any]):
        """
        Add a finding to the results with validation
        
        Args:
            finding: Finding dictionary to add
        """
        try:
            # Validate finding structure
            required_fields = ['id', 'type', 'severity', 'title']
            for field in required_fields:
                if field not in finding:
                    self.logger.warning(f"Finding missing required field '{field}': {finding}")
                    return
            
            # Ensure severity is valid
            finding['severity'] = self._validate_severity(finding['severity'])
            
            # Ensure confidence is valid
            if 'confidence' in finding:
                finding['confidence'] = self._validate_confidence(finding['confidence'])
            
            self.findings.append(finding)
            self.analysis_stats['patterns_matched'] += 1
            
        except Exception as e:
            self.logger.error(f"Error adding finding: {e}")
            self.analysis_stats['errors_encountered'] += 1
    
    def get_findings_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of findings
        
        Returns:
            Summary dictionary
        """
        if not self.findings:
            return {
                'total_findings': 0,
                'by_severity': {},
                'by_type': {},
                'by_confidence': {},
                'unique_files': 0
            }
        
        # Count by severity
        severity_counts = {}
        type_counts = {}
        confidence_ranges = {'high': 0, 'medium': 0, 'low': 0}
        unique_files = set()
        
        for finding in self.findings:
            # Count by severity
            severity = finding.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by type
            finding_type = finding.get('type', 'UNKNOWN')
            type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
            
            # Count by confidence range
            confidence = finding.get('confidence', 0.5)
            if confidence >= 0.8:
                confidence_ranges['high'] += 1
            elif confidence >= 0.5:
                confidence_ranges['medium'] += 1
            else:
                confidence_ranges['low'] += 1
            
            # Track unique files
            file_path = finding.get('file_path', '')
            if file_path:
                unique_files.add(file_path)
        
        return {
            'total_findings': len(self.findings),
            'by_severity': severity_counts,
            'by_type': type_counts,
            'by_confidence': confidence_ranges,
            'unique_files': len(unique_files),
            'analysis_stats': self.analysis_stats
        }
    
    def __str__(self) -> str:
        """String representation for debugging"""
        return f"{self.__class__.__name__}(findings={len(self.findings)})"
    
    def __repr__(self) -> str:
        return self.__str__()

if __name__ == "__main__":
    # Test the base analyzer
    import tempfile
    import os
    
    logging.basicConfig(level=logging.DEBUG)
    
    class TestAnalyzer(BaseSecurityAnalyzer):
        def analyze(self, content: str, file_path: str) -> List[Dict[str, Any]]:
            self.start_analysis()
            
            # Test finding creation
            test_finding = self._create_finding(
                type='TEST_FINDING',
                severity='HIGH',
                title='Test Security Issue',
                description='This is a test finding',
                location=f"{file_path}:1",
                evidence='test evidence',
                cwe_id='CWE-79'
            )
            
            self.add_finding(test_finding)
            
            stats = self.end_analysis()
            return self.findings
    
    # Test with temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
        f.write('public class Test {\n    // Test content\n}')
        temp_file = f.name
    
    try:
        analyzer = TestAnalyzer()
        
        # Test file reading
        content, success = analyzer._safe_file_read(temp_file)
        print(f"File read: {success}, content length: {len(content) if content else 0}")
        
        # Test analysis
        findings = analyzer.analyze(content, temp_file)
        print(f"Findings generated: {len(findings)}")
        
        # Test summary
        summary = analyzer.get_findings_summary()
        print(f"Summary: {summary}")
        
        # Test context extraction
        if content:
            context = analyzer._extract_context(content, 0, 10)
            print(f"Context example:\n{context}")
        
        print("Base analyzer test completed successfully!")
        
    finally:
        # Cleanup
        os.unlink(temp_file) 
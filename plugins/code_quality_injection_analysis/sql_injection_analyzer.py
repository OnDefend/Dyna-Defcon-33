"""
SQL Injection Analyzer for Code Quality & Injection Analysis Plugin

This module implements MASTG-TEST-0019: Testing SQL Injection
Detects SQL injection vulnerabilities in Android applications.
"""

import re
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path

from .data_structures import CodeVulnerability, PatternMatch, VulnerabilityType, SeverityLevel
from .pattern_libraries import InjectionPatterns

logger = logging.getLogger(__name__)

class SQLInjectionAnalyzer:
    """Analyzes code for SQL injection vulnerabilities"""
    
    def __init__(self):
        """Initialize SQL injection analyzer"""
        self.pattern_library = InjectionPatterns()
        self.sql_patterns = self.pattern_library.get_sql_injection_patterns()
        self.logger = logging.getLogger(__name__)
        
    def analyze_sql_injection(self, file_path: str, content: str) -> List[CodeVulnerability]:
        """
        Analyze file content for SQL injection vulnerabilities
        
        Args:
            file_path: Path to the file being analyzed
            content: File content to analyze
            
        Returns:
            List[CodeVulnerability]: List of found SQL injection vulnerabilities
        """
        vulnerabilities = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('*'):
                continue
                
            # Check each SQL injection pattern
            for pattern in self.sql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerability = self._create_sql_vulnerability(
                        file_path, line, line_num, pattern
                    )
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _create_sql_vulnerability(self, file_path: str, line: str, line_num: int, pattern: str) -> Optional[CodeVulnerability]:
        """Create a SQL injection vulnerability object"""
        try:
            # Extract SQL query if possible
            sql_query = self._extract_sql_query(line)
            
            # Generate payload
            payload = self._generate_sql_injection_payload(line)
            
            # Determine confidence based on pattern specificity
            confidence = self._calculate_confidence(line, pattern)
            
            # Create vulnerability
            vulnerability = CodeVulnerability(
                vuln_type=VulnerabilityType.SQL_INJECTION.value,
                location=file_path,
                value=sql_query or line.strip(),
                line_number=line_num,
                severity=SeverityLevel.HIGH.value,
                description=f"Potential SQL injection vulnerability detected in {Path(file_path).name}",
                payload=payload,
                context=line.strip(),
                confidence=confidence
            )
            
            return vulnerability
            
        except Exception as e:
            self.logger.error(f"Error creating SQL vulnerability: {e}")
            return None
    
    def _extract_sql_query(self, line: str) -> Optional[str]:
        """Extract SQL query from code line"""
        # Look for string literals containing SQL keywords
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER']
        
        # Try to extract string content
        string_patterns = [
            r'"([^"]*(?:' + '|'.join(sql_keywords) + ')[^"]*)"',
            r"'([^']*(?:" + '|'.join(sql_keywords) + ")[^']*)'",
        ]
        
        for pattern in string_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _generate_sql_injection_payload(self, line: str) -> str:
        """Generate SQL injection payload for testing"""
        # Basic SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT 1,2,3 --",
            "admin'--",
            "' OR 1=1 --"
        ]
        
        # Return first payload for now (could be enhanced with context-aware selection)
        return payloads[0]
    
    def _calculate_confidence(self, line: str, pattern: str) -> float:
        """Calculate confidence score for SQL injection detection"""
        confidence = 0.6  # Base confidence
        
        # Increase confidence for specific indicators
        if any(keyword in line.upper() for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
            confidence += 0.2
        
        if 'rawQuery' in line or 'execSQL' in line:
            confidence += 0.2
        
        if '+' in line and any(char in line for char in ['"', "'"]):
            confidence += 0.1
        
        if 'WHERE' in line.upper() and ('+' in line or 'concat' in line.lower()):
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def check_sql_injection_patterns(self, file_path: str, content: str) -> List[PatternMatch]:
        """
        Check for SQL injection patterns and return detailed matches
        
        Args:
            file_path: Path to the file being analyzed
            content: File content to analyze
            
        Returns:
            List[PatternMatch]: List of pattern matches found
        """
        matches = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//'):
                continue
                
            for pattern in self.sql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    match = PatternMatch(
                        pattern=pattern,
                        line=line,
                        line_number=line_num,
                        file_path=file_path,
                        confidence=self._calculate_confidence(line, pattern)
                    )
                    matches.append(match)
        
        return matches
    
    def validate_sql_context(self, line: str, context_lines: List[str]) -> bool:
        """Validate if the SQL pattern is in a valid vulnerability context"""
        # Check surrounding context for validation patterns
        context_text = ' '.join(context_lines).lower()
        
        # Look for input validation or parameterized queries
        safe_patterns = [
            'preparedstatement',
            'bind',
            'parameter',
            'sanitize',
            'escape',
            'validate'
        ]
        
        for safe_pattern in safe_patterns:
            if safe_pattern in context_text:
                return False  # Likely safe
        
        return True  # Potentially vulnerable
    
    def get_remediation_advice(self, vulnerability: CodeVulnerability) -> str:
        """Get specific remediation advice for SQL injection vulnerability"""
        advice = [
            "Use parameterized queries or prepared statements",
            "Validate and sanitize all user input",
            "Use ORM frameworks that handle SQL injection prevention",
            "Implement input length restrictions",
            "Use allowlist validation for input parameters",
            "Avoid dynamic SQL query construction with user input"
        ]
        
        return "; ".join(advice)
    
    def get_test_cases(self, vulnerability: CodeVulnerability) -> List[str]:
        """Generate test cases for SQL injection vulnerability"""
        test_cases = [
            "Test with single quote: '",
            "Test with SQL comment: --",
            "Test with UNION injection: ' UNION SELECT 1,2,3--",
            "Test with boolean injection: ' OR '1'='1",
            "Test with time-based injection: '; WAITFOR DELAY '00:00:05'--",
            "Test with error-based injection: ' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
        ]
        
        return test_cases 
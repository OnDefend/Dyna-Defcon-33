#!/usr/bin/env python3
"""
Enhanced False Positive Reduction with Accuracy Preservation
"""

import re
from typing import Dict, List, Any, Optional

class EnhancedFalsePositiveFilter:
    """Enhanced filter that reduces false positives while preserving real vulnerabilities."""
    
    def __init__(self):
        self.critical_vulnerability_patterns = [
            r'permission:\s*null',
            r'cleartext\s+traffic.*enabled',
            r'mastg.*fail',
            r'api\s+key.*detected',
            r'hardcoded.*credential',
            r'sql\s+injection',
            r'path\s+traversal',
            r'xss\s+vulnerability'
        ]
        
        self.definitive_false_positive_patterns = [
            r'no\s+vulnerabilities?\s+(?:found|detected)',
            r'analysis\s+completed\s+successfully',
            r'all\s+(?:tests?\s+)?passed',
            r'status:\s*pass(?:ed)?',
            r'✅.*(?:success|complete)',
            r'0\s+vulnerabilities'
        ]
    
    def is_likely_vulnerability(self, content: str, title: str = "") -> Dict[str, Any]:
        """Determine if content represents a likely vulnerability."""
        full_text = f"{content} {title}".lower()
        
        # Check for critical vulnerability patterns first
        for pattern in self.critical_vulnerability_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                return {
                    'is_vulnerability': True,
                    'confidence': 0.9,
                    'reason': f'Critical pattern detected: {pattern}',
                    'pattern_matched': pattern
                }
        
        # Check for definitive false positive patterns
        for pattern in self.definitive_false_positive_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                return {
                    'is_vulnerability': False,
                    'confidence': 0.95,
                    'reason': f'False positive pattern: {pattern}',
                    'pattern_matched': pattern
                }
        
        # Look for general vulnerability indicators
        vuln_indicators = [
            'vulnerability', 'security issue', 'exposed', 'insecure', 
            'weak', 'missing', 'unauthorized', 'bypass'
        ]
        
        indicator_count = sum(1 for indicator in vuln_indicators if indicator in full_text)
        
        if indicator_count >= 2:
            return {
                'is_vulnerability': True,
                'confidence': 0.7,
                'reason': f'Multiple vulnerability indicators ({indicator_count})',
                'indicators_found': [ind for ind in vuln_indicators if ind in full_text]
            }
        elif indicator_count == 1:
            return {
                'is_vulnerability': True,
                'confidence': 0.5,
                'reason': 'Single vulnerability indicator found',
                'indicators_found': [ind for ind in vuln_indicators if ind in full_text]
            }
        
        # Default to non-vulnerability
        return {
            'is_vulnerability': False,
            'confidence': 0.6,
            'reason': 'No clear vulnerability indicators',
            'indicators_found': []
        }

# Global instance for easy access
enhanced_filter = EnhancedFalsePositiveFilter()

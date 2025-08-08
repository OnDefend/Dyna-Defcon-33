#!/usr/bin/env python3
"""
Resource Analyzer

Analyzes Android resource files for encrypted content and decryption patterns.
"""

import logging
import re
import base64
from typing import Dict, List, Any, Optional, Set
from pathlib import Path

logger = logging.getLogger(__name__)

class ResourceDecryptionAnalyzer:
    """Analyzes Android resource files for encryption and decryption patterns."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the resource analyzer."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Patterns for encrypted content detection
        self.encryption_patterns = {
            'base64_content': r'[A-Za-z0-9+/]{20,}={0,2}',
            'hex_content': r'[0-9a-fA-F]{32,}',
            'encrypted_string': r'encrypted[_\-]?(?:data|string|content)',
            'cipher_reference': r'(?:aes|des|rsa|cipher)[_\-]?(?:key|data|encrypted)',
            'obfuscated_string': r'[A-Za-z0-9]{16,}(?:\$[A-Za-z0-9]+)?'
        }
        
        # Resource file types to analyze
        self.resource_extensions = {'.xml', '.json', '.properties', '.txt'}
    
    def analyze_resource_directory(self, resource_dir: Path) -> List[Dict[str, Any]]:
        """Analyze all resource files in a directory."""
        results = []
        
        if not resource_dir.exists():
            self.logger.warning(f"Resource directory does not exist: {resource_dir}")
            return results
        
        resource_files = []
        for ext in self.resource_extensions:
            resource_files.extend(resource_dir.rglob(f"*{ext}"))
        
        self.logger.info(f"Found {len(resource_files)} resource files to analyze")
        
        for resource_file in resource_files:
            result = self.analyze_resource_file(resource_file)
            if result['findings']:  # Only include files with findings
                results.append(result)
        
        return results
    
    def analyze_resource_file(self, resource_file: Path) -> Dict[str, Any]:
        """Analyze a single resource file for encrypted content."""
        try:
            with open(resource_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            findings = []
            
            # Check for encryption patterns
            for pattern_name, pattern in self.encryption_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    matched_text = match.group()
                    
                    # Additional validation for potential encrypted content
                    confidence = self._calculate_confidence(pattern_name, matched_text, content)
                    
                    if confidence > 0.3:  # Only report high-confidence findings
                        finding = {
                            'type': 'encrypted_resource_content',
                            'pattern_name': pattern_name,
                            'file': str(resource_file),
                            'line_number': line_number,
                            'matched_text': matched_text[:100] + '...' if len(matched_text) > 100 else matched_text,
                            'severity': self._assess_severity(pattern_name, matched_text),
                            'confidence': confidence,
                            'analysis': self._analyze_content(pattern_name, matched_text)
                        }
                        findings.append(finding)
            
            return {
                'file': str(resource_file),
                'file_type': resource_file.suffix,
                'findings': findings,
                'summary': {
                    'total_patterns': len(findings),
                    'file_size': resource_file.stat().st_size if resource_file.exists() else 0
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing resource file {resource_file}: {e}")
            return {
                'file': str(resource_file),
                'findings': [],
                'error': str(e)
            }
    
    def _calculate_confidence(self, pattern_name: str, matched_text: str, full_content: str) -> float:
        """Calculate confidence score for encrypted content detection."""
        base_confidence = 0.3
        
        # Pattern-specific confidence adjustments
        if pattern_name == 'base64_content':
            # Check if it's valid base64
            try:
                base64.b64decode(matched_text)
                base_confidence += 0.3
            except:
                base_confidence -= 0.1
            
            # Longer base64 strings are more likely to be encrypted
            if len(matched_text) > 100:
                base_confidence += 0.2
        
        elif pattern_name == 'hex_content':
            # Even-length hex strings are more suspicious
            if len(matched_text) % 2 == 0:
                base_confidence += 0.2
            
            # Very long hex strings are likely encrypted
            if len(matched_text) > 64:
                base_confidence += 0.3
        
        elif pattern_name in ['encrypted_string', 'cipher_reference']:
            # These are explicit indicators
            base_confidence += 0.4
        
        # Context clues in surrounding content
        context_keywords = ['password', 'secret', 'key', 'token', 'credential']
        for keyword in context_keywords:
            if keyword in full_content.lower():
                base_confidence += 0.1
                break
        
        return min(1.0, base_confidence)
    
    def _assess_severity(self, pattern_name: str, matched_text: str) -> str:
        """Assess severity based on pattern type and content."""
        if pattern_name in ['encrypted_string', 'cipher_reference']:
            return 'HIGH'  # Explicit encryption references
        
        if pattern_name == 'base64_content' and len(matched_text) > 200:
            return 'MEDIUM'  # Large base64 content could be sensitive
        
        if pattern_name == 'hex_content' and len(matched_text) > 128:
            return 'MEDIUM'  # Large hex content could be encrypted
        
        return 'LOW'
    
    def _analyze_content(self, pattern_name: str, matched_text: str) -> Dict[str, Any]:
        """Analyze the matched content for additional insights."""
        analysis = {
            'content_length': len(matched_text),
            'pattern_type': pattern_name
        }
        
        if pattern_name == 'base64_content':
            analysis['is_valid_base64'] = self._is_valid_base64(matched_text)
            if analysis['is_valid_base64']:
                analysis['decoded_length'] = len(base64.b64decode(matched_text))
        
        elif pattern_name == 'hex_content':
            analysis['is_even_length'] = len(matched_text) % 2 == 0
            analysis['byte_length'] = len(matched_text) // 2
        
        return analysis
    
    def _is_valid_base64(self, content: str) -> bool:
        """Check if content is valid base64."""
        try:
            base64.b64decode(content)
            return True
        except:
            return False
    
    def generate_resource_report(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a comprehensive resource analysis report."""
        total_files = len(results)
        total_findings = sum(len(result['findings']) for result in results)
        
        # Group findings by type and severity
        pattern_summary = {}
        severity_summary = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        file_type_summary = {}
        
        for result in results:
            file_type = result.get('file_type', 'unknown')
            if file_type not in file_type_summary:
                file_type_summary[file_type] = 0
            file_type_summary[file_type] += len(result['findings'])
            
            for finding in result['findings']:
                pattern_name = finding['pattern_name']
                severity = finding['severity']
                
                if pattern_name not in pattern_summary:
                    pattern_summary[pattern_name] = 0
                pattern_summary[pattern_name] += 1
                
                severity_summary[severity] += 1
        
        # Risk assessment
        risk_score = (
            severity_summary['HIGH'] * 3 +
            severity_summary['MEDIUM'] * 2 +
            severity_summary['LOW'] * 1
        )
        
        if risk_score == 0:
            risk_level = 'NONE'
        elif risk_score <= 3:
            risk_level = 'LOW'
        elif risk_score <= 10:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'HIGH'
        
        return {
            'summary': {
                'files_analyzed': total_files,
                'total_findings': total_findings,
                'risk_level': risk_level,
                'risk_score': risk_score
            },
            'pattern_breakdown': pattern_summary,
            'severity_breakdown': severity_summary,
            'file_type_breakdown': file_type_summary,
            'recommendations': self._generate_resource_recommendations(pattern_summary, severity_summary)
        }
    
    def _generate_resource_recommendations(self, pattern_summary: Dict[str, int], 
                                         severity_summary: Dict[str, int]) -> List[str]:
        """Generate security recommendations for resource analysis."""
        recommendations = []
        
        if pattern_summary.get('encrypted_string', 0) > 0:
            recommendations.append(
                "Explicit encryption references found in resources. Verify proper key management."
            )
        
        if pattern_summary.get('base64_content', 0) > 5:
            recommendations.append(
                "Multiple Base64 encoded content found. Ensure sensitive data is properly encrypted."
            )
        
        if severity_summary['HIGH'] > 0:
            recommendations.append(
                "High-severity encrypted content detected. Review for hardcoded secrets."
            )
        
        if not recommendations:
            recommendations.append("No significant encrypted content issues detected in resources.")
        
        return recommendations 
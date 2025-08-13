#!/usr/bin/env python3
"""
ML-Enhanced Security Analyzer for AODS
Provides machine learning-based confidence scoring and pattern analysis
Foundation for advanced vulnerability detection using ML techniques
"""

import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import json

@dataclass
class MLVulnerabilityScore:
    """ML-enhanced vulnerability score with confidence metrics"""
    base_confidence: float
    ml_confidence: float
    combined_confidence: float
    risk_factors: List[str]
    code_complexity: float
    pattern_strength: float
    context_relevance: float

class MLSecurityAnalyzer:
    """
    Machine Learning-enhanced security analyzer for vulnerability detection
    
    Features:
    - Pattern strength analysis
    - Code complexity assessment  
    - Context relevance scoring
    - Multi-factor confidence calculation
    - Learning from vulnerability patterns
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.pattern_weights = self._init_pattern_weights()
        self.vulnerability_history = []
        self.confidence_threshold = 0.7
        
    def _init_pattern_weights(self) -> Dict[str, float]:
        """Initialize ML pattern weights for different vulnerability types"""
        return {
            # High-confidence patterns
            'hardcoded_secrets': {
                'exact_match': 0.95,
                'contextual': 0.85,
                'partial': 0.65
            },
            'sql_injection': {
                'concatenation': 0.90,
                'dynamic_query': 0.80,
                'user_input': 0.85
            },
            'weak_crypto': {
                'deprecated_algorithm': 0.95,
                'weak_key_size': 0.80,
                'insecure_mode': 0.85
            },
            'cleartext_http': {
                'hardcoded_url': 0.90,
                'dynamic_url': 0.75,
                'config_based': 0.70
            },
            'insecure_storage': {
                'world_readable': 0.95,
                'unencrypted': 0.80,
                'external_storage': 0.75
            },
            'insecure_logging': {
                'sensitive_data': 0.85,
                'production_logs': 0.75,
                'debug_only': 0.60
            }
        }
    
    def analyze_vulnerability_confidence(
        self, 
        vulnerability_type: str,
        code_snippet: str,
        file_path: str,
        line_number: int,
        base_confidence: float = 0.5
    ) -> MLVulnerabilityScore:
        """
        Analyze vulnerability using ML-enhanced confidence scoring
        
        Args:
            vulnerability_type: Type of vulnerability detected
            code_snippet: Code snippet containing the vulnerability
            file_path: Path to the file containing the vulnerability
            line_number: Line number of the vulnerability
            base_confidence: Base confidence from pattern matching
            
        Returns:
            MLVulnerabilityScore with enhanced confidence metrics
        """
        try:
            # Analyze code complexity
            complexity_score = self._analyze_code_complexity(code_snippet)
            
            # Analyze pattern strength
            pattern_strength = self._analyze_pattern_strength(
                vulnerability_type, code_snippet
            )
            
            # Analyze context relevance
            context_relevance = self._analyze_context_relevance(
                file_path, code_snippet, vulnerability_type
            )
            
            # Identify risk factors
            risk_factors = self._identify_risk_factors(
                vulnerability_type, code_snippet, file_path
            )
            
            # Calculate ML-enhanced confidence
            ml_confidence = self._calculate_ml_confidence(
                base_confidence, complexity_score, pattern_strength, context_relevance
            )
            
            # Combine with base confidence
            combined_confidence = self._combine_confidences(base_confidence, ml_confidence)
            
            score = MLVulnerabilityScore(
                base_confidence=base_confidence,
                ml_confidence=ml_confidence,
                combined_confidence=combined_confidence,
                risk_factors=risk_factors,
                code_complexity=complexity_score,
                pattern_strength=pattern_strength,
                context_relevance=context_relevance
            )
            
            # Learn from this analysis
            self._update_learning_data(vulnerability_type, score)
            
            return score
            
        except Exception as e:
            self.logger.warning(f"ML analysis failed: {e}")
            # Fallback to base confidence
            return MLVulnerabilityScore(
                base_confidence=base_confidence,
                ml_confidence=base_confidence,
                combined_confidence=base_confidence,
                risk_factors=[],
                code_complexity=0.5,
                pattern_strength=0.5,
                context_relevance=0.5
            )
    
    def _analyze_code_complexity(self, code_snippet: str) -> float:
        """Analyze code complexity factors that affect vulnerability confidence"""
        complexity_factors = 0
        total_factors = 8
        
        # Check for nested structures
        if re.search(r'\{[^}]*\{[^}]*\}[^}]*\}', code_snippet):
            complexity_factors += 1
        
        # Check for multiple method calls
        if len(re.findall(r'\.\w+\s*\(', code_snippet)) > 2:
            complexity_factors += 1
        
        # Check for conditional logic
        if re.search(r'\b(if|when|switch)\s*\(', code_snippet):
            complexity_factors += 1
        
        # Check for loops
        if re.search(r'\b(for|while|forEach)\s*\(', code_snippet):
            complexity_factors += 1
        
        # Check for exception handling
        if re.search(r'\b(try|catch|finally)\b', code_snippet):
            complexity_factors += 1
        
        # Check for lambda expressions
        if re.search(r'->', code_snippet) or re.search(r'=>', code_snippet):
            complexity_factors += 1
        
        # Check for string manipulation
        if re.search(r'(StringBuilder|StringBuffer|String\.format|\+.*")', code_snippet):
            complexity_factors += 1
        
        # Check for variable assignments
        if len(re.findall(r'(\w+\s*=\s*)', code_snippet)) > 1:
            complexity_factors += 1
        
        return complexity_factors / total_factors
    
    def _analyze_pattern_strength(self, vulnerability_type: str, code_snippet: str) -> float:
        """Analyze the strength of the vulnerability pattern match"""
        if vulnerability_type not in self.pattern_weights:
            return 0.5  # Default strength
        
        weights = self.pattern_weights[vulnerability_type]
        max_strength = 0.0
        
        # Analyze different pattern types
        if vulnerability_type == 'hardcoded_secrets':
            if re.search(r'(password|secret|key|token)\s*=\s*"[^"]{8,}"', code_snippet, re.IGNORECASE):
                max_strength = max(max_strength, weights['exact_match'])
            elif re.search(r'(password|secret|key|token)', code_snippet, re.IGNORECASE):
                max_strength = max(max_strength, weights['contextual'])
            else:
                max_strength = max(max_strength, weights['partial'])
        
        elif vulnerability_type == 'sql_injection':
            if re.search(r'"\s*\+\s*\w+\s*\+\s*"', code_snippet):
                max_strength = max(max_strength, weights['concatenation'])
            elif re.search(r'(execSQL|rawQuery)\s*\(\s*[^)]*\+', code_snippet):
                max_strength = max(max_strength, weights['dynamic_query'])
            elif re.search(r'(user|input|param)', code_snippet, re.IGNORECASE):
                max_strength = max(max_strength, weights['user_input'])
        
        elif vulnerability_type == 'weak_crypto':
            if re.search(r'(MD5|SHA1|DES|RC4)', code_snippet):
                max_strength = max(max_strength, weights['deprecated_algorithm'])
            elif re.search(r'(64|128)', code_snippet):
                max_strength = max(max_strength, weights['weak_key_size'])
            elif re.search(r'(ECB|NONE)', code_snippet):
                max_strength = max(max_strength, weights['insecure_mode'])
        
        return max_strength
    
    def _analyze_context_relevance(self, file_path: str, code_snippet: str, vulnerability_type: str) -> float:
        """Analyze how relevant the context is for the vulnerability type"""
        relevance_score = 0.0
        
        # File path analysis
        path_lower = file_path.lower()
        
        if vulnerability_type == 'hardcoded_secrets':
            if any(keyword in path_lower for keyword in ['auth', 'login', 'credential', 'key', 'config']):
                relevance_score += 0.3
        
        elif vulnerability_type == 'sql_injection':
            if any(keyword in path_lower for keyword in ['database', 'db', 'dao', 'repository', 'model']):
                relevance_score += 0.3
        
        elif vulnerability_type == 'insecure_storage':
            if any(keyword in path_lower for keyword in ['storage', 'preferences', 'cache', 'temp']):
                relevance_score += 0.3
        
        elif vulnerability_type == 'cleartext_http':
            if any(keyword in path_lower for keyword in ['network', 'api', 'client', 'request']):
                relevance_score += 0.3
        
        # Code context analysis
        context_keywords = {
            'hardcoded_secrets': ['authentication', 'authorization', 'login', 'credential'],
            'sql_injection': ['database', 'query', 'cursor', 'table'],
            'weak_crypto': ['encryption', 'cipher', 'hash', 'digest'],
            'cleartext_http': ['network', 'request', 'url', 'http'],
            'insecure_storage': ['preferences', 'file', 'cache', 'storage'],
            'insecure_logging': ['log', 'debug', 'trace', 'print']
        }
        
        if vulnerability_type in context_keywords:
            for keyword in context_keywords[vulnerability_type]:
                if keyword in code_snippet.lower():
                    relevance_score += 0.1
        
        # Security-related imports/references
        security_indicators = ['security', 'crypto', 'ssl', 'tls', 'certificate', 'keystore']
        for indicator in security_indicators:
            if indicator in code_snippet.lower():
                relevance_score += 0.1
        
        return min(relevance_score, 1.0)  # Cap at 1.0
    
    def _identify_risk_factors(self, vulnerability_type: str, code_snippet: str, file_path: str) -> List[str]:
        """Identify specific risk factors that increase vulnerability severity"""
        risk_factors = []
        
        # Production code indicators
        if any(indicator in file_path.lower() for indicator in ['release', 'prod', 'production']):
            risk_factors.append("Production code")
        
        # Public/exposed code
        if re.search(r'\bpublic\s+', code_snippet):
            risk_factors.append("Public method")
        
        # Network-related risks
        if re.search(r'\b(http|network|request|api)\b', code_snippet, re.IGNORECASE):
            risk_factors.append("Network exposure")
        
        # User input handling
        if re.search(r'\b(user|input|param|request|getParameter)\b', code_snippet, re.IGNORECASE):
            risk_factors.append("User input handling")
        
        # External storage
        if re.search(r'\b(external|sdcard|getExternalStorageDirectory)\b', code_snippet, re.IGNORECASE):
            risk_factors.append("External storage")
        
        # Reflection usage
        if re.search(r'\b(reflection|invoke|getMethod|getDeclaredMethod)\b', code_snippet, re.IGNORECASE):
            risk_factors.append("Reflection usage")
        
        # Debugging code in production
        if re.search(r'\b(debug|test|TODO|FIXME)\b', code_snippet, re.IGNORECASE):
            risk_factors.append("Debug/test code")
        
        return risk_factors
    
    def _calculate_ml_confidence(
        self, 
        base_confidence: float, 
        complexity: float, 
        pattern_strength: float, 
        context_relevance: float
    ) -> float:
        """Calculate ML-enhanced confidence score"""
        # Weighted combination of factors
        weights = {
            'base': 0.4,
            'pattern_strength': 0.3,
            'context_relevance': 0.2,
            'complexity': 0.1
        }
        
        ml_confidence = (
            weights['base'] * base_confidence +
            weights['pattern_strength'] * pattern_strength +
            weights['context_relevance'] * context_relevance +
            weights['complexity'] * (1.0 - complexity)  # Lower complexity = higher confidence
        )
        
        return min(max(ml_confidence, 0.0), 1.0)
    
    def _combine_confidences(self, base_confidence: float, ml_confidence: float) -> float:
        """Combine base and ML confidence scores"""
        # Use weighted average with bias toward higher score
        weight_base = 0.6
        weight_ml = 0.4
        
        combined = weight_base * base_confidence + weight_ml * ml_confidence
        
        # Apply confidence boost if both scores are high
        if base_confidence > 0.8 and ml_confidence > 0.8:
            combined = min(combined * 1.1, 1.0)
        
        # Apply confidence penalty if scores diverge significantly
        divergence = abs(base_confidence - ml_confidence)
        if divergence > 0.3:
            combined = combined * (1.0 - divergence * 0.2)
        
        return min(max(combined, 0.0), 1.0)
    
    def _update_learning_data(self, vulnerability_type: str, score: MLVulnerabilityScore):
        """Update learning data for future improvements"""
        learning_entry = {
            'vulnerability_type': vulnerability_type,
            'base_confidence': score.base_confidence,
            'ml_confidence': score.ml_confidence,
            'combined_confidence': score.combined_confidence,
            'code_complexity': score.code_complexity,
            'pattern_strength': score.pattern_strength,
            'context_relevance': score.context_relevance,
            'risk_factors_count': len(score.risk_factors)
        }
        
        self.vulnerability_history.append(learning_entry)
        
        # Keep only recent entries (last 1000)
        if len(self.vulnerability_history) > 1000:
            self.vulnerability_history = self.vulnerability_history[-1000:]
    
    def get_ml_statistics(self) -> Dict[str, Any]:
        """Get ML analyzer statistics and performance metrics"""
        if not self.vulnerability_history:
            return {'status': 'No learning data available'}
        
        # Calculate statistics
        total_analyses = len(self.vulnerability_history)
        avg_base_confidence = sum(entry['base_confidence'] for entry in self.vulnerability_history) / total_analyses
        avg_ml_confidence = sum(entry['ml_confidence'] for entry in self.vulnerability_history) / total_analyses
        avg_combined_confidence = sum(entry['combined_confidence'] for entry in self.vulnerability_history) / total_analyses
        
        # Vulnerability type distribution
        type_counts = {}
        for entry in self.vulnerability_history:
            vuln_type = entry['vulnerability_type']
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        return {
            'total_analyses': total_analyses,
            'average_base_confidence': round(avg_base_confidence, 3),
            'average_ml_confidence': round(avg_ml_confidence, 3),
            'average_combined_confidence': round(avg_combined_confidence, 3),
            'confidence_improvement': round(avg_combined_confidence - avg_base_confidence, 3),
            'vulnerability_distribution': type_counts,
            'high_confidence_rate': len([e for e in self.vulnerability_history if e['combined_confidence'] > 0.8]) / total_analyses
        }

# Global ML analyzer instance
ml_analyzer = MLSecurityAnalyzer()

def enhance_vulnerability_with_ml(
    vulnerability_type: str,
    code_snippet: str,
    file_path: str,
    line_number: int,
    base_confidence: float = 0.5
) -> MLVulnerabilityScore:
    """
    Enhance vulnerability detection with ML analysis
    
    Args:
        vulnerability_type: Type of vulnerability
        code_snippet: Code snippet containing the vulnerability
        file_path: Path to the vulnerable file
        line_number: Line number of the vulnerability
        base_confidence: Base confidence from pattern matching
        
    Returns:
        MLVulnerabilityScore with enhanced confidence metrics
    """
    return ml_analyzer.analyze_vulnerability_confidence(
        vulnerability_type=vulnerability_type,
        code_snippet=code_snippet,
        file_path=file_path,
        line_number=line_number,
        base_confidence=base_confidence
    )

def get_ml_stats() -> Dict[str, Any]:
    """Get ML analyzer statistics"""
    return ml_analyzer.get_ml_statistics() 
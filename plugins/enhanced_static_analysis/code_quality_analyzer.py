"""
Enhanced Static Analysis - Code Quality Analyzer Component

This module provides comprehensive code quality analysis capabilities including
complexity metrics, maintainability assessment, and quality scoring.
"""

import logging
import os
from typing import Dict, List, Optional, Any
from pathlib import Path
import re
import datetime

from .data_structures import CodeQualityMetrics, AnalysisConfiguration

class CodeQualityAnalyzer:
    """Advanced code quality analyzer for maintainability and complexity assessment."""
    
    def __init__(self, config: Optional[AnalysisConfiguration] = None):
        """Initialize the code quality analyzer with configuration."""
        self.config = config or AnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        self.supported_extensions = {'.java', '.kt', '.xml', '.smali'}
        
    def analyze_code_quality(self, extraction_path: str) -> Optional[CodeQualityMetrics]:
        """
        Analyze code quality metrics for the extracted APK.
        
        Args:
            extraction_path: Path to the extracted APK files
            
        Returns:
            CodeQualityMetrics object with analysis results
        """
        try:
            if not os.path.exists(extraction_path):
                self.logger.warning(f"Extraction path does not exist: {extraction_path}")
                return None
                
            metrics = CodeQualityMetrics()
            
            # Analyze files in the extraction path
            for root, dirs, files in os.walk(extraction_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._is_code_file(file_path):
                        self._analyze_file(file_path, metrics)
                        
            # Calculate derived metrics
            self._calculate_derived_metrics(metrics)
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Code quality analysis failed: {e}")
            return None
    
    def _is_code_file(self, file_path: str) -> bool:
        """Check if a file is a code file that should be analyzed."""
        return Path(file_path).suffix.lower() in self.supported_extensions
    
    def _analyze_file(self, file_path: str, metrics: CodeQualityMetrics) -> None:
        """Analyze a single file and update metrics."""
        try:
            metrics.total_files += 1
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Count lines of code (excluding empty lines and comments)
            lines = content.split('\n')
            code_lines = [line for line in lines if line.strip() and not line.strip().startswith('//')]
            
            if code_lines:
                metrics.code_files += 1
                metrics.lines_of_code += len(code_lines)
                
                # Analyze complexity
                complexity = self._calculate_complexity(content)
                metrics.cyclomatic_complexity += complexity
                
                # Analyze obfuscation
                obfuscation = self._analyze_obfuscation(content)
                metrics.obfuscation_level += obfuscation
                
                # Analyze dead code
                dead_code = self._analyze_dead_code(content)
                metrics.dead_code_ratio += dead_code
                
        except Exception as e:
            self.logger.warning(f"Failed to analyze file {file_path}: {e}")
    
    def _calculate_complexity(self, content: str) -> float:
        """Calculate cyclomatic complexity for the code."""
        # Count decision points (if, while, for, case, catch, etc.)
        complexity_patterns = [
            r'\bif\s*\(',
            r'\bwhile\s*\(',
            r'\bfor\s*\(',
            r'\bcase\s+',
            r'\bcatch\s*\(',
            r'\b&&\b',
            r'\b\|\|\b',
            r'\?.*:',  # ternary operator
        ]
        
        complexity = 1  # Base complexity
        for pattern in complexity_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            complexity += len(matches)
            
        return complexity
    
    def _analyze_obfuscation(self, content: str) -> float:
        """Analyze code obfuscation level."""
        # Check for obfuscated identifiers
        obfuscated_patterns = [
            r'\b[a-zA-Z][a-zA-Z0-9]{1,2}\b',  # Very short identifiers
            r'\b[a-zA-Z][0-9]+[a-zA-Z][0-9]*\b',  # Mixed letters and numbers
            r'\b[a-zA-Z]{1}[0-9]{3,}\b',  # Single letter followed by numbers
        ]
        
        total_identifiers = len(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', content))
        obfuscated_count = 0
        
        for pattern in obfuscated_patterns:
            matches = re.findall(pattern, content)
            obfuscated_count += len(matches)
            
        return obfuscated_count / max(total_identifiers, 1)
    
    def _analyze_dead_code(self, content: str) -> float:
        """Analyze potential dead code."""
        # Look for unused variables, unreachable code, etc.
        dead_code_patterns = [
            r'//.*TODO',
            r'//.*FIXME',
            r'//.*XXX',
            r'if\s*\(\s*false\s*\)',
            r'if\s*\(\s*0\s*\)',
            r'return\s*;\s*\n.*',  # Code after return
        ]
        
        lines = content.split('\n')
        dead_code_lines = 0
        
        for pattern in dead_code_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            dead_code_lines += len(matches)
            
        return dead_code_lines / max(len(lines), 1)
    
    def _calculate_derived_metrics(self, metrics: CodeQualityMetrics) -> None:
        """Calculate derived metrics from basic measurements."""
        if metrics.code_files > 0:
            # Average complexity per file
            metrics.cyclomatic_complexity /= metrics.code_files
            
            # Average obfuscation level
            metrics.obfuscation_level /= metrics.code_files
            
            # Average dead code ratio
            metrics.dead_code_ratio /= metrics.code_files
            
            # Calculate maintainability index (simplified)
            # Scale: 0-100, higher is better
            complexity_factor = max(0, 100 - (metrics.cyclomatic_complexity * 2))
            obfuscation_factor = max(0, 100 - (metrics.obfuscation_level * 100))
            dead_code_factor = max(0, 100 - (metrics.dead_code_ratio * 100))
            
            metrics.maintainability_index = (complexity_factor + obfuscation_factor + dead_code_factor) / 3
            
            # Calculate overall quality score
            metrics.quality_score = self._calculate_quality_score(metrics)
            
            # Update complexity distribution
            self._update_complexity_distribution(metrics)
    
    def _calculate_quality_score(self, metrics: CodeQualityMetrics) -> float:
        """Calculate overall quality score (0-100)."""
        maintainability_weight = 0.4
        complexity_weight = 0.3
        obfuscation_weight = 0.2
        dead_code_weight = 0.1
        
        # Normalize complexity (lower is better)
        complexity_score = max(0, 100 - (metrics.cyclomatic_complexity * 5))
        
        # Normalize obfuscation (lower is better)
        obfuscation_score = max(0, 100 - (metrics.obfuscation_level * 100))
        
        # Normalize dead code (lower is better)
        dead_code_score = max(0, 100 - (metrics.dead_code_ratio * 100))
        
        quality_score = (
            metrics.maintainability_index * maintainability_weight +
            complexity_score * complexity_weight +
            obfuscation_score * obfuscation_weight +
            dead_code_score * dead_code_weight
        )
        
        return min(100, max(0, quality_score))
    
    def _update_complexity_distribution(self, metrics: CodeQualityMetrics) -> None:
        """Update complexity distribution categories."""
        complexity = metrics.cyclomatic_complexity
        
        if complexity <= 5:
            metrics.complexity_distribution['low'] = 1
        elif complexity <= 10:
            metrics.complexity_distribution['medium'] = 1
        elif complexity <= 20:
            metrics.complexity_distribution['high'] = 1
        else:
            metrics.complexity_distribution['very_high'] = 1 
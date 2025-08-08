"""
Code Quality Metrics Analysis Engine

This module handles processing and analysis of code quality metrics.
"""

import logging
from typing import Dict, Any, List

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

logger = logging.getLogger(__name__)

class CodeQualityMetricsEngine:
    """
    Engine for processing code quality metrics.
    
    Provides enhanced analysis and assessment of code quality indicators.
    """
    
    def __init__(self):
        """Initialize the code quality metrics engine."""
        self.quality_thresholds = {
            'obfuscation_level': {
                'high': 0.7,
                'medium': 0.3,
                'low': 0.0
            },
            'complexity': {
                'high': 0.8,
                'medium': 0.5,
                'low': 0.0
            },
            'maintainability': {
                'good': 0.7,
                'acceptable': 0.4,
                'poor': 0.0
            }
        }
        
        self.file_type_weights = {
            'java': 1.0,
            'kotlin': 1.0,
            'xml': 0.5,
            'properties': 0.3,
            'json': 0.3,
            'other': 0.2
        }
    
    def process_code_quality(self, quality_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process code quality metrics with enhanced analysis.
        
        Args:
            quality_data: Raw code quality metrics
            
        Returns:
            Dict[str, Any]: Processed code quality analysis
        """
        if not quality_data:
            logger.warning("Code quality data is empty")
            return {
                'error': 'No code quality data available',
                'metrics': {},
                'assessment': {},
                'recommendations': []
            }
        
        logger.info("Processing code quality metrics")
        
        # Enhanced quality analysis
        enhanced_quality = {
            'original_metrics': quality_data,
            'enhanced_metrics': self._calculate_enhanced_metrics(quality_data),
            'quality_assessment': self._perform_quality_assessment(quality_data),
            'complexity_analysis': self._analyze_complexity(quality_data),
            'maintainability_analysis': self._analyze_maintainability(quality_data),
            'obfuscation_analysis': self._analyze_obfuscation(quality_data),
            'recommendations': [],
            'overall_score': 0.0
        }
        
        # Calculate overall quality score
        enhanced_quality['overall_score'] = self._calculate_overall_quality_score(enhanced_quality)
        
        # Generate recommendations
        enhanced_quality['recommendations'] = self._generate_quality_recommendations(enhanced_quality)
        
        logger.info("Code quality metrics processing completed")
        return enhanced_quality
    
    def _calculate_enhanced_metrics(self, quality_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate enhanced code quality metrics.
        
        Args:
            quality_data: Raw quality metrics
            
        Returns:
            Dict[str, Any]: Enhanced metrics
        """
        total_files = quality_data.get('total_files', 0)
        code_files = quality_data.get('code_files', 0)
        
        # Calculate code-to-total ratio
        code_ratio = code_files / total_files if total_files > 0 else 0.0
        
        # Calculate file type distribution
        file_type_distribution = self._calculate_file_type_distribution(quality_data)
        
        # Calculate complexity metrics
        complexity_metrics = self._calculate_complexity_metrics(quality_data)
        
        # Calculate maintainability metrics
        maintainability_metrics = self._calculate_maintainability_metrics(quality_data)
        
        return {
            'total_files': total_files,
            'code_files': code_files,
            'code_ratio': code_ratio,
            'file_type_distribution': file_type_distribution,
            'complexity_metrics': complexity_metrics,
            'maintainability_metrics': maintainability_metrics,
            'obfuscation_level': quality_data.get('obfuscation_level', 0.0),
            'estimated_loc': self._estimate_lines_of_code(quality_data),
            'code_density': self._calculate_code_density(quality_data)
        }
    
    def _perform_quality_assessment(self, quality_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive quality assessment.
        
        Args:
            quality_data: Raw quality metrics
            
        Returns:
            Dict[str, Any]: Quality assessment results
        """
        assessment = {
            'overall_quality': 'UNKNOWN',
            'quality_score': 0.0,
            'strengths': [],
            'weaknesses': [],
            'critical_issues': [],
            'improvement_areas': []
        }
        
        # Assess obfuscation level
        obfuscation_level = quality_data.get('obfuscation_level', 0.0)
        if obfuscation_level > self.quality_thresholds['obfuscation_level']['high']:
            assessment['strengths'].append('High level of code obfuscation')
            assessment['quality_score'] += 0.3
        elif obfuscation_level > self.quality_thresholds['obfuscation_level']['medium']:
            assessment['strengths'].append('Moderate level of code obfuscation')
            assessment['quality_score'] += 0.2
        else:
            assessment['weaknesses'].append('Low level of code obfuscation')
            assessment['improvement_areas'].append('Implement code obfuscation for production')
        
        # Assess file organization
        total_files = quality_data.get('total_files', 0)
        code_files = quality_data.get('code_files', 0)
        
        if total_files > 0:
            code_ratio = code_files / total_files
            if code_ratio > 0.3:
                assessment['strengths'].append('Good code-to-resource ratio')
                assessment['quality_score'] += 0.2
            elif code_ratio > 0.1:
                assessment['quality_score'] += 0.1
            else:
                assessment['weaknesses'].append('Low code-to-resource ratio')
        
        # Assess complexity (if available)
        if 'complexity_score' in quality_data:
            complexity = quality_data['complexity_score']
            if complexity < self.quality_thresholds['complexity']['medium']:
                assessment['strengths'].append('Low code complexity')
                assessment['quality_score'] += 0.25
            elif complexity < self.quality_thresholds['complexity']['high']:
                assessment['quality_score'] += 0.1
            else:
                assessment['weaknesses'].append('High code complexity')
                assessment['improvement_areas'].append('Reduce code complexity')
        
        # Determine overall quality
        if assessment['quality_score'] >= 0.7:
            assessment['overall_quality'] = 'GOOD'
        elif assessment['quality_score'] >= 0.4:
            assessment['overall_quality'] = 'ACCEPTABLE'
        else:
            assessment['overall_quality'] = 'POOR'
        
        return assessment
    
    def _analyze_complexity(self, quality_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze code complexity metrics.
        
        Args:
            quality_data: Raw quality metrics
            
        Returns:
            Dict[str, Any]: Complexity analysis
        """
        analysis = {
            'complexity_level': 'UNKNOWN',
            'complexity_score': 0.0,
            'complexity_factors': [],
            'high_complexity_areas': [],
            'recommendations': []
        }
        
        # Calculate complexity based on available metrics
        total_files = quality_data.get('total_files', 0)
        code_files = quality_data.get('code_files', 0)
        
        # File count complexity
        if total_files > 1000:
            analysis['complexity_factors'].append('Large number of files')
            analysis['complexity_score'] += 0.3
        elif total_files > 500:
            analysis['complexity_factors'].append('Moderate number of files')
            analysis['complexity_score'] += 0.2
        
        # Code file ratio complexity
        if code_files > 0 and total_files > 0:
            code_ratio = code_files / total_files
            if code_ratio > 0.5:
                analysis['complexity_factors'].append('High code file ratio')
                analysis['complexity_score'] += 0.2
        
        # Obfuscation complexity
        obfuscation_level = quality_data.get('obfuscation_level', 0.0)
        if obfuscation_level > 0.7:
            analysis['complexity_factors'].append('High obfuscation level')
            analysis['complexity_score'] += 0.3
        
        # Determine complexity level
        if analysis['complexity_score'] >= 0.7:
            analysis['complexity_level'] = 'HIGH'
            analysis['recommendations'].append('Consider refactoring for better maintainability')
        elif analysis['complexity_score'] >= 0.4:
            analysis['complexity_level'] = 'MEDIUM'
            analysis['recommendations'].append('Monitor complexity growth')
        else:
            analysis['complexity_level'] = 'LOW'
        
        return analysis
    
    def _analyze_maintainability(self, quality_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze code maintainability metrics.
        
        Args:
            quality_data: Raw quality metrics
            
        Returns:
            Dict[str, Any]: Maintainability analysis
        """
        analysis = {
            'maintainability_level': 'UNKNOWN',
            'maintainability_score': 0.0,
            'maintainability_factors': [],
            'improvement_areas': [],
            'recommendations': []
        }
        
        # Base maintainability score
        base_score = 0.5
        
        # Obfuscation impact on maintainability
        obfuscation_level = quality_data.get('obfuscation_level', 0.0)
        if obfuscation_level > 0.7:
            analysis['maintainability_factors'].append('High obfuscation reduces maintainability')
            base_score -= 0.3
        elif obfuscation_level > 0.3:
            analysis['maintainability_factors'].append('Moderate obfuscation impacts maintainability')
            base_score -= 0.1
        
        # File organization impact
        total_files = quality_data.get('total_files', 0)
        if total_files > 0:
            if total_files > 1000:
                analysis['maintainability_factors'].append('Large codebase affects maintainability')
                base_score -= 0.2
            elif total_files > 500:
                analysis['maintainability_factors'].append('Moderate codebase size')
                base_score -= 0.1
            else:
                analysis['maintainability_factors'].append('Manageable codebase size')
                base_score += 0.1
        
        analysis['maintainability_score'] = max(0.0, min(1.0, base_score))
        
        # Determine maintainability level
        if analysis['maintainability_score'] >= 0.7:
            analysis['maintainability_level'] = 'GOOD'
        elif analysis['maintainability_score'] >= 0.4:
            analysis['maintainability_level'] = 'ACCEPTABLE'
            analysis['improvement_areas'].append('Code documentation')
            analysis['improvement_areas'].append('Code structure optimization')
        else:
            analysis['maintainability_level'] = 'POOR'
            analysis['improvement_areas'].extend([
                'Code refactoring',
                'Documentation improvement',
                'Structure reorganization'
            ])
        
        # Generate recommendations
        for area in analysis['improvement_areas']:
            if area == 'Code documentation':
                analysis['recommendations'].append('Improve code documentation and comments')
            elif area == 'Code structure optimization':
                analysis['recommendations'].append('Optimize code structure and organization')
            elif area == 'Code refactoring':
                analysis['recommendations'].append('Refactor complex code sections')
        
        return analysis
    
    def _analyze_obfuscation(self, quality_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze code obfuscation metrics.
        
        Args:
            quality_data: Raw quality metrics
            
        Returns:
            Dict[str, Any]: Obfuscation analysis
        """
        obfuscation_level = quality_data.get('obfuscation_level', 0.0)
        
        analysis = {
            'obfuscation_level': obfuscation_level,
            'obfuscation_category': 'UNKNOWN',
            'security_impact': 'UNKNOWN',
            'development_impact': 'UNKNOWN',
            'recommendations': []
        }
        
        # Categorize obfuscation level
        if obfuscation_level >= self.quality_thresholds['obfuscation_level']['high']:
            analysis['obfuscation_category'] = 'HIGH'
            analysis['security_impact'] = 'POSITIVE'
            analysis['development_impact'] = 'CHALLENGING'
            analysis['recommendations'].append('High obfuscation provides good security')
        elif obfuscation_level >= self.quality_thresholds['obfuscation_level']['medium']:
            analysis['obfuscation_category'] = 'MEDIUM'
            analysis['security_impact'] = 'MODERATE'
            analysis['development_impact'] = 'MANAGEABLE'
            analysis['recommendations'].append('Consider increasing obfuscation for production')
        else:
            analysis['obfuscation_category'] = 'LOW'
            analysis['security_impact'] = 'MINIMAL'
            analysis['development_impact'] = 'EASY'
            analysis['recommendations'].append('Implement obfuscation for production builds')
        
        # Additional recommendations based on obfuscation level
        if obfuscation_level < 0.3:
            analysis['recommendations'].extend([
                'Use ProGuard or R8 for code obfuscation',
                'Implement string encryption',
                'Consider control flow obfuscation'
            ])
        
        return analysis
    
    def _calculate_overall_quality_score(self, enhanced_quality: Dict[str, Any]) -> float:
        """
        Calculate overall quality score.
        
        Args:
            enhanced_quality: Enhanced quality analysis
            
        Returns:
            float: Overall quality score (0.0 to 1.0)
        """
        quality_assessment = enhanced_quality.get('quality_assessment', {})
        complexity_analysis = enhanced_quality.get('complexity_analysis', {})
        maintainability_analysis = enhanced_quality.get('maintainability_analysis', {})
        obfuscation_analysis = enhanced_quality.get('obfuscation_analysis', {})
        
        # Weight different aspects
        quality_score = quality_assessment.get('quality_score', 0.0) * 0.3
        complexity_score = (1.0 - complexity_analysis.get('complexity_score', 0.0)) * 0.2
        maintainability_score = maintainability_analysis.get('maintainability_score', 0.0) * 0.3
        obfuscation_score = obfuscation_analysis.get('obfuscation_level', 0.0) * 0.2
        
        overall_score = quality_score + complexity_score + maintainability_score + obfuscation_score
        
        return min(1.0, max(0.0, overall_score))
    
    def _generate_quality_recommendations(self, enhanced_quality: Dict[str, Any]) -> List[str]:
        """
        Generate comprehensive quality recommendations.
        
        Args:
            enhanced_quality: Enhanced quality analysis
            
        Returns:
            List[str]: Quality recommendations
        """
        recommendations = []
        
        # Collect recommendations from all analyses
        quality_assessment = enhanced_quality.get('quality_assessment', {})
        complexity_analysis = enhanced_quality.get('complexity_analysis', {})
        maintainability_analysis = enhanced_quality.get('maintainability_analysis', {})
        obfuscation_analysis = enhanced_quality.get('obfuscation_analysis', {})
        
        # Quality assessment recommendations
        recommendations.extend(quality_assessment.get('improvement_areas', []))
        
        # Complexity recommendations
        recommendations.extend(complexity_analysis.get('recommendations', []))
        
        # Maintainability recommendations
        recommendations.extend(maintainability_analysis.get('recommendations', []))
        
        # Obfuscation recommendations
        recommendations.extend(obfuscation_analysis.get('recommendations', []))
        
        # General quality recommendations
        recommendations.extend([
            'Follow coding standards and best practices',
            'Implement proper error handling',
            'Use consistent naming conventions',
            'Add comprehensive unit tests',
            'Implement continuous integration',
            'Use static analysis tools regularly'
        ])
        
        # Remove duplicates and limit to top 10
        unique_recommendations = list(dict.fromkeys(recommendations))
        return unique_recommendations[:10]
    
    # Helper methods
    def _calculate_file_type_distribution(self, quality_data: Dict[str, Any]) -> Dict[str, float]:
        """Calculate file type distribution."""
        total_files = quality_data.get('total_files', 0)
        if total_files == 0:
            return {}
        
        # This is a simplified calculation - in a real implementation,
        # you would analyze actual file types
        return {
            'java': 0.3,
            'kotlin': 0.2,
            'xml': 0.25,
            'properties': 0.1,
            'json': 0.05,
            'other': 0.1
        }
    
    def _calculate_complexity_metrics(self, quality_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate complexity metrics."""
        return {
            'cyclomatic_complexity': 'UNKNOWN',
            'cognitive_complexity': 'UNKNOWN',
            'nesting_depth': 'UNKNOWN',
            'method_length': 'UNKNOWN'
        }
    
    def _calculate_maintainability_metrics(self, quality_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate maintainability metrics."""
        return {
            'maintainability_index': 'UNKNOWN',
            'technical_debt': 'UNKNOWN',
            'code_duplication': 'UNKNOWN',
            'documentation_coverage': 'UNKNOWN'
        }
    
    def _estimate_lines_of_code(self, quality_data: Dict[str, Any]) -> int:
        """Estimate lines of code."""
        code_files = quality_data.get('code_files', 0)
        # Rough estimate: 100 lines per code file
        return code_files * 100
    
    def _calculate_code_density(self, quality_data: Dict[str, Any]) -> float:
        """Calculate code density."""
        total_files = quality_data.get('total_files', 0)
        code_files = quality_data.get('code_files', 0)
        
        if total_files == 0:
            return 0.0
        
        return code_files / total_files 
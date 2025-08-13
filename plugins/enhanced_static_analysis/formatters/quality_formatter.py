"""
Code Quality Formatter

This module handles the formatting of code quality metrics for reports.
"""

import logging
from typing import Dict, Any, Union

from rich.text import Text

logger = logging.getLogger(__name__)

class CodeQualityFormatter:
    """
    Formatter for code quality metrics.
    
    Provides rich formatting for code quality analysis in reports.
    """
    
    def __init__(self):
        """Initialize the code quality formatter."""
        self.quality_colors = {
            "GOOD": "green",
            "ACCEPTABLE": "yellow",
            "POOR": "red"
        }
        
        self.complexity_colors = {
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "red"
        }
        
        self.obfuscation_colors = {
            "HIGH": "green",
            "MEDIUM": "yellow",
            "LOW": "red"
        }
    
    def format_code_quality(self, quality_data: Union[Dict[str, Any], Any]) -> Text:
        """
        Format code quality metrics for display.
        
        Args:
            quality_data: Code quality metrics data (dict or CodeQualityMetrics object)
            
        Returns:
            Text: Formatted code quality metrics
        """
        # Handle both CodeQualityMetrics objects and dictionaries
        if hasattr(quality_data, '__dict__'):
            # CodeQualityMetrics object - convert to dict for processing
            if hasattr(quality_data, 'to_dict'):
                quality_dict = quality_data.to_dict()
            else:
                quality_dict = vars(quality_data)
        elif isinstance(quality_data, dict):
            quality_dict = quality_data
        else:
            # Neither dict nor object with attributes
            return Text("❌ Code quality analysis not available\n", style="red")
        
        # Check for error in the processed dictionary
        if not quality_dict or quality_dict.get("error"):
            return Text("❌ Code quality analysis not available\n", style="red")
        
        logger.info("Formatting code quality metrics")
        
        quality_text = Text()
        quality_text.append("📈 Code Quality Metrics\n", style="bold blue")
        
        # Enhanced metrics
        enhanced_metrics = quality_dict.get("enhanced_metrics", {})
        if enhanced_metrics:
            quality_text.append(self._format_enhanced_metrics(enhanced_metrics))
        
        # Quality assessment
        quality_assessment = quality_dict.get("quality_assessment", {})
        if quality_assessment:
            quality_text.append(self._format_quality_assessment(quality_assessment))
        
        # Complexity analysis
        complexity_analysis = quality_dict.get("complexity_analysis", {})
        if complexity_analysis:
            quality_text.append(self._format_complexity_analysis(complexity_analysis))
        
        # Obfuscation analysis
        obfuscation_analysis = quality_dict.get("obfuscation_analysis", {})
        if obfuscation_analysis:
            quality_text.append(self._format_obfuscation_analysis(obfuscation_analysis))
        
        # Overall score
        overall_score = quality_dict.get("overall_score", 0.0)
        quality_text.append(self._format_overall_score(overall_score))
        
        quality_text.append("\n")
        return quality_text
    
    def _format_enhanced_metrics(self, metrics: Union[Dict[str, Any], Any]) -> Text:
        """
        Format enhanced metrics section.
        
        Args:
            metrics: Enhanced metrics data (dict or CodeQualityMetrics object)
            
        Returns:
            Text: Formatted enhanced metrics
        """
        section = Text()
        section.append("\nBasic Metrics:\n", style="blue")
        
        # Handle both CodeQualityMetrics objects and dictionaries
        if hasattr(metrics, '__dict__'):
            # CodeQualityMetrics object - convert to dict for processing
            if hasattr(metrics, 'to_dict'):
                metrics_dict = metrics.to_dict()
            else:
                metrics_dict = vars(metrics)
        elif isinstance(metrics, dict):
            metrics_dict = metrics
        else:
            # Neither dict nor object with attributes
            return Text("❌ Enhanced metrics data not available\n", style="red")
        
        # File statistics
        total_files = metrics_dict.get("total_files", 0)
        code_files = metrics_dict.get("code_files", 0)
        code_ratio = metrics_dict.get("code_ratio", 0.0)
        
        section.append(f"  Total Files: {total_files}\n")
        section.append(f"  Code Files: {code_files}\n")
        section.append(f"  Code Ratio: {code_ratio:.1%}\n")
        
        # Estimated lines of code
        estimated_loc = metrics_dict.get("estimated_loc", 0)
        if estimated_loc > 0:
            section.append(f"  Estimated LOC: {estimated_loc:,}\n")
        
        # Code density
        code_density = metrics_dict.get("code_density", 0.0)
        if code_density > 0:
            section.append(f"  Code Density: {code_density:.2f}\n")
        
        return section
    
    def _format_quality_assessment(self, assessment: Union[Dict[str, Any], Any]) -> Text:
        """
        Format quality assessment section.
        
        Args:
            assessment: Quality assessment data (dict or CodeQualityMetrics object)
            
        Returns:
            Text: Formatted quality assessment
        """
        section = Text()
        
        # Handle both CodeQualityMetrics objects and dictionaries
        if hasattr(assessment, '__dict__'):
            # CodeQualityMetrics object - convert to dict for processing
            if hasattr(assessment, 'to_dict'):
                assessment_dict = assessment.to_dict()
            else:
                assessment_dict = vars(assessment)
        elif isinstance(assessment, dict):
            assessment_dict = assessment
        else:
            # Neither dict nor object with attributes
            return Text("❌ Quality assessment data not available\n", style="red")
        
        overall_quality = assessment_dict.get("overall_quality", "UNKNOWN")
        quality_score = assessment_dict.get("quality_score", 0.0)
        
        section.append("\nQuality Assessment:\n", style="blue")
        
        # Overall quality
        quality_color = self.quality_colors.get(overall_quality, "dim")
        section.append(
            f"  Overall Quality: {overall_quality} ({quality_score:.2f})\n",
            style=f"bold {quality_color}"
        )
        
        # Strengths
        strengths = assessment_dict.get("strengths", [])
        if strengths:
            section.append("  ✅ Strengths:\n", style="green")
            for strength in strengths[:3]:
                section.append(f"    • {strength}\n", style="green")
        
        # Weaknesses
        weaknesses = assessment_dict.get("weaknesses", [])
        if weaknesses:
            section.append("  ⚠️ Weaknesses:\n", style="yellow")
            for weakness in weaknesses[:3]:
                section.append(f"    • {weakness}\n", style="yellow")
        
        # Improvement areas
        improvement_areas = assessment_dict.get("improvement_areas", [])
        if improvement_areas:
            section.append("  🔧 Improvement Areas:\n", style="yellow")
            for area in improvement_areas[:3]:
                section.append(f"    • {area}\n", style="yellow")
        
        return section
    
    def _format_complexity_analysis(self, analysis: Union[Dict[str, Any], Any]) -> Text:
        """
        Format complexity analysis section.
        
        Args:
            analysis: Complexity analysis data (dict or CodeQualityMetrics object)
            
        Returns:
            Text: Formatted complexity analysis
        """
        section = Text()
        
        # Handle both CodeQualityMetrics objects and dictionaries
        if hasattr(analysis, '__dict__'):
            # CodeQualityMetrics object - convert to dict for processing
            if hasattr(analysis, 'to_dict'):
                analysis_dict = analysis.to_dict()
            else:
                analysis_dict = vars(analysis)
        elif isinstance(analysis, dict):
            analysis_dict = analysis
        else:
            # Neither dict nor object with attributes
            return Text("❌ Complexity analysis data not available\n", style="red")
        
        complexity_level = analysis_dict.get("complexity_level", "UNKNOWN")
        complexity_score = analysis_dict.get("complexity_score", 0.0)
        
        section.append("\nComplexity Analysis:\n", style="blue")
        
        # Complexity level
        complexity_color = self.complexity_colors.get(complexity_level, "dim")
        section.append(
            f"  Complexity Level: {complexity_level} ({complexity_score:.2f})\n",
            style=f"bold {complexity_color}"
        )
        
        # Complexity factors
        complexity_factors = analysis_dict.get("complexity_factors", [])
        if complexity_factors:
            section.append("  📊 Complexity Factors:\n", style="cyan")
            for factor in complexity_factors[:3]:
                section.append(f"    • {factor}\n", style="cyan")
        
        # High complexity areas
        high_complexity_areas = analysis_dict.get("high_complexity_areas", [])
        if high_complexity_areas:
            section.append("  🔴 High Complexity Areas:\n", style="red")
            for area in high_complexity_areas[:3]:
                section.append(f"    • {area}\n", style="red")
        
        return section
    
    def _format_obfuscation_analysis(self, analysis: Union[Dict[str, Any], Any]) -> Text:
        """
        Format obfuscation analysis section.
        
        Args:
            analysis: Obfuscation analysis data (dict or CodeQualityMetrics object)
            
        Returns:
            Text: Formatted obfuscation analysis
        """
        section = Text()
        
        # Handle both CodeQualityMetrics objects and dictionaries
        if hasattr(analysis, '__dict__'):
            # CodeQualityMetrics object - convert to dict for processing
            if hasattr(analysis, 'to_dict'):
                analysis_dict = analysis.to_dict()
            else:
                analysis_dict = vars(analysis)
        elif isinstance(analysis, dict):
            analysis_dict = analysis
        else:
            # Neither dict nor object with attributes
            return Text("❌ Obfuscation analysis data not available\n", style="red")
        
        obfuscation_level = analysis_dict.get("obfuscation_level", 0.0)
        obfuscation_category = analysis_dict.get("obfuscation_category", "UNKNOWN")
        
        section.append("\nObfuscation Analysis:\n", style="blue")
        
        # Obfuscation level
        obfuscation_color = self.obfuscation_colors.get(obfuscation_category, "dim")
        section.append(
            f"  Obfuscation Level: {obfuscation_level:.1%} ({obfuscation_category})\n",
            style=f"bold {obfuscation_color}"
        )
        
        # Security impact
        security_impact = analysis_dict.get("security_impact", "UNKNOWN")
        if security_impact == "POSITIVE":
            section.append("  🔒 Security Impact: Positive\n", style="green")
        elif security_impact == "MODERATE":
            section.append("  🔐 Security Impact: Moderate\n", style="yellow")
        else:
            section.append("  🔓 Security Impact: Minimal\n", style="red")
        
        # Development impact
        development_impact = analysis_dict.get("development_impact", "UNKNOWN")
        if development_impact == "EASY":
            section.append("  👍 Development Impact: Easy\n", style="green")
        elif development_impact == "MANAGEABLE":
            section.append("  👌 Development Impact: Manageable\n", style="yellow")
        else:
            section.append("  👎 Development Impact: Challenging\n", style="red")
        
        return section
    
    def _format_overall_score(self, overall_score: float) -> Text:
        """
        Format overall quality score.
        
        Args:
            overall_score: Overall quality score
            
        Returns:
            Text: Formatted overall score
        """
        section = Text()
        
        section.append("\nOverall Quality Score:\n", style="blue")
        
        # Determine color based on score
        if overall_score >= 0.8:
            color = "green"
            rating = "EXCELLENT"
        elif overall_score >= 0.6:
            color = "yellow"
            rating = "GOOD"
        elif overall_score >= 0.4:
            color = "orange"
            rating = "FAIR"
        else:
            color = "red"
            rating = "POOR"
        
        section.append(
            f"  Score: {overall_score:.2f}/1.0 ({rating})\n",
            style=f"bold {color}"
        )
        
        # Score breakdown
        section.append("  📊 Score Components:\n", style="cyan")
        section.append("    • Quality Assessment: 30%\n", style="dim")
        section.append("    • Maintainability: 30%\n", style="dim")
        section.append("    • Complexity (inverted): 20%\n", style="dim")
        section.append("    • Obfuscation: 20%\n", style="dim")
        
        return section
    
    def format_quality_summary(self, quality_data: Union[Dict[str, Any], Any]) -> Text:
        """
        Format a summary of code quality.
        
        Args:
            quality_data: Code quality data (dict or CodeQualityMetrics object)
            
        Returns:
            Text: Formatted summary
        """
        summary = Text()
        
        # Handle both CodeQualityMetrics objects and dictionaries
        if hasattr(quality_data, '__dict__'):
            # CodeQualityMetrics object - convert to dict for processing
            if hasattr(quality_data, 'to_dict'):
                quality_dict = quality_data.to_dict()
            else:
                quality_dict = vars(quality_data)
        elif isinstance(quality_data, dict):
            quality_dict = quality_data
        else:
            # Neither dict nor object with attributes
            summary.append("❌ Code quality analysis not available\n", style="red")
            return summary
        
        if not quality_dict or quality_dict.get("error"):
            summary.append("❌ Code quality analysis not available\n", style="red")
            return summary
        
        # Overall score
        overall_score = quality_dict.get("overall_score", 0.0)
        enhanced_metrics = quality_dict.get("enhanced_metrics", {})
        
        # Handle enhanced_metrics if it's also an object
        if hasattr(enhanced_metrics, '__dict__'):
            if hasattr(enhanced_metrics, 'to_dict'):
                enhanced_metrics = enhanced_metrics.to_dict()
            else:
                enhanced_metrics = vars(enhanced_metrics)
        elif not isinstance(enhanced_metrics, dict):
            enhanced_metrics = {}
        
        # Determine rating
        if overall_score >= 0.8:
            rating = "EXCELLENT"
            color = "green"
        elif overall_score >= 0.6:
            rating = "GOOD"
            color = "yellow"
        elif overall_score >= 0.4:
            rating = "FAIR"
            color = "orange"
        else:
            rating = "POOR"
            color = "red"
        
        summary.append(f"📈 Code Quality: {rating} ({overall_score:.2f})\n", style=f"bold {color}")
        
        # Key metrics
        total_files = enhanced_metrics.get("total_files", 0)
        code_files = enhanced_metrics.get("code_files", 0)
        obfuscation_level = enhanced_metrics.get("obfuscation_level", 0.0)
        
        summary.append(f"  Files: {total_files} total, {code_files} code\n")
        summary.append(f"  Obfuscation: {obfuscation_level:.1%}\n")
        
        return summary
    
    def format_quality_recommendations(self, quality_data: Dict[str, Any]) -> Text:
        """
        Format quality recommendations.
        
        Args:
            quality_data: Code quality data
            
        Returns:
            Text: Formatted recommendations
        """
        if not quality_data or "error" in quality_data:
            return Text()
        
        recommendations = quality_data.get("recommendations", [])
        
        if not recommendations:
            return Text()
        
        rec_text = Text()
        rec_text.append("💡 Code Quality Recommendations:\n", style="bold yellow")
        
        for i, rec in enumerate(recommendations[:5], 1):
            rec_text.append(f"  {i}. {rec}\n", style="yellow")
        
        return rec_text 
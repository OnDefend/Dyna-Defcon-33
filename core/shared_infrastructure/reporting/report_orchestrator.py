#!/usr/bin/env python3
"""
Unified Report Orchestrator for AODS

Main orchestrator that coordinates all reporting components including generators,
formatters, templates, and output management for comprehensive report creation.

Features:
- Unified report generation interface
- Multi-format output coordination
- Template management integration
- Performance optimization
- Error handling and recovery
- Plugin integration support
"""

import logging
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from datetime import datetime

from .data_structures import (
    ReportFormat, ReportType, ReportConfiguration, ReportContext,
    SecurityFinding, ReportMetadata, create_default_metadata
)
from .generators import (
    ReportGenerator, SecurityAnalysisReportGenerator, ExecutiveSummaryGenerator,
    TechnicalReportGenerator, ComplianceReportGenerator, CustomReportGenerator
)
from .formatters import FormatterFactory, BaseFormatter

logger = logging.getLogger(__name__)

class UnifiedReportOrchestrator:
    """Main orchestrator for unified report generation."""
    
    def __init__(self, config: Optional[ReportConfiguration] = None):
        self.config = config or ReportConfiguration(
            output_format=ReportFormat.JSON,
            report_type=ReportType.SECURITY_ANALYSIS
        )
        self.logger = logging.getLogger(__name__)
    
    def generate_report(self, 
                       findings: List[Union[SecurityFinding, Dict[str, Any]]],
                       context: Optional[ReportContext] = None,
                       output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a complete report with specified configuration.
        
        Args:
            findings: List of security findings
            context: Report generation context
            output_path: Optional output file path
            
        Returns:
            Dict containing the generated report data
        """
        try:
            self.logger.info(f"Starting report generation: {self.config.report_type.value} -> {self.config.output_format.value}")
            
            # Prepare input data
            input_data = self._prepare_input_data(findings, context)
            
            # Generate report using appropriate generator
            generator = self._create_generator()
            report_data = generator.generate(input_data)
            
            # Format report using appropriate formatter
            if self.config.output_format != ReportFormat.JSON:
                formatted_output = self._format_report(report_data)
                report_data['formatted_output'] = formatted_output
            
            # Save to file if path specified
            if output_path:
                self._save_report(report_data, output_path)
            
            self.logger.info(f"Report generation completed successfully")
            return report_data
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            raise
    
    def generate_multi_format_report(self,
                                   findings: List[Union[SecurityFinding, Dict[str, Any]]],
                                   formats: List[ReportFormat],
                                   base_output_path: str,
                                   context: Optional[ReportContext] = None) -> Dict[str, str]:
        """
        Generate reports in multiple formats.
        
        Args:
            findings: List of security findings
            formats: List of output formats to generate
            base_output_path: Base path for output files (without extension)
            context: Report generation context
            
        Returns:
            Dict mapping format to output file path
        """
        output_files = {}
        
        # Prepare input data once
        input_data = self._prepare_input_data(findings, context)
        
        # Generate base report data once
        generator = self._create_generator()
        base_report_data = generator.generate(input_data)
        
        # Generate each format
        for format_type in formats:
            try:
                self.logger.info(f"Generating {format_type.value} format")
                
                # Create formatter for this format
                formatter = FormatterFactory.create_formatter(format_type)
                formatted_output = formatter.format(base_report_data)
                
                # Determine output file path
                file_extension = self._get_file_extension(format_type)
                output_file = f"{base_output_path}.{file_extension}"
                
                # Save formatted output
                self._save_formatted_output(formatted_output, output_file, format_type)
                output_files[format_type.value] = output_file
                
                self.logger.info(f"Successfully generated {format_type.value}: {output_file}")
                
            except Exception as e:
                self.logger.error(f"Failed to generate {format_type.value} format: {e}")
                continue
        
        return output_files
    
    def create_generator(self, report_type: Optional[ReportType] = None, **kwargs) -> BaseFormatter:
        """
        Create a report generator for external use.
        
        Args:
            report_type: Type of report to generate
            **kwargs: Additional configuration parameters
            
        Returns:
            BaseFormatter: Configured report generator
        """
        target_type = report_type or self.config.report_type
        return ReportGenerator.create_generator(target_type, configuration=self.config, **kwargs)
    
    def _prepare_input_data(self, 
                          findings: List[Union[SecurityFinding, Dict[str, Any]]],
                          context: Optional[ReportContext]) -> Dict[str, Any]:
        """Prepare and validate input data for report generation."""
        # Standardize findings format with robust object-to-dict conversion
        standardized_findings = []
        for finding in findings:
            standardized_findings.append(self._safe_object_to_dict(finding))
        
        # Create metadata
        metadata = create_default_metadata(self.config.report_type, self.config.output_format)
        metadata.total_findings = len(standardized_findings)
        
        # Prepare context data with safe conversion
        context_data = {}
        if context:
            context_data = self._safe_object_to_dict(context)
        
        return {
            'findings': standardized_findings,
            'metadata': self._safe_object_to_dict(metadata),
            'context': context_data,
            'configuration': self._safe_object_to_dict(self.config)
        }
    
    def _create_generator(self):
        """Create appropriate report generator based on configuration."""
        if self.config.report_type == ReportType.SECURITY_ANALYSIS:
            return SecurityAnalysisReportGenerator(self.config)
        elif self.config.report_type == ReportType.EXECUTIVE_SUMMARY:
            return ExecutiveSummaryGenerator(self.config)
        elif self.config.report_type == ReportType.TECHNICAL_DETAILS:
            return TechnicalReportGenerator(self.config)
        elif self.config.report_type == ReportType.COMPLIANCE_ASSESSMENT:
            return ComplianceReportGenerator(configuration=self.config)
        elif self.config.report_type == ReportType.CUSTOM:
            template_config = getattr(self.config, 'custom_template', {})
            return CustomReportGenerator(template_config, configuration=self.config)
        else:
            return SecurityAnalysisReportGenerator(self.config)
    
    def _format_report(self, report_data: Dict[str, Any]) -> Union[str, bytes]:
        """Format report data using appropriate formatter."""
        formatter = FormatterFactory.create_formatter(self.config.output_format)
        return formatter.format(report_data)
    
    def _save_report(self, report_data: Dict[str, Any], output_path: str) -> None:
        """Save report to specified path."""
        try:
            output_file = Path(output_path)
            
            # Ensure output directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Handle different output formats
            if self.config.output_format == ReportFormat.JSON:
                import json
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
            
            elif 'formatted_output' in report_data:
                formatted_output = report_data['formatted_output']
                
                if isinstance(formatted_output, bytes):
                    # Binary format (e.g., PDF)
                    with open(output_file, 'wb') as f:
                        f.write(formatted_output)
                else:
                    # Text format (e.g., HTML, XML, Markdown)
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(formatted_output)
            
            self.logger.info(f"Report saved to: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save report to {output_path}: {e}")
            raise
    
    def _save_formatted_output(self, formatted_output: Union[str, bytes], 
                             output_path: str, format_type: ReportFormat) -> None:
        """Save formatted output to file."""
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            if isinstance(formatted_output, bytes):
                with open(output_file, 'wb') as f:
                    f.write(formatted_output)
            else:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(formatted_output)
                    
        except Exception as e:
            self.logger.error(f"Failed to save {format_type.value} output: {e}")
            raise
    
    def _get_file_extension(self, format_type: ReportFormat) -> str:
        """Get appropriate file extension for format type."""
        extensions = {
            ReportFormat.JSON: 'json',
            ReportFormat.HTML: 'html',
            ReportFormat.PDF: 'pdf',
            ReportFormat.XML: 'xml',
            ReportFormat.MARKDOWN: 'md',
            ReportFormat.CSV: 'csv',
            ReportFormat.EXCEL: 'xlsx'
        }
        
        return extensions.get(format_type, 'txt')
    
    def get_report_summary(self, findings: List[Union[SecurityFinding, Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Get a quick summary of what the report would contain.
        
        Args:
            findings: List of security findings
            
        Returns:
            Dict containing report summary information
        """
        # Convert findings to standard format with robust object-to-dict conversion
        standardized_findings = []
        for finding in findings:
            standardized_findings.append(self._safe_object_to_dict(finding))
        
        # Calculate summary statistics
        total_findings = len(standardized_findings)
        
        severity_counts = {}
        category_counts = {}
        confidence_scores = []
        
        for finding in standardized_findings:
            # Count by severity
            severity = finding.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by category
            category = finding.get('category', 'unknown')
            category_counts[category] = category_counts.get(category, 0) + 1
            
            # Collect confidence scores
            confidence = finding.get('confidence', 0)
            if isinstance(confidence, (int, float)):
                confidence_scores.append(confidence)
        
        # Calculate average confidence
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        # Estimate risk score (simplified)
        severity_weights = {'critical': 10, 'high': 7, 'medium': 5, 'low': 2, 'info': 0}
        total_weighted_score = sum(severity_weights.get(sev.lower(), 0) * count 
                                 for sev, count in severity_counts.items())
        risk_score = min(100, (total_weighted_score / max(total_findings, 1)) * 10)
        
        return {
            'total_findings': total_findings,
            'severity_distribution': severity_counts,
            'category_distribution': category_counts,
            'average_confidence': avg_confidence,
            'estimated_risk_score': risk_score,
            'report_type': self.config.report_type.value,
            'output_format': self.config.output_format.value,
            'estimated_generation_time': self._estimate_generation_time(total_findings)
        }
    
    def _estimate_generation_time(self, finding_count: int) -> str:
        """Estimate report generation time based on finding count and format."""
        base_time = 1  # Base time in seconds
        
        # Adjust for finding count
        if finding_count > 1000:
            base_time += 10
        elif finding_count > 500:
            base_time += 5
        elif finding_count > 100:
            base_time += 2
        
        # Adjust for format complexity
        if self.config.output_format == ReportFormat.PDF:
            base_time += 5
        elif self.config.output_format == ReportFormat.HTML:
            base_time += 2
        
        # Adjust for report type complexity
        if self.config.report_type == ReportType.COMPLIANCE_ASSESSMENT:
            base_time += 3
        elif self.config.report_type == ReportType.TECHNICAL_DETAILS:
            base_time += 2
        
        if base_time <= 5:
            return "< 5 seconds"
        elif base_time <= 15:
            return "5-15 seconds"
        elif base_time <= 30:
            return "15-30 seconds"
        else:
            return "> 30 seconds"
    
    def validate_configuration(self) -> Dict[str, Any]:
        """
        Validate current configuration and return validation results.
        
        Returns:
            Dict containing validation results and recommendations
        """
        validation_results = {
            'is_valid': True,
            'errors': [],
            'warnings': [],
            'recommendations': []
        }
        
        # Check format support
        try:
            FormatterFactory.create_formatter(self.config.output_format)
        except (ValueError, ImportError) as e:
            validation_results['is_valid'] = False
            validation_results['errors'].append(f"Unsupported output format: {e}")
        
        # Check generator compatibility
        if self.config.report_type == ReportType.COMPLIANCE_ASSESSMENT:
            if not hasattr(self.config, 'compliance_framework'):
                validation_results['warnings'].append("No compliance framework specified, using default MASVS")
        
        # Check template configuration for custom reports
        if self.config.report_type == ReportType.CUSTOM:
            if not hasattr(self.config, 'custom_template'):
                validation_results['is_valid'] = False
                validation_results['errors'].append("Custom report type requires template configuration")
        
        # Performance recommendations
        if self.config.output_format == ReportFormat.PDF:
            validation_results['recommendations'].append("PDF generation requires additional dependencies (reportlab)")
        
        if self.config.include_charts and self.config.output_format in [ReportFormat.JSON, ReportFormat.XML]:
            validation_results['warnings'].append("Chart generation not supported for JSON/XML formats")
        
        return validation_results
    
    def _safe_object_to_dict(self, obj) -> Dict[str, Any]:
        """
        Safely convert an object to dictionary format.
        
        Handles both objects with __dict__ attribute and plain dictionaries,
        preventing the "'dict' object has no attribute '__dict__'" error.
        
        Args:
            obj: Object to convert to dictionary
            
        Returns:
            Dictionary representation of the object
        """
        if obj is None:
            return {}
        
        # If it's already a dictionary, return as-is
        if isinstance(obj, dict):
            return obj
        
        # Try using dataclasses.asdict() for dataclass objects
        try:
            from dataclasses import asdict, is_dataclass
            if is_dataclass(obj):
                return asdict(obj)
        except (ImportError, TypeError):
            pass
        
        # Try using __dict__ attribute for regular objects
        if hasattr(obj, '__dict__'):
            try:
                return obj.__dict__
            except AttributeError:
                pass
        
        # Try using vars() for objects with __dict__
        try:
            return vars(obj)
        except TypeError:
            pass
        
        # For objects that can be converted to dict (like namedtuples)
        try:
            if hasattr(obj, '_asdict'):
                return obj._asdict()
        except (AttributeError, TypeError):
            pass
        
        # Last resort: try to convert primitive types to dict
        if isinstance(obj, (str, int, float, bool, list, tuple)):
            return {'value': obj}
        
        # If all else fails, return string representation in dict
        return {'raw_value': str(obj), 'type': type(obj).__name__}

# Convenience functions for easy access
def create_security_report(findings: List[Union[SecurityFinding, Dict[str, Any]]], 
                         output_format: str = "json",
                         output_path: Optional[str] = None,
                         **kwargs) -> Dict[str, Any]:
    """
    Create a comprehensive security analysis report.
    
    Args:
        findings: List of security findings
        output_format: Output format (json, html, pdf, xml, markdown)
        output_path: Optional output file path
        **kwargs: Additional configuration options
        
    Returns:
        Dict containing the generated report
    """
    config = ReportConfiguration(
        output_format=ReportFormat(output_format.lower()),
        report_type=ReportType.SECURITY_ANALYSIS,
        **kwargs
    )
    
    orchestrator = UnifiedReportOrchestrator(config)
    return orchestrator.generate_report(findings, output_path=output_path)

def create_executive_summary(findings: List[Union[SecurityFinding, Dict[str, Any]]],
                           output_format: str = "html",
                           output_path: Optional[str] = None,
                           **kwargs) -> Dict[str, Any]:
    """
    Create an executive summary report.
    
    Args:
        findings: List of security findings
        output_format: Output format
        output_path: Optional output file path
        **kwargs: Additional configuration options
        
    Returns:
        Dict containing the generated report
    """
    config = ReportConfiguration(
        output_format=ReportFormat(output_format.lower()),
        report_type=ReportType.EXECUTIVE_SUMMARY,
        **kwargs
    )
    
    orchestrator = UnifiedReportOrchestrator(config)
    return orchestrator.generate_report(findings, output_path=output_path)

def generate_multi_format_reports(findings: List[Union[SecurityFinding, Dict[str, Any]]],
                                 base_output_path: str,
                                 formats: Optional[List[str]] = None,
                                 **kwargs) -> Dict[str, str]:
    """
    Generate reports in multiple formats.
    
    Args:
        findings: List of security findings
        base_output_path: Base path for output files
        formats: List of formats to generate (default: json, html, pdf)
        **kwargs: Additional configuration options
        
    Returns:
        Dict mapping format names to output file paths
    """
    if formats is None:
        formats = ['json', 'html', 'pdf']
    
    format_enums = [ReportFormat(fmt.lower()) for fmt in formats]
    
    config = ReportConfiguration(
        output_format=format_enums[0],  # Use first format as primary
        report_type=ReportType.SECURITY_ANALYSIS,
        **kwargs
    )
    
    orchestrator = UnifiedReportOrchestrator(config)
    return orchestrator.generate_multi_format_report(findings, format_enums, base_output_path) 
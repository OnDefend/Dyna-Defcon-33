#!/usr/bin/env python3
"""
AODS Unified Reporting Framework

Comprehensive reporting framework supporting multiple output formats (JSON, HTML, PDF, XML)
with standardized templates, generators, and formatting utilities.

Features:
- Multiple format support (JSON, HTML, PDF, XML)
- Template-based report generation
- Standardized report structures
- Rich formatting and styling
- Interactive elements support
- Performance-optimized generation
- Plugin-specific report customization
- Executive summary generation
- Compliance reporting support
- Export and sharing capabilities

This framework provides unified reporting capabilities for all AODS components,
ensuring consistent, professional, and comprehensive security analysis reports.
"""

# Core report structures and types
from .data_structures import (
    ReportFormat,
    ReportType,
    ReportSection,
    ReportMetadata,
    SecurityFinding,
    ReportConfiguration,
    ReportTemplate,
    ReportContext,
    DynamicCoordinationAnalysisResult,
    ComponentAnalysisResult,
    RuntimePatternResult,
    CorrelationAnalysisResult
)

# Format-specific generators
from .formatters import (
    JSONFormatter,
    HTMLFormatter,
    PDFFormatter,
    XMLFormatter,
    MarkdownFormatter
)

# Report generation orchestration
from .generators import (
    ReportGenerator,
    ExecutiveSummaryGenerator,
    TechnicalReportGenerator,
    ComplianceReportGenerator,
    CustomReportGenerator,
    DynamicCoordinationReportGenerator
)

# Template management - temporarily disabled
# from .templates import (
#     TemplateManager,
#     DefaultTemplates,
#     CustomTemplateLoader,
#     TemplateRenderer
# )

# Report utilities - temporarily disabled
# from .utilities import (
#     ReportValidator,
#     ReportMerger,
#     ReportExporter,
#     ReportMetrics,
#     ChartGenerator,
#     TableGenerator
# )

# Main report orchestrator
from .report_orchestrator import UnifiedReportOrchestrator

# Export all public interfaces
__all__ = [
    # Core data structures
    'ReportFormat',
    'ReportType', 
    'ReportSection',
    'ReportMetadata',
    'SecurityFinding',
    'ReportConfiguration',
    'ReportTemplate',
    'ReportContext',
    
    # Formatters
    'JSONFormatter',
    'HTMLFormatter',
    'PDFFormatter',
    'XMLFormatter',
    'MarkdownFormatter',
    
    # Generators
    'ReportGenerator',
    'ExecutiveSummaryGenerator',
    'TechnicalReportGenerator',
    'ComplianceReportGenerator',
    'CustomReportGenerator',
    
    # Template system - temporarily disabled
    # 'TemplateManager',
    # 'DefaultTemplates',
    # 'CustomTemplateLoader',
    # 'TemplateRenderer',
    
    # Utilities - temporarily disabled
    # 'ReportValidator',
    # 'ReportMerger',
    # 'ReportExporter',
    # 'ReportMetrics',
    # 'ChartGenerator',
    # 'TableGenerator',
    
    # Main orchestrator
    'UnifiedReportOrchestrator'
]

# Package metadata
__version__ = "2.0.0"
__author__ = "AODS Development Team"
__description__ = "Unified reporting framework with multi-format support"
__category__ = "SHARED_INFRASTRUCTURE"

# Convenience functions for easy access
def create_report_generator(format_type: str = "json", **kwargs) -> ReportGenerator:
    """
    Create a report generator for the specified format.
    
    Args:
        format_type: Output format (json, html, pdf, xml, markdown)
        **kwargs: Additional configuration parameters
        
    Returns:
        ReportGenerator: Configured report generator
    """
    orchestrator = UnifiedReportOrchestrator()
    return orchestrator.create_generator(format_type, **kwargs)

def generate_security_report(findings: list, format_type: str = "json", **kwargs) -> dict:
    """
    Generate a security report from findings.
    
    Args:
        findings: List of security findings
        format_type: Output format
        **kwargs: Additional configuration
        
    Returns:
        dict: Generated report data
    """
    generator = create_report_generator(format_type, **kwargs)
    return generator.generate_security_report(findings)

def generate_executive_summary(analysis_results: dict, **kwargs) -> dict:
    """
    Generate an executive summary report.
    
    Args:
        analysis_results: Complete analysis results
        **kwargs: Additional configuration
        
    Returns:
        dict: Executive summary report
    """
    generator = ExecutiveSummaryGenerator(**kwargs)
    return generator.generate(analysis_results)

def generate_compliance_report(findings: list, framework: str = "MASVS", **kwargs) -> dict:
    """
    Generate a compliance framework report.
    
    Args:
        findings: List of security findings
        framework: Compliance framework (MASVS, NIST, etc.)
        **kwargs: Additional configuration
        
    Returns:
        dict: Compliance report
    """
    generator = ComplianceReportGenerator(framework=framework, **kwargs)
    return generator.generate(findings)

# Available formatters registry
AVAILABLE_FORMATTERS = {
    'json': JSONFormatter,
    'html': HTMLFormatter,
    'pdf': PDFFormatter,
    'xml': XMLFormatter,
    'markdown': MarkdownFormatter
}

# Available report types
AVAILABLE_REPORT_TYPES = {
    'security': 'Comprehensive security analysis report',
    'executive': 'Executive summary report',
    'technical': 'Detailed technical analysis report',
    'compliance': 'Compliance framework assessment report',
    'custom': 'Custom report with user-defined structure'
}

def get_supported_formats() -> list:
    """Get list of supported output formats."""
    return list(AVAILABLE_FORMATTERS.keys())

def get_supported_report_types() -> dict:
    """Get dictionary of supported report types."""
    return AVAILABLE_REPORT_TYPES.copy() 
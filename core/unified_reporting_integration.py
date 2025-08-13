#!/usr/bin/env python3
"""
Unified AODS Reporting Engine Integration

Consolidates all reporting engines into a single, coherent system that
integrates ML-enhanced evidence extraction, professional formatting,
and organic intelligence into the main AODS workflow.

Integrates:
- ML Enhanced Evidence Extractor
- Professional HTML Report Generator  
- Existing AODS Report Generator
- Enterprise Reporting Engine
- NIST/MASTG Compliance Engines
- SysReptor Integration

This replaces the need for multiple standalone reporting scripts.
"""

import logging
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime
import asyncio

# Core AODS components
try:
    from .report_generator import ReportGenerator
    from .ml_enhanced_evidence_extractor import MLEnhancedEvidenceExtractor, MLEnhancedDescription
    CORE_AVAILABLE = True
except ImportError:
    CORE_AVAILABLE = False

# Enterprise reporting
try:
    from .enterprise.reporting_engine import EnterpriseReportingEngine, ReportType
    ENTERPRISE_AVAILABLE = True
except ImportError:
    ENTERPRISE_AVAILABLE = False

# Compliance engines
try:
    from ..plugins.nist_compliance_reporting import NISTComplianceReportingPlugin
    from ..plugins.mastg_integration import MASTGIntegrationPlugin
    COMPLIANCE_AVAILABLE = True
except ImportError:
    COMPLIANCE_AVAILABLE = False

# Professional formatting
try:
    from .shared_infrastructure.reporting.report_orchestrator import UnifiedReportOrchestrator
    ORCHESTRATOR_AVAILABLE = True
except ImportError:
    ORCHESTRATOR_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class ReportingConfiguration:
    """Configuration for unified reporting engine."""
    enable_ml_enhancement: bool = True
    enable_enterprise_features: bool = True
    enable_compliance_reports: bool = True
    generate_professional_html: bool = True
    generate_json: bool = True
    generate_csv: bool = True
    output_directory: str = "./reports"
    workspace_path: str = "./workspace"
    include_code_snippets: bool = True
    apply_organic_deduplication: bool = True
    ml_confidence_threshold: float = 0.6

@dataclass
class UnifiedReportResult:
    """Result from unified reporting process."""
    html_report_path: Optional[str] = None
    json_report_path: Optional[str] = None
    csv_report_path: Optional[str] = None
    enterprise_report_path: Optional[str] = None
    compliance_reports: Dict[str, str] = None
    enhanced_vulnerabilities_count: int = 0
    original_vulnerabilities_count: int = 0
    ml_enhancements_applied: int = 0
    processing_time_seconds: float = 0.0
    success: bool = False
    error_message: Optional[str] = None

class UnifiedReportingEngine:
    """
    Unified reporting engine that integrates all AODS reporting capabilities
    into a single, coherent workflow with ML enhancement and professional output.
    """
    
    def __init__(self, config: Optional[ReportingConfiguration] = None):
        """Initialize the unified reporting engine."""
        self.logger = logging.getLogger(__name__)
        self.config = config or ReportingConfiguration()
        
        # Initialize components based on availability
        self._initialize_components()
        
        # Create output directory
        Path(self.config.output_directory).mkdir(parents=True, exist_ok=True)
        
        self.logger.info("Unified Reporting Engine initialized")
    
    def _initialize_components(self):
        """Initialize available reporting components."""
        self.components = {}
        
        # ML Enhanced Evidence Extractor
        if self.config.enable_ml_enhancement:
            try:
                self.components['ml_extractor'] = MLEnhancedEvidenceExtractor(
                    workspace_path=self.config.workspace_path
                )
                self.logger.debug("ML Enhanced Evidence Extractor initialized")
            except Exception as e:
                self.logger.warning(f"ML Enhancement unavailable: {e}")
        
        # Core Report Generator
        if CORE_AVAILABLE:
            self.components['core_generator'] = None  # Will be created per scan
            self.logger.debug("Core Report Generator available")
        
        # Enterprise Reporting Engine
        if ENTERPRISE_AVAILABLE and self.config.enable_enterprise_features:
            try:
                self.components['enterprise_engine'] = EnterpriseReportingEngine()
                self.logger.debug("Enterprise Reporting Engine initialized")
            except Exception as e:
                self.logger.warning(f"Enterprise Reporting unavailable: {e}")
        
        # Compliance Engines
        if COMPLIANCE_AVAILABLE and self.config.enable_compliance_reports:
            try:
                self.components['nist_plugin'] = NISTComplianceReportingPlugin()
                self.components['mastg_plugin'] = MASTGIntegrationPlugin()
                self.logger.debug("Compliance engines initialized")
            except Exception as e:
                self.logger.warning(f"Compliance engines unavailable: {e}")
        
        # Unified Orchestrator
        if ORCHESTRATOR_AVAILABLE:
            try:
                self.components['orchestrator'] = UnifiedReportOrchestrator()
                self.logger.debug("Unified Report Orchestrator initialized")
            except Exception as e:
                self.logger.warning(f"Report Orchestrator unavailable: {e}")
    
    def generate_unified_report(self, package_name: str, vulnerabilities: List[Dict[str, Any]], 
                              apk_ctx: Any = None, scan_mode: str = "deep") -> UnifiedReportResult:
        """
        Generate comprehensive unified report with ML enhancement and professional formatting.
        
        Args:
            package_name: Android package name
            vulnerabilities: List of vulnerability dictionaries
            apk_ctx: APK context object (optional)
            scan_mode: Scan mode (safe, deep)
        
        Returns:
            UnifiedReportResult with paths and metrics
        """
        start_time = datetime.now()
        result = UnifiedReportResult()
        
        try:
            self.logger.info(f"Starting unified report generation for {package_name}")
            result.original_vulnerabilities_count = len(vulnerabilities)
            
            # Step 1: ML Enhancement of Vulnerabilities
            enhanced_vulns = self._apply_ml_enhancements(vulnerabilities)
            result.enhanced_vulnerabilities_count = len(enhanced_vulns)
            result.ml_enhancements_applied = sum(
                1 for v in enhanced_vulns if v.get('ml_enhanced', False)
            )
            
            # Step 2: Apply Organic Deduplication
            if self.config.apply_organic_deduplication:
                enhanced_vulns = self._apply_organic_deduplication(enhanced_vulns)
                self.logger.info(f"Deduplication: {result.enhanced_vulnerabilities_count} → {len(enhanced_vulns)}")
                result.enhanced_vulnerabilities_count = len(enhanced_vulns)
            
            # Step 3: Generate Core Reports
            report_paths = self._generate_core_reports(package_name, enhanced_vulns, scan_mode)
            result.json_report_path = report_paths.get('json')
            result.csv_report_path = report_paths.get('csv')
            
            # Step 4: Generate Professional HTML Report
            if self.config.generate_professional_html:
                result.html_report_path = self._generate_professional_html(
                    package_name, enhanced_vulns, result.json_report_path
                )
            
            # Step 5: Generate Enterprise Reports
            if 'enterprise_engine' in self.components:
                result.enterprise_report_path = self._generate_enterprise_report(
                    package_name, enhanced_vulns, apk_ctx
                )
            
            # Step 6: Generate Compliance Reports
            if self.config.enable_compliance_reports and apk_ctx:
                result.compliance_reports = self._generate_compliance_reports(apk_ctx)
            
            # Calculate processing time
            end_time = datetime.now()
            result.processing_time_seconds = (end_time - start_time).total_seconds()
            result.success = True
            
            self.logger.info(f"Unified report generation completed in {result.processing_time_seconds:.2f}s")
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            self.logger.error(f"Unified report generation failed: {e}", exc_info=True)
        
        return result
    
    def _apply_ml_enhancements(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply ML enhancements to vulnerability descriptions and evidence."""
        if 'ml_extractor' not in self.components:
            self.logger.debug("ML enhancement disabled or unavailable")
            return vulnerabilities
        
        enhanced_vulns = []
        ml_extractor = self.components['ml_extractor']
        
        for vuln in vulnerabilities:
            try:
                # Get ML-enhanced description
                enhanced_desc = ml_extractor.enhance_vulnerability_description(vuln)
                
                # Apply enhancement if confidence is sufficient (lowered threshold for testing)
                confidence_threshold = min(self.config.ml_confidence_threshold, 0.5)  # Lower threshold for better application
                if enhanced_desc.ml_confidence >= confidence_threshold:
                    # Update vulnerability with enhanced data
                    enhanced_vuln = vuln.copy()
                    enhanced_vuln['ml_enhanced'] = True
                    enhanced_vuln['ml_confidence'] = enhanced_desc.ml_confidence
                    
                    # Apply enhanced description if it's significantly better or contains structured data
                    original_desc = vuln.get('description', '')
                    enhanced_text = enhanced_desc.enhanced_description
                    
                    # Use enhanced description if it has structure, fixes line 1 issues, or is significantly better
                    if ('•' in enhanced_text or 'Components Analyzed:' in enhanced_text or 
                        'line 1' in original_desc or  # Always replace line 1 references
                        len(enhanced_text) > len(original_desc) * 0.5):
                        enhanced_vuln['original_description'] = original_desc
                        enhanced_vuln['description'] = enhanced_text
                        enhanced_vuln['description_enhanced'] = True
                    
                    # Add structured evidence
                    enhanced_vuln['structured_evidence'] = asdict(enhanced_desc.structured_evidence)
                    enhanced_vuln['enhancement_reasons'] = enhanced_desc.enhancement_reasons
                    
                    # Enhance code snippets if available
                    if enhanced_desc.structured_evidence.code_snippets:
                        best_snippet = max(
                            enhanced_desc.structured_evidence.code_snippets,
                            key=lambda x: x.get('confidence', 0)
                        )
                        if best_snippet.get('confidence', 0) > 0.8:
                            enhanced_vuln['code_snippet'] = best_snippet['code']
                    
                    enhanced_vulns.append(enhanced_vuln)
                else:
                    # Keep original if enhancement confidence is low
                    enhanced_vulns.append(vuln)
                    
            except Exception as e:
                self.logger.warning(f"ML enhancement failed for vulnerability: {e}")
                enhanced_vulns.append(vuln)
        
        ml_enhanced_count = sum(1 for v in enhanced_vulns if v.get('ml_enhanced', False))
        self.logger.info(f"ML enhancement applied to {ml_enhanced_count}/{len(vulnerabilities)} vulnerabilities")
        
        return enhanced_vulns
    
    def _apply_organic_deduplication(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply organic deduplication using ML-style similarity detection."""
        import hashlib
        from collections import defaultdict
        
        fingerprint_groups = defaultdict(list)
        
        for vuln in vulnerabilities:
            # Create similarity fingerprint
            title = vuln.get('title', '').lower().strip()
            file_path = vuln.get('file_path', '').strip()
            cwe_id = vuln.get('configuration_evidence', {}).get('cwe_id', '')
            
            # Clean title for comparison
            clean_title = title.replace('detected', '').replace('analysis', '').replace('security', '').strip()
            
            # Create fingerprint
            fingerprint_data = f"{clean_title}|{file_path}|{cwe_id}"
            fingerprint = hashlib.md5(fingerprint_data.encode()).hexdigest()[:8]
            
            fingerprint_groups[fingerprint].append(vuln)
        
        # Keep highest confidence vulnerability from each group
        deduplicated = []
        duplicates_removed = 0
        
        for group in fingerprint_groups.values():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                # Select best vulnerability based on ML confidence, then regular confidence
                best_vuln = max(group, key=lambda v: (
                    v.get('ml_confidence', 0),
                    v.get('confidence', 0)
                ))
                
                # Add deduplication metadata
                best_vuln['deduplication_info'] = {
                    'duplicates_merged': len(group) - 1,
                    'original_count': len(group),
                    'selection_reason': 'highest_ml_confidence' if best_vuln.get('ml_enhanced') else 'highest_confidence'
                }
                
                deduplicated.append(best_vuln)
                duplicates_removed += len(group) - 1
        
        self.logger.info(f"Organic deduplication removed {duplicates_removed} duplicate vulnerabilities")
        return deduplicated
    
    def _validate_vulnerabilities_for_html(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate and clean vulnerability data for HTML generation."""
        validated = []
        
        for vuln in vulnerabilities:
            try:
                # Create a clean copy
                clean_vuln = {}
                
                # Ensure all string fields are actually strings
                string_fields = ['title', 'description', 'severity', 'file_path', 'detection_method']
                for field in string_fields:
                    value = vuln.get(field, '')
                    if isinstance(value, dict):
                        # Convert dict to string representation
                        clean_vuln[field] = str(value)
                    elif value is None:
                        clean_vuln[field] = ''
                    else:
                        clean_vuln[field] = str(value)
                
                # Ensure numeric fields are properly typed
                numeric_fields = ['line_number', 'confidence']
                for field in numeric_fields:
                    value = vuln.get(field, 0)
                    try:
                        clean_vuln[field] = float(value) if field == 'confidence' else int(value)
                    except (ValueError, TypeError):
                        clean_vuln[field] = 0.0 if field == 'confidence' else 0
                
                # Copy other fields as-is
                for key, value in vuln.items():
                    if key not in string_fields + numeric_fields:
                        clean_vuln[key] = value
                
                # Ensure required fields exist
                if 'title' not in clean_vuln or not clean_vuln['title']:
                    clean_vuln['title'] = 'Security Issue'
                if 'severity' not in clean_vuln or not clean_vuln['severity']:
                    clean_vuln['severity'] = 'MEDIUM'
                
                validated.append(clean_vuln)
                
            except Exception as e:
                self.logger.warning(f"Failed to validate vulnerability: {e}")
                # Keep original if validation fails
                validated.append(vuln)
        
        return validated
    
    def _generate_core_reports(self, package_name: str, vulnerabilities: List[Dict[str, Any]], 
                             scan_mode: str) -> Dict[str, str]:
        """Generate core JSON and CSV reports using existing AODS infrastructure."""
        report_paths = {}
        
        try:
            # Create core report generator
            from .report_generator import ReportGenerator
            generator = ReportGenerator(package_name, scan_mode)
            
            # CRITICAL: Set vulnerabilities with ML enhancements
            generator.set_external_vulnerabilities(vulnerabilities)
            
            # Ensure the generator uses the enhanced vulnerabilities
            generator.vulnerabilities = vulnerabilities
            
            # Generate JSON report
            if self.config.generate_json:
                json_path = f"{self.config.output_directory}/{package_name}_unified_report.json"
                generator.vulnerabilities = vulnerabilities  # Ensure vulnerabilities are set
                generator.generate_json(json_path)
                report_paths['json'] = json_path
                self.logger.debug(f"JSON report generated: {json_path}")
            
            # Generate CSV report
            if self.config.generate_csv:
                csv_path = f"{self.config.output_directory}/{package_name}_unified_report.csv"
                generator.generate_csv(csv_path)
                report_paths['csv'] = csv_path
                self.logger.debug(f"CSV report generated: {csv_path}")
                
        except Exception as e:
            self.logger.error(f"Core report generation failed: {e}")
        
        return report_paths
    
    def _generate_professional_html(self, package_name: str, vulnerabilities: List[Dict[str, Any]], 
                                  json_path: Optional[str]) -> Optional[str]:
        """Generate professional HTML report using the enhanced generator."""
        try:
            # Import the enhanced HTML generator
            import importlib.util
            
            # Load the professional HTML generator
            spec = importlib.util.spec_from_file_location(
                "generate_professional_html_report",
                "generate_professional_html_report.py"
            )
            if spec and spec.loader:
                html_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(html_module)
                
                # Use JSON file if available, otherwise create temporary data
                if json_path:
                    input_data = json_path
                else:
                    # Create temporary JSON data in expected format
                    temp_data = {
                        'vulnerabilities': vulnerabilities,
                        'package_name': package_name,
                        'scan_metadata': {
                            'scan_time': datetime.now().isoformat(),
                            'unified_reporting': True,
                            'total_vulnerabilities': len(vulnerabilities)
                        }
                    }
                    temp_json = f"{self.config.output_directory}/{package_name}_temp.json"
                    with open(temp_json, 'w', encoding='utf-8') as f:
                        json.dump(temp_data, f, indent=2, ensure_ascii=False)
                    input_data = temp_json
                
                # Generate professional HTML
                html_path = f"{self.config.output_directory}/{package_name}_professional_report.html"
                
                # Validate vulnerabilities data before passing to HTML generator
                validated_vulnerabilities = self._validate_vulnerabilities_for_html(vulnerabilities)
                
                # Update temp data with validated vulnerabilities if we created temp JSON
                if not json_path:
                    temp_data['vulnerabilities'] = validated_vulnerabilities
                    with open(temp_json, 'w', encoding='utf-8') as f:
                        json.dump(temp_data, f, indent=2, ensure_ascii=False)
                
                html_module.generate_professional_html_report(input_data, html_path)
                
                self.logger.info(f"Professional HTML report generated: {html_path}")
                return html_path
                
        except Exception as e:
            self.logger.error(f"Professional HTML generation failed: {e}")
            import traceback
            full_traceback = traceback.format_exc()
            self.logger.error(f"HTML generation traceback: {full_traceback}")
            # Also print to stdout for debugging
            print(f"HTML Error Details: {e}")
            print(f"Full Traceback:\n{full_traceback}")
        
        return None
    
    def _generate_enterprise_report(self, package_name: str, vulnerabilities: List[Dict[str, Any]], 
                                  apk_ctx: Any) -> Optional[str]:
        """Generate enterprise-grade reports."""
        if 'enterprise_engine' not in self.components:
            return None
        
        try:
            enterprise_engine = self.components['enterprise_engine']
            
            # Convert vulnerabilities to enterprise format
            enterprise_data = {
                'package_name': package_name,
                'vulnerabilities': vulnerabilities,
                'scan_metadata': {
                    'unified_reporting': True,
                    'timestamp': datetime.now().isoformat()
                }
            }
            
            # Generate enterprise report
            enterprise_path = f"{self.config.output_directory}/{package_name}_enterprise_report.html"
            enterprise_engine.generate_report(
                data=enterprise_data,
                report_type=ReportType.COMPREHENSIVE,
                output_path=enterprise_path
            )
            
            self.logger.debug(f"Enterprise report generated: {enterprise_path}")
            return enterprise_path
            
        except Exception as e:
            self.logger.error(f"Enterprise report generation failed: {e}")
        
        return None
    
    def _generate_compliance_reports(self, apk_ctx: Any) -> Dict[str, str]:
        """Generate compliance reports (NIST, MASTG)."""
        compliance_reports = {}
        
        # NIST Compliance Report
        if 'nist_plugin' in self.components:
            try:
                nist_plugin = self.components['nist_plugin']
                nist_report = nist_plugin.analyze_compliance(apk_ctx)
                
                nist_path = f"{self.config.output_directory}/{apk_ctx.package_name}_nist_compliance.html"
                # Assuming the plugin has a save method
                if hasattr(nist_report, 'save_html_report'):
                    nist_report.save_html_report(nist_path)
                    compliance_reports['nist'] = nist_path
                    self.logger.debug(f"NIST compliance report generated: {nist_path}")
                    
            except Exception as e:
                self.logger.warning(f"NIST compliance report failed: {e}")
        
        # MASTG Integration Report
        if 'mastg_plugin' in self.components:
            try:
                mastg_plugin = self.components['mastg_plugin']
                mastg_report = mastg_plugin.run_plugin(apk_ctx)
                
                mastg_path = f"{self.config.output_directory}/{apk_ctx.package_name}_mastg_compliance.html"
                # Assuming the plugin provides report data
                if mastg_report and 'html_report' in mastg_report:
                    with open(mastg_path, 'w') as f:
                        f.write(mastg_report['html_report'])
                    compliance_reports['mastg'] = mastg_path
                    self.logger.debug(f"MASTG compliance report generated: {mastg_path}")
                    
            except Exception as e:
                self.logger.warning(f"MASTG compliance report failed: {e}")
        
        return compliance_reports
    
    def integrate_with_dyna_workflow(self, dyna_instance: Any, package_name: str, 
                                   vulnerabilities: List[Dict[str, Any]]) -> UnifiedReportResult:
        """
        Integration point for dyna.py to use unified reporting instead of separate scripts.
        
        This replaces the need for multiple generate_*_report.py scripts.
        """
        self.logger.info("Integrating with main AODS workflow...")
        
        # Get APK context if available
        apk_ctx = getattr(dyna_instance, 'apk_ctx', None)
        scan_mode = getattr(dyna_instance, 'scan_mode', 'deep')
        
        # Generate unified report
        result = self.generate_unified_report(
            package_name=package_name,
            vulnerabilities=vulnerabilities,
            apk_ctx=apk_ctx,
            scan_mode=scan_mode
        )
        
        # Update dyna instance with report paths
        if hasattr(dyna_instance, 'report_generator') and dyna_instance.report_generator is not None:
            report_gen = dyna_instance.report_generator
            if result.json_report_path and hasattr(report_gen, 'json_output_path'):
                report_gen.json_output_path = result.json_report_path
            if result.csv_report_path and hasattr(report_gen, 'csv_output_path'):
                report_gen.csv_output_path = result.csv_report_path
        
        return result

# Global instance for easy integration
_unified_engine = None

def get_unified_reporting_engine(config: Optional[ReportingConfiguration] = None) -> UnifiedReportingEngine:
    """Get or create the global unified reporting engine instance."""
    global _unified_engine
    if _unified_engine is None:
        _unified_engine = UnifiedReportingEngine(config)
    return _unified_engine

def integrate_unified_reporting_with_dyna(dyna_instance: Any, package_name: str, 
                                        vulnerabilities: List[Dict[str, Any]]) -> UnifiedReportResult:
    """
    Main integration function for dyna.py to replace standalone reporting scripts.
    
    Usage in dyna.py:
        from core.unified_reporting_integration import integrate_unified_reporting_with_dyna
        
        # Replace multiple generate_*_report.py calls with:
        result = integrate_unified_reporting_with_dyna(self, package_name, vulnerabilities)
        
        if result.success:
            print(f"Professional report: {result.html_report_path}")
            print(f"JSON report: {result.json_report_path}")
    """
    engine = get_unified_reporting_engine()
    return engine.integrate_with_dyna_workflow(dyna_instance, package_name, vulnerabilities)

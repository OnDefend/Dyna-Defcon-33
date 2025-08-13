"""
AODS SysReptor Integration Module
================================

penetration testing report generation using SysReptor platform.
Transforms AODS vulnerability findings into professional, stakeholder-ready reports.

Features:
- Automated report generation from AODS scan results
- finding templates for OWASP MASVS categories
- Multi-format export (PDF, HTML, Word)
- Collaborative reporting workflows
- High-quality report customization
"""

import logging
import json
import subprocess
import tempfile
import os
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
import requests
import time

try:
    import toml
    TOML_AVAILABLE = True
except ImportError:
    TOML_AVAILABLE = False
    # Note: Warning will be logged when TOML functionality is actually needed

@dataclass
class SysReptorConfig:
    """SysReptor configuration settings"""
    server_url: str
    api_token: str
    project_id: Optional[str] = None
    template_id: Optional[str] = None
    verify_ssl: bool = True
    timeout: int = 30
    report_format: str = "pdf"  # pdf, html, docx
    auto_create_project: bool = True
    collaborative_mode: bool = False

@dataclass
class AODSFinding:
    """AODS finding structure for SysReptor conversion"""
    title: str
    description: str
    severity: str
    category: str
    masvs_category: str
    file_location: Optional[str] = None
    line_number: Optional[int] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: Optional[float] = None
    references: Optional[List[str]] = None

@dataclass
class SysReptorReport:
    """SysReptor report metadata and content"""
    project_id: str
    project_name: str
    findings_count: int
    severity_distribution: Dict[str, int]
    report_url: str
    export_formats: List[str]
    creation_timestamp: str
    last_updated: str

class SysReptorIntegration:
    """
    SysReptor integration for professional AODS reporting.
    
    Provides seamless integration between AODS vulnerability findings
    and SysReptor's technical reporting platform.
    """
    
    def __init__(self, config: SysReptorConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Token {config.api_token}',
            'Content-Type': 'application/json'
        })
        
        # SysReptor CLI availability
        self.reptor_available = self._check_reptor_cli()
        
        # MASVS category mapping to SysReptor templates
        self.masvs_template_mapping = self._initialize_masvs_templates()
        
        # Severity mapping
        self.severity_mapping = {
            'critical': 'Critical',
            'high': 'High', 
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Info'
        }
        
        self.logger.info("SysReptor integration initialized")
    
    def _check_reptor_cli(self) -> bool:
        """Check if reptor CLI is available"""
        try:
            result = subprocess.run(['reptor', '--help'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.logger.warning("reptor CLI not found - using API integration only")
            return False
    
    def _initialize_masvs_templates(self) -> Dict[str, str]:
        """Initialize MASVS category to SysReptor template mapping"""
        return {
            'MASVS-STORAGE': 'mobile-data-storage-vulnerability',
            'MASVS-CRYPTO': 'mobile-cryptography-vulnerability', 
            'MASVS-AUTH': 'mobile-authentication-vulnerability',
            'MASVS-NETWORK': 'mobile-network-security-vulnerability',
            'MASVS-PLATFORM': 'mobile-platform-vulnerability',
            'MASVS-CODE': 'mobile-code-quality-vulnerability',
            'MASVS-RESILIENCE': 'mobile-resilience-vulnerability',
            'MASVS-PRIVACY': 'mobile-privacy-vulnerability',
            'general': 'mobile-security-vulnerability'
        }
    
    def create_project(self, project_name: str, app_info: Dict[str, Any]) -> str:
        """Create a new SysReptor project for AODS scan results"""
        try:
            if self.reptor_available:
                return self._create_project_cli(project_name, app_info)
            else:
                return self._create_project_api(project_name, app_info)
        except Exception as e:
            self.logger.error(f"Failed to create SysReptor project: {e}")
            raise
    
    def _create_project_cli(self, project_name: str, app_info: Dict[str, Any]) -> str:
        """Create project using reptor CLI"""
        try:
            # Create project configuration
            project_config = {
                'name': project_name,
                'description': f"Mobile Security Assessment - {app_info.get('package_name', 'Unknown App')}",
                'tags': ['mobile-security', 'aods', 'automated-scan'],
                'metadata': {
                    'app_package': app_info.get('package_name'),
                    'app_version': app_info.get('version'),
                    'target_sdk': app_info.get('target_sdk'),
                    'scan_timestamp': datetime.now().isoformat(),
                    'scanner': 'AODS'
                }
            }
            
            # Write project config to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(project_config, f, indent=2)
                config_file = f.name
            
            try:
                # Create project using reptor CLI
                cmd = [
                    'reptor', 'createproject',
                    '--server', self.config.server_url,
                    '--token', self.config.api_token,
                    '--file', config_file
                ]
                
                if not self.config.verify_ssl:
                    cmd.append('--insecure')
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    # Extract project ID from output
                    project_id = self._extract_project_id_from_output(result.stdout)
                    self.logger.info(f"Created SysReptor project: {project_id}")
                    return project_id
                else:
                    raise Exception(f"reptor command failed: {result.stderr}")
                    
            finally:
                # Clean up temporary file
                os.unlink(config_file)
                
        except Exception as e:
            self.logger.error(f"CLI project creation failed: {e}")
            raise
    
    def _create_project_api(self, project_name: str, app_info: Dict[str, Any]) -> str:
        """Create project using SysReptor API"""
        try:
            project_data = {
                'name': project_name,
                'description': f"Mobile Security Assessment - {app_info.get('package_name', 'Unknown App')}",
                'project_type': 'mobile-security',
                'tags': ['mobile-security', 'aods', 'automated-scan'],
                'custom_fields': {
                    'app_package': app_info.get('package_name'),
                    'app_version': app_info.get('version'),
                    'target_sdk': app_info.get('target_sdk'),
                    'scan_timestamp': datetime.now().isoformat(),
                    'scanner_version': 'AODS v2.0'
                }
            }
            
            response = self.session.post(
                f"{self.config.server_url}/api/v1/projects/",
                json=project_data,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl
            )
            
            if response.status_code == 201:
                project = response.json()
                project_id = project['id']
                self.logger.info(f"Created SysReptor project via API: {project_id}")
                return project_id
            else:
                raise Exception(f"API project creation failed: {response.status_code} - {response.text}")
                
        except Exception as e:
            self.logger.error(f"API project creation failed: {e}")
            raise
    
    def convert_aods_findings(self, scan_results: Dict[str, Any]) -> List[AODSFinding]:
        """Convert AODS scan results to structured findings"""
        findings = []
        
        # Extract vulnerabilities from AODS scan results
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            try:
                finding = AODSFinding(
                    title=vuln.get('title', 'Unknown Vulnerability'),
                    description=vuln.get('description', ''),
                    severity=vuln.get('severity', 'medium').lower(),
                    category=vuln.get('category', 'general'),
                    masvs_category=vuln.get('masvs_category', 'general'),
                    file_location=vuln.get('file_location'),
                    line_number=vuln.get('line_number'),
                    evidence=vuln.get('evidence'),
                    recommendation=vuln.get('recommendation'),
                    cwe_id=vuln.get('cwe_id'),
                    cvss_score=vuln.get('cvss_score'),
                    confidence=vuln.get('confidence'),
                    references=vuln.get('references', [])
                )
                findings.append(finding)
                
            except Exception as e:
                self.logger.warning(f"Failed to convert finding: {e}")
                continue
        
        self.logger.info(f"Converted {len(findings)} AODS findings")
        return findings
    
    def upload_findings(self, project_id: str, findings: List[AODSFinding]) -> Dict[str, Any]:
        """Upload findings to SysReptor project"""
        try:
            if self.reptor_available:
                return self._upload_findings_cli(project_id, findings)
            else:
                return self._upload_findings_api(project_id, findings)
        except Exception as e:
            self.logger.error(f"Failed to upload findings: {e}")
            raise
    
    def _upload_findings_cli(self, project_id: str, findings: List[AODSFinding]) -> Dict[str, Any]:
        """Upload findings using reptor CLI"""
        try:
            upload_results = {'success': 0, 'failed': 0, 'details': []}
            
            for finding in findings:
                try:
                    # Convert finding to SysReptor format
                    sysreptor_finding = self._convert_to_sysreptor_format(finding)
                    
                    # Write finding to temporary file
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                        json.dump(sysreptor_finding, f, indent=2)
                        finding_file = f.name
                    
                    try:
                        # Upload finding using reptor CLI
                        cmd = [
                            'reptor', 'finding',
                            '--server', self.config.server_url,
                            '--token', self.config.api_token,
                            '--project-id', project_id,
                            '--file', finding_file
                        ]
                        
                        if not self.config.verify_ssl:
                            cmd.append('--insecure')
                        
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                        
                        if result.returncode == 0:
                            upload_results['success'] += 1
                            upload_results['details'].append({
                                'title': finding.title,
                                'status': 'success'
                            })
                        else:
                            upload_results['failed'] += 1
                            upload_results['details'].append({
                                'title': finding.title,
                                'status': 'failed',
                                'error': result.stderr
                            })
                            
                    finally:
                        # Clean up temporary file
                        os.unlink(finding_file)
                        
                except Exception as e:
                    upload_results['failed'] += 1
                    upload_results['details'].append({
                        'title': finding.title,
                        'status': 'failed',
                        'error': str(e)
                    })
                    self.logger.warning(f"Failed to upload finding '{finding.title}': {e}")
            
            self.logger.info(f"Upload complete: {upload_results['success']} success, {upload_results['failed']} failed")
            return upload_results
            
        except Exception as e:
            self.logger.error(f"CLI findings upload failed: {e}")
            raise
    
    def _upload_findings_api(self, project_id: str, findings: List[AODSFinding]) -> Dict[str, Any]:
        """Upload findings using SysReptor API"""
        try:
            upload_results = {'success': 0, 'failed': 0, 'details': []}
            
            for finding in findings:
                try:
                    # Convert finding to SysReptor format
                    sysreptor_finding = self._convert_to_sysreptor_format(finding)
                    
                    # Upload via API
                    response = self.session.post(
                        f"{self.config.server_url}/api/v1/projects/{project_id}/findings/",
                        json=sysreptor_finding,
                        timeout=self.config.timeout,
                        verify=self.config.verify_ssl
                    )
                    
                    if response.status_code == 201:
                        upload_results['success'] += 1
                        upload_results['details'].append({
                            'title': finding.title,
                            'status': 'success'
                        })
                    else:
                        upload_results['failed'] += 1
                        upload_results['details'].append({
                            'title': finding.title,
                            'status': 'failed',
                            'error': f"HTTP {response.status_code}: {response.text}"
                        })
                        
                except Exception as e:
                    upload_results['failed'] += 1
                    upload_results['details'].append({
                        'title': finding.title,
                        'status': 'failed',
                        'error': str(e)
                    })
                    self.logger.warning(f"Failed to upload finding '{finding.title}': {e}")
            
            self.logger.info(f"Upload complete: {upload_results['success']} success, {upload_results['failed']} failed")
            return upload_results
            
        except Exception as e:
            self.logger.error(f"API findings upload failed: {e}")
            raise
    
    def _convert_to_sysreptor_format(self, finding: AODSFinding) -> Dict[str, Any]:
        """Convert AODS finding to SysReptor finding format"""
        # Get appropriate template for MASVS category
        template_name = self.masvs_template_mapping.get(
            finding.masvs_category, 
            self.masvs_template_mapping['general']
        )
        
        # Build SysReptor finding structure
        sysreptor_finding = {
            'title': finding.title,
            'template': template_name,
            'severity': self.severity_mapping.get(finding.severity, 'Medium'),
            'data': {
                'description': finding.description,
                'impact': self._generate_impact_description(finding),
                'recommendation': finding.recommendation or self._generate_recommendation(finding),
                'references': finding.references or [],
                'affected_components': [finding.file_location] if finding.file_location else [],
                'technical_details': self._generate_technical_details(finding),
                'evidence': finding.evidence or '',
                'masvs_category': finding.masvs_category,
                'confidence_score': finding.confidence,
                'cvss_score': finding.cvss_score
            },
            'custom_fields': {
                'cwe_id': finding.cwe_id,
                'scanner': 'AODS',
                'scan_timestamp': datetime.now().isoformat(),
                'original_category': finding.category
            }
        }
        
        # Add location information if available
        if finding.file_location:
            sysreptor_finding['data']['file_location'] = finding.file_location
            if finding.line_number:
                sysreptor_finding['data']['line_number'] = finding.line_number
        
        return sysreptor_finding
    
    def _generate_impact_description(self, finding: AODSFinding) -> str:
        """Generate impact description based on finding characteristics"""
        impact_templates = {
            'MASVS-STORAGE': "This vulnerability could lead to unauthorized access to sensitive data stored on the device.",
            'MASVS-CRYPTO': "This cryptographic vulnerability could compromise data confidentiality and integrity.",
            'MASVS-AUTH': "This authentication vulnerability could allow unauthorized access to the application.",
            'MASVS-NETWORK': "This network security vulnerability could expose data in transit to interception.",
            'MASVS-PLATFORM': "This platform vulnerability could be exploited to compromise application security.",
            'MASVS-CODE': "This code quality issue could introduce security vulnerabilities.",
            'MASVS-RESILIENCE': "This resilience vulnerability could facilitate reverse engineering attacks.",
            'MASVS-PRIVACY': "This privacy vulnerability could lead to unauthorized data disclosure."
        }
        
        return impact_templates.get(
            finding.masvs_category, 
            "This security vulnerability could compromise application security."
        )
    
    def _generate_recommendation(self, finding: AODSFinding) -> str:
        """Generate recommendation based on finding characteristics"""
        recommendation_templates = {
            'MASVS-STORAGE': "Implement proper data encryption and secure storage mechanisms.",
            'MASVS-CRYPTO': "Use strong cryptographic algorithms and proper key management.",
            'MASVS-AUTH': "Implement secure authentication mechanisms and session management.",
            'MASVS-NETWORK': "Implement certificate pinning and secure communication protocols.",
            'MASVS-PLATFORM': "Follow platform security best practices and secure coding guidelines.",
            'MASVS-CODE': "Review and remediate code quality issues following secure coding practices.",
            'MASVS-RESILIENCE': "Implement anti-tampering and obfuscation mechanisms.",
            'MASVS-PRIVACY': "Implement privacy controls and data protection mechanisms."
        }
        
        return recommendation_templates.get(
            finding.masvs_category,
            "Review and remediate this security vulnerability following security best practices."
        )
    
    def _generate_technical_details(self, finding: AODSFinding) -> str:
        """Generate technical details for the finding"""
        details = []
        
        if finding.file_location:
            details.append(f"**File Location:** `{finding.file_location}`")
        
        if finding.line_number:
            details.append(f"**Line Number:** {finding.line_number}")
        
        if finding.cwe_id:
            details.append(f"**CWE ID:** {finding.cwe_id}")
        
        if finding.cvss_score:
            details.append(f"**CVSS Score:** {finding.cvss_score}")
        
        if finding.confidence:
            details.append(f"**Confidence:** {finding.confidence:.2f}")
        
        details.append(f"**MASVS Category:** {finding.masvs_category}")
        details.append(f"**Detection Category:** {finding.category}")
        
        return "\n".join(details)
    
    def generate_report(self, project_id: str, report_format: str = None) -> SysReptorReport:
        """Generate and export professional report from SysReptor"""
        try:
            format_to_use = report_format or self.config.report_format
            
            if self.reptor_available:
                return self._generate_report_cli(project_id, format_to_use)
            else:
                return self._generate_report_api(project_id, format_to_use)
                
        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}")
            raise
    
    def _generate_report_cli(self, project_id: str, report_format: str) -> SysReptorReport:
        """Generate report using reptor CLI"""
        try:
            # Export report using reptor CLI
            cmd = [
                'reptor', 'exportfindings',
                '--server', self.config.server_url,
                '--token', self.config.api_token,
                '--project-id', project_id,
                '--format', report_format
            ]
            
            if not self.config.verify_ssl:
                cmd.append('--insecure')
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Get project details for report metadata
                project_info = self._get_project_info(project_id)
                
                return SysReptorReport(
                    project_id=project_id,
                    project_name=project_info.get('name', 'Mobile Security Assessment'),
                    findings_count=project_info.get('findings_count', 0),
                    severity_distribution=project_info.get('severity_distribution', {}),
                    report_url=f"{self.config.server_url}/projects/{project_id}",
                    export_formats=[report_format],
                    creation_timestamp=datetime.now().isoformat(),
                    last_updated=datetime.now().isoformat()
                )
            else:
                raise Exception(f"Report generation failed: {result.stderr}")
                
        except Exception as e:
            self.logger.error(f"CLI report generation failed: {e}")
            raise
    
    def _generate_report_api(self, project_id: str, report_format: str) -> SysReptorReport:
        """Generate report using SysReptor API"""
        try:
            # Trigger report generation via API
            response = self.session.post(
                f"{self.config.server_url}/api/v1/projects/{project_id}/export/",
                json={'format': report_format},
                timeout=60,
                verify=self.config.verify_ssl
            )
            
            if response.status_code == 200:
                export_data = response.json()
                
                # Get project details for report metadata
                project_info = self._get_project_info(project_id)
                
                return SysReptorReport(
                    project_id=project_id,
                    project_name=project_info.get('name', 'Mobile Security Assessment'),
                    findings_count=project_info.get('findings_count', 0),
                    severity_distribution=project_info.get('severity_distribution', {}),
                    report_url=export_data.get('download_url', f"{self.config.server_url}/projects/{project_id}"),
                    export_formats=[report_format],
                    creation_timestamp=datetime.now().isoformat(),
                    last_updated=datetime.now().isoformat()
                )
            else:
                raise Exception(f"API report generation failed: {response.status_code} - {response.text}")
                
        except Exception as e:
            self.logger.error(f"API report generation failed: {e}")
            raise
    
    def _get_project_info(self, project_id: str) -> Dict[str, Any]:
        """Get project information from SysReptor"""
        try:
            response = self.session.get(
                f"{self.config.server_url}/api/v1/projects/{project_id}/",
                timeout=self.config.timeout,
                verify=self.config.verify_ssl
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.warning(f"Failed to get project info: {response.status_code}")
                return {}
                
        except Exception as e:
            self.logger.warning(f"Failed to get project info: {e}")
            return {}
    
    def _extract_project_id_from_output(self, output: str) -> str:
        """Extract project ID from reptor command output"""
        # This would need to be adapted based on actual reptor output format
        import re
        
        # Look for project ID pattern in output
        match = re.search(r'Project ID:\s*([a-f0-9\-]+)', output)
        if match:
            return match.group(1)
        
        # Fallback: look for UUID pattern
        match = re.search(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', output)
        if match:
            return match.group(1)
        
        raise Exception("Could not extract project ID from reptor output")

def create_sysreptor_integration(config: Dict[str, Any]) -> SysReptorIntegration:
    """Factory function to create SysReptor integration instance"""
    try:
        sysreptor_config = SysReptorConfig(
            server_url=config.get('server_url', 'https://demo.sysreptor.com'),
            api_token=config.get('api_token', ''),
            project_id=config.get('project_id'),
            template_id=config.get('template_id'),
            verify_ssl=config.get('verify_ssl', True),
            timeout=config.get('timeout', 30),
            report_format=config.get('report_format', 'pdf'),
            auto_create_project=config.get('auto_create_project', True),
            collaborative_mode=config.get('collaborative_mode', False)
        )
        
        return SysReptorIntegration(sysreptor_config)
        
    except Exception as e:
        logging.error(f"Failed to create SysReptor integration: {e}")
        raise

def integrate_with_aods_pipeline(scan_results: Dict[str, Any], 
                                sysreptor_config: Dict[str, Any],
                                app_info: Dict[str, Any]) -> SysReptorReport:
    """
    Complete AODS to SysReptor integration pipeline.
    
    Args:
        scan_results: AODS scan results dictionary
        sysreptor_config: SysReptor configuration
        app_info: Application information
        
    Returns:
        SysReptorReport with professional report details
    """
    try:
        # Initialize SysReptor integration
        integration = create_sysreptor_integration(sysreptor_config)
        
        # Create project
        project_name = f"Mobile Security Assessment - {app_info.get('package_name', 'Unknown App')}"
        project_id = integration.create_project(project_name, app_info)
        
        # Convert AODS findings
        findings = integration.convert_aods_findings(scan_results)
        
        # Upload findings
        upload_results = integration.upload_findings(project_id, findings)
        
        # Generate professional report
        report = integration.generate_report(project_id)
        
        logging.info(f"SysReptor integration complete: {len(findings)} findings uploaded, report generated")
        
        return report
        
    except Exception as e:
        logging.error(f"AODS to SysReptor integration failed: {e}")
        raise
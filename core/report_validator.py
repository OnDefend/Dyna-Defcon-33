import json
import logging
from typing import Dict, List, Any, Tuple
from bs4 import BeautifulSoup
from datetime import datetime
import re
import os

class ReportValidator:
    """Validates consistency between report summary and detailed findings"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def validate_report_consistency(self, json_report_path: str, html_report_path: str = None) -> Dict[str, Any]:
        """Validate consistency between JSON and HTML reports"""
        try:
            # Load JSON report
            with open(json_report_path, 'r') as f:
                json_data = json.load(f)
            
            # Load HTML report if provided
            html_content = None
            if html_report_path and os.path.exists(html_report_path):
                with open(html_report_path, 'r') as f:
                    html_content = f.read()
            
            # Extract vulnerability counts from different sections
            json_summary = self._extract_json_summary(json_data)
            html_summary = self._extract_html_summary(html_content) if html_content else {}
            detailed_analysis = self._analyze_detailed_findings(json_data)
            
            # Validate consistency
            validation_results = {
                'json_summary': json_summary,
                'html_summary': html_summary,  
                'detailed_analysis': detailed_analysis,
                'consistency_check': self._check_consistency(json_summary, html_summary, detailed_analysis),
                'validation_timestamp': datetime.utcnow().isoformat(),
                'json_report_path': json_report_path,
                'html_report_path': html_report_path
            }
            
            return validation_results
            
        except Exception as e:
            self.logger.error(f"Report validation failed: {e}")
            return {'error': str(e), 'validation_status': 'FAILED'}
    
    def _extract_json_summary(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract vulnerability summary from JSON report"""
        summary = {
            'vulnerabilities_found': json_data.get('vulnerabilities_found', 0),
            'total_issues': len(json_data.get('vulnerabilities', [])),
            'summary_counts': json_data.get('summary', {}).get('vulnerability_counts', {}),
            'has_vulnerabilities_array': bool(json_data.get('vulnerabilities')),
            'has_summary_section': bool(json_data.get('summary'))
        }
        
        # Also check for alternative summary locations
        if json_data.get('scan_summary'):
            summary['scan_summary'] = json_data['scan_summary']
        
        return summary
    
    def _extract_html_summary(self, html_content: str) -> Dict[str, Any]:
        """Extract vulnerability summary from HTML report"""
        if not html_content:
            return {}
            
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Look for various dashboard/summary elements
        summary = {
            'critical_count': self._extract_count_from_html(soup, ['critical-count', 'critical_count']),
            'high_count': self._extract_count_from_html(soup, ['high-count', 'high_count']),
            'medium_count': self._extract_count_from_html(soup, ['medium-count', 'medium_count']),
            'low_count': self._extract_count_from_html(soup, ['low-count', 'low_count']),
            'total_displayed': self._find_total_vulnerabilities_html(soup)
        }
        
        return summary
    
    def _extract_count_from_html(self, soup: BeautifulSoup, class_names: List[str]) -> int:
        """Extract count from HTML elements with various possible class names"""
        for class_name in class_names:
            elem = soup.find(class_=class_name) or soup.find(id=class_name)
            if elem:
                text = elem.get_text(strip=True)
                # Extract numeric value
                match = re.search(r'\d+', text)
                if match:
                    return int(match.group())
        return 0
    
    def _find_total_vulnerabilities_html(self, soup: BeautifulSoup) -> int:
        """Find total vulnerability count displayed in HTML"""
        # Look for various total indicators
        total_indicators = [
            'total-vulnerabilities', 'total_vulnerabilities', 'vuln-total',
            'vulnerabilities-found', 'total-issues', 'issue-count'
        ]
        
        for indicator in total_indicators:
            elem = soup.find(class_=indicator) or soup.find(id=indicator)
            if elem:
                text = elem.get_text(strip=True)
                match = re.search(r'\d+', text)
                if match:
                    return int(match.group())
        
        # If no explicit total, look for text patterns
        text_patterns = [
            r'(\d+)\s+vulnerabilities?\s+found',
            r'Total\s+issues?\s*:\s*(\d+)',
            r'Found\s+(\d+)\s+security\s+issues?'
        ]
        
        full_text = soup.get_text()
        for pattern in text_patterns:
            match = re.search(pattern, full_text, re.IGNORECASE)
            if match:
                return int(match.group(1))
        
        return 0
    
    def _analyze_detailed_findings(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze detailed findings to count actual security issues"""
        detailed_results = json_data.get('detailed_results', {})
        security_issues = []
        
        # Check various sections for security issues
        network_issues = self._check_network_security_issues(detailed_results)
        component_issues = self._check_component_security_issues(detailed_results)
        compliance_issues = self._check_mastg_compliance_issues(detailed_results)
        permission_issues = self._check_permission_issues(detailed_results)
        crypto_issues = self._check_crypto_issues(detailed_results)
        
        all_issues = network_issues + component_issues + compliance_issues + permission_issues + crypto_issues
        
        # Also check for any explicit vulnerability listings
        explicit_vulnerabilities = []
        if json_data.get('vulnerabilities'):
            explicit_vulnerabilities = json_data['vulnerabilities']
        
        return {
            'actual_security_issues': len(all_issues),
            'network_security_issues': len(network_issues),
            'component_security_issues': len(component_issues),
            'compliance_issues': len(compliance_issues),
            'permission_issues': len(permission_issues),
            'crypto_issues': len(crypto_issues),
            'explicit_vulnerabilities': len(explicit_vulnerabilities),
            'detailed_issues': all_issues,
            'issue_breakdown': {
                'network': network_issues,
                'components': component_issues,
                'compliance': compliance_issues,
                'permissions': permission_issues,
                'crypto': crypto_issues
            }
        }
    
    def _check_network_security_issues(self, detailed_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for network security issues in detailed results"""
        issues = []
        
        # Check for cleartext traffic
        if self._has_security_issue(detailed_results, 'cleartext_traffic', ['enabled', 'true', 'permitted']):
            issues.append({
                'type': 'CLEARTEXT_TRAFFIC',
                'severity': 'HIGH',
                'description': 'Clear-text traffic enabled',
                'source': 'network_security_config'
            })
        
        # Check for missing certificate pinning
        if self._has_security_issue(detailed_results, 'certificate_pinning', ['missing', 'false', 'disabled']):
            issues.append({
                'type': 'MISSING_CERT_PINNING',
                'severity': 'HIGH',
                'description': 'Certificate pinning not implemented',
                'source': 'network_security'
            })
        
        return issues
    
    def _check_component_security_issues(self, detailed_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for component security issues"""
        issues = []
        
        # Check for exported activities without permissions
        activities = detailed_results.get('activity_analysis', {})
        if isinstance(activities, dict):
            for activity_name, activity_data in activities.items():
                if isinstance(activity_data, dict):
                    if (activity_data.get('exported') in ['true', True] and 
                        not activity_data.get('permission')):
                        issues.append({
                            'type': 'EXPORTED_COMPONENT_NO_PERMISSION',
                            'severity': 'CRITICAL',
                            'description': f'{activity_name} exported without permission protection',
                            'source': 'component_analysis'
                        })
        
        return issues
    
    def _check_mastg_compliance_issues(self, detailed_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for MASTG compliance issues"""
        issues = []
        
        mastg_results = detailed_results.get('mastg_compliance', {})
        if isinstance(mastg_results, dict):
            if mastg_results.get('status') == 'FAIL' or mastg_results.get('result') == 'FAIL':
                passed = mastg_results.get('passed', 0)
                total = mastg_results.get('total', 8)
                if passed < total:
                    issues.append({
                        'type': 'MASTG_COMPLIANCE_FAILURE',
                        'severity': 'HIGH',
                        'description': f'MASTG compliance failed: {passed}/{total} controls passed',
                        'source': 'mastg_compliance'
                    })
        
        return issues
    
    def _check_permission_issues(self, detailed_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for permission-related security issues"""
        issues = []
        
        permissions = detailed_results.get('permissions', {})
        if isinstance(permissions, dict):
            dangerous_permissions = permissions.get('dangerous', [])
            if dangerous_permissions:
                issues.append({
                    'type': 'DANGEROUS_PERMISSIONS',
                    'severity': 'MEDIUM',
                    'description': f'Dangerous permissions detected: {len(dangerous_permissions)}',
                    'source': 'permission_analysis'
                })
        
        return issues
    
    def _check_crypto_issues(self, detailed_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for cryptographic issues"""
        issues = []
        
        crypto_results = detailed_results.get('crypto_analysis', {})
        if isinstance(crypto_results, dict):
            if crypto_results.get('weak_encryption') or crypto_results.get('weak_algorithms'):
                issues.append({
                    'type': 'WEAK_CRYPTOGRAPHY',
                    'severity': 'HIGH',
                    'description': 'Weak cryptographic implementations detected',
                    'source': 'crypto_analysis'
                })
        
        return issues
    
    def _has_security_issue(self, detailed_results: Dict[str, Any], key: str, 
                           issue_indicators: List[str]) -> bool:
        """Check if a specific security issue exists in detailed results"""
        def check_nested_dict(data, target_key, indicators):
            if isinstance(data, dict):
                for k, v in data.items():
                    if k == target_key:
                        if isinstance(v, str) and any(indicator in v.lower() for indicator in indicators):
                            return True
                        elif isinstance(v, bool) and v:
                            return True
                    elif isinstance(v, dict):
                        if check_nested_dict(v, target_key, indicators):
                            return True
            return False
        
        return check_nested_dict(detailed_results, key, issue_indicators)
    
    def _check_consistency(self, json_summary: Dict, html_summary: Dict, detailed_analysis: Dict) -> Dict[str, Any]:
        """Check consistency between different report sections"""
        issues = []
        
        # Check if summary matches detailed analysis
        summary_total = json_summary.get('vulnerabilities_found', 0)
        actual_issues = detailed_analysis.get('actual_security_issues', 0)
        
        if summary_total != actual_issues:
            issues.append({
                'type': 'SUMMARY_MISMATCH',
                'description': f"Summary shows {summary_total} vulnerabilities but detailed analysis found {actual_issues}",
                'severity': 'CRITICAL',
                'impact': 'Executive dashboards show incorrect vulnerability counts',
                'recommendation': 'Update vulnerability classification logic to properly count security issues'
            })
        
        # Check HTML vs JSON consistency
        if html_summary:
            html_total = html_summary.get('total_displayed', 0)
            if html_total != summary_total:
                issues.append({
                    'type': 'FORMAT_MISMATCH',
                    'description': f"HTML shows {html_total} vulnerabilities but JSON shows {summary_total}",
                    'severity': 'HIGH',
                    'impact': 'Inconsistent vulnerability counts across report formats',
                    'recommendation': 'Synchronize HTML and JSON report generation'
                })
        
        # Check for empty vulnerabilities array despite findings
        if (actual_issues > 0 and 
            not json_summary.get('has_vulnerabilities_array', False)):
            issues.append({
                'type': 'MISSING_VULNERABILITIES_ARRAY',
                'description': f"Found {actual_issues} security issues but vulnerabilities array is empty",
                'severity': 'CRITICAL',
                'impact': 'Detailed vulnerability information not provided in machine-readable format',
                'recommendation': 'Populate vulnerabilities array with classified security issues'
            })
        
        return {
            'is_consistent': len(issues) == 0,
            'consistency_issues': issues,
            'total_issues': len(issues),
            'critical_issues': len([i for i in issues if i['severity'] == 'CRITICAL']),
            'high_issues': len([i for i in issues if i['severity'] == 'HIGH']),
            'recommendation': self._generate_fix_recommendation(issues)
        }
    
    def _generate_fix_recommendation(self, issues: List[Dict[str, Any]]) -> str:
        """Generate comprehensive fix recommendation"""
        if not issues:
            return "No consistency issues detected. Reports are accurate."
        
        critical_count = len([i for i in issues if i['severity'] == 'CRITICAL'])
        high_count = len([i for i in issues if i['severity'] == 'HIGH'])
        
        recommendations = []
        
        if critical_count > 0:
            recommendations.append(
                f"CRITICAL: {critical_count} critical consistency issues require immediate attention. "
                "These issues can lead to incorrect security assessments and executive decisions."
            )
        
        if high_count > 0:
            recommendations.append(
                f"HIGH: {high_count} high-priority issues affect report reliability."
            )
        
        recommendations.append(
            "Recommended actions: 1) Implement vulnerability classification system, "
            "2) Fix summary generation logic, 3) Validate cross-format consistency, "
            "4) Add automated validation checks to prevent future issues."
        )
        
        return " ".join(recommendations)
    
    def auto_correct_report(self, json_report_path: str, detailed_analysis: Dict) -> Dict[str, Any]:
        """Auto-correct report summary based on detailed analysis"""
        try:
            # Load original report
            with open(json_report_path, 'r') as f:
                json_data = json.load(f)
            
            # Create backup
            backup_path = json_report_path.replace('.json', '_backup.json')
            with open(backup_path, 'w') as f:
                json.dump(json_data, f, indent=2)
            
            # Update summary to match detailed analysis
            corrected_count = detailed_analysis['actual_security_issues']
            json_data['vulnerabilities_found'] = corrected_count
            
            # Update vulnerability array if needed
            if corrected_count > 0 and not json_data.get('vulnerabilities'):
                json_data['vulnerabilities'] = detailed_analysis['detailed_issues']
            
            # Add correction metadata
            json_data['correction_metadata'] = {
                'corrected_at': datetime.utcnow().isoformat(),
                'original_count': 0,
                'corrected_count': corrected_count,
                'correction_applied': True,
                'backup_file': backup_path
            }
            
            # Save corrected report
            corrected_path = json_report_path.replace('.json', '_corrected.json')
            with open(corrected_path, 'w') as f:
                json.dump(json_data, f, indent=2)
            
            self.logger.info(f"Report auto-corrected: {corrected_count} vulnerabilities identified")
            
            return {
                'correction_applied': True,
                'corrected_file': corrected_path,
                'backup_file': backup_path,
                'original_count': 0,
                'corrected_count': corrected_count,
                'correction_summary': f"Updated vulnerability count from 0 to {corrected_count}"
            }
            
        except Exception as e:
            self.logger.error(f"Auto-correction failed: {e}")
            return {'correction_applied': False, 'error': str(e)}
    
    def validate_corellium_cafe_report(self, json_report_path: str) -> Dict[str, Any]:
        """Specific validation for Corellium Cafe report to verify fix"""
        validation_results = self.validate_report_consistency(json_report_path)
        
        # Add specific checks for known Corellium Cafe issues
        expected_issues = [
            'cleartext_traffic',
            'exported_activities',
            'certificate_pinning',
            'backup_enabled',
            'mastg_compliance'
        ]
        
        detailed_analysis = validation_results.get('detailed_analysis', {})
        actual_count = detailed_analysis.get('actual_security_issues', 0)
        
        cafe_specific_validation = {
            'expected_min_vulnerabilities': 5,
            'actual_vulnerabilities': actual_count,
            'meets_expectation': actual_count >= 5,
            'critical_fix_needed': actual_count >= 5 and validation_results.get('json_summary', {}).get('vulnerabilities_found', 0) == 0
        }
        
        validation_results['corellium_cafe_validation'] = cafe_specific_validation
        
        return validation_results 
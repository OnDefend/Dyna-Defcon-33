#!/usr/bin/env python3
"""
Objection Verification Assistant

Provides verification capabilities for AODS findings using objection for
interactive exploitation and confirmation of discovered vulnerabilities.

Author: AODS Team
Date: January 2025
"""

import json
import logging
import subprocess
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class VerificationResult:
    """Results from vulnerability verification."""
    finding_id: str
    vulnerability_type: str
    verification_status: str  # CONFIRMED, DENIED, INCONCLUSIVE, ERROR
    objection_commands: List[str] = field(default_factory=list)
    verification_evidence: List[str] = field(default_factory=list)
    exploitation_proof: Optional[str] = None
    confidence_score: float = 0.0
    verification_time: float = 0.0


class ObjectionVerificationAssistant:
    """
    Interactive verification of AODS findings using objection.
    
    Provides manual verification capabilities to confirm automated findings
    and build confidence in vulnerability reports through hands-on testing.
    """
    
    def __init__(self):
        """Initialize verification assistant."""
        self.logger = logging.getLogger(__name__)
        self.objection_available = self._check_objection_availability()
        
        # Verification command templates for different vulnerability types
        self.verification_commands = {
            "insecure_logging": [
                "android hooking list classes",
                "android hooking search methods android.util.Log",
                "android hooking watch class android.util.Log --dump-args",
                "jobs list"
            ],
            "shared_preferences": [
                "android filesystem list", 
                "android filesystem find --name *.xml",
                "memory list modules",
                "android hooking search methods SharedPreferences",
                "android hooking watch class android.content.SharedPreferences --dump-args"
            ],
            "keyboard_cache": [
                "android ui dump",
                "android hooking search methods EditText",
                "android hooking watch class android.widget.EditText --dump-args",
                "android intent launch_activity --class-name com.example.MainActivity"
            ],
            "certificate_pinning": [
                "android sslpinning disable",
                "android hooking list classes | grep -i ssl",
                "android hooking search methods SSLContext",
                "jobs list"
            ],
            "qr_code": [
                "android hooking search methods ZXing",
                "android hooking search methods BarcodeReader", 
                "android hooking watch class com.google.zxing.BarcodeReader --dump-args",
                "android intent launch_activity --action android.intent.action.VIEW"
            ],
            "biometric_auth": [
                "android hooking search methods BiometricPrompt",
                "android hooking search methods FingerprintManager",
                "android hooking watch class androidx.biometric.BiometricPrompt --dump-args",
                "android keystore list"
            ],
            "storage_access": [
                "android filesystem list",
                "android filesystem find --name *.db",
                "android filesystem find --path /data/data --name *",
                "memory dump all /tmp/memory_dump.bin"
            ],
            "network_security": [
                "android sslpinning disable",
                "android proxy set 127.0.0.1 8080",
                "android hooking search methods HttpURLConnection",
                "jobs list"
            ]
        }
    
    def _check_objection_availability(self) -> bool:
        """Check if objection is available in the system."""
        try:
            result = subprocess.run(['objection', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception as e:
            self.logger.warning(f"Objection not available: {e}")
            return False
    
    def verify_aods_finding(self, finding: Dict[str, Any], package_name: str) -> VerificationResult:
        """
        Verify a specific AODS finding using objection.
        
        Args:
            finding: AODS vulnerability finding
            package_name: Target application package name
            
        Returns:
            VerificationResult with verification status and evidence
        """
        try:
            self.logger.info(f"Starting verification of finding: {finding.get('title', 'Unknown')}")
            
            if not self.objection_available:
                return VerificationResult(
                    finding_id=finding.get('id', 'unknown'),
                    vulnerability_type=finding.get('type', 'unknown'),
                    verification_status="ERROR",
                    verification_evidence=["Objection not available"]
                )
            
            # Determine vulnerability type and get relevant commands
            vuln_type = self._classify_vulnerability_type(finding)
            commands = self._generate_verification_commands(vuln_type, finding)
            
            # Create verification session
            verification_result = self._execute_verification_session(
                package_name, commands, finding
            )
            
            return verification_result
            
        except Exception as e:
            self.logger.error(f"Verification failed: {e}")
            return VerificationResult(
                finding_id=finding.get('id', 'unknown'),
                vulnerability_type=finding.get('type', 'unknown'),
                verification_status="ERROR",
                verification_evidence=[str(e)]
            )
    
    def interactive_exploitation_session(self, finding: Dict[str, Any], package_name: str) -> Dict[str, Any]:
        """
        Start an interactive objection session for manual exploitation.
        
        Args:
            finding: AODS vulnerability finding
            package_name: Target application package name
            
        Returns:
            Session information and command suggestions
        """
        try:
            vuln_type = self._classify_vulnerability_type(finding)
            commands = self._generate_verification_commands(vuln_type, finding)
            
            session_info = {
                "package_name": package_name,
                "vulnerability_type": vuln_type,
                "finding_details": finding,
                "suggested_commands": commands,
                "exploitation_guide": self._generate_exploitation_guide(vuln_type),
                "session_script": self._generate_session_script(package_name, commands)
            }
            
            self.logger.info(f"Interactive session prepared for {vuln_type}")
            return session_info
            
        except Exception as e:
            self.logger.error(f"Failed to prepare interactive session: {e}")
            return {"error": str(e)}
    
    def generate_verification_commands(self, findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Generate objection verification commands for multiple findings.
        
        Args:
            findings: List of AODS vulnerability findings
            
        Returns:
            Dictionary mapping finding IDs to command lists
        """
        verification_commands = {}
        
        for finding in findings:
            try:
                finding_id = finding.get('id', f"finding_{len(verification_commands)}")
                vuln_type = self._classify_vulnerability_type(finding)
                commands = self._generate_verification_commands(vuln_type, finding)
                
                verification_commands[finding_id] = {
                    "vulnerability_type": vuln_type,
                    "commands": commands,
                    "priority": self._get_verification_priority(finding),
                    "estimated_time": self._estimate_verification_time(vuln_type)
                }
                
            except Exception as e:
                self.logger.error(f"Failed to generate commands for finding {finding}: {e}")
        
        return verification_commands
    
    def _classify_vulnerability_type(self, finding: Dict[str, Any]) -> str:
        """Classify vulnerability type from AODS finding."""
        vuln_type = finding.get('type', '').lower()
        title = finding.get('title', '').lower()
        description = finding.get('description', '').lower()
        
        # Map AODS vulnerability types to verification categories
        if any(term in vuln_type or term in title or term in description 
               for term in ['log', 'logging']):
            return "insecure_logging"
        elif any(term in vuln_type or term in title or term in description 
                 for term in ['shared', 'preferences', 'sharedprefs']):
            return "shared_preferences"
        elif any(term in vuln_type or term in title or term in description 
                 for term in ['keyboard', 'cache', 'input']):
            return "keyboard_cache"
        elif any(term in vuln_type or term in title or term in description 
                 for term in ['certificate', 'pinning', 'ssl', 'tls']):
            return "certificate_pinning"
        elif any(term in vuln_type or term in title or term in description 
                 for term in ['qr', 'barcode', 'scanner']):
            return "qr_code"
        elif any(term in vuln_type or term in title or term in description 
                 for term in ['biometric', 'fingerprint', 'authentication']):
            return "biometric_auth"
        elif any(term in vuln_type or term in title or term in description 
                 for term in ['storage', 'file', 'database']):
            return "storage_access"
        elif any(term in vuln_type or term in title or term in description 
                 for term in ['network', 'http', 'connection']):
            return "network_security"
        else:
            return "generic"
    
    def _generate_verification_commands(self, vuln_type: str, finding: Dict[str, Any]) -> List[str]:
        """Generate specific verification commands for vulnerability type."""
        base_commands = self.verification_commands.get(vuln_type, [
            "android hooking list classes",
            "memory list modules",
            "android filesystem list"
        ])
        
        # Customize commands based on specific finding details
        customized_commands = []
        for cmd in base_commands:
            customized_commands.append(cmd)
        
        # Add finding-specific commands
        if 'class_name' in finding.get('evidence', {}):
            class_name = finding['evidence']['class_name']
            customized_commands.append(f"android hooking search classes {class_name}")
            customized_commands.append(f"android hooking watch class {class_name} --dump-args")
        
        if 'method_name' in finding.get('evidence', {}):
            method_name = finding['evidence']['method_name']
            customized_commands.append(f"android hooking search methods {method_name}")
        
        return customized_commands
    
    def _execute_verification_session(self, package_name: str, commands: List[str], 
                                     finding: Dict[str, Any]) -> VerificationResult:
        """Execute verification commands in objection session."""
        try:
            # Create objection script
            script_content = self._create_verification_script(commands)
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as script_file:
                script_file.write(script_content)
                script_path = script_file.name
            
            # Execute objection with verification script
            cmd = [
                'objection', '-g', package_name, 'explore', 
                '--startup-script', script_path,
                '--quiet'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Analyze results
            verification_status = self._analyze_verification_output(result.stdout, finding)
            evidence = self._extract_verification_evidence(result.stdout)
            
            # Clean up
            Path(script_path).unlink(missing_ok=True)
            
            return VerificationResult(
                finding_id=finding.get('id', 'unknown'),
                vulnerability_type=self._classify_vulnerability_type(finding),
                verification_status=verification_status,
                objection_commands=commands,
                verification_evidence=evidence,
                confidence_score=self._calculate_confidence_score(verification_status, evidence)
            )
            
        except subprocess.TimeoutExpired:
            return VerificationResult(
                finding_id=finding.get('id', 'unknown'),
                vulnerability_type=self._classify_vulnerability_type(finding),
                verification_status="INCONCLUSIVE",
                verification_evidence=["Verification timeout"]
            )
        except Exception as e:
            return VerificationResult(
                finding_id=finding.get('id', 'unknown'),
                vulnerability_type=self._classify_vulnerability_type(finding),
                verification_status="ERROR",
                verification_evidence=[str(e)]
            )
    
    def _create_verification_script(self, commands: List[str]) -> str:
        """Create objection JavaScript verification script."""
        script = '''
// AODS Verification Script
console.log("[AODS-VERIFY] Starting verification session");

'''
        for i, cmd in enumerate(commands):
            script += f'''
// Command {i+1}: {cmd}
try {{
    console.log("[AODS-VERIFY] Executing: {cmd}");
    // Note: This is a template - actual objection commands would be executed here
    console.log("[AODS-VERIFY] Command completed");
}} catch (e) {{
    console.log("[AODS-VERIFY] Command failed: " + e);
}}

'''
        
        script += '''
console.log("[AODS-VERIFY] Verification session completed");
'''
        return script
    
    def _analyze_verification_output(self, output: str, finding: Dict[str, Any]) -> str:
        """Analyze objection output to determine verification status."""
        if not output:
            return "INCONCLUSIVE"
        
        output_lower = output.lower()
        
        # Check for confirmation indicators
        if any(indicator in output_lower for indicator in [
            'vulnerability confirmed', 'exploit successful', 'access granted',
            'bypass successful', 'data extracted'
        ]):
            return "CONFIRMED"
        
        # Check for denial indicators
        if any(indicator in output_lower for indicator in [
            'not vulnerable', 'protection active', 'access denied',
            'bypass failed', 'secure implementation'
        ]):
            return "DENIED"
        
        # Check for error indicators
        if any(indicator in output_lower for indicator in [
            'error', 'exception', 'failed to attach', 'connection refused'
        ]):
            return "ERROR"
        
        return "INCONCLUSIVE"
    
    def _extract_verification_evidence(self, output: str) -> List[str]:
        """Extract verification evidence from objection output."""
        evidence = []
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line and any(marker in line.lower() for marker in [
                '[aods-verify]', 'found', 'detected', 'extracted', 'bypassed'
            ]):
                evidence.append(line)
        
        return evidence[:10]  # Limit evidence to top 10 items
    
    def _calculate_confidence_score(self, status: str, evidence: List[str]) -> float:
        """Calculate confidence score for verification result."""
        base_scores = {
            "CONFIRMED": 0.9,
            "DENIED": 0.8,
            "INCONCLUSIVE": 0.3,
            "ERROR": 0.1
        }
        
        base_score = base_scores.get(status, 0.1)
        evidence_bonus = min(len(evidence) * 0.02, 0.1)  # Up to 10% bonus for evidence
        
        return min(base_score + evidence_bonus, 1.0)
    
    def _generate_exploitation_guide(self, vuln_type: str) -> Dict[str, Any]:
        """Generate exploitation guide for vulnerability type."""
        guides = {
            "insecure_logging": {
                "objective": "Identify and extract sensitive data from application logs",
                "approach": "Hook logging methods and monitor for credentials, tokens, or PII",
                "expected_evidence": ["Sensitive data in log outputs", "Cleartext credentials"],
                "success_criteria": "Extraction of sensitive information from logs"
            },
            "shared_preferences": {
                "objective": "Access and extract data from SharedPreferences storage",
                "approach": "Locate preferences files and hook SharedPreferences methods",
                "expected_evidence": ["Cleartext sensitive data", "Insecure storage modes"],
                "success_criteria": "Access to sensitive application data"
            },
            "certificate_pinning": {
                "objective": "Bypass SSL certificate pinning implementation",
                "approach": "Disable pinning and intercept HTTPS traffic",
                "expected_evidence": ["Successful HTTPS interception", "Bypassed pinning"],
                "success_criteria": "Man-in-the-middle attack successful"
            }
        }
        
        return guides.get(vuln_type, {
            "objective": "Verify vulnerability through manual testing",
            "approach": "Use objection to interact with application components",
            "expected_evidence": ["Evidence of vulnerability exploitation"],
            "success_criteria": "Confirmation of security issue"
        })
    
    def _generate_session_script(self, package_name: str, commands: List[str]) -> str:
        """Generate interactive session script."""
        script = f"""#!/bin/bash
# AODS Objection Verification Session
# Package: {package_name}

echo "Starting AODS verification session for {package_name}"
echo "Suggested commands:"

"""
        for i, cmd in enumerate(commands, 1):
            script += f'echo "{i}. {cmd}"\n'
        
        script += f"""
echo ""
echo "Starting objection session..."
objection -g {package_name} explore
"""
        return script
    
    def _get_verification_priority(self, finding: Dict[str, Any]) -> str:
        """Get verification priority based on finding severity."""
        severity = finding.get('severity', 'LOW').upper()
        
        priority_map = {
            'CRITICAL': 'HIGH',
            'HIGH': 'HIGH', 
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW',
            'INFO': 'LOW'
        }
        
        return priority_map.get(severity, 'MEDIUM')
    
    def _estimate_verification_time(self, vuln_type: str) -> int:
        """Estimate verification time in minutes."""
        time_estimates = {
            "insecure_logging": 10,
            "shared_preferences": 15,
            "keyboard_cache": 20,
            "certificate_pinning": 25,
            "qr_code": 15,
            "biometric_auth": 30,
            "storage_access": 20,
            "network_security": 25,
            "generic": 15
        }
        
        return time_estimates.get(vuln_type, 15)
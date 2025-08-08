#!/usr/bin/env python3
"""
Update Mechanism Analyzer for AODS - MASVS-CODE-4 Compliance

Analyzes in-app update implementations, forced update mechanisms, and update security.
"""

import json
import logging
import re
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class UpdateMechanismAnalyzer:
    """Update mechanism analyzer for MASVS-CODE-4 compliance."""
    
    def __init__(self, apk_ctx):
        self.apk_ctx = apk_ctx
        self.package_name = apk_ctx.package_name
        self.findings = []
        
        # Update mechanism patterns
        self.update_patterns = {
            "google_play_updates": {
                "patterns": [
                    r"AppUpdateManager", r"AppUpdateManagerFactory",
                    r"requestAppUpdateInfo", r"startUpdateFlowForResult",
                    r"UpdateAvailability", r"AppUpdateType\.IMMEDIATE"
                ],
                "security_level": "HIGH", "recommended": True
            },
            "custom_updates": {
                "patterns": [
                    r"downloadUpdate", r"installUpdate", r"checkUpdate",
                    r"forceUpdate", r"apkDownload", r"versionCheck"
                ],
                "security_level": "MEDIUM", "recommended": False
            }
        }
        
        self.security_patterns = {
            "signature_verification": [r"checkSignatures", r"verifySignature"],
            "integrity_checks": [r"MessageDigest", r"checksum", r"SHA256"],
            "secure_download": [r"https://", r"HttpsURLConnection"],
            "insecure_download": [r"http://(?!localhost)", r"trustAllCerts"]
        }

    def analyze(self) -> Dict[str, Any]:
        """Perform update mechanism analysis."""
        logger.debug("Starting update mechanism analysis...")
        
        results = {
            "update_mechanisms": [],
            "security_features": {},
            "compliance_status": "UNKNOWN",
            "risk_score": 0,
            "recommendations": [],
            "masvs_controls": []
        }
        
        try:
            self._analyze_update_mechanisms(results)
            self._analyze_security_features(results)
            self._calculate_compliance_status(results)
            self._calculate_risk_score(results)
            self._generate_recommendations(results)
            self._map_masvs_controls(results)
            
            logger.debug(f"Update mechanism analysis completed. Found {len(self.findings)} findings.")
            
        except Exception as e:
            logger.error(f"Error during update mechanism analysis: {e}")
            results["error"] = str(e)
            
        return results

    def _analyze_update_mechanisms(self, results: Dict[str, Any]) -> None:
        """Analyze update mechanism implementations."""
        mechanisms = []
        
        if hasattr(self.apk_ctx, 'get_java_files'):
            java_files = self.apk_ctx.get_java_files()
            for file_path, content in java_files.items():
                mechanisms.extend(self._find_update_mechanisms_in_file(file_path, content))
        
        results["update_mechanisms"] = mechanisms

    def _find_update_mechanisms_in_file(self, file_path: str, content: str) -> List[Dict]:
        """Find update mechanisms in a Java file."""
        mechanisms = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for mechanism_type, info in self.update_patterns.items():
                for pattern in info["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        mechanisms.append({
                            "type": mechanism_type,
                            "file": file_path,
                            "line": line_num,
                            "code": line.strip(),
                            "security_level": info["security_level"],
                            "recommended": info["recommended"]
                        })
                        
                        self._create_finding(
                            f"{mechanism_type}_usage",
                            f"{file_path}:{line_num}",
                            "INFO" if info["recommended"] else "MEDIUM",
                            f"{mechanism_type} detected",
                            line.strip(),
                            "Use Google Play In-App Updates for better security" if not info["recommended"] else "Ensure proper implementation"
                        )
        
        return mechanisms

    def _analyze_security_features(self, results: Dict[str, Any]) -> None:
        """Analyze security features in update implementation."""
        security_features = {
            "signature_verification": False,
            "integrity_checks": False,
            "secure_download": False,
            "insecure_practices": []
        }
        
        if hasattr(self.apk_ctx, 'get_java_files'):
            java_files = self.apk_ctx.get_java_files()
            for file_path, content in java_files.items():
                self._analyze_security_in_file(file_path, content, security_features)
        
        results["security_features"] = security_features

    def _analyze_security_in_file(self, file_path: str, content: str, security_features: Dict) -> None:
        """Analyze security features in a file."""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for signature verification
            for pattern in self.security_patterns["signature_verification"]:
                if re.search(pattern, line, re.IGNORECASE):
                    security_features["signature_verification"] = True
            
            # Check for integrity checks
            for pattern in self.security_patterns["integrity_checks"]:
                if re.search(pattern, line, re.IGNORECASE):
                    security_features["integrity_checks"] = True
            
            # Check for secure download
            for pattern in self.security_patterns["secure_download"]:
                if re.search(pattern, line):
                    security_features["secure_download"] = True
            
            # Check for insecure practices
            for pattern in self.security_patterns["insecure_download"]:
                if re.search(pattern, line):
                    security_features["insecure_practices"].append({
                        "file": file_path, "line": line_num, "code": line.strip()
                    })
                    
                    self._create_finding(
                        "insecure_update_download",
                        f"{file_path}:{line_num}",
                        "HIGH",
                        "Insecure update download detected",
                        line.strip(),
                        "Use HTTPS and proper certificate validation"
                    )

    def _calculate_compliance_status(self, results: Dict[str, Any]) -> None:
        """Calculate MASVS-CODE-4 compliance status."""
        mechanisms = results.get("update_mechanisms", [])
        security_features = results.get("security_features", {})
        
        has_mechanism = len(mechanisms) > 0
        uses_recommended = any(m["recommended"] for m in mechanisms)
        has_security = any([
            security_features.get("signature_verification", False),
            security_features.get("integrity_checks", False),
            security_features.get("secure_download", False)
        ])
        has_insecure = len(security_features.get("insecure_practices", [])) > 0
        
        if not has_mechanism:
            results["compliance_status"] = "NON_COMPLIANT"
        elif has_insecure:
            results["compliance_status"] = "NON_COMPLIANT"
        elif uses_recommended and has_security:
            results["compliance_status"] = "COMPLIANT"
        elif has_mechanism:
            results["compliance_status"] = "PARTIALLY_COMPLIANT"
        else:
            results["compliance_status"] = "NON_COMPLIANT"

    def _calculate_risk_score(self, results: Dict[str, Any]) -> None:
        """Calculate risk score."""
        mechanisms = results.get("update_mechanisms", [])
        security_features = results.get("security_features", {})
        
        score = 0
        
        # Points for mechanisms
        if mechanisms:
            score += 30
            if any(m["recommended"] for m in mechanisms):
                score += 25
        
        # Points for security features
        if security_features.get("signature_verification", False):
            score += 15
        if security_features.get("integrity_checks", False):
            score += 15
        if security_features.get("secure_download", False):
            score += 10
        
        # Deduct for insecure practices
        score -= len(security_features.get("insecure_practices", [])) * 20
        
        results["risk_score"] = max(0, min(100, score))

    def _generate_recommendations(self, results: Dict[str, Any]) -> None:
        """Generate recommendations."""
        recommendations = []
        mechanisms = results.get("update_mechanisms", [])
        security_features = results.get("security_features", {})
        
        if not mechanisms:
            recommendations.append({
                "category": "Implementation",
                "title": "Implement Update Mechanism",
                "description": "Add in-app update mechanism for security updates",
                "priority": "CRITICAL"
            })
        
        if not any(m["recommended"] for m in mechanisms):
            recommendations.append({
                "category": "Security",
                "title": "Use Google Play In-App Updates",
                "description": "Migrate to secure Google Play update API",
                "priority": "HIGH"
            })
        
        if security_features.get("insecure_practices"):
            recommendations.append({
                "category": "Security",
                "title": "Fix Insecure Update Practices",
                "description": "Address insecure download mechanisms",
                "priority": "HIGH"
            })
        
        results["recommendations"] = recommendations

    def _map_masvs_controls(self, results: Dict[str, Any]) -> None:
        """Map to MASVS controls."""
        compliance_status = results.get("compliance_status", "UNKNOWN")
        
        status = "PASS"
        if compliance_status == "NON_COMPLIANT":
            status = "FAIL"
        elif compliance_status == "PARTIALLY_COMPLIANT":
            status = "PARTIAL"
        
        results["masvs_controls"] = [{
            "control_id": "MASVS-CODE-4",
            "control_name": "Update Mechanism Implementation",
            "status": status,
            "compliance_status": compliance_status,
            "description": "The app has a mechanism to enforce updates"
        }]

    def _create_finding(self, finding_type: str, location: str, severity: str,
                       description: str, evidence: str, remediation: str) -> None:
        """Create a finding."""
        finding = {
            "finding_type": finding_type,
            "location": location,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "masvs_control": "MASVS-CODE-4"
        }
        self.findings.append(finding)

def run_plugin(apk_ctx, deep_mode: bool = False) -> Dict[str, Any]:
    """Execute update mechanism analysis plugin."""
    try:
        analyzer = UpdateMechanismAnalyzer(apk_ctx)
        results = analyzer.analyze()
        
        return {
            "plugin_name": "Update Mechanism Analysis",
            "version": "1.0.0",
            "masvs_controls": results.get("masvs_controls", []),
            "compliance_status": results.get("compliance_status", "UNKNOWN"),
            "risk_score": results.get("risk_score", 0),
            "findings": results.get("update_mechanisms", []),
            "recommendations": results.get("recommendations", []),
            "summary": f"Update mechanism analysis: {results.get('compliance_status', 'UNKNOWN')}"
        }
        
    except Exception as e:
        logger.error(f"Update mechanism analysis failed: {e}")
        return {"plugin_name": "Update Mechanism Analysis", "error": str(e), "status": "FAILED"}

# Plugin characteristics
PLUGIN_CHARACTERISTICS = {
    "name": "Update Mechanism Analysis",
    "description": "MASVS-CODE-4 compliance analysis for update mechanisms",
    "version": "1.0.0",
    "masvs_controls": ["MASVS-CODE-4"],
    "requires_device": False,
    "execution_time_estimate": 25
} 
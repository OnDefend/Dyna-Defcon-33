# HTML Report Generation for AODS

# Vulnerability categorization that properly identifies security issues

import datetime
import json
from pathlib import Path
from typing import Dict, List

class VulnerabilityCategorizationEngine:
    """
    Enhanced vulnerability categorization that properly identifies security issues
    """

    def __init__(self):
        self.vulnerability_patterns = {
            "clear_text_traffic": {
                "keywords": ["Clear-Text-Traffic", "FAIL", "usesCleartextTraffic"],
                "severity": "MEDIUM",
                "category": "Network Security",
                "masvs": "MSTG-NETWORK-01",
            },
            "exported_components": {
                "keywords": ["Exported component without permission", "CRITICAL"],
                "severity": "HIGH",
                "category": "Platform Security",
                "masvs": "MSTG-PLATFORM-01",
            },
            "debug_enabled": {
                "keywords": ["debuggable.*ENABLED", "Application is debuggable"],
                "severity": "MEDIUM",
                "category": "Platform Security",
                "masvs": "MSTG-PLATFORM-10",
            },
            "backup_enabled": {
                "keywords": ["allowBackup.*ENABLED", "allowBackup not explicitly set"],
                "severity": "MEDIUM",
                "category": "Data Protection",
                "masvs": "MSTG-STORAGE-01",
            },
            "missing_cert_pinning": {
                "keywords": ["Certificate Pinning", "No certificate pinning"],
                "severity": "MEDIUM",
                "category": "Network Security",
                "masvs": "MSTG-NETWORK-04",
            },
            "missing_screenshot_protection": {
                "keywords": ["Screenshot Protection", "FLAG_SECURE"],
                "severity": "LOW",
                "category": "Privacy Protection",
                "masvs": "MSTG-PRIVACY-01",
            },
        }

    def categorize_findings(self, detailed_results: List[Dict]) -> Dict:
        """Categorize findings into proper vulnerabilities"""
        vulnerabilities = []

        for result in detailed_results:
            title = result.get("title", "")
            content = str(result.get("content", ""))

            vuln = self._analyze_finding(title, content)
            if vuln:
                vulnerabilities.append(vuln)

        # Count by severity
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for vuln in vulnerabilities:
            counts[vuln["severity"]] += 1

        return {
            "vulnerabilities": vulnerabilities,
            "counts": counts,
            "total": len(vulnerabilities),
        }

    def _analyze_finding(self, title: str, content: str) -> Dict:
        """Analyze individual finding for vulnerability classification"""

        # Check for clear-text traffic issues
        if (
            any(
                keyword in title or keyword in content
                for keyword in ["Clear-Text-Traffic", "usesCleartextTraffic"]
            )
            and "FAIL" in content
        ):
            return {
                "title": "Clear-Text Traffic Enabled",
                "severity": "MEDIUM",
                "category": "Network Security",
                "description": "Application allows clear-text traffic communication",
                "evidence": "android:usesCleartextTraffic not explicitly disabled",
                "recommendation": 'Set android:usesCleartextTraffic="false" in AndroidManifest.xml',
                "masvs": "MSTG-NETWORK-01",
            }

        # Check for exported components
        if (
            "Enhanced Manifest Analysis" in title
            and "Exported component without permission" in content
        ):
            count = content.count("Exported component without permission")
            return {
                "title": f"Unprotected Exported Components ({count} found)",
                "severity": "HIGH",
                "category": "Platform Security",
                "description": "Exported Android components lack permission protection",
                "evidence": f"{count} components exported without permission requirements",
                "recommendation": "Add permission requirements to exported components or make them non-exported",
                "masvs": "MSTG-PLATFORM-01",
            }

        # Check for debug mode
        if (
            "debuggable" in content and "ENABLED" in content
        ) or "Application is debuggable" in content:
            return {
                "title": "Debug Mode Enabled in Production",
                "severity": "MEDIUM",
                "category": "Platform Security",
                "description": "Application has debugging enabled which poses security risks",
                "evidence": 'android:debuggable="true" detected in manifest',
                "recommendation": 'Set android:debuggable="false" for production builds',
                "masvs": "MSTG-PLATFORM-10",
            }

        # Check for backup issues
        if (
            "allowBackup" in content and "ENABLED" in content
        ) or "allowBackup not explicitly set" in content:
            return {
                "title": "Application Backup Enabled",
                "severity": "MEDIUM",
                "category": "Data Protection",
                "description": "Application data can be backed up, potentially exposing sensitive information",
                "evidence": "android:allowBackup not disabled in manifest",
                "recommendation": 'Set android:allowBackup="false" in AndroidManifest.xml',
                "masvs": "MSTG-STORAGE-01",
            }

        # Check for missing certificate pinning
        if "Certificate Pinning" in title and "No certificate pinning" in content:
            return {
                "title": "Missing Certificate Pinning",
                "severity": "MEDIUM",
                "category": "Network Security",
                "description": "Application does not implement certificate pinning for secure connections",
                "evidence": "No certificate pinning implementation detected",
                "recommendation": "Implement certificate or public key pinning for critical connections",
                "masvs": "MSTG-NETWORK-04",
            }

        # Check for screenshot protection
        if "Screenshot Protection" in title and "MEDIUM" in content:
            return {
                "title": "Missing Screenshot Protection",
                "severity": "LOW",
                "category": "Privacy Protection",
                "description": "Sensitive screens are not protected from screenshots",
                "evidence": "FLAG_SECURE not implemented for sensitive activities",
                "recommendation": "Implement FLAG_SECURE for activities containing sensitive data",
                "masvs": "MSTG-PRIVACY-01",
            }

        return None

# Export for integration
def get_vulnerability_categorization_engine():
    return VulnerabilityCategorizationEngine()

def get_vulnerability_categorization_engine():
    return VulnerabilityCategorizationEngine()

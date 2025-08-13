#!/usr/bin/env python3
"""
MASVS Tagging Service

Comprehensive service for automatically applying MASVS controls to vulnerability findings.
This service ensures all vulnerabilities are properly tagged with relevant MASVS controls
and categories for compliance reporting.
"""

import logging
import json
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

class MASVSTaggingService:
    """Service for applying MASVS controls to vulnerability findings."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the MASVS tagging service."""
        self.config_path = config_path or "config/masvs_config.json"
        self.masvs_config = self._load_masvs_config()
        
        # Category to MASVS control mappings
        self.category_mappings = {
            # Network Security
            "network_security": ["MASVS-NETWORK-1", "MASVS-NETWORK-2"],
            "cleartext_traffic": ["MASVS-NETWORK-1"],
            "ssl_tls": ["MASVS-NETWORK-2"],
            "certificate_pinning": ["MASVS-NETWORK-2"],
            
            # Storage & Data
            "data_storage": ["MASVS-STORAGE-1", "MASVS-STORAGE-2"],
            "insecure_storage": ["MASVS-STORAGE-1"],
            "database_security": ["MASVS-STORAGE-2"],
            "permission_issue": ["MASVS-STORAGE-1", "MASVS-PLATFORM-1"],
            
            # Cryptography
            "cryptographic": ["MASVS-CRYPTO-1", "MASVS-CRYPTO-2"],
            "weak_crypto": ["MASVS-CRYPTO-1"],
            "key_management": ["MASVS-CRYPTO-2"],
            "encryption": ["MASVS-CRYPTO-1"],
            
            # Authentication
            "authentication": ["MASVS-AUTH-1", "MASVS-AUTH-2"],
            "session_management": ["MASVS-AUTH-3"],
            "biometric": ["MASVS-AUTH-2"],
            
            # Platform Interaction
            "platform_interaction": ["MASVS-PLATFORM-1", "MASVS-PLATFORM-2"],
            "intent_security": ["MASVS-PLATFORM-1"],
            "webview_security": ["MASVS-PLATFORM-2"],
            "deep_link": ["MASVS-PLATFORM-3"],
            
            # Code Quality
            "code_quality": ["MASVS-CODE-1", "MASVS-CODE-2"],
            "injection": ["MASVS-CODE-1"],
            "xss": ["MASVS-CODE-1"],
            "code_injection": ["MASVS-CODE-1"],
            "sql_injection": ["MASVS-CODE-1"],
            "debug_issue": ["MASVS-CODE-3"],
            "obfuscation": ["MASVS-CODE-4"],
            
            # Resilience
            "anti_tampering": ["MASVS-RESILIENCE-1"],
            "root_detection": ["MASVS-RESILIENCE-2"],
            "emulator_detection": ["MASVS-RESILIENCE-2"],
            "reverse_engineering": ["MASVS-RESILIENCE-3"],
            "binary_protection": ["MASVS-RESILIENCE-4"],
            
            # Privacy
            "privacy": ["MASVS-PRIVACY-1", "MASVS-PRIVACY-2"],
            "data_minimization": ["MASVS-PRIVACY-2"],
            "consent": ["MASVS-PRIVACY-3"],
            "tracking": ["MASVS-PRIVACY-4"],
            
            # General mappings
            "general_security": ["MASVS-CODE-1"],
            "information_disclosure": ["MASVS-STORAGE-1"],
            "path_traversal": ["MASVS-PLATFORM-1", "MASVS-CODE-1"]
        }
        
        # Vulnerability type to MASVS mappings
        self.vulnerability_type_mappings = {
            "sql_injection": ["MASVS-CODE-1"],
            "xss": ["MASVS-CODE-1"],
            "hardcoded_secrets": ["MASVS-CRYPTO-1", "MASVS-STORAGE-1"],
            "weak_cryptography": ["MASVS-CRYPTO-1"],
            "cleartext_communication": ["MASVS-NETWORK-1"],
            "insecure_data_storage": ["MASVS-STORAGE-1"],
            "improper_platform_usage": ["MASVS-PLATFORM-1"],
            "insufficient_cryptography": ["MASVS-CRYPTO-1"],
            "insecure_communication": ["MASVS-NETWORK-1"],
            "poor_code_quality": ["MASVS-CODE-1"],
            "client_side_injection": ["MASVS-CODE-1"],
            "reverse_engineering": ["MASVS-RESILIENCE-1"]
        }
        
        # Plugin to MASVS mappings
        self.plugin_mappings = self.masvs_config.get("plugin_mapping", {})
        
    def _load_masvs_config(self) -> Dict[str, Any]:
        """Load MASVS configuration from file."""
        try:
            config_path = Path(self.config_path)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"MASVS config file not found: {config_path}")
                return {}
        except Exception as e:
            logger.error(f"Error loading MASVS config: {e}")
            return {}
    
    def apply_masvs_tags(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply MASVS controls to a list of vulnerabilities."""
        logger.info(f"🏷️ Applying MASVS tags to {len(vulnerabilities)} vulnerabilities...")
        
        tagged_vulnerabilities = []
        stats = defaultdict(int)
        
        for vuln in vulnerabilities:
            tagged_vuln = self._apply_masvs_tags_to_vulnerability(vuln)
            tagged_vulnerabilities.append(tagged_vuln)
            
            # Update statistics
            masvs_controls = tagged_vuln.get("masvs_controls", [])
            if masvs_controls:
                stats["tagged_vulnerabilities"] += 1
                stats["total_controls_applied"] += len(masvs_controls)
            else:
                stats["untagged_vulnerabilities"] += 1
        
        # Log statistics
        logger.info(f"✅ MASVS tagging complete:")
        logger.info(f"   Tagged vulnerabilities: {stats['tagged_vulnerabilities']}")
        logger.info(f"   Untagged vulnerabilities: {stats['untagged_vulnerabilities']}")
        logger.info(f"   Total controls applied: {stats['total_controls_applied']}")
        
        return tagged_vulnerabilities
    
    def _apply_masvs_tags_to_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Apply MASVS controls to a single vulnerability."""
        # Create a copy to avoid modifying the original
        tagged_vuln = vulnerability.copy()
        
        # Skip if already has MASVS controls
        if tagged_vuln.get("masvs_controls") or tagged_vuln.get("masvs_refs"):
            return tagged_vuln
        
        # Collect MASVS controls from multiple sources
        controls = set()
        
        # 1. Map by category
        category = vulnerability.get("category", "").lower()
        if category:
            controls.update(self._get_controls_by_category(category))
        
        # 2. Map by vulnerability type
        vuln_type = vulnerability.get("vulnerability_type", "").lower()
        if vuln_type:
            controls.update(self._get_controls_by_type(vuln_type))
        
        # 3. Map by title keywords
        title = vulnerability.get("title", "").lower()
        if title:
            controls.update(self._get_controls_by_keywords(title))
        
        # 4. Map by description keywords
        description = vulnerability.get("description", "").lower()
        if description:
            controls.update(self._get_controls_by_keywords(description))
        
        # 5. Map by plugin source (if available)
        plugin_name = vulnerability.get("plugin_name", "")
        if plugin_name:
            controls.update(self._get_controls_by_plugin(plugin_name))
        
        # Apply the controls
        if controls:
            tagged_vuln["masvs_controls"] = sorted(list(controls))
            tagged_vuln["masvs_category"] = self._determine_primary_category(controls)
            
            # Add MSTG references
            mstg_refs = self._get_mstg_references(controls)
            if mstg_refs:
                tagged_vuln["mstg_refs"] = mstg_refs
        
        return tagged_vuln
    
    def _get_controls_by_category(self, category: str) -> Set[str]:
        """Get MASVS controls based on vulnerability category."""
        controls = set()
        
        # Direct mapping
        if category in self.category_mappings:
            controls.update(self.category_mappings[category])
        
        # Partial keyword matching
        for cat_key, cat_controls in self.category_mappings.items():
            if cat_key in category or category in cat_key:
                controls.update(cat_controls)
        
        return controls
    
    def _get_controls_by_type(self, vuln_type: str) -> Set[str]:
        """Get MASVS controls based on vulnerability type."""
        controls = set()
        
        # Direct mapping
        if vuln_type in self.vulnerability_type_mappings:
            controls.update(self.vulnerability_type_mappings[vuln_type])
        
        # Partial keyword matching
        for type_key, type_controls in self.vulnerability_type_mappings.items():
            if type_key in vuln_type or vuln_type in type_key:
                controls.update(type_controls)
        
        return controls
    
    def _get_controls_by_keywords(self, text: str) -> Set[str]:
        """Get MASVS controls based on keywords in text."""
        controls = set()
        text_lower = text.lower()
        
        # Keyword to control mappings
        keyword_mappings = {
            # Network keywords
            "cleartext": ["MASVS-NETWORK-1"],
            "http": ["MASVS-NETWORK-1"],
            "ssl": ["MASVS-NETWORK-2"],
            "tls": ["MASVS-NETWORK-2"],
            "certificate": ["MASVS-NETWORK-2"],
            "pinning": ["MASVS-NETWORK-2"],
            
            # Storage keywords
            "storage": ["MASVS-STORAGE-1"],
            "database": ["MASVS-STORAGE-2"],
            "sqlite": ["MASVS-STORAGE-2"],
            "preferences": ["MASVS-STORAGE-1"],
            "file": ["MASVS-STORAGE-1"],
            
            # Crypto keywords
            "encryption": ["MASVS-CRYPTO-1"],
            "crypto": ["MASVS-CRYPTO-1"],
            "cipher": ["MASVS-CRYPTO-1"],
            "key": ["MASVS-CRYPTO-2"],
            "hash": ["MASVS-CRYPTO-1"],
            "des": ["MASVS-CRYPTO-1"],
            "md5": ["MASVS-CRYPTO-1"],
            
            # Code keywords
            "injection": ["MASVS-CODE-1"],
            "sql": ["MASVS-CODE-1"],
            "xss": ["MASVS-CODE-1"],
            "debug": ["MASVS-CODE-3"],
            
            # Platform keywords
            "intent": ["MASVS-PLATFORM-1"],
            "webview": ["MASVS-PLATFORM-2"],
            "deeplink": ["MASVS-PLATFORM-3"],
            "permission": ["MASVS-PLATFORM-1"],
            
            # Privacy keywords
            "privacy": ["MASVS-PRIVACY-1"],
            "tracking": ["MASVS-PRIVACY-4"],
            "consent": ["MASVS-PRIVACY-3"],
            
            # Resilience keywords
            "tampering": ["MASVS-RESILIENCE-1"],
            "root": ["MASVS-RESILIENCE-2"],
            "emulator": ["MASVS-RESILIENCE-2"],
            "obfuscation": ["MASVS-RESILIENCE-3"]
        }
        
        for keyword, keyword_controls in keyword_mappings.items():
            if keyword in text_lower:
                controls.update(keyword_controls)
        
        return controls
    
    def _get_controls_by_plugin(self, plugin_name: str) -> Set[str]:
        """Get MASVS controls based on plugin name."""
        controls = set()
        
        # Map plugin names to MASVS categories
        for category, plugins in self.plugin_mappings.items():
            if plugin_name in plugins:
                category_controls = self.masvs_config.get("masvs_compliance", {}).get("categories", {}).get(category, {}).get("controls", [])
                controls.update(category_controls)
        
        return controls
    
    def _determine_primary_category(self, controls: Set[str]) -> str:
        """Determine the primary MASVS category from a set of controls."""
        if not controls:
            return "GENERAL"
        
        # Count controls by category
        category_counts = defaultdict(int)
        for control in controls:
            if "-" in control:
                category = control.split("-")[1]
                category_counts[category] += 1
        
        # Return the category with the most controls
        if category_counts:
            return max(category_counts, key=category_counts.get)
        
        return "GENERAL"
    
    def _get_mstg_references(self, controls: Set[str]) -> List[str]:
        """Get MSTG references for MASVS controls."""
        # Simple mapping from MASVS to MSTG
        masvs_to_mstg = {
            "MASVS-STORAGE-1": "MSTG-STORAGE-1",
            "MASVS-STORAGE-2": "MSTG-STORAGE-2",
            "MASVS-CRYPTO-1": "MSTG-CRYPTO-1",
            "MASVS-CRYPTO-2": "MSTG-CRYPTO-2",
            "MASVS-AUTH-1": "MSTG-AUTH-1",
            "MASVS-AUTH-2": "MSTG-AUTH-2", 
            "MASVS-AUTH-3": "MSTG-AUTH-3",
            "MASVS-NETWORK-1": "MSTG-NETWORK-1",
            "MASVS-NETWORK-2": "MSTG-NETWORK-2",
            "MASVS-PLATFORM-1": "MSTG-PLATFORM-1",
            "MASVS-PLATFORM-2": "MSTG-PLATFORM-2",
            "MASVS-PLATFORM-3": "MSTG-PLATFORM-3",
            "MASVS-CODE-1": "MSTG-CODE-1",
            "MASVS-CODE-2": "MSTG-CODE-2",
            "MASVS-CODE-3": "MSTG-CODE-3",
            "MASVS-CODE-4": "MSTG-CODE-4",
            "MASVS-RESILIENCE-1": "MSTG-RESILIENCE-1",
            "MASVS-RESILIENCE-2": "MSTG-RESILIENCE-2",
            "MASVS-RESILIENCE-3": "MSTG-RESILIENCE-3",
            "MASVS-RESILIENCE-4": "MSTG-RESILIENCE-4",
            "MASVS-PRIVACY-1": "MSTG-PRIVACY-1",
            "MASVS-PRIVACY-2": "MSTG-PRIVACY-2",
            "MASVS-PRIVACY-3": "MSTG-PRIVACY-3",
            "MASVS-PRIVACY-4": "MSTG-PRIVACY-4"
        }
        
        mstg_refs = []
        for control in controls:
            if control in masvs_to_mstg:
                mstg_refs.append(masvs_to_mstg[control])
        
        return sorted(list(set(mstg_refs)))
    
    def generate_compliance_summary(self, tagged_vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate MASVS compliance summary from tagged vulnerabilities."""
        total_controls = 24  # MASVS v2.0 has 24 controls
        controls_tested = set()
        categories_covered = set()
        
        for vuln in tagged_vulnerabilities:
            masvs_controls = vuln.get("masvs_controls", [])
            for control in masvs_controls:
                controls_tested.add(control)
                if "-" in control:
                    category = control.split("-")[1]
                    categories_covered.add(category)
        
        compliance_summary = {
            "version": "2.0",
            "controls_tested": len(controls_tested),
            "total_controls": total_controls,
            "compliance_percentage": (len(controls_tested) / total_controls) * 100,
            "categories_covered": sorted(list(categories_covered)),
            "operational_categories": len(categories_covered),
            "controls_list": sorted(list(controls_tested))
        }
        
        return compliance_summary

def apply_masvs_tagging_to_report(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Apply MASVS tagging to a complete security report."""
    logger.info("🏷️ Applying MASVS tagging to security report...")
    
    # Initialize tagging service
    tagging_service = MASVSTaggingService()
    
    # Apply tags to vulnerabilities
    if "vulnerabilities" in report_data:
        tagged_vulnerabilities = tagging_service.apply_masvs_tags(report_data["vulnerabilities"])
        report_data["vulnerabilities"] = tagged_vulnerabilities
        
        # Update MASVS compliance section
        compliance_summary = tagging_service.generate_compliance_summary(tagged_vulnerabilities)
        report_data["masvs_compliance"] = compliance_summary
        
        # Update metadata
        if "metadata" in report_data:
            report_data["metadata"]["masvs_controls_covered"] = compliance_summary["controls_tested"]
            report_data["metadata"]["masvs_compliance_percentage"] = compliance_summary["compliance_percentage"]
        
        if "report_metadata" in report_data:
            report_data["report_metadata"]["masvs_controls_covered"] = compliance_summary["controls_tested"]
        
        logger.info(f"✅ MASVS tagging applied: {compliance_summary['controls_tested']}/24 controls covered")
    
    return report_data

if __name__ == "__main__":
    # Test the tagging service
    test_vulnerabilities = [
        {
            "id": "TEST-1",
            "title": "Network Cleartext Traffic",
            "category": "network_security",
            "description": "Application sends data over HTTP without encryption"
        },
        {
            "id": "TEST-2", 
            "title": "SQL Injection Vulnerability",
            "category": "code_quality",
            "vulnerability_type": "sql_injection",
            "description": "Database query vulnerable to SQL injection"
        }
    ]
    
    service = MASVSTaggingService()
    tagged = service.apply_masvs_tags(test_vulnerabilities)
    
    print(json.dumps(tagged, indent=2)) 
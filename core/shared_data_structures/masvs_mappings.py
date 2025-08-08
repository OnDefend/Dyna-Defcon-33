#!/usr/bin/env python3
"""
MASVS Mappings and Compliance Data Structures

This module provides standardized MASVS (Mobile Application Security Verification Standard)
mappings and compliance structures used across all AODS plugins.

Features:
- Complete MASVS control mappings
- Compliance standard definitions
- Security requirement structures
- MSTG (Mobile Security Testing Guide) integration
- CWE (Common Weakness Enumeration) mappings
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union, Set
from enum import Enum

logger = logging.getLogger(__name__)

class ComplianceStandard(Enum):
    """Supported compliance standards."""
    MASVS = "MASVS"
    MSTG = "MSTG"
    CWE = "CWE"
    OWASP_TOP_10 = "OWASP_TOP_10"
    NIST = "NIST"
    ISO_27001 = "ISO_27001"
    SOC_2 = "SOC_2"
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI_DSS"
    
    def __str__(self) -> str:
        return self.value

class MAVSCategory(Enum):
    """MASVS categories."""
    ARCHITECTURE = "V1"  # Architecture, Design and Threat Modeling
    DATA_STORAGE = "V2"  # Data Storage and Privacy
    CRYPTOGRAPHY = "V3"  # Cryptography
    AUTHENTICATION = "V4"  # Authentication and Session Management
    NETWORK = "V5"  # Network Communication
    PLATFORM = "V6"  # Platform Interaction
    CODE_QUALITY = "V7"  # Code Quality and Build Settings
    RESILIENCE = "V8"  # Resilience Against Reverse Engineering
    
    def __str__(self) -> str:
        return self.value
    
    @property
    def description(self) -> str:
        """Get category description."""
        descriptions = {
            MAVSCategory.ARCHITECTURE: "Architecture, Design and Threat Modeling",
            MAVSCategory.DATA_STORAGE: "Data Storage and Privacy",
            MAVSCategory.CRYPTOGRAPHY: "Cryptography",
            MAVSCategory.AUTHENTICATION: "Authentication and Session Management",
            MAVSCategory.NETWORK: "Network Communication",
            MAVSCategory.PLATFORM: "Platform Interaction",
            MAVSCategory.CODE_QUALITY: "Code Quality and Build Settings",
            MAVSCategory.RESILIENCE: "Resilience Against Reverse Engineering"
        }
        return descriptions.get(self, "Unknown")

@dataclass
class MAVSControl:
    """MASVS control definition."""
    
    # Control identification
    control_id: str  # e.g., "MSTG-STORAGE-1"
    control_number: str  # e.g., "V2.1"
    category: MAVSCategory
    
    # Control details
    title: str
    description: str
    detailed_description: str = ""
    
    # Verification levels
    level_1: bool = False  # Standard
    level_2: bool = False  # Defense in Depth
    level_r: bool = False  # Resiliency Against Reverse Engineering
    
    # Related standards
    mstg_refs: List[str] = field(default_factory=list)
    cwe_refs: List[str] = field(default_factory=list)
    owasp_refs: List[str] = field(default_factory=list)
    
    # Testing information
    test_procedures: List[str] = field(default_factory=list)
    test_tools: List[str] = field(default_factory=list)
    
    # Compliance metadata
    compliance_notes: str = ""
    implementation_guidance: str = ""
    common_weaknesses: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate control data."""
        if not self.control_id:
            raise ValueError("Control ID cannot be empty")
        if not self.control_number:
            raise ValueError("Control number cannot be empty")
        if not self.title:
            raise ValueError("Control title cannot be empty")
        if not self.description:
            raise ValueError("Control description cannot be empty")
    
    @property
    def verification_levels(self) -> List[str]:
        """Get applicable verification levels."""
        levels = []
        if self.level_1:
            levels.append("L1")
        if self.level_2:
            levels.append("L2")
        if self.level_r:
            levels.append("R")
        return levels
    
    def is_applicable_for_level(self, level: str) -> bool:
        """Check if control is applicable for verification level."""
        level_upper = level.upper()
        if level_upper in ["L1", "LEVEL1", "STANDARD"]:
            return self.level_1
        elif level_upper in ["L2", "LEVEL2", "DEFENSE"]:
            return self.level_2
        elif level_upper in ["R", "RESILIENCE", "REVERSE"]:
            return self.level_r
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert control to dictionary."""
        return {
            'control_id': self.control_id,
            'control_number': self.control_number,
            'category': self.category.value,
            'title': self.title,
            'description': self.description,
            'detailed_description': self.detailed_description,
            'verification_levels': self.verification_levels,
            'level_1': self.level_1,
            'level_2': self.level_2,
            'level_r': self.level_r,
            'mstg_refs': self.mstg_refs,
            'cwe_refs': self.cwe_refs,
            'owasp_refs': self.owasp_refs,
            'test_procedures': self.test_procedures,
            'test_tools': self.test_tools,
            'compliance_notes': self.compliance_notes,
            'implementation_guidance': self.implementation_guidance,
            'common_weaknesses': self.common_weaknesses
        }

@dataclass
class SecurityRequirement:
    """Security requirement definition."""
    
    # Requirement identification
    requirement_id: str
    requirement_name: str
    category: str
    
    # Requirement details
    description: str
    rationale: str = ""
    
    # Compliance mappings
    masvs_controls: List[str] = field(default_factory=list)
    mstg_controls: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    
    # Implementation details
    implementation_methods: List[str] = field(default_factory=list)
    verification_methods: List[str] = field(default_factory=list)
    testing_approaches: List[str] = field(default_factory=list)
    
    # Risk assessment
    risk_level: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    business_impact: str = ""
    
    # Compliance metadata
    mandatory: bool = True
    applicable_platforms: List[str] = field(default_factory=lambda: ["Android", "iOS"])
    
    def __post_init__(self):
        """Validate requirement data."""
        if not self.requirement_id:
            raise ValueError("Requirement ID cannot be empty")
        if not self.requirement_name:
            raise ValueError("Requirement name cannot be empty")
        if not self.description:
            raise ValueError("Requirement description cannot be empty")
        if self.risk_level not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            raise ValueError("Invalid risk level")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert requirement to dictionary."""
        return {
            'requirement_id': self.requirement_id,
            'requirement_name': self.requirement_name,
            'category': self.category,
            'description': self.description,
            'rationale': self.rationale,
            'masvs_controls': self.masvs_controls,
            'mstg_controls': self.mstg_controls,
            'cwe_ids': self.cwe_ids,
            'implementation_methods': self.implementation_methods,
            'verification_methods': self.verification_methods,
            'testing_approaches': self.testing_approaches,
            'risk_level': self.risk_level,
            'business_impact': self.business_impact,
            'mandatory': self.mandatory,
            'applicable_platforms': self.applicable_platforms
        }

class MAVSMapping:
    """
    MASVS mapping and compliance management system.
    
    Provides comprehensive mapping between vulnerabilities and MASVS controls,
    compliance assessment, and verification guidance.
    """
    
    def __init__(self):
        """Initialize MASVS mapping system."""
        self.controls: Dict[str, MAVSControl] = {}
        self.requirements: Dict[str, SecurityRequirement] = {}
        self.category_mappings: Dict[MAVSCategory, List[str]] = {}
        
        # Initialize with standard MASVS controls
        self._initialize_standard_controls()
        
        logger.info("MASVS mapping system initialized")
    
    def _initialize_standard_controls(self):
        """Initialize standard MASVS controls."""
        # V1 - Architecture, Design and Threat Modeling
        self.add_control(MAVSControl(
            control_id="MSTG-ARCH-1",
            control_number="V1.1",
            category=MAVSCategory.ARCHITECTURE,
            title="Security Architecture Review",
            description="All app components are identified and have a known security function.",
            level_1=True,
            level_2=True,
            mstg_refs=["MSTG-ARCH-1"],
            test_procedures=["Review app architecture", "Identify security components"]
        ))
        
        self.add_control(MAVSControl(
            control_id="MSTG-ARCH-2",
            control_number="V1.2",
            category=MAVSCategory.ARCHITECTURE,
            title="Data Flow Security",
            description="Security controls are never enforced only on the client side, but on the respective remote endpoints.",
            level_1=True,
            level_2=True,
            mstg_refs=["MSTG-ARCH-2"],
            test_procedures=["Analyze data flow", "Verify server-side controls"]
        ))
        
        # V2 - Data Storage and Privacy
        self.add_control(MAVSControl(
            control_id="MSTG-STORAGE-1",
            control_number="V2.1",
            category=MAVSCategory.DATA_STORAGE,
            title="Secure Local Storage",
            description="System credential storage facilities are used appropriately to store sensitive data.",
            level_1=True,
            level_2=True,
            mstg_refs=["MSTG-STORAGE-1"],
            cwe_refs=["CWE-922", "CWE-359"],
            test_procedures=["Review storage mechanisms", "Test credential storage"]
        ))
        
        self.add_control(MAVSControl(
            control_id="MSTG-STORAGE-2",
            control_number="V2.2",
            category=MAVSCategory.DATA_STORAGE,
            title="Sensitive Data in Logs",
            description="No sensitive data should be written to application logs.",
            level_1=True,
            level_2=True,
            mstg_refs=["MSTG-STORAGE-2"],
            cwe_refs=["CWE-532"],
            test_procedures=["Review log outputs", "Test for sensitive data leakage"]
        ))
        
        # V3 - Cryptography
        self.add_control(MAVSControl(
            control_id="MSTG-CRYPTO-1",
            control_number="V3.1",
            category=MAVSCategory.CRYPTOGRAPHY,
            title="Cryptographic Standards",
            description="The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption.",
            level_1=True,
            level_2=True,
            mstg_refs=["MSTG-CRYPTO-1"],
            cwe_refs=["CWE-321", "CWE-798"],
            test_procedures=["Review cryptographic implementation", "Test key management"]
        ))
        
        # V4 - Authentication and Session Management
        self.add_control(MAVSControl(
            control_id="MSTG-AUTH-1",
            control_number="V4.1",
            category=MAVSCategory.AUTHENTICATION,
            title="Authentication Architecture",
            description="If the app provides users access to a remote service, some form of authentication is performed at the remote endpoint.",
            level_1=True,
            level_2=True,
            mstg_refs=["MSTG-AUTH-1"],
            test_procedures=["Review authentication mechanisms", "Test remote authentication"]
        ))
        
        # V5 - Network Communication
        self.add_control(MAVSControl(
            control_id="MSTG-NETWORK-1",
            control_number="V5.1",
            category=MAVSCategory.NETWORK,
            title="Network Security",
            description="Data is encrypted on the network using TLS. The secure channel is used consistently throughout the app.",
            level_1=True,
            level_2=True,
            mstg_refs=["MSTG-NETWORK-1"],
            cwe_refs=["CWE-319"],
            test_procedures=["Test network communications", "Verify TLS implementation"]
        ))
        
        # V6 - Platform Interaction
        self.add_control(MAVSControl(
            control_id="MSTG-PLATFORM-1",
            control_number="V6.1",
            category=MAVSCategory.PLATFORM,
            title="Platform Permissions",
            description="The app only uses the minimum set of permissions necessary.",
            level_1=True,
            level_2=True,
            mstg_refs=["MSTG-PLATFORM-1"],
            cwe_refs=["CWE-250"],
            test_procedures=["Review app permissions", "Test permission usage"]
        ))
        
        # V7 - Code Quality and Build Settings
        self.add_control(MAVSControl(
            control_id="MSTG-CODE-1",
            control_number="V7.1",
            category=MAVSCategory.CODE_QUALITY,
            title="Code Signing",
            description="The app is signed and provisioned with a valid certificate.",
            level_1=True,
            level_2=True,
            mstg_refs=["MSTG-CODE-1"],
            test_procedures=["Verify code signing", "Test certificate validity"]
        ))
        
        # V8 - Resilience Against Reverse Engineering
        self.add_control(MAVSControl(
            control_id="MSTG-RESILIENCE-1",
            control_number="V8.1",
            category=MAVSCategory.RESILIENCE,
            title="Root/Jailbreak Detection",
            description="The app detects and responds to the presence of a rooted or jailbroken device.",
            level_r=True,
            mstg_refs=["MSTG-RESILIENCE-1"],
            test_procedures=["Test root detection", "Verify response mechanisms"]
        ))
        
        self.add_control(MAVSControl(
            control_id="MSTG-RESILIENCE-2",
            control_number="V8.2",
            category=MAVSCategory.RESILIENCE,
            title="Debugger Detection",
            description="The app prevents debugging and/or detects and responds to debugging.",
            level_r=True,
            mstg_refs=["MSTG-RESILIENCE-2"],
            test_procedures=["Test debugger detection", "Verify anti-debugging measures"]
        ))
        
        # Build category mappings
        self._build_category_mappings()
    
    def add_control(self, control: MAVSControl):
        """Add a MASVS control to the mapping system."""
        self.controls[control.control_id] = control
        
        # Update category mappings
        if control.category not in self.category_mappings:
            self.category_mappings[control.category] = []
        
        if control.control_id not in self.category_mappings[control.category]:
            self.category_mappings[control.category].append(control.control_id)
    
    def get_control(self, control_id: str) -> Optional[MAVSControl]:
        """Get a MASVS control by ID."""
        return self.controls.get(control_id)
    
    def get_controls_by_category(self, category: MAVSCategory) -> List[MAVSControl]:
        """Get all controls for a specific category."""
        control_ids = self.category_mappings.get(category, [])
        return [self.controls[cid] for cid in control_ids if cid in self.controls]
    
    def get_controls_by_level(self, level: str) -> List[MAVSControl]:
        """Get all controls applicable for a verification level."""
        return [
            control for control in self.controls.values()
            if control.is_applicable_for_level(level)
        ]
    
    def add_requirement(self, requirement: SecurityRequirement):
        """Add a security requirement."""
        self.requirements[requirement.requirement_id] = requirement
    
    def get_requirement(self, requirement_id: str) -> Optional[SecurityRequirement]:
        """Get a security requirement by ID."""
        return self.requirements.get(requirement_id)
    
    def map_vulnerability_to_controls(self, 
                                    vulnerability_type: str,
                                    vulnerability_details: Dict[str, Any]) -> List[str]:
        """Map vulnerability to applicable MASVS controls."""
        applicable_controls = []
        
        # Mapping logic based on vulnerability type
        mapping_rules = {
            "insecure_storage": ["MSTG-STORAGE-1", "MSTG-STORAGE-2"],
            "weak_cryptography": ["MSTG-CRYPTO-1"],
            "insecure_network": ["MSTG-NETWORK-1"],
            "improper_authentication": ["MSTG-AUTH-1"],
            "platform_misuse": ["MSTG-PLATFORM-1"],
            "code_quality": ["MSTG-CODE-1"],
            "anti_tampering": ["MSTG-RESILIENCE-1", "MSTG-RESILIENCE-2"]
        }
        
        # Get controls for vulnerability type
        if vulnerability_type in mapping_rules:
            applicable_controls.extend(mapping_rules[vulnerability_type])
        
        # Additional context-based mapping
        if vulnerability_details.get("involves_root_detection"):
            applicable_controls.append("MSTG-RESILIENCE-1")
        
        if vulnerability_details.get("involves_debugging"):
            applicable_controls.append("MSTG-RESILIENCE-2")
        
        return list(set(applicable_controls))  # Remove duplicates
    
    def assess_compliance(self, 
                         vulnerability_findings: List[Dict[str, Any]],
                         target_level: str = "L1") -> Dict[str, Any]:
        """Assess MASVS compliance based on vulnerability findings."""
        applicable_controls = self.get_controls_by_level(target_level)
        
        compliance_results = {}
        total_controls = len(applicable_controls)
        compliant_controls = 0
        
        for control in applicable_controls:
            # Check if any findings violate this control
            violations = self._find_control_violations(control, vulnerability_findings)
            
            is_compliant = len(violations) == 0
            if is_compliant:
                compliant_controls += 1
            
            compliance_results[control.control_id] = {
                'control': control.to_dict(),
                'compliant': is_compliant,
                'violations': violations,
                'violation_count': len(violations)
            }
        
        overall_compliance = compliant_controls / total_controls if total_controls > 0 else 0.0
        
        return {
            'target_level': target_level,
            'total_controls': total_controls,
            'compliant_controls': compliant_controls,
            'overall_compliance_percentage': overall_compliance * 100,
            'compliance_status': 'COMPLIANT' if overall_compliance >= 0.9 else 'NON_COMPLIANT',
            'control_results': compliance_results
        }
    
    def _find_control_violations(self, 
                               control: MAVSControl,
                               vulnerability_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find vulnerability findings that violate a specific control."""
        violations = []
        
        for finding in vulnerability_findings:
            # Check if finding has MASVS references that match this control
            masvs_refs = finding.get('masvs_refs', [])
            if control.control_id in masvs_refs:
                violations.append({
                    'finding_id': finding.get('id', 'unknown'),
                    'finding_title': finding.get('title', 'Unknown'),
                    'severity': finding.get('severity', 'UNKNOWN'),
                    'confidence': finding.get('confidence', 0.0)
                })
        
        return violations
    
    def _build_category_mappings(self):
        """Build category mappings from controls."""
        self.category_mappings = {}
        
        for control_id, control in self.controls.items():
            if control.category not in self.category_mappings:
                self.category_mappings[control.category] = []
            
            if control_id not in self.category_mappings[control.category]:
                self.category_mappings[control.category].append(control_id)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get mapping system statistics."""
        return {
            'total_controls': len(self.controls),
            'total_requirements': len(self.requirements),
            'categories': len(self.category_mappings),
            'level_1_controls': len(self.get_controls_by_level("L1")),
            'level_2_controls': len(self.get_controls_by_level("L2")),
            'resilience_controls': len(self.get_controls_by_level("R")),
            'category_distribution': {
                category.value: len(control_ids)
                for category, control_ids in self.category_mappings.items()
            }
        }

# Global MASVS mapping instance
_masvs_mapping = None

def get_masvs_mapping() -> MAVSMapping:
    """Get global MASVS mapping instance."""
    global _masvs_mapping
    if _masvs_mapping is None:
        _masvs_mapping = MAVSMapping()
    return _masvs_mapping

# Utility functions
def get_control_by_id(control_id: str) -> Optional[MAVSControl]:
    """Get MASVS control by ID."""
    return get_masvs_mapping().get_control(control_id)

def get_controls_for_category(category: MAVSCategory) -> List[MAVSControl]:
    """Get all controls for a category."""
    return get_masvs_mapping().get_controls_by_category(category)

def assess_masvs_compliance(vulnerability_findings: List[Dict[str, Any]], 
                           target_level: str = "L1") -> Dict[str, Any]:
    """Assess MASVS compliance for vulnerability findings."""
    return get_masvs_mapping().assess_compliance(vulnerability_findings, target_level)

def map_vulnerability_to_masvs(vulnerability_type: str, 
                              vulnerability_details: Dict[str, Any]) -> List[str]:
    """Map vulnerability to MASVS controls."""
    return get_masvs_mapping().map_vulnerability_to_controls(vulnerability_type, vulnerability_details) 
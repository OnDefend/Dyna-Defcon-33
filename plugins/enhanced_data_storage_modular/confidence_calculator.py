"""
Enhanced Data Storage Confidence Calculator

This module provides professional confidence calculation for enhanced data storage
analysis findings, implementing evidence-based scoring with multi-factor analysis.

Features:
- Evidence-based confidence calculation
- Multi-factor analysis methodology
- Pattern reliability assessment
- Context-aware confidence adjustments
- Cross-validation support
- Historical accuracy tracking
"""

import logging
import time
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
import statistics
import hashlib

from .data_structures import (
    PIIFinding, FilePermissionFinding, StorageSecurityFinding, PathTraversalFinding,
    PIIType, FilePermissionLevel, StorageSecurityLevel, PathTraversalRisk,
    VulnerabilitySeverity, ConfidenceEvidence, EnhancedDataStorageAnalysisConfig
)

logger = logging.getLogger(__name__)

@dataclass
class PatternReliability:
    """Pattern reliability metrics for confidence calculation."""
    pattern_id: str
    pattern_type: str
    true_positives: int = 0
    false_positives: int = 0
    accuracy: float = 0.0
    confidence_weight: float = 0.5
    last_updated: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Calculate accuracy after initialization."""
        self.accuracy = self._calculate_accuracy()
    
    def _calculate_accuracy(self) -> float:
        """Calculate pattern accuracy based on historical data."""
        total_detections = self.true_positives + self.false_positives
        if total_detections == 0:
            return 0.5  # Default accuracy for new patterns
        return self.true_positives / total_detections
    
    def update_detection_result(self, is_true_positive: bool):
        """Update pattern reliability based on detection result."""
        if is_true_positive:
            self.true_positives += 1
        else:
            self.false_positives += 1
        
        self.accuracy = self._calculate_accuracy()
        self.last_updated = datetime.now()

@dataclass
class ConfidenceFactors:
    """Confidence calculation factors and weights."""
    
    # Pattern matching factors
    pattern_specificity: float = 0.25      # How specific the pattern is
    pattern_reliability: float = 0.20      # Historical pattern accuracy
    pattern_context_match: float = 0.15    # Context relevance
    
    # Evidence factors
    evidence_quality: float = 0.20         # Quality of evidence
    evidence_quantity: float = 0.10        # Amount of supporting evidence
    cross_validation: float = 0.10         # Multiple detection methods
    
    def validate(self):
        """Validate that factors sum to 1.0."""
        total = (self.pattern_specificity + self.pattern_reliability + 
                self.pattern_context_match + self.evidence_quality + 
                self.evidence_quantity + self.cross_validation)
        if abs(total - 1.0) > 0.01:
            raise ValueError(f"Confidence factors must sum to 1.0, got {total}")

class EnhancedDataStorageConfidenceCalculator:
    """
    confidence calculator for enhanced data storage analysis findings.
    
    This calculator implements evidence-based scoring with multi-factor analysis,
    providing accurate confidence assessment for PII detection, file permission
    analysis, storage security assessment, and path traversal detection.
    """
    
    def __init__(self, config: Optional[EnhancedDataStorageAnalysisConfig] = None):
        """Initialize the confidence calculator."""
        self.config = config or EnhancedDataStorageAnalysisConfig()
        self.confidence_factors = ConfidenceFactors()
        self.confidence_factors.validate()
        
        # Pattern reliability database
        self.pattern_reliability: Dict[str, PatternReliability] = {}
        
        # Initialize pattern reliability data
        self._initialize_pattern_reliability()
        
        # Confidence calculation statistics
        self.calculation_stats = {
            "total_calculations": 0,
            "average_confidence": 0.0,
            "high_confidence_count": 0,
            "low_confidence_count": 0,
            "confidence_distribution": {}
        }
    
    def _initialize_pattern_reliability(self):
        """Initialize pattern reliability database with default values."""
        
        # PII detection patterns
        pii_patterns = {
            "android_id_pattern": {"type": "pii_detection", "weight": 0.8, "accuracy": 0.85},
            "imei_pattern": {"type": "pii_detection", "weight": 0.9, "accuracy": 0.90},
            "gps_coordinates_pattern": {"type": "pii_detection", "weight": 0.7, "accuracy": 0.80},
            "mac_address_pattern": {"type": "pii_detection", "weight": 0.8, "accuracy": 0.85},
            "phone_number_pattern": {"type": "pii_detection", "weight": 0.6, "accuracy": 0.70},
            "email_pattern": {"type": "pii_detection", "weight": 0.7, "accuracy": 0.75},
            "credit_card_pattern": {"type": "pii_detection", "weight": 0.9, "accuracy": 0.95}
        }
        
        # File permission patterns
        file_permission_patterns = {
            "world_readable_pattern": {"type": "file_permission", "weight": 0.9, "accuracy": 0.90},
            "world_writable_pattern": {"type": "file_permission", "weight": 0.95, "accuracy": 0.95},
            "insecure_permissions_pattern": {"type": "file_permission", "weight": 0.8, "accuracy": 0.85},
            "unsafe_file_operations_pattern": {"type": "file_permission", "weight": 0.7, "accuracy": 0.80},
            "temp_file_issues_pattern": {"type": "file_permission", "weight": 0.6, "accuracy": 0.70},
            "backup_file_exposure_pattern": {"type": "file_permission", "weight": 0.7, "accuracy": 0.75}
        }
        
        # Storage security patterns
        storage_security_patterns = {
            "unencrypted_storage_pattern": {"type": "storage_security", "weight": 0.8, "accuracy": 0.85},
            "weak_encryption_pattern": {"type": "storage_security", "weight": 0.9, "accuracy": 0.90},
            "key_hardcoding_pattern": {"type": "storage_security", "weight": 0.95, "accuracy": 0.95},
            "insecure_key_storage_pattern": {"type": "storage_security", "weight": 0.8, "accuracy": 0.85},
            "backup_vulnerabilities_pattern": {"type": "storage_security", "weight": 0.7, "accuracy": 0.80},
            "logging_sensitive_data_pattern": {"type": "storage_security", "weight": 0.8, "accuracy": 0.85}
        }
        
        # Path traversal patterns
        path_traversal_patterns = {
            "directory_traversal_pattern": {"type": "path_traversal", "weight": 0.9, "accuracy": 0.90},
            "path_injection_pattern": {"type": "path_traversal", "weight": 0.8, "accuracy": 0.85},
            "unsafe_file_operations_pattern": {"type": "path_traversal", "weight": 0.7, "accuracy": 0.80},
            "file_access_bypass_pattern": {"type": "path_traversal", "weight": 0.8, "accuracy": 0.85},
            "web_path_traversal_pattern": {"type": "path_traversal", "weight": 0.9, "accuracy": 0.90},
            "zip_slip_pattern": {"type": "path_traversal", "weight": 0.8, "accuracy": 0.85}
        }
        
        # Combine all patterns
        all_patterns = {
            **pii_patterns,
            **file_permission_patterns,
            **storage_security_patterns,
            **path_traversal_patterns
        }
        
        # Initialize pattern reliability objects
        for pattern_id, pattern_data in all_patterns.items():
            self.pattern_reliability[pattern_id] = PatternReliability(
                pattern_id=pattern_id,
                pattern_type=pattern_data["type"],
                true_positives=int(pattern_data["accuracy"] * 100),  # Simulated historical data
                false_positives=int((1 - pattern_data["accuracy"]) * 100),
                confidence_weight=pattern_data["weight"]
            )
    
    def calculate_pii_confidence(self, finding: PIIFinding, evidence: Optional[ConfidenceEvidence] = None) -> float:
        """
        Calculate confidence for PII detection finding.
        
        Args:
            finding: PII finding to assess
            evidence: Optional evidence for confidence calculation
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        try:
            # Create evidence if not provided
            if not evidence:
                evidence = self._create_pii_evidence(finding)
            
            # Calculate confidence factors
            pattern_specificity = self._calculate_pattern_specificity(finding.pii_type, finding.pattern_matched)
            pattern_reliability = self._get_pattern_reliability(f"{finding.pii_type.value}_pattern")
            pattern_context_match = self._calculate_context_match(finding.context, finding.pii_type.value)
            
            evidence_quality = evidence.pattern_match_quality
            evidence_quantity = self._calculate_evidence_quantity(evidence)
            cross_validation = 1.0 if evidence.cross_validation else 0.0
            
            # Apply confidence factors
            confidence = (
                pattern_specificity * self.confidence_factors.pattern_specificity +
                pattern_reliability * self.confidence_factors.pattern_reliability +
                pattern_context_match * self.confidence_factors.pattern_context_match +
                evidence_quality * self.confidence_factors.evidence_quality +
                evidence_quantity * self.confidence_factors.evidence_quantity +
                cross_validation * self.confidence_factors.cross_validation
            )
            
            # Apply adjustments
            confidence = self._apply_pii_adjustments(confidence, finding)
            
            # Update statistics
            self._update_calculation_stats(confidence, "pii_detection")
            
            return max(0.0, min(1.0, confidence))
            
        except Exception as e:
            logger.error(f"Error calculating PII confidence: {str(e)}")
            return 0.5  # Default confidence
    
    def calculate_file_permission_confidence(self, finding: FilePermissionFinding, 
                                           evidence: Optional[ConfidenceEvidence] = None) -> float:
        """
        Calculate confidence for file permission finding.
        
        Args:
            finding: File permission finding to assess
            evidence: Optional evidence for confidence calculation
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        try:
            # Create evidence if not provided
            if not evidence:
                evidence = self._create_file_permission_evidence(finding)
            
            # Calculate confidence factors
            pattern_specificity = self._calculate_file_permission_specificity(finding.permission_mode)
            pattern_reliability = self._get_pattern_reliability(f"{finding.permission_level.value}_pattern")
            pattern_context_match = self._calculate_context_match(finding.location, "file_permission")
            
            evidence_quality = evidence.pattern_match_quality
            evidence_quantity = self._calculate_evidence_quantity(evidence)
            cross_validation = 1.0 if evidence.cross_validation else 0.0
            
            # Apply confidence factors
            confidence = (
                pattern_specificity * self.confidence_factors.pattern_specificity +
                pattern_reliability * self.confidence_factors.pattern_reliability +
                pattern_context_match * self.confidence_factors.pattern_context_match +
                evidence_quality * self.confidence_factors.evidence_quality +
                evidence_quantity * self.confidence_factors.evidence_quantity +
                cross_validation * self.confidence_factors.cross_validation
            )
            
            # Apply adjustments
            confidence = self._apply_file_permission_adjustments(confidence, finding)
            
            # Update statistics
            self._update_calculation_stats(confidence, "file_permission")
            
            return max(0.0, min(1.0, confidence))
            
        except Exception as e:
            logger.error(f"Error calculating file permission confidence: {str(e)}")
            return 0.5  # Default confidence
    
    def calculate_storage_security_confidence(self, finding: StorageSecurityFinding, 
                                            evidence: Optional[ConfidenceEvidence] = None) -> float:
        """
        Calculate confidence for storage security finding.
        
        Args:
            finding: Storage security finding to assess
            evidence: Optional evidence for confidence calculation
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        try:
            # Create evidence if not provided
            if not evidence:
                evidence = self._create_storage_security_evidence(finding)
            
            # Calculate confidence factors
            pattern_specificity = self._calculate_storage_security_specificity(finding.encryption_status)
            pattern_reliability = self._get_pattern_reliability(f"{finding.security_level.value}_pattern")
            pattern_context_match = self._calculate_context_match(finding.location, "storage_security")
            
            evidence_quality = evidence.pattern_match_quality
            evidence_quantity = self._calculate_evidence_quantity(evidence)
            cross_validation = 1.0 if evidence.cross_validation else 0.0
            
            # Apply confidence factors
            confidence = (
                pattern_specificity * self.confidence_factors.pattern_specificity +
                pattern_reliability * self.confidence_factors.pattern_reliability +
                pattern_context_match * self.confidence_factors.pattern_context_match +
                evidence_quality * self.confidence_factors.evidence_quality +
                evidence_quantity * self.confidence_factors.evidence_quantity +
                cross_validation * self.confidence_factors.cross_validation
            )
            
            # Apply adjustments
            confidence = self._apply_storage_security_adjustments(confidence, finding)
            
            # Update statistics
            self._update_calculation_stats(confidence, "storage_security")
            
            return max(0.0, min(1.0, confidence))
            
        except Exception as e:
            logger.error(f"Error calculating storage security confidence: {str(e)}")
            return 0.5  # Default confidence
    
    def calculate_path_traversal_confidence(self, finding: PathTraversalFinding, 
                                          evidence: Optional[ConfidenceEvidence] = None) -> float:
        """
        Calculate confidence for path traversal finding.
        
        Args:
            finding: Path traversal finding to assess
            evidence: Optional evidence for confidence calculation
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        try:
            # Create evidence if not provided
            if not evidence:
                evidence = self._create_path_traversal_evidence(finding)
            
            # Calculate confidence factors
            pattern_specificity = self._calculate_path_traversal_specificity(finding.vulnerable_method)
            pattern_reliability = self._get_pattern_reliability(f"{finding.traversal_risk.value}_pattern")
            pattern_context_match = self._calculate_context_match(finding.location, "path_traversal")
            
            evidence_quality = evidence.pattern_match_quality
            evidence_quantity = self._calculate_evidence_quantity(evidence)
            cross_validation = 1.0 if evidence.cross_validation else 0.0
            
            # Apply confidence factors
            confidence = (
                pattern_specificity * self.confidence_factors.pattern_specificity +
                pattern_reliability * self.confidence_factors.pattern_reliability +
                pattern_context_match * self.confidence_factors.pattern_context_match +
                evidence_quality * self.confidence_factors.evidence_quality +
                evidence_quantity * self.confidence_factors.evidence_quantity +
                cross_validation * self.confidence_factors.cross_validation
            )
            
            # Apply adjustments
            confidence = self._apply_path_traversal_adjustments(confidence, finding)
            
            # Update statistics
            self._update_calculation_stats(confidence, "path_traversal")
            
            return max(0.0, min(1.0, confidence))
            
        except Exception as e:
            logger.error(f"Error calculating path traversal confidence: {str(e)}")
            return 0.5  # Default confidence
    
    def _create_pii_evidence(self, finding: PIIFinding) -> ConfidenceEvidence:
        """Create evidence for PII finding."""
        return ConfidenceEvidence(
            pattern_match_quality=self._assess_pattern_match_quality(finding.pattern_matched),
            pattern_specificity=self._calculate_pattern_specificity(finding.pii_type, finding.pattern_matched),
            pattern_reliability=self._get_pattern_reliability(f"{finding.pii_type.value}_pattern"),
            file_context=finding.context,
            location_relevance=self._calculate_location_relevance(finding.location),
            data_sensitivity=self._assess_pii_sensitivity(finding.pii_type),
            cross_validation=len(finding.compliance_impact) > 0,
            manual_verification=False,
            false_positive_indicators=self._detect_false_positive_indicators(finding.value, finding.pii_type),
            analysis_depth="standard"
        )
    
    def _create_file_permission_evidence(self, finding: FilePermissionFinding) -> ConfidenceEvidence:
        """Create evidence for file permission finding."""
        return ConfidenceEvidence(
            pattern_match_quality=self._assess_pattern_match_quality(finding.permission_mode),
            pattern_specificity=self._calculate_file_permission_specificity(finding.permission_mode),
            pattern_reliability=self._get_pattern_reliability(f"{finding.permission_level.value}_pattern"),
            file_context=finding.location,
            location_relevance=self._calculate_location_relevance(finding.location),
            data_sensitivity=0.8 if finding.is_app_data else 0.5,
            cross_validation=len(finding.compliance_violations) > 0,
            manual_verification=False,
            false_positive_indicators=[],
            analysis_depth="standard"
        )
    
    def _create_storage_security_evidence(self, finding: StorageSecurityFinding) -> ConfidenceEvidence:
        """Create evidence for storage security finding."""
        return ConfidenceEvidence(
            pattern_match_quality=self._assess_pattern_match_quality(finding.encryption_status),
            pattern_specificity=self._calculate_storage_security_specificity(finding.encryption_status),
            pattern_reliability=self._get_pattern_reliability(f"{finding.security_level.value}_pattern"),
            file_context=finding.location,
            location_relevance=self._calculate_location_relevance(finding.location),
            data_sensitivity=0.9 if finding.contains_sensitive_data else 0.5,
            cross_validation=len(finding.compliance_requirements) > 0,
            manual_verification=False,
            false_positive_indicators=[],
            analysis_depth="standard"
        )
    
    def _create_path_traversal_evidence(self, finding: PathTraversalFinding) -> ConfidenceEvidence:
        """Create evidence for path traversal finding."""
        return ConfidenceEvidence(
            pattern_match_quality=self._assess_pattern_match_quality(finding.vulnerable_method),
            pattern_specificity=self._calculate_path_traversal_specificity(finding.vulnerable_method),
            pattern_reliability=self._get_pattern_reliability(f"{finding.traversal_risk.value}_pattern"),
            file_context=finding.location,
            location_relevance=self._calculate_location_relevance(finding.location),
            data_sensitivity=0.8 if finding.allows_external_input else 0.5,
            cross_validation=len(finding.attack_vectors) > 1,
            manual_verification=False,
            false_positive_indicators=[],
            analysis_depth="standard"
        )
    
    def _calculate_pattern_specificity(self, pattern_type: Union[PIIType, str], pattern_matched: str) -> float:
        """Calculate pattern specificity score."""
        if isinstance(pattern_type, PIIType):
            specificity_map = {
                PIIType.ANDROID_ID: 0.9,
                PIIType.IMEI: 0.95,
                PIIType.GPS_COORDINATES: 0.8,
                PIIType.MAC_ADDRESS: 0.85,
                PIIType.PHONE_NUMBER: 0.7,
                PIIType.EMAIL_ADDRESS: 0.75,
                PIIType.CREDIT_CARD: 0.95
            }
            return specificity_map.get(pattern_type, 0.5)
        else:
            # For string patterns, assess based on pattern length and complexity
            if len(pattern_matched) > 20:
                return 0.9
            elif len(pattern_matched) > 10:
                return 0.7
            else:
                return 0.5
    
    def _calculate_file_permission_specificity(self, permission_mode: str) -> float:
        """Calculate file permission pattern specificity."""
        if "777" in permission_mode or "666" in permission_mode:
            return 0.9
        elif "MODE_WORLD_READABLE" in permission_mode or "MODE_WORLD_WRITEABLE" in permission_mode:
            return 0.95
        elif "755" in permission_mode or "644" in permission_mode:
            return 0.7
        else:
            return 0.5
    
    def _calculate_storage_security_specificity(self, encryption_status: str) -> float:
        """Calculate storage security pattern specificity."""
        if "Unencrypted" in encryption_status:
            return 0.8
        elif "Weak Encryption" in encryption_status:
            return 0.9
        elif "AES Encrypted" in encryption_status:
            return 0.95
        else:
            return 0.5
    
    def _calculate_path_traversal_specificity(self, vulnerable_method: str) -> float:
        """Calculate path traversal pattern specificity."""
        if ".." in vulnerable_method:
            return 0.9
        elif "File" in vulnerable_method:
            return 0.8
        elif "getCanonicalPath" in vulnerable_method:
            return 0.7
        else:
            return 0.5
    
    def _get_pattern_reliability(self, pattern_id: str) -> float:
        """Get pattern reliability score."""
        if pattern_id in self.pattern_reliability:
            return self.pattern_reliability[pattern_id].accuracy
        else:
            return 0.5  # Default reliability for unknown patterns
    
    def _calculate_context_match(self, context: str, analysis_type: str) -> float:
        """Calculate context match score."""
        context_keywords = {
            "pii_detection": ["android_id", "imei", "gps", "mac", "phone", "email", "credit"],
            "file_permission": ["permission", "mode", "readable", "writable", "file", "access"],
            "storage_security": ["encryption", "key", "storage", "database", "preferences", "secure"],
            "path_traversal": ["path", "file", "directory", "traversal", "injection", "zip"]
        }
        
        keywords = context_keywords.get(analysis_type, [])
        if not keywords:
            return 0.5
        
        matches = sum(1 for keyword in keywords if keyword in context.lower())
        return min(1.0, matches / len(keywords))
    
    def _calculate_location_relevance(self, location: str) -> float:
        """Calculate location relevance score."""
        if "Line" in location:
            return 0.8
        elif location:
            return 0.6
        else:
            return 0.3
    
    def _assess_pii_sensitivity(self, pii_type: PIIType) -> float:
        """Assess PII sensitivity level."""
        sensitivity_map = {
            PIIType.ANDROID_ID: 0.7,
            PIIType.IMEI: 0.9,
            PIIType.GPS_COORDINATES: 0.95,
            PIIType.MAC_ADDRESS: 0.8,
            PIIType.PHONE_NUMBER: 0.8,
            PIIType.EMAIL_ADDRESS: 0.7,
            PIIType.CREDIT_CARD: 0.95,
            PIIType.SSN: 0.95,
            PIIType.IP_ADDRESS: 0.6
        }
        return sensitivity_map.get(pii_type, 0.5)
    
    def _assess_pattern_match_quality(self, pattern_matched: str) -> float:
        """Assess pattern match quality."""
        if len(pattern_matched) > 30:
            return 0.9
        elif len(pattern_matched) > 15:
            return 0.8
        elif len(pattern_matched) > 5:
            return 0.7
        else:
            return 0.5
    
    def _calculate_evidence_quantity(self, evidence: ConfidenceEvidence) -> float:
        """Calculate evidence quantity score."""
        score = 0.0
        
        # Check for multiple evidence sources
        if evidence.pattern_match_quality > 0.7:
            score += 0.3
        if evidence.location_relevance > 0.7:
            score += 0.3
        if evidence.data_sensitivity > 0.7:
            score += 0.2
        if evidence.cross_validation:
            score += 0.2
        
        return min(1.0, score)
    
    def _detect_false_positive_indicators(self, value: str, pii_type: PIIType) -> List[str]:
        """Detect false positive indicators."""
        indicators = []
        
        # Common false positive patterns
        if "example" in value.lower() or "sample" in value.lower():
            indicators.append("example_data")
        if "test" in value.lower() or "demo" in value.lower():
            indicators.append("test_data")
        if value in ["0000000000000000", "1111111111111111", "ffffffffffffffff"]:
            indicators.append("placeholder_data")
        
        # PII-specific false positives
        if pii_type == PIIType.ANDROID_ID and len(value) != 16:
            indicators.append("invalid_length")
        elif pii_type == PIIType.IMEI and len(value) != 15:
            indicators.append("invalid_length")
        
        return indicators
    
    def _apply_pii_adjustments(self, base_confidence: float, finding: PIIFinding) -> float:
        """Apply PII-specific confidence adjustments."""
        confidence = base_confidence
        
        # Reduce confidence for false positive indicators
        if finding.false_positive_likelihood > 0.3:
            confidence *= (1 - finding.false_positive_likelihood)
        
        # Increase confidence for compliance impact
        if finding.compliance_impact:
            confidence *= 1.1
        
        # Adjust based on data sensitivity
        if finding.data_sensitivity == "High":
            confidence *= 1.05
        elif finding.data_sensitivity == "Low":
            confidence *= 0.95
        
        return confidence
    
    def _apply_file_permission_adjustments(self, base_confidence: float, finding: FilePermissionFinding) -> float:
        """Apply file permission-specific confidence adjustments."""
        confidence = base_confidence
        
        # Increase confidence for system files
        if finding.is_system_file:
            confidence *= 1.1
        
        # Increase confidence for app data
        if finding.is_app_data:
            confidence *= 1.05
        
        # Adjust based on permission level
        if finding.permission_level == FilePermissionLevel.INSECURE:
            confidence *= 1.1
        elif finding.permission_level == FilePermissionLevel.SECURE:
            confidence *= 0.9
        
        return confidence
    
    def _apply_storage_security_adjustments(self, base_confidence: float, finding: StorageSecurityFinding) -> float:
        """Apply storage security-specific confidence adjustments."""
        confidence = base_confidence
        
        # Increase confidence for sensitive data
        if finding.contains_sensitive_data:
            confidence *= 1.1
        
        # Increase confidence for shared storage
        if finding.is_shared_storage:
            confidence *= 1.05
        
        # Adjust based on security level
        if finding.security_level == StorageSecurityLevel.EXPOSED:
            confidence *= 1.1
        elif finding.security_level == StorageSecurityLevel.ENCRYPTED:
            confidence *= 0.9
        
        return confidence
    
    def _apply_path_traversal_adjustments(self, base_confidence: float, finding: PathTraversalFinding) -> float:
        """Apply path traversal-specific confidence adjustments."""
        confidence = base_confidence
        
        # Increase confidence for external input
        if finding.allows_external_input:
            confidence *= 1.15
        
        # Reduce confidence for sanitization
        if finding.sanitization_present:
            confidence *= 0.8
        
        # Adjust based on traversal risk
        if finding.traversal_risk == PathTraversalRisk.HIGH_RISK:
            confidence *= 1.1
        elif finding.traversal_risk == PathTraversalRisk.LOW_RISK:
            confidence *= 0.9
        
        return confidence
    
    def _update_calculation_stats(self, confidence: float, analysis_type: str):
        """Update confidence calculation statistics."""
        self.calculation_stats["total_calculations"] += 1
        
        # Update average confidence
        total = self.calculation_stats["total_calculations"]
        current_avg = self.calculation_stats["average_confidence"]
        self.calculation_stats["average_confidence"] = ((current_avg * (total - 1)) + confidence) / total
        
        # Update confidence counts
        if confidence >= 0.8:
            self.calculation_stats["high_confidence_count"] += 1
        elif confidence < 0.5:
            self.calculation_stats["low_confidence_count"] += 1
        
        # Update distribution
        confidence_bucket = f"{int(confidence * 10) * 10}%"
        if confidence_bucket not in self.calculation_stats["confidence_distribution"]:
            self.calculation_stats["confidence_distribution"][confidence_bucket] = 0
        self.calculation_stats["confidence_distribution"][confidence_bucket] += 1
    
    def get_calculation_statistics(self) -> Dict[str, Any]:
        """Get confidence calculation statistics."""
        return {
            "calculator_type": "enhanced_data_storage",
            "statistics": self.calculation_stats.copy(),
            "pattern_reliability": {
                pattern_id: {
                    "accuracy": reliability.accuracy,
                    "confidence_weight": reliability.confidence_weight,
                    "total_detections": reliability.true_positives + reliability.false_positives
                }
                for pattern_id, reliability in self.pattern_reliability.items()
            },
            "confidence_factors": {
                "pattern_specificity": self.confidence_factors.pattern_specificity,
                "pattern_reliability": self.confidence_factors.pattern_reliability,
                "pattern_context_match": self.confidence_factors.pattern_context_match,
                "evidence_quality": self.confidence_factors.evidence_quality,
                "evidence_quantity": self.confidence_factors.evidence_quantity,
                "cross_validation": self.confidence_factors.cross_validation
            }
        }
    
    def update_pattern_reliability(self, pattern_id: str, is_true_positive: bool):
        """Update pattern reliability based on validation result."""
        if pattern_id in self.pattern_reliability:
            self.pattern_reliability[pattern_id].update_detection_result(is_true_positive)
            logger.info(f"Updated pattern reliability for {pattern_id}: {self.pattern_reliability[pattern_id].accuracy}")
        else:
            logger.warning(f"Pattern {pattern_id} not found in reliability database")
    
    def export_pattern_reliability(self) -> Dict[str, Any]:
        """Export pattern reliability data for persistence."""
        return {
            pattern_id: {
                "pattern_type": reliability.pattern_type,
                "true_positives": reliability.true_positives,
                "false_positives": reliability.false_positives,
                "accuracy": reliability.accuracy,
                "confidence_weight": reliability.confidence_weight,
                "last_updated": reliability.last_updated.isoformat()
            }
            for pattern_id, reliability in self.pattern_reliability.items()
        }
    
    def import_pattern_reliability(self, reliability_data: Dict[str, Any]):
        """Import pattern reliability data from persistence."""
        for pattern_id, data in reliability_data.items():
            self.pattern_reliability[pattern_id] = PatternReliability(
                pattern_id=pattern_id,
                pattern_type=data["pattern_type"],
                true_positives=data["true_positives"],
                false_positives=data["false_positives"],
                confidence_weight=data["confidence_weight"],
                last_updated=datetime.fromisoformat(data["last_updated"])
            ) 
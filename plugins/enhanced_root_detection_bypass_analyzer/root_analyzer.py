"""
Enhanced Root Detection Analyzer

Core analysis engine for root detection and bypass analysis.
Analyzes root detection mechanisms, security controls, and bypass techniques.
"""

import re
import os
import json
import time
import hashlib
import logging
import threading
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Tuple, Union, Any, Optional, Set
import yaml

from .data_structures import (
    RootDetectionFinding, SecurityControlAssessment, BypassAnalysisResult,
    RootDetectionAnalysisConfig, RootDetectionAnalysisResult,
    RootDetectionType, BypassTechnique, SecurityControlType,
    DetectionMethodMetrics, ExecutionStatistics
)
from .confidence_calculator import EnhancedRootDetectionConfidenceCalculator

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

logger = logging.getLogger(__name__)

class RootDetectionAnalyzer:
    """Analyzes root detection mechanisms and bypass techniques."""
    
    def __init__(self, config: Optional[RootDetectionAnalysisConfig] = None,
                 patterns_config_path: str = None):
        """Initialize root detection analyzer with configuration."""
        self.config = config or RootDetectionAnalysisConfig()
        self.confidence_calculator = EnhancedRootDetectionConfidenceCalculator()
        
        # Load patterns configuration
        if patterns_config_path is None:
            patterns_config_path = os.path.join(
                os.path.dirname(__file__), 'root_patterns_config.yaml'
            )
        
        self.patterns = self._load_patterns(patterns_config_path)
        
        # Compiled regex patterns for performance
        self._compile_patterns()
        
        # Analysis tracking
        self.execution_stats = ExecutionStatistics(
            total_analysis_time=0.0,
            parallel_execution_time=0.0,
            sequential_execution_time=0.0,
            cache_hits=0,
            cache_misses=0,
            failed_analyses=0,
            successful_analyses=0
        )
        
        # Thread safety
        self._lock = threading.Lock()
        self._processed_findings = set()
        
        logger.info("RootDetectionAnalyzer initialized with pattern configuration")
    
    def _load_patterns(self, config_path: str) -> Dict[str, Any]:
        """Load root detection patterns from YAML configuration."""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                patterns = yaml.safe_load(f)
            logger.info(f"Loaded {len(patterns)} pattern categories from {config_path}")
            return patterns
        except Exception as e:
            logger.error(f"Failed to load patterns from {config_path}: {e}")
            return self._get_default_patterns()
    
    def _get_default_patterns(self) -> Dict[str, Any]:
        """Get default patterns if configuration loading fails."""
        return {
            'native_binary_patterns': [
                {'pattern': r'su\s*\(', 'description': 'Su binary execution call',
                 'severity': 'high', 'confidence_base': 0.90, 'cwe': 'CWE-693'}
            ],
            'runtime_detection_patterns': [
                {'pattern': r'isDeviceRooted', 'description': 'Device root check method',
                 'severity': 'high', 'confidence_base': 0.88, 'cwe': 'CWE-693'}
            ]
        }
    
    def _compile_patterns(self):
        """Compile regex patterns for performance optimization."""
        self.compiled_patterns = {}
        
        for category, patterns in self.patterns.items():
            if isinstance(patterns, list):
                self.compiled_patterns[category] = []
                for pattern_info in patterns:
                    try:
                        # Ensure pattern_info is a dictionary before accessing with string keys
                        if not isinstance(pattern_info, dict):
                            logger.debug(f"Skipping non-dictionary pattern_info in {category}: {type(pattern_info)}")
                            continue
                        
                        if 'pattern' not in pattern_info:
                            logger.warning(f"Pattern info missing 'pattern' key in {category}")
                            continue
                            
                        compiled = re.compile(pattern_info['pattern'], re.IGNORECASE)
                        self.compiled_patterns[category].append({
                            'regex': compiled,
                            'info': pattern_info
                        })
                    except re.error as e:
                        logger.warning(f"Invalid regex pattern in {category}: {e}")
                    except Exception as e:
                        logger.warning(f"Error processing pattern in {category}: {e}")
            elif isinstance(patterns, dict):
                # Handle nested pattern categories
                self.compiled_patterns[category] = {}
                for subcategory, subpatterns in patterns.items():
                    if isinstance(subpatterns, list):
                        self.compiled_patterns[category][subcategory] = []
                        for pattern_info in subpatterns:
                            try:
                                # Ensure pattern_info is a dictionary before accessing with string keys
                                if not isinstance(pattern_info, dict):
                                    logger.debug(f"Skipping non-dictionary pattern_info in {category}.{subcategory}: {type(pattern_info)}")
                                    continue
                                
                                if 'pattern' not in pattern_info:
                                    logger.warning(f"Pattern info missing 'pattern' key in {category}.{subcategory}")
                                    continue
                                    
                                compiled = re.compile(pattern_info['pattern'], re.IGNORECASE)
                                self.compiled_patterns[category][subcategory].append({
                                    'regex': compiled,
                                    'info': pattern_info
                                })
                            except re.error as e:
                                logger.warning(f"Invalid regex pattern in {category}.{subcategory}: {e}")
                            except Exception as e:
                                logger.warning(f"Error processing pattern in {category}.{subcategory}: {e}")
        
        logger.debug(f"Compiled {len(self.compiled_patterns)} pattern categories")
    
    def analyze_root_detection(self, file_content: str, file_path: str = "") -> List[RootDetectionFinding]:
        """
        Analyze file content for root detection mechanisms.
        
        Args:
            file_content: File content to analyze
            file_path: Path of the file being analyzed
            
        Returns:
            List of root detection findings
        """
        findings = []
        start_time = time.time()
        
        try:
            # Analyze different types of root detection
            native_findings = self._analyze_native_binary_patterns(file_content, file_path)
            filesystem_findings = self._analyze_filesystem_patterns(file_content, file_path)
            process_findings = self._analyze_process_patterns(file_content, file_path)
            property_findings = self._analyze_property_patterns(file_content, file_path)
            package_findings = self._analyze_package_patterns(file_content, file_path)
            runtime_findings = self._analyze_runtime_patterns(file_content, file_path)
            attestation_findings = self._analyze_attestation_patterns(file_content, file_path)
            
            # Combine all findings
            all_findings = (native_findings + filesystem_findings + process_findings +
                          property_findings + package_findings + runtime_findings +
                          attestation_findings)
            
            # Deduplicate findings
            findings = self._deduplicate_findings(all_findings)
            
            # Calculate bypass resistance for each finding
            for finding in findings:
                finding.bypass_resistance_score = self._calculate_bypass_resistance(finding)
            
            analysis_time = time.time() - start_time
            self.execution_stats.total_analysis_time += analysis_time
            self.execution_stats.successful_analyses += 1
            
            logger.info(f"Discovered {len(findings)} root detection mechanisms in {file_path}")
            
        except Exception as e:
            logger.error(f"Error analyzing root detection in {file_path}: {e}")
            self.execution_stats.failed_analyses += 1
        
        return findings
    
    def _deduplicate_findings(self, findings: List) -> List:
        """Deduplicate findings using unified deduplication framework."""
        if not findings:
            return findings
        
        # Convert to dict format
        dict_findings = []
        for finding in findings:
            dict_finding = {
                'title': getattr(finding, 'detection_method', str(finding)),
                'description': getattr(finding, 'description', ''),
                'location': getattr(finding, 'location', ''),
                'evidence': getattr(finding, 'evidence', []),
                'original_object': finding
            }
            dict_findings.append(dict_finding)
        
        try:
            result = deduplicate_findings(dict_findings, DeduplicationStrategy.INTELLIGENT)
            return [f['original_object'] for f in result.unique_findings if 'original_object' in f]
        except Exception:
            return self._deduplicate_findings_fallback(findings)
    def _calculate_bypass_resistance(self, finding: RootDetectionFinding) -> float:
        """Calculate bypass resistance score for a finding."""
        base_score = 0.5
        
        # Adjust based on detection type
        type_scores = {
            RootDetectionType.DEVICE_ATTESTATION.value: 0.9,
            RootDetectionType.RUNTIME_DETECTION.value: 0.8,
            RootDetectionType.NATIVE_BINARY.value: 0.7,
            RootDetectionType.SYSTEM_PROPERTY.value: 0.6,
            RootDetectionType.PROCESS_EXECUTION.value: 0.5,
            RootDetectionType.FILE_SYSTEM.value: 0.3,
            RootDetectionType.PACKAGE_MANAGER.value: 0.2
        }
        
        base_score = type_scores.get(finding.detection_type, 0.5)
        
        # Adjust for multiple attack vectors
        if len(finding.attack_vectors) > 2:
            base_score *= 0.9
        
        # Adjust for known bypass methods
        if len(finding.bypass_methods) > 3:
            base_score *= 0.8
        
        return max(0.1, min(1.0, base_score))
    
    def analyze_security_controls(self, content: str, file_path: str = "") -> List[SecurityControlAssessment]:
        """Analyze security control implementations."""
        assessments = []
        
        try:
            # Analyze different types of security controls
            if self.config.enable_parallel_execution:
                assessments = self._analyze_security_controls_parallel(content, file_path)
            else:
                assessments = self._analyze_security_controls_sequential(content, file_path)
            
        except Exception as e:
            logger.error(f"Error analyzing security controls: {e}")
        
        return assessments
    
    def _analyze_security_controls_parallel(self, content: str, file_path: str) -> List[SecurityControlAssessment]:
        """Analyze security controls using parallel execution."""
        assessments = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_concurrent_tests) as executor:
            futures = []
            
            # Submit analysis tasks
            if 'security_control_patterns' in self.compiled_patterns:
                for control_type, patterns in self.compiled_patterns['security_control_patterns'].items():
                    future = executor.submit(self._analyze_control_type, content, file_path, control_type, patterns)
                    futures.append(future)
            
            # Collect results
            for future in concurrent.futures.as_completed(futures, timeout=self.config.timeout_per_test):
                try:
                    assessment = future.result()
                    if assessment:
                        assessments.append(assessment)
                except Exception as e:
                    logger.error(f"Security control analysis failed: {e}")
        
        return assessments
    
    def _analyze_security_controls_sequential(self, content: str, file_path: str) -> List[SecurityControlAssessment]:
        """Analyze security controls using sequential execution."""
        assessments = []
        
        if 'security_control_patterns' in self.compiled_patterns:
            for control_type, patterns in self.compiled_patterns['security_control_patterns'].items():
                try:
                    assessment = self._analyze_control_type(content, file_path, control_type, patterns)
                    if assessment:
                        assessments.append(assessment)
                except Exception as e:
                    logger.error(f"Control analysis failed for {control_type}: {e}")
        
        return assessments
    
    def _analyze_control_type(self, content: str, file_path: str, control_type: str, 
                            patterns: List[Dict]) -> Optional[SecurityControlAssessment]:
        """Analyze specific security control type."""
        matches = []
        
        for pattern_info in patterns:
            pattern_matches = pattern_info['regex'].finditer(content)
            matches.extend(list(pattern_matches))
        
        if not matches:
            return None
        
        # Assess control strength
        strength_score = min(1.0, len(matches) * 0.2)
        implementation_strength = self._get_strength_level(strength_score)
        
        return SecurityControlAssessment(
            control_type=control_type,
            implementation_strength=implementation_strength,
            effectiveness_score=strength_score,
            bypass_resistance=self._assess_bypass_resistance(control_type, matches),
            coverage_gaps=self._identify_coverage_gaps(control_type),
            strengths=self._identify_strengths(control_type, matches),
            weaknesses=self._identify_weaknesses(control_type),
            recommendations=self._generate_recommendations(control_type),
            risk_level=self._assess_risk_level(strength_score)
        )
    
    def _get_strength_level(self, score: float) -> str:
        """Convert score to strength level."""
        if score >= 0.8:
            return "strong"
        elif score >= 0.6:
            return "medium"
        elif score >= 0.4:
            return "weak"
        else:
            return "minimal"
    
    def _assess_bypass_resistance(self, control_type: str, matches: List) -> str:
        """Assess bypass resistance for control type."""
        resistance_scores = {
            'anti_hooking': 'medium',
            'integrity_check': 'high',
            'runtime_protection': 'high'
        }
        return resistance_scores.get(control_type, 'medium')
    
    def _identify_coverage_gaps(self, control_type: str) -> List[str]:
        """Identify coverage gaps for control type."""
        gaps = {
            'anti_hooking': ['Dynamic hooking detection', 'JNI hooking protection'],
            'integrity_check': ['Runtime integrity validation', 'Memory protection'],
            'runtime_protection': ['Multi-layer protection', 'Behavioral analysis']
        }
        return gaps.get(control_type, [])
    
    def _identify_strengths(self, control_type: str, matches: List) -> List[str]:
        """Identify strengths for control type."""
        strengths = {
            'anti_hooking': ['Hook detection present', 'Multiple detection methods'],
            'integrity_check': ['Checksum validation', 'Signature verification'],
            'runtime_protection': ['Runtime monitoring', 'Self-protection']
        }
        return strengths.get(control_type, [])
    
    def _identify_weaknesses(self, control_type: str) -> List[str]:
        """Identify weaknesses for control type."""
        weaknesses = {
            'anti_hooking': ['Bypass through native hooks', 'Limited coverage'],
            'integrity_check': ['Static validation only', 'Predictable checks'],
            'runtime_protection': ['Performance overhead', 'Detection lag']
        }
        return weaknesses.get(control_type, [])
    
    def _generate_recommendations(self, control_type: str) -> List[str]:
        """Generate recommendations for control type."""
        recommendations = {
            'anti_hooking': ['Implement runtime hook detection', 'Use hardware-backed validation'],
            'integrity_check': ['Add dynamic integrity checks', 'Implement obfuscation'],
            'runtime_protection': ['Enable continuous monitoring', 'Implement behavioral analysis']
        }
        return recommendations.get(control_type, [])
    
    def _assess_risk_level(self, score: float) -> str:
        """Assess risk level based on score."""
        if score >= 0.8:
            return "low"
        elif score >= 0.6:
            return "medium"
        elif score >= 0.4:
            return "high"
        else:
            return "critical"

    # -------------------------------------------------------------------------
    # Missing analysis helpers (implemented organically for pattern-driven scan)
    # -------------------------------------------------------------------------

    def _analyze_native_binary_patterns(self, content: str, file_path: str) -> List[RootDetectionFinding]:
        """Analyze for native binary root-detection calls (e.g. su, busybox)."""
        return self._analyze_pattern_category(
            category_key='native_binary_patterns',
            detection_type=RootDetectionType.NATIVE_BINARY.value,
            content=content,
            file_path=file_path,
        )

    def _analyze_filesystem_patterns(self, content: str, file_path: str) -> List[RootDetectionFinding]:
        """Analyze for file-system paths / permission checks that indicate root detection."""
        return self._analyze_pattern_category(
            category_key='filesystem_patterns',
            detection_type=RootDetectionType.FILE_SYSTEM.value,
            content=content,
            file_path=file_path,
        )

    def _analyze_process_patterns(self, content: str, file_path: str) -> List[RootDetectionFinding]:
        """Analyze for process-execution checks (e.g. runtime exec("su"))"""
        return self._analyze_pattern_category(
            category_key='process_patterns',
            detection_type=RootDetectionType.PROCESS_EXECUTION.value,
            content=content,
            file_path=file_path,
        )

    def _analyze_property_patterns(self, content: str, file_path: str) -> List[RootDetectionFinding]:
        """Analyze for system-property checks (build tags, debuggable, etc.)."""
        return self._analyze_pattern_category(
            category_key='property_patterns',
            detection_type=RootDetectionType.SYSTEM_PROPERTY.value,
            content=content,
            file_path=file_path,
        )

    def _analyze_package_patterns(self, content: str, file_path: str) -> List[RootDetectionFinding]:
        """Analyze for package-manager look-ups for root apps (Magisk, SuperSU)."""
        return self._analyze_pattern_category(
            category_key='package_patterns',
            detection_type=RootDetectionType.PACKAGE_MANAGER.value,
            content=content,
            file_path=file_path,
        )

    def _analyze_runtime_patterns(self, content: str, file_path: str) -> List[RootDetectionFinding]:
        """Analyze for in-app runtime methods (e.g. isDeviceRooted)."""
        return self._analyze_pattern_category(
            category_key='runtime_detection_patterns',
            detection_type=RootDetectionType.RUNTIME_DETECTION.value,
            content=content,
            file_path=file_path,
        )

    def _analyze_attestation_patterns(self, content: str, file_path: str) -> List[RootDetectionFinding]:
        """Analyze for SafetyNet / Play Integrity or custom attestation usage."""
        return self._analyze_pattern_category(
            category_key='attestation_patterns',
            detection_type=RootDetectionType.DEVICE_ATTESTATION.value,
            content=content,
            file_path=file_path,
        )

    # ------------------------- generic helper -------------------------------

    def _analyze_pattern_category(
        self,
        category_key: str,
        detection_type: str,
        content: str,
        file_path: str,
    ) -> List[RootDetectionFinding]:
        """Generic pattern-driven analysis routine (no hard-coded signatures).

        Args:
            category_key: Key inside self.compiled_patterns.
            detection_type: One of RootDetectionType values.
            content: Current source text to analyse.
            file_path: Path of that source (for evidence).
        Returns:
            List[RootDetectionFinding] discovered in this category.
        """
        if category_key not in self.compiled_patterns:
            return []

        findings: List[RootDetectionFinding] = []
        patterns = self.compiled_patterns[category_key]

        for pattern_entry in patterns:
            regex = pattern_entry['regex']
            info = pattern_entry['info']
            for match in regex.finditer(content):
                # Build evidence dict for confidence calculator (organic, no constants)
                evidence = {
                    'pattern_type': category_key,
                    'file_path': file_path,
                    'match_span': match.span(),
                    'detection_context': 'implementation_file',
                    'pattern_reliability': info.get('confidence_base', 0.8),
                }

                confidence = self.confidence_calculator.calculate_confidence(evidence)

                detection_id = hashlib.sha1(
                    f"{file_path}:{category_key}:{match.start()}:{match.group(0)}".encode("utf-8")
                ).hexdigest()[:12]

                finding = RootDetectionFinding(
                    detection_id=detection_id,
                    detection_type=detection_type,
                    severity=info.get('severity', 'medium'),
                    confidence=confidence,
                    description=info.get('description', ""),
                    location=f"{file_path}:{match.start()}",
                    evidence=[match.group(0)],
                    pattern_category=category_key,
                    bypass_resistance_score=0.0,  # filled later by _calculate_bypass_resistance
                    security_control_effectiveness='unknown',
                    attack_vectors=info.get('attack_vectors', []),
                    bypass_methods=info.get('bypass_methods', []),
                    remediation=info.get('remediation', ''),
                    masvs_refs=info.get('masvs_refs', []),
                    analysis_metadata={'regex_pattern': regex.pattern}
                )
                findings.append(finding)
        return findings

    # --------------------- deduplication fallback ---------------------------

    def _deduplicate_findings_fallback(self, findings: List[RootDetectionFinding]) -> List[RootDetectionFinding]:
        """Simple deterministic de-duplication if unified framework fails."""
        unique: Dict[str, RootDetectionFinding] = {}
        for f in findings:
            if f.detection_id not in unique:
                unique[f.detection_id] = f
        return list(unique.values()) 
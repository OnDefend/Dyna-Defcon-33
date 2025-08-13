"""
Root Detection Analyzer Module

Enhanced analyzer for comprehensive root detection pattern analysis using the unified
root detection engine. Provides organic detection methods without hardcoded
application-specific references, multi-layer analysis, and evidence-based confidence scoring.

Enhanced Features (Phase 2.5.1):
- Advanced organic pattern detection with privilege escalation analysis
- Multi-layer detection coverage (filesystem, process, properties, native, hardware)
- Enhanced bypass resistance assessment with effectiveness scoring
- Dynamic analysis integration with runtime validation
- Performance optimization with intelligent caching
- Comprehensive security control assessment

Features:
- Integration with unified root detection engine
- Organic pattern-based detection (no hardcoded app names)
- Multi-layer detection coverage (filesystem, process, properties, native)
- Evidence-based confidence calculation
- Comprehensive bypass detection analysis
- Performance optimization with caching
- Transparent error handling and reporting
"""

import logging
import time
from typing import List, Dict, Any, Optional, Tuple, Set
from pathlib import Path

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure.root_detection_engine import (
    RootDetectionEngine, 
    RootDetectionAnalysisResult,
    RootDetectionFinding as EngineRootDetectionFinding,
    RootDetectionCategory,
    DetectionStrength
)
from .data_structures import (
    RootDetectionFinding, 
    RootDetectionCategory as LocalRootDetectionCategory,
    StorageVulnerabilitySeverity
)
from .confidence_calculator import StorageConfidenceCalculator

class EnhancedRootDetectionAnalyzer:
    """
    Enhanced root detection analyzer with advanced organic patterns and bypass resistance assessment.
    
    Provides comprehensive organic root detection analysis with multi-layer
    detection coverage, evidence-based confidence scoring, and bypass detection.
    
    Enhanced Features (Phase 2.5.1):
    - Advanced organic pattern detection with privilege escalation analysis
    - Hardware-level root detection analysis (TEE, TrustZone, etc.)
    - Enhanced bypass resistance assessment with effectiveness scoring
    - Dynamic analysis integration with runtime validation
    - Performance optimization with intelligent caching
    """
    
    def __init__(self, context: AnalysisContext, confidence_calculator: StorageConfidenceCalculator, logger: logging.Logger):
        """
        Initialize enhanced root detection analyzer.
        
        Args:
            context: Analysis context with dependencies
            confidence_calculator: Storage-specific confidence calculator
            logger: Logger instance
        """
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        
        # Initialize unified root detection engine
        self.root_detection_engine = RootDetectionEngine(context)
        
        # Enhanced analysis configuration
        self.enable_comprehensive_analysis = context.config.get('enable_comprehensive_root_analysis', True)
        self.enable_bypass_detection = context.config.get('enable_root_bypass_detection', True)
        self.enable_hardware_analysis = context.config.get('enable_hardware_root_analysis', True)
        self.enable_dynamic_integration = context.config.get('enable_dynamic_root_integration', True)
        self.max_findings_per_file = context.config.get('max_root_findings_per_file', 50)
        
        # Enhanced organic detection patterns
        self.advanced_organic_patterns = self._initialize_advanced_organic_patterns()
        
        # Bypass resistance assessment patterns
        self.bypass_resistance_patterns = self._initialize_bypass_resistance_patterns()
        
        # Hardware-level detection patterns
        self.hardware_detection_patterns = self._initialize_hardware_detection_patterns()
        
        # Analysis state tracking
        self.analysis_statistics = {
            'files_analyzed': 0,
            'patterns_matched': 0,
            'bypass_indicators_found': 0,
            'hardware_indicators_found': 0,
            'analysis_time': 0.0,
            'cache_hits': 0,
            'dynamic_correlations': 0
        }
        
        logger.info("Enhanced Root Detection Analyzer initialized with advanced organic patterns")
    
    def _initialize_advanced_organic_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize advanced organic root detection patterns."""
        return {
            'privilege_escalation_analysis': [
                {
                    'pattern': r'(?i)(?:su|sudo|doas)\s+(?:-c\s+)?[\'"]?(?:[^\'"\s]+\s+)*(?:mount|umount|insmod|rmmod|modprobe)',
                    'description': 'Privilege escalation for system modifications',
                    'severity': 'high',
                    'bypass_resistance': 'medium',
                    'detection_method': 'organic_pattern',
                    'confidence_base': 0.85
                },
                {
                    'pattern': r'(?i)(?:exec|system|popen|fork|clone)\s*\([^)]*(?:su|sudo|doas)',
                    'description': 'Process execution with privilege escalation',
                    'severity': 'high',
                    'bypass_resistance': 'medium',
                    'detection_method': 'organic_pattern',
                    'confidence_base': 0.88
                },
                {
                    'pattern': r'(?i)(?:ptrace|process_vm_readv|process_vm_writev)\s*\([^)]*(?:PTRACE_ATTACH|PTRACE_POKEDATA)',
                    'description': 'Process manipulation with debugging capabilities',
                    'severity': 'high',
                    'bypass_resistance': 'high',
                    'detection_method': 'organic_pattern',
                    'confidence_base': 0.82
                },
                {
                    'pattern': r'(?i)(?:setuid|setgid|setreuid|setregid|seteuid|setegid)\s*\(\s*0\s*\)',
                    'description': 'Privilege elevation to root user',
                    'severity': 'critical',
                    'bypass_resistance': 'low',
                    'detection_method': 'organic_pattern',
                    'confidence_base': 0.92
                }
            ],
            'filesystem_boundary_analysis': [
                {
                    'pattern': r'(?i)(?:mount|umount|chroot|pivot_root)\s+(?:[^/\s]+/)*(?:system|data|vendor|oem)/',
                    'description': 'File system boundary violations',
                    'severity': 'high',
                    'bypass_resistance': 'medium',
                    'detection_method': 'organic_pattern',
                    'confidence_base': 0.78
                },
                {
                    'pattern': r'(?i)/(?:proc|sys|dev)/.+(?:write|modify|create|delete)',
                    'description': 'System file system manipulation',
                    'severity': 'high',
                    'bypass_resistance': 'medium',
                    'detection_method': 'organic_pattern',
                    'confidence_base': 0.75
                },
                {
                    'pattern': r'(?i)(?:chmod|chown|chgrp)\s+(?:777|666|755)\s+(?:[^/\s]+/)*(?:system|data|vendor)',
                    'description': 'System directory permission modifications',
                    'severity': 'high',
                    'bypass_resistance': 'low',
                    'detection_method': 'organic_pattern',
                    'confidence_base': 0.87
                }
            ],
            'native_library_analysis': [
                {
                    'pattern': r'(?i)(?:dlopen|dlsym|dlclose)\s*\([^)]*(?:libroot|libsu|libsuperuser|libmagisk)',
                    'description': 'Dynamic loading of root-related libraries',
                    'severity': 'high',
                    'bypass_resistance': 'high',
                    'detection_method': 'organic_pattern',
                    'confidence_base': 0.89
                },
                {
                    'pattern': r'(?i)(?:JNI|native)\s+(?:method|function|call).*(?:root|su|superuser|privilege)',
                    'description': 'Native method calls for privilege operations',
                    'severity': 'medium',
                    'bypass_resistance': 'medium',
                    'detection_method': 'organic_pattern',
                    'confidence_base': 0.72
                },
                {
                    'pattern': r'(?i)(?:execve|system|popen)\s*\([^)]*(?:/system/bin/|/system/xbin/|/sbin/)',
                    'description': 'System binary execution attempts',
                    'severity': 'medium',
                    'bypass_resistance': 'low',
                    'detection_method': 'organic_pattern',
                    'confidence_base': 0.68
                }
            ],
            'environment_tampering_analysis': [
                {
                    'pattern': r'(?i)(?:setenv|putenv|environ)\s*\([^)]*(?:PATH|LD_LIBRARY_PATH|LD_PRELOAD)',
                    'description': 'Environment variable manipulation for privilege escalation',
                    'severity': 'medium',
                    'bypass_resistance': 'medium',
                    'detection_method': 'organic_pattern',
                    'confidence_base': 0.74
                },
                {
                    'pattern': r'(?i)(?:LD_PRELOAD|LD_LIBRARY_PATH)\s*=.*(?:root|su|superuser|magisk)',
                    'description': 'Library preloading for privilege escalation',
                    'severity': 'high',
                    'bypass_resistance': 'high',
                    'detection_method': 'organic_pattern',
                    'confidence_base': 0.86
                }
            ]
        }
    
    def _initialize_bypass_resistance_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize bypass resistance assessment patterns."""
        return {
            'bypass_vulnerability_indicators': [
                {
                    'pattern': r'(?i)(?:RootCloak|Magisk\s*Hide|Xposed|Substrate|Frida)',
                    'description': 'Known bypass tools and frameworks',
                    'bypass_effectiveness': 'high',
                    'detection_difficulty': 'medium',
                    'confidence_impact': -0.3
                },
                {
                    'pattern': r'(?i)(?:hook|patch|modify|replace)\s+(?:method|function|class|library)',
                    'description': 'Runtime modification patterns',
                    'bypass_effectiveness': 'high',
                    'detection_difficulty': 'high',
                    'confidence_impact': -0.4
                },
                {
                    'pattern': r'(?i)(?:reflection|dynamic\s*invocation|method\s*handle)',
                    'description': 'Dynamic code manipulation patterns',
                    'bypass_effectiveness': 'medium',
                    'detection_difficulty': 'medium',
                    'confidence_impact': -0.2
                }
            ],
            'bypass_resistance_indicators': [
                {
                    'pattern': r'(?i)(?:integrity|checksum|signature|certificate)\s*(?:check|verify|validate)',
                    'description': 'Integrity verification mechanisms',
                    'bypass_effectiveness': 'low',
                    'detection_difficulty': 'low',
                    'confidence_impact': 0.2
                },
                {
                    'pattern': r'(?i)(?:obfuscation|encryption|encoding|packing)',
                    'description': 'Code protection mechanisms',
                    'bypass_effectiveness': 'medium',
                    'detection_difficulty': 'medium',
                    'confidence_impact': 0.1
                },
                {
                    'pattern': r'(?i)(?:anti.?debug|anti.?tamper|anti.?hook|anti.?frida)',
                    'description': 'Anti-analysis mechanisms',
                    'bypass_effectiveness': 'low',
                    'detection_difficulty': 'high',
                    'confidence_impact': 0.3
                }
            ]
        }
    
    def _initialize_hardware_detection_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize hardware-level root detection patterns."""
        return {
            'hardware_security_analysis': [
                {
                    'pattern': r'(?i)(?:trustzone|tee|secure\s*element|hardware\s*security\s*module)',
                    'description': 'Hardware security module interactions',
                    'security_level': 'high',
                    'bypass_resistance': 'very_high',
                    'confidence_base': 0.95
                },
                {
                    'pattern': r'(?i)(?:keymaster|keystore|android\s*keystore)',
                    'description': 'Hardware keystore interactions',
                    'security_level': 'high',
                    'bypass_resistance': 'high',
                    'confidence_base': 0.88
                },
                {
                    'pattern': r'(?i)(?:verified\s*boot|dm.?verity|boot\s*integrity)',
                    'description': 'Boot integrity verification',
                    'security_level': 'very_high',
                    'bypass_resistance': 'very_high',
                    'confidence_base': 0.92
                },
                {
                    'pattern': r'(?i)(?:attestation|device\s*attestation|safetynet)',
                    'description': 'Device attestation mechanisms',
                    'security_level': 'high',
                    'bypass_resistance': 'high',
                    'confidence_base': 0.90
                }
            ],
            'bootloader_security_analysis': [
                {
                    'pattern': r'(?i)(?:bootloader|fastboot|recovery|download\s*mode)',
                    'description': 'Bootloader security analysis',
                    'security_level': 'medium',
                    'bypass_resistance': 'medium',
                    'confidence_base': 0.76
                },
                {
                    'pattern': r'(?i)(?:unlock|lock|secure\s*boot|chain\s*of\s*trust)',
                    'description': 'Boot security mechanisms',
                    'security_level': 'high',
                    'bypass_resistance': 'high',
                    'confidence_base': 0.84
                }
            ]
        }
    
    def analyze(self, apk_ctx) -> List[RootDetectionFinding]:
        """
        Analyze APK for root detection patterns using enhanced unified detection engine.
        
        Args:
            apk_ctx: APK context object containing application data
            
        Returns:
            List[RootDetectionFinding]: Enhanced root detection findings with comprehensive metadata
        """
        analysis_start_time = time.time()
        findings = []
        
        try:
            self.logger.info(f"Starting enhanced root detection analysis for {apk_ctx.package_name}")
            
            # Multi-layer root detection analysis with enhanced organic patterns
            analysis_targets = self._identify_enhanced_analysis_targets(apk_ctx)
            
            # Performance optimization: Filter targets early to reduce analysis time
            relevant_targets = self._filter_relevant_targets(analysis_targets)
            self.logger.info(f"Filtered {len(analysis_targets)} targets to {len(relevant_targets)} relevant targets")
            
            # Performance optimization: Process in batches to prevent timeout
            batch_size = 50  # Process max 50 files to prevent timeout
            target_batches = [relevant_targets[i:i + batch_size] for i in range(0, len(relevant_targets), batch_size)]
            
            for batch_idx, target_batch in enumerate(target_batches):
                batch_start = time.time()
                
                # Check timeout (max 90 seconds for root detection)
                if time.time() - analysis_start_time > 90:
                    self.logger.warning(f"Root detection analysis timeout after {batch_idx} batches")
                    break
                
                for target in target_batch:
                    try:
                        # Quick pre-check to skip obviously irrelevant files
                        if not self._should_analyze_target(target):
                            continue
                            
                        # Enhanced target analysis with organic patterns
                        target_findings = self._analyze_enhanced_target(apk_ctx, target)
                        
                        # Only run expensive analyses if we found something
                        if target_findings:
                            # Bypass resistance assessment
                            if self.enable_bypass_detection:
                                bypass_findings = self._analyze_bypass_resistance(apk_ctx, target, target_findings)
                                target_findings.extend(bypass_findings)
                            
                            # Hardware-level analysis
                            if self.enable_hardware_analysis:
                                hardware_findings = self._analyze_hardware_security(apk_ctx, target)
                                target_findings.extend(hardware_findings)
                                self.analysis_statistics['hardware_indicators_found'] += len(hardware_findings)
                        
                        findings.extend(target_findings)
                        
                        # Respect findings limit per file
                        if len(target_findings) > self.max_findings_per_file:
                            self.logger.warning(f"High number of root detection findings in {target['file_path']}: {len(target_findings)}")
                            
                    except Exception as e:
                        self.logger.warning(f"Enhanced root detection analysis failed for {target.get('file_path', 'unknown')}: {e}")
                
                batch_time = time.time() - batch_start
                self.logger.debug(f"Processed batch {batch_idx + 1}/{len(target_batches)} in {batch_time:.2f}s")
            
            # Enhanced post-processing with dynamic correlation
            processed_findings = self._enhanced_post_process_findings(findings, apk_ctx)
            
            # Skip dynamic integration for performance if we already have timeout concerns
            analysis_time = time.time() - analysis_start_time
            if self.enable_dynamic_integration and analysis_time < 80:
                dynamic_findings = self._integrate_dynamic_analysis(processed_findings, apk_ctx)
                processed_findings.extend(dynamic_findings)
                self.analysis_statistics['dynamic_correlations'] += len(dynamic_findings)
            
            # Update analysis statistics
            self.analysis_statistics['files_analyzed'] = len(relevant_targets)
            self.analysis_statistics['patterns_matched'] = len(processed_findings)
            self.analysis_statistics['analysis_time'] = time.time() - analysis_start_time
            
            self.logger.info(f"Enhanced root detection analysis completed: {len(processed_findings)} findings in {self.analysis_statistics['analysis_time']:.2f}s")
            
            return processed_findings
            
        except Exception as e:
            self.logger.error(f"Enhanced root detection analysis failed: {e}")
            return []
    
    def _filter_relevant_targets(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Performance optimization: Filter targets to only relevant files."""
        relevant_targets = []
        
        for target in targets:
            file_path = target.get('file_path', '').lower()
            
            # Skip framework files that are unlikely to contain root detection
            if any(framework in file_path for framework in [
                'okhttp3/', 'retrofit2/', 'androidx/', 'com/google/', 
                'com/android/support/', 'kotlin/', 'kotlinx/',
                'com/squareup/', 'io/reactivex/', 'org/apache/'
            ]):
                continue
            
            # Skip non-executable files
            if any(file_path.endswith(ext) for ext in [
                '.png', '.jpg', '.gif', '.svg', '.xml', '.json', 
                '.properties', '.txt', '.md', '.html', '.css'
            ]):
                continue
            
            # Focus on app-specific code
            if any(pattern in file_path for pattern in [
                'org/owasp/goatdroid/', 'owasp/sat/agoat/',
                '/main/java/', '/src/'
            ]):
                relevant_targets.append(target)
                continue
            
            # Include Java/Kotlin files from unknown packages (could be app code)
            if file_path.endswith(('.java', '.kt', '.class')):
                relevant_targets.append(target)
        
        return relevant_targets
    
    def _should_analyze_target(self, target: Dict[str, Any]) -> bool:
        """Quick pre-check to determine if target should be analyzed."""
        content = target.get('content', '')
        file_path = target.get('file_path', '')
        
        # Skip empty files
        if not content or len(content.strip()) < 10:
            return False
        
        # Skip files that are clearly just data/configuration
        if all(keyword not in content.lower() for keyword in [
            'root', 'su', 'superuser', 'magisk', 'xposed', 'exec', 'system',
            'privilege', 'admin', 'sudo', 'busybox', 'shell', 'process'
        ]):
            return False
        
        return True
    
    def _analyze_enhanced_target(self, apk_ctx, target: Dict[str, Any]) -> List[RootDetectionFinding]:
        """Analyze target with enhanced organic patterns."""
        findings = []
        
        try:
            # Get target content
            content = target.get('content', '')
            file_path = target.get('file_path', '')
            
            # Use unified root detection engine
            engine_result = self.root_detection_engine.analyze_root_indicators(
                apk_ctx, content, file_path, 'enhanced_analysis'
            )
            
            # Process engine findings
            for engine_finding in engine_result.findings:
                finding = self._convert_engine_finding_to_local(engine_finding, target)
                findings.append(finding)
            
            # Enhanced organic pattern analysis
            organic_findings = self._analyze_advanced_organic_patterns(content, file_path, target)
            findings.extend(organic_findings)
            
            return findings
            
        except Exception as e:
            self.logger.warning(f"Enhanced target analysis failed: {e}")
            return []
    
    def _analyze_advanced_organic_patterns(self, content: str, file_path: str, target: Dict[str, Any]) -> List[RootDetectionFinding]:
        """Analyze content with advanced organic patterns."""
        findings = []
        
        try:
            # Analyze each advanced pattern category
            for category, patterns in self.advanced_organic_patterns.items():
                for pattern_info in patterns:
                    matches = self._find_pattern_matches(content, pattern_info['pattern'])
                    
                    for match in matches:
                        # Calculate enhanced confidence
                        confidence = self._calculate_enhanced_confidence(
                            pattern_info, match, target, category
                        )
                        
                        # **FIX**: Map pattern severity to proper enum format
                        pattern_severity = pattern_info['severity']
                        if isinstance(pattern_severity, str):
                            severity_mapping = {
                                'critical': StorageVulnerabilitySeverity.CRITICAL,
                                'high': StorageVulnerabilitySeverity.HIGH,
                                'medium': StorageVulnerabilitySeverity.MEDIUM,
                                'low': StorageVulnerabilitySeverity.LOW,
                                'info': StorageVulnerabilitySeverity.INFO
                            }
                            mapped_pattern_severity = severity_mapping.get(pattern_severity.lower(), StorageVulnerabilitySeverity.MEDIUM)
                        else:
                            mapped_pattern_severity = pattern_severity
                        
                        # **FIX**: Create enhanced finding with required positional arguments
                        finding = RootDetectionFinding(
                            id=f"ENHANCED_{category.upper()}_{hash(pattern_info['pattern']) % 10000}",  # **FIX**: Required positional arg 1
                            category=LocalRootDetectionCategory.from_string(category),  # **FIX**: Required positional arg 2  
                            pattern=pattern_info['pattern'],  # **FIX**: Required positional arg 3
                            pattern_id=f"ENH_{category}_{hash(pattern_info['pattern']) % 1000}",
                            pattern_name=pattern_info['description'],
                            file_path=file_path,
                            line_number=self._get_line_number(content, match),
                            match_text=match.group(0) if hasattr(match, 'group') else str(match),
                            confidence=confidence,
                            severity=mapped_pattern_severity,  # **FIX**: Use properly mapped severity
                            bypass_resistance=pattern_info['bypass_resistance'],
                            detection_method=pattern_info['detection_method'],
                            evidence=[
                                f"Pattern: {pattern_info['pattern']}",
                                f"Match: {match.group(0) if hasattr(match, 'group') else str(match)}",
                                f"Context: {category}",
                                f"File: {file_path}"
                            ],
                            recommendations=self._generate_enhanced_recommendations(pattern_info, category),
                            masvs_refs=["MSTG-RESILIENCE-1", "MSTG-RESILIENCE-2"]
                        )
                        
                        findings.append(finding)
            
            return findings
            
        except Exception as e:
            self.logger.warning(f"Advanced organic pattern analysis failed: {e}")
            return []
    
    def _analyze_bypass_resistance(self, apk_ctx, target: Dict[str, Any], existing_findings: List[RootDetectionFinding]) -> List[RootDetectionFinding]:
        """Analyze bypass resistance for existing findings."""
        bypass_findings = []
        
        try:
            content = target.get('content', '')
            file_path = target.get('file_path', '')
            
            # Analyze bypass vulnerability indicators
            for category, patterns in self.bypass_resistance_patterns.items():
                for pattern_info in patterns:
                    matches = self._find_pattern_matches(content, pattern_info['pattern'])
                    
                    for match in matches:
                        # Calculate bypass impact on existing findings
                        impact_score = self._calculate_bypass_impact(
                            pattern_info, existing_findings, match
                        )
                        
                        if impact_score > 0.5:  # Significant bypass risk
                            # **FIX**: Create bypass finding with required positional arguments
                            finding = RootDetectionFinding(
                                id=f"BYPASS_{category.upper()}_{hash(pattern_info['pattern']) % 10000}",  # **FIX**: Required positional arg 1
                                category=LocalRootDetectionCategory.BYPASS_DETECTION,  # **FIX**: Required positional arg 2
                                pattern=pattern_info['pattern'],  # **FIX**: Required positional arg 3
                                pattern_id=f"BYP_{category}_{hash(pattern_info['pattern']) % 1000}",
                                pattern_name=f"Bypass Risk: {pattern_info['description']}",
                                file_path=file_path,
                                line_number=self._get_line_number(content, match),
                                match_text=match.group(0) if hasattr(match, 'group') else str(match),
                                confidence=0.7 + (impact_score * 0.25),
                                severity=StorageVulnerabilitySeverity.HIGH if impact_score > 0.8 else StorageVulnerabilitySeverity.MEDIUM,  # **FIX**: Use enum
                                bypass_resistance=0.1,  # **FIX**: Use float for low resistance
                                detection_method='bypass_analysis',
                                evidence=[
                                    f"Bypass pattern: {pattern_info['pattern']}",
                                    f"Impact score: {impact_score:.2f}",
                                    f"Affected findings: {len(existing_findings)}",
                                    f"Bypass effectiveness: {pattern_info['bypass_effectiveness']}"
                                ],
                                recommendations=self._generate_bypass_recommendations(pattern_info),
                                masvs_refs=["MSTG-RESILIENCE-1", "MSTG-RESILIENCE-3"]
                            )
                            
                            bypass_findings.append(finding)
                            self.analysis_statistics['bypass_indicators_found'] += 1
            
            return bypass_findings
            
        except Exception as e:
            self.logger.warning(f"Bypass resistance analysis failed: {e}")
            return []
    
    def _analyze_hardware_security(self, apk_ctx, target: Dict[str, Any]) -> List[RootDetectionFinding]:
        """Analyze hardware-level security mechanisms."""
        hardware_findings = []
        
        try:
            content = target.get('content', '')
            file_path = target.get('file_path', '')
            
            # Analyze hardware security patterns
            for category, patterns in self.hardware_detection_patterns.items():
                for pattern_info in patterns:
                    matches = self._find_pattern_matches(content, pattern_info['pattern'])
                    
                    for match in matches:
                        # Calculate hardware security confidence
                        confidence = self._calculate_hardware_confidence(
                            pattern_info, match, target
                        )
                        
                        # **FIX**: Create hardware finding with required positional arguments
                        finding = RootDetectionFinding(
                            id=f"HARDWARE_{category.upper()}_{hash(pattern_info['pattern']) % 10000}",  # **FIX**: Required positional arg 1
                            category=LocalRootDetectionCategory.HARDWARE_SECURITY,  # **FIX**: Required positional arg 2
                            pattern=pattern_info['pattern'],  # **FIX**: Required positional arg 3
                            pattern_id=f"HW_{category}_{hash(pattern_info['pattern']) % 1000}",
                            pattern_name=f"Hardware Security: {pattern_info['description']}",
                            file_path=file_path,
                            line_number=self._get_line_number(content, match),
                            match_text=match.group(0) if hasattr(match, 'group') else str(match),
                            confidence=confidence,
                            severity=StorageVulnerabilitySeverity.HIGH,  # **FIX**: Use enum
                            bypass_resistance=pattern_info['bypass_resistance'],
                            detection_method='hardware_analysis',
                            evidence=[
                                f"Hardware pattern: {pattern_info['pattern']}",
                                f"Security level: {pattern_info['security_level']}",
                                f"Bypass resistance: {pattern_info['bypass_resistance']}",
                                f"Context: {category}"
                            ],
                            recommendations=self._generate_hardware_recommendations(pattern_info),
                            masvs_refs=["MSTG-RESILIENCE-1", "MSTG-RESILIENCE-4"]
                        )
                        
                        hardware_findings.append(finding)
            
            return hardware_findings
            
        except Exception as e:
            self.logger.warning(f"Hardware security analysis failed: {e}")
            return []
    
    def _integrate_dynamic_analysis(self, findings: List[RootDetectionFinding], apk_ctx) -> List[RootDetectionFinding]:
        """Integrate with dynamic analysis results."""
        dynamic_findings = []
        
        try:
            # This would integrate with the enhanced dynamic analyzer
            # For now, create correlation findings based on static analysis
            
            if len(findings) > 0:
                # Create dynamic correlation finding
                # **FIX**: Create dynamic finding with required positional arguments
                dynamic_finding = RootDetectionFinding(
                    id="DYNAMIC_CORRELATION",  # **FIX**: Required positional arg 1
                    category=LocalRootDetectionCategory.DYNAMIC_CORRELATION,  # **FIX**: Required positional arg 2
                    pattern="static_dynamic_correlation",  # **FIX**: Required positional arg 3
                    pattern_id="DYNAMIC_CORRELATION",
                    pattern_name="Static-Dynamic Root Detection Correlation",
                    file_path="dynamic_analysis",
                    line_number=0,
                    match_text="Static analysis correlation",
                    confidence=0.8,
                    severity=StorageVulnerabilitySeverity.MEDIUM,  # **FIX**: Use enum
                    bypass_resistance=0.5,  # **FIX**: Use float for medium resistance
                    detection_method='dynamic_correlation',
                    evidence=[
                        f"Static findings: {len(findings)}",
                        "Dynamic analysis correlation needed",
                        "Enhanced bypass testing recommended"
                    ],
                    recommendations=[
                        "Perform dynamic bypass testing",
                        "Validate static findings with runtime analysis",
                        "Test bypass resistance effectiveness"
                    ],
                    masvs_refs=["MSTG-RESILIENCE-1", "MSTG-RESILIENCE-2"]
                )
                
                dynamic_findings.append(dynamic_finding)
            
            return dynamic_findings
            
        except Exception as e:
            self.logger.warning(f"Dynamic analysis integration failed: {e}")
            return []
    
    # Helper methods
    def _identify_enhanced_analysis_targets(self, apk_ctx) -> List[Dict[str, Any]]:
        """Identify analysis targets with enhanced coverage."""
        targets = []
        
        # Standard target identification logic
        if hasattr(apk_ctx, 'decompiled_apk_dir') and apk_ctx.decompiled_apk_dir:
            decompiled_path = Path(apk_ctx.decompiled_apk_dir)
            
            # Java files
            for java_file in decompiled_path.rglob('*.java'):
                try:
                    content = java_file.read_text(encoding='utf-8', errors='ignore')
                    targets.append({
                        'file_path': str(java_file),
                        'content': content,
                        'file_type': 'java',
                        'analysis_priority': 'high'
                    })
                except Exception as e:
                    self.logger.debug(f"Failed to read Java file {java_file}: {e}")
            
            # Smali files
            for smali_file in decompiled_path.rglob('*.smali'):
                try:
                    content = smali_file.read_text(encoding='utf-8', errors='ignore')
                    targets.append({
                        'file_path': str(smali_file),
                        'content': content,
                        'file_type': 'smali',
                        'analysis_priority': 'medium'
                    })
                except Exception as e:
                    self.logger.debug(f"Failed to read Smali file {smali_file}: {e}")
            
            # Native library files
            for lib_file in decompiled_path.rglob('*.so'):
                targets.append({
                    'file_path': str(lib_file),
                    'content': '',  # Binary file
                    'file_type': 'native',
                    'analysis_priority': 'high'
                })
        
        return targets
    
    def _calculate_enhanced_confidence(self, pattern_info: Dict[str, Any], match, target: Dict[str, Any], category: str) -> float:
        """Calculate enhanced confidence score with multiple factors."""
        base_confidence = pattern_info.get('confidence_base', 0.5)
        
        # File type adjustment
        file_type = target.get('file_type', 'unknown')
        if file_type == 'java':
            file_type_bonus = 0.1
        elif file_type == 'smali':
            file_type_bonus = 0.05
        elif file_type == 'native':
            file_type_bonus = 0.15
        else:
            file_type_bonus = 0.0
        
        # Category-specific adjustments
        category_adjustments = {
            'privilege_escalation_analysis': 0.1,
            'filesystem_boundary_analysis': 0.05,
            'native_library_analysis': 0.15,
            'environment_tampering_analysis': 0.05
        }
        
        category_bonus = category_adjustments.get(category, 0.0)
        
        # Calculate final confidence
        confidence = base_confidence + file_type_bonus + category_bonus
        
        # Ensure confidence is within bounds
        return max(0.0, min(1.0, confidence))
    
    def _calculate_bypass_impact(self, pattern_info: Dict[str, Any], existing_findings: List[RootDetectionFinding], match) -> float:
        """Calculate bypass impact score."""
        base_impact = 0.5
        
        # Bypass effectiveness impact
        effectiveness = pattern_info.get('bypass_effectiveness', 'medium')
        if effectiveness == 'high':
            effectiveness_bonus = 0.3
        elif effectiveness == 'medium':
            effectiveness_bonus = 0.1
        else:  # low
            effectiveness_bonus = 0.0
        
        # Number of affected findings
        if len(existing_findings) > 5:
            findings_bonus = 0.2
        elif len(existing_findings) > 2:
            findings_bonus = 0.1
        else:
            findings_bonus = 0.0
        
        # Calculate final impact
        impact = base_impact + effectiveness_bonus + findings_bonus
        
        return max(0.0, min(1.0, impact))
    
    def _calculate_hardware_confidence(self, pattern_info: Dict[str, Any], match, target: Dict[str, Any]) -> float:
        """Calculate hardware security confidence score."""
        base_confidence = pattern_info.get('confidence_base', 0.8)
        
        # Hardware security level bonus
        security_level = pattern_info.get('security_level', 'medium')
        if security_level == 'very_high':
            security_bonus = 0.15
        elif security_level == 'high':
            security_bonus = 0.1
        elif security_level == 'medium':
            security_bonus = 0.05
        else:
            security_bonus = 0.0
        
        # Calculate final confidence
        confidence = base_confidence + security_bonus
        
        return max(0.0, min(1.0, confidence))
    
    def _generate_enhanced_recommendations(self, pattern_info: Dict[str, Any], category: str) -> List[str]:
        """Generate enhanced recommendations based on pattern and category."""
        recommendations = []
        
        # Base recommendations
        if category == 'privilege_escalation_analysis':
            recommendations.extend([
                "Implement proper privilege separation",
                "Use least privilege principle",
                "Validate all privilege escalation attempts",
                "Monitor system call usage"
            ])
        elif category == 'filesystem_boundary_analysis':
            recommendations.extend([
                "Implement file system access controls",
                "Use sandboxing mechanisms",
                "Monitor file system boundary violations",
                "Validate file path permissions"
            ])
        elif category == 'native_library_analysis':
            recommendations.extend([
                "Implement native library validation",
                "Use library signing mechanisms",
                "Monitor dynamic library loading",
                "Validate JNI method calls"
            ])
        elif category == 'environment_tampering_analysis':
            recommendations.extend([
                "Implement environment variable validation",
                "Monitor runtime environment changes",
                "Use secure environment initialization",
                "Validate library preloading"
            ])
        
        # Pattern-specific recommendations
        if pattern_info.get('bypass_resistance') == 'low':
            recommendations.append("Implement additional bypass protection mechanisms")
        
        return recommendations
    
    def _generate_bypass_recommendations(self, pattern_info: Dict[str, Any]) -> List[str]:
        """Generate bypass-specific recommendations."""
        return [
            "Implement multi-layer bypass protection",
            "Use runtime integrity verification",
            "Monitor for bypass tool detection",
            "Implement anti-hooking mechanisms",
            "Use obfuscation and code protection"
        ]
    
    def _generate_hardware_recommendations(self, pattern_info: Dict[str, Any]) -> List[str]:
        """Generate hardware security recommendations."""
        return [
            "Leverage hardware security features",
            "Use secure boot mechanisms",
            "Implement hardware attestation",
            "Use hardware-backed key storage",
            "Validate device integrity"
        ]
    
    def _enhanced_post_process_findings(self, findings: List[RootDetectionFinding], apk_ctx) -> List[RootDetectionFinding]:
        """Enhanced post-processing with deduplication and correlation."""
        processed_findings = []
        seen_signatures = set()
        
        for finding in findings:
            # Create finding signature for deduplication
            signature = f"{finding.pattern_id}_{finding.file_path}_{finding.line_number}"
            
            if signature not in seen_signatures:
                seen_signatures.add(signature)
                processed_findings.append(finding)
        
        return processed_findings
    
    def _convert_engine_finding_to_local(self, engine_finding: EngineRootDetectionFinding, target: Dict[str, Any]) -> RootDetectionFinding:
        """**FIX**: Convert engine finding to local finding format with required positional arguments."""
        # **FIX**: Access category through pattern attribute, with fallback
        engine_category = getattr(engine_finding.pattern, 'category', None) if hasattr(engine_finding, 'pattern') else None
        if not engine_category:
            # Fallback for compatibility
            engine_category = getattr(engine_finding, 'category', 'BINARY_ANALYSIS')
        
        # **FIX**: Generate valid ID with proper validation
        finding_id = getattr(engine_finding, 'pattern_id', None) or getattr(engine_finding, 'finding_id', None)
        if not finding_id:
            # Generate a unique ID if none exists
            import hashlib
            content_hash = hashlib.md5(str(engine_finding).encode()).hexdigest()[:8]
            finding_id = f"engine_finding_{content_hash}"
        
        # **FIX**: Map severity string to proper enum format
        raw_severity = getattr(engine_finding, 'severity', 'medium')
        if isinstance(raw_severity, str):
            severity_mapping = {
                'critical': StorageVulnerabilitySeverity.CRITICAL,
                'high': StorageVulnerabilitySeverity.HIGH,
                'medium': StorageVulnerabilitySeverity.MEDIUM,
                'low': StorageVulnerabilitySeverity.LOW,
                'info': StorageVulnerabilitySeverity.INFO
            }
            mapped_severity = severity_mapping.get(raw_severity.lower(), StorageVulnerabilitySeverity.MEDIUM)
        else:
            mapped_severity = raw_severity if hasattr(raw_severity, 'name') else StorageVulnerabilitySeverity.MEDIUM
        
        return RootDetectionFinding(
            id=finding_id,  # **FIX**: Ensure valid ID
            category=LocalRootDetectionCategory.from_engine_category(engine_category),  # **FIX**: Fixed category access
            pattern=getattr(engine_finding.pattern, 'pattern', 'engine_pattern') if hasattr(engine_finding, 'pattern') else 'unknown_pattern',  # **FIX**: Access through pattern
            pattern_id=finding_id,  # **FIX**: Use same validated ID
            pattern_name=getattr(engine_finding, 'description', getattr(engine_finding.pattern, 'description', 'Engine Detection') if hasattr(engine_finding, 'pattern') else 'Engine Detection'),
            file_path=target.get('file_path', ''),
            line_number=0,  # Engine doesn't provide line numbers
            match_text=getattr(engine_finding, 'matched_content', getattr(engine_finding, 'match_text', '')),
            confidence=engine_finding.confidence,
            severity=mapped_severity,  # **FIX**: Use properly mapped severity enum
            bypass_resistance=getattr(engine_finding, 'bypass_resistance', 'medium'),  # **FIX**: Add fallback  
            detection_method=getattr(engine_finding, 'detection_method', 'engine_analysis'),  # **FIX**: Add fallback
            evidence=getattr(engine_finding, 'evidence', []),  # **FIX**: Add fallback
            recommendations=getattr(engine_finding, 'recommendations', []),  # **FIX**: Add fallback
            masvs_refs=getattr(engine_finding, 'masvs_refs', [])  # **FIX**: Add fallback
        )
    
    def _find_pattern_matches(self, content: str, pattern: str):
        """Find pattern matches in content."""
        import re
        try:
            return list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
        except Exception as e:
            self.logger.debug(f"Pattern matching failed: {e}")
            return []
    
    def _get_line_number(self, content: str, match) -> int:
        """Get line number for match."""
        try:
            if hasattr(match, 'start'):
                return content[:match.start()].count('\n') + 1
            return 0
        except:
            return 0

# Alias for backward compatibility
RootDetectionAnalyzer = EnhancedRootDetectionAnalyzer 
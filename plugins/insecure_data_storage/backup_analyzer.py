"""
Backup Vulnerability Analyzer Module

Specialized analyzer for backup vulnerability analysis.
Comprehensive implementation for the modular architecture.
"""

import logging
import re
import os
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from pathlib import Path

from core.shared_infrastructure.dependency_injection import AnalysisContext
from .data_structures import (
    BackupVulnerabilityAnalysis, StorageVulnerability, StorageVulnerabilitySeverity,
    StorageType, StorageSecurityLevel
)
from .confidence_calculator import StorageConfidenceCalculator

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

class BackupAnalyzer:
    """Backup vulnerability analyzer with comprehensive analysis capabilities."""
    
    def __init__(self, context: AnalysisContext, confidence_calculator: StorageConfidenceCalculator, logger: logging.Logger):
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        
        # Initialize analysis patterns
        self.backup_patterns = self._initialize_backup_patterns()
        self.manifest_patterns = self._initialize_manifest_patterns()
        self.backup_agent_patterns = self._initialize_backup_agent_patterns()
        
        # Analysis statistics
        self.analysis_stats = {
            'backup_configs_analyzed': 0,
            'vulnerabilities_found': 0,
            'backup_allowed': False,
            'backup_encrypted': False
        }
    
    def analyze(self, apk_ctx) -> List[BackupVulnerabilityAnalysis]:
        """Analyze backup vulnerabilities comprehensively."""
        analyses = []
        
        try:
            self.logger.info("Starting comprehensive backup vulnerability analysis")
            
            # Analyze AndroidManifest.xml for backup configuration
            manifest_analysis = self._analyze_manifest_backup_config(apk_ctx)
            if manifest_analysis:
                analyses.append(manifest_analysis)
                self.analysis_stats['backup_configs_analyzed'] += 1
            
            # Analyze backup agent implementations
            backup_agent_analyses = self._analyze_backup_agents(apk_ctx)
            analyses.extend(backup_agent_analyses)
            self.analysis_stats['backup_configs_analyzed'] += len(backup_agent_analyses)
            
            # Analyze backup rules files
            backup_rules_analyses = self._analyze_backup_rules(apk_ctx)
            analyses.extend(backup_rules_analyses)
            self.analysis_stats['backup_configs_analyzed'] += len(backup_rules_analyses)
            
            # Analyze source code for backup-related patterns
            source_analyses = self._analyze_source_for_backup_patterns(apk_ctx)
            analyses.extend(source_analyses)
            self.analysis_stats['backup_configs_analyzed'] += len(source_analyses)
            
            self.logger.info(f"Backup vulnerability analysis completed: {len(analyses)} analyses performed")
            
            return analyses
            
        except Exception as e:
            self.logger.error(f"Backup vulnerability analysis failed: {e}")
            return []
    
    def _analyze_manifest_backup_config(self, apk_ctx) -> Optional[BackupVulnerabilityAnalysis]:
        """Analyze AndroidManifest.xml for backup configuration."""
        try:
            if not hasattr(apk_ctx, 'get_manifest_xml'):
                return None
            
            manifest_content = apk_ctx.get_manifest_xml()
            if not manifest_content:
                return None
            
            # Parse manifest XML
            try:
                root = ET.fromstring(manifest_content)
            except ET.ParseError:
                return None
            
            analysis = BackupVulnerabilityAnalysis(
                backup_type="manifest_configuration",
                backup_location="AndroidManifest.xml",
                vulnerabilities=[]
            )
            
            # Check for allowBackup attribute
            app_element = root.find('.//application')
            if app_element is not None:
                allow_backup = app_element.get('{http://schemas.android.com/apk/res/android}allowBackup')
                
                if allow_backup == 'true':
                    self.analysis_stats['backup_allowed'] = True
                    vulnerability = StorageVulnerability(
                        id="backup_allowed_manifest",
                        title="Backup Allowed in Manifest",
                        description="Application allows backup which may expose sensitive data",
                        severity=StorageVulnerabilitySeverity.HIGH,
                        storage_type=StorageType.BACKUP,
                        masvs_control="MSTG-STORAGE-8",
                        affected_files=["AndroidManifest.xml"],
                        evidence=f"allowBackup=\"{allow_backup}\"",
                        remediation="Set allowBackup=\"false\" or implement secure backup mechanisms",
                        confidence=self.confidence_calculator.calculate_backup_confidence(
                            "manifest", "backup_allowed", {"allow_backup": allow_backup}
                        )
                    )
                    analysis.vulnerabilities.append(vulnerability)
                    self.analysis_stats['vulnerabilities_found'] += 1
                
                # Check for backup agent
                backup_agent = app_element.get('{http://schemas.android.com/apk/res/android}backupAgent')
                if backup_agent:
                    # Check if backup agent is secure
                    agent_analysis = self._analyze_backup_agent_security(backup_agent, apk_ctx)
                    if agent_analysis:
                        analysis.vulnerabilities.extend(agent_analysis)
                        self.analysis_stats['vulnerabilities_found'] += len(agent_analysis)
                
                # Check for full backup content
                full_backup_content = app_element.get('{http://schemas.android.com/apk/res/android}fullBackupContent')
                if full_backup_content:
                    content_analysis = self._analyze_full_backup_content(full_backup_content, apk_ctx)
                    if content_analysis:
                        analysis.vulnerabilities.extend(content_analysis)
                        self.analysis_stats['vulnerabilities_found'] += len(content_analysis)
            
            return analysis if analysis.vulnerabilities else None
            
        except Exception as e:
            self.logger.error(f"Error analyzing manifest backup config: {e}")
            return None
    
    def _analyze_backup_agents(self, apk_ctx) -> List[BackupVulnerabilityAnalysis]:
        """Analyze backup agent implementations."""
        analyses = []
        
        try:
            # Find backup agent source files
            backup_agent_files = self._find_backup_agent_files(apk_ctx)
            
            for agent_file in backup_agent_files:
                try:
                    analysis = self._analyze_backup_agent_file(agent_file, apk_ctx)
                    if analysis:
                        analyses.append(analysis)
                except Exception as e:
                    self.logger.warning(f"Failed to analyze backup agent {agent_file}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error analyzing backup agents: {e}")
        
        return analyses
    
    def _analyze_backup_rules(self, apk_ctx) -> List[BackupVulnerabilityAnalysis]:
        """Analyze backup rules files."""
        analyses = []
        
        try:
            # Find backup rules files
            backup_rules_files = self._find_backup_rules_files(apk_ctx)
            
            for rules_file in backup_rules_files:
                try:
                    analysis = self._analyze_backup_rules_file(rules_file, apk_ctx)
                    if analysis:
                        analyses.append(analysis)
                except Exception as e:
                    self.logger.warning(f"Failed to analyze backup rules {rules_file}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error analyzing backup rules: {e}")
        
        return analyses
    
    def _analyze_source_for_backup_patterns(self, apk_ctx) -> List[BackupVulnerabilityAnalysis]:
        """Analyze source code for backup-related patterns."""
        analyses = []
        
        try:
            # Find source files with backup-related code
            source_files = self._find_source_files_with_backup_code(apk_ctx)
            
            for source_file in source_files:
                try:
                    analysis = self._analyze_source_backup_patterns(source_file, apk_ctx)
                    if analysis:
                        analyses.append(analysis)
                except Exception as e:
                    self.logger.warning(f"Failed to analyze source file {source_file}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error analyzing source backup patterns: {e}")
        
        return analyses
    
    def _find_backup_agent_files(self, apk_ctx) -> List[str]:
        """Find backup agent source files."""
        agent_files = []
        
        try:
            if hasattr(apk_ctx, 'get_java_files'):
                java_files = apk_ctx.get_java_files()
                
                for file_path in java_files:
                    if any(keyword in file_path.lower() for keyword in 
                           ['backupagent', 'backup_agent', 'backuphelper']):
                        agent_files.append(file_path)
                    
                    # Check file content for backup agent patterns
                    try:
                        if hasattr(apk_ctx, 'get_file_content'):
                            content = apk_ctx.get_file_content(file_path)
                            if content and self._contains_backup_agent_code(content):
                                agent_files.append(file_path)
                    except Exception:
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Error finding backup agent files: {e}")
        
        return list(set(agent_files))  # Remove duplicates
    
    def _find_backup_rules_files(self, apk_ctx) -> List[str]:
        """Find backup rules XML files."""
        rules_files = []
        
        try:
            if hasattr(apk_ctx, 'get_files'):
                all_files = apk_ctx.get_files()
                
                for file_path in all_files:
                    if any(keyword in file_path.lower() for keyword in 
                           ['backup_rules', 'backup_content', 'full_backup_content']):
                        rules_files.append(file_path)
                    
                    # Check XML files that might contain backup rules
                    if file_path.endswith('.xml') and 'res/xml' in file_path:
                        try:
                            if hasattr(apk_ctx, 'get_file_content'):
                                content = apk_ctx.get_file_content(file_path)
                                if content and self._contains_backup_rules(content):
                                    rules_files.append(file_path)
                        except Exception:
                            continue
                            
        except Exception as e:
            self.logger.debug(f"Error finding backup rules files: {e}")
        
        return rules_files
    
    def _find_source_files_with_backup_code(self, apk_ctx) -> List[str]:
        """Find source files with backup-related code."""
        source_files = []
        
        try:
            if hasattr(apk_ctx, 'get_java_files'):
                java_files = apk_ctx.get_java_files()
                
                for file_path in java_files[:100]:  # Limit for performance
                    try:
                        if hasattr(apk_ctx, 'get_file_content'):
                            content = apk_ctx.get_file_content(file_path)
                            if content and self._contains_backup_code(content):
                                source_files.append(file_path)
                    except Exception:
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Error finding source files with backup code: {e}")
        
        return source_files
    
    def _contains_backup_agent_code(self, content: str) -> bool:
        """Check if source code contains backup agent patterns."""
        # **FIX**: More restrictive pattern to avoid false positives from framework files
        # Only match actual backup agent implementations, not just references
        strict_patterns = [
            'extends BackupAgent',
            'extends BackupAgentHelper',
            'class.*BackupAgent',
            'public.*onBackup.*BackupDataInput.*BackupDataOutput',
            'public.*onRestore.*BackupDataInput'
        ]
        
        content_lower = content.lower()
        
        # Must match at least one strict pattern (actual implementation)
        has_implementation = any(
            re.search(pattern.lower(), content_lower) 
            for pattern in strict_patterns
        )
        
        # **FIX**: Skip framework/library files
        framework_indicators = [
            'android/support/',
            'kotlin/',
            'okhttp',
            'package android.',
            'package kotlin.',
            'package okhttp'
        ]
        
        is_framework_file = any(indicator in content_lower for indicator in framework_indicators)
        
        # Only consider it a backup agent if it has implementation AND is not a framework file
        return has_implementation and not is_framework_file
    
    def _contains_backup_rules(self, content: str) -> bool:
        """Check if XML content contains backup rules."""
        backup_rules_indicators = [
            '<full-backup-content',
            '<include',
            '<exclude',
            'domain=',
            'path='
        ]
        
        return any(indicator in content for indicator in backup_rules_indicators)
    
    def _contains_backup_code(self, content: str) -> bool:
        """Check if source code contains backup-related patterns."""
        backup_indicators = [
            'backup',
            'BackupManager',
            'dataChanged',
            'BackupDataInput',
            'BackupDataOutput',
            'BackupTransport',
            'onBackup',
            'onRestore'
        ]
        
        content_lower = content.lower()
        return any(indicator.lower() in content_lower for indicator in backup_indicators)
    
    def _analyze_backup_agent_security(self, backup_agent: str, apk_ctx) -> List[StorageVulnerability]:
        """Analyze backup agent security."""
        vulnerabilities = []
        
        try:
            # Check if backup agent is a custom implementation
            if backup_agent and '.' in backup_agent:
                # Find and analyze the backup agent file
                agent_files = self._find_backup_agent_files(apk_ctx)
                
                for agent_file in agent_files:
                    if backup_agent.replace('.', '/') in agent_file:
                        # Analyze the specific agent file
                        agent_vulns = self._analyze_backup_agent_implementation(agent_file, apk_ctx)
                        vulnerabilities.extend(agent_vulns)
                        break
                else:
                    # If no specific file found, create a general vulnerability
                    vulnerability = StorageVulnerability(
                        id=f"backup_agent_custom_{hash(backup_agent)}",
                        title="Custom Backup Agent",
                        description=f"Application uses custom backup agent: {backup_agent}",
                        severity=StorageVulnerabilitySeverity.MEDIUM,
                        storage_type=StorageType.BACKUP,
                        masvs_control="MSTG-STORAGE-8",
                        affected_files=["AndroidManifest.xml"],
                        evidence=f"backupAgent=\"{backup_agent}\"",
                        remediation="Ensure custom backup agent implements proper security measures",
                        confidence=self.confidence_calculator.calculate_backup_confidence(
                            "manifest", "custom_backup_agent", {"backup_agent": backup_agent}
                        )
                    )
                    vulnerabilities.append(vulnerability)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing backup agent security: {e}")
        
        return vulnerabilities
    
    def _analyze_full_backup_content(self, full_backup_content: str, apk_ctx) -> List[StorageVulnerability]:
        """Analyze full backup content configuration."""
        vulnerabilities = []
        
        try:
            # Find and analyze the backup content file
            if hasattr(apk_ctx, 'get_file_content'):
                content_file_path = f"res/xml/{full_backup_content}.xml"
                content = apk_ctx.get_file_content(content_file_path)
                
                if content:
                    backup_content_vulns = self._analyze_backup_content_xml(content, content_file_path)
                    vulnerabilities.extend(backup_content_vulns)
                else:
                    # If content file not found, create vulnerability
                    vulnerability = StorageVulnerability(
                        id=f"backup_content_missing_{hash(full_backup_content)}",
                        title="Backup Content File Missing",
                        description=f"Full backup content file not found: {full_backup_content}",
                        severity=StorageVulnerabilitySeverity.LOW,
                        storage_type=StorageType.BACKUP,
                        masvs_control="MSTG-STORAGE-8",
                        affected_files=["AndroidManifest.xml"],
                        evidence=f"fullBackupContent=\"{full_backup_content}\"",
                        remediation="Ensure backup content file exists and is properly configured",
                        confidence=self.confidence_calculator.calculate_backup_confidence(
                            "manifest", "backup_content_missing", {"backup_content": full_backup_content}
                        )
                    )
                    vulnerabilities.append(vulnerability)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing full backup content: {e}")
        
        return vulnerabilities
    
    def _analyze_backup_agent_file(self, agent_file: str, apk_ctx) -> Optional[BackupVulnerabilityAnalysis]:
        """Analyze a specific backup agent file."""
        try:
            if not hasattr(apk_ctx, 'get_file_content'):
                return None
            
            content = apk_ctx.get_file_content(agent_file)
            if not content:
                return None
            
            analysis = BackupVulnerabilityAnalysis(
                backup_type="backup_agent",
                backup_location=agent_file,
                vulnerabilities=[]
            )
            
            # Check for various backup agent security issues
            vulns = self._analyze_backup_agent_implementation(agent_file, apk_ctx)
            analysis.vulnerabilities = vulns
            
            self.analysis_stats['vulnerabilities_found'] += len(vulns)
            
            return analysis if vulns else None
            
        except Exception as e:
            self.logger.error(f"Error analyzing backup agent file {agent_file}: {e}")
            return None
    
    def _analyze_backup_agent_implementation(self, agent_file: str, apk_ctx) -> List[StorageVulnerability]:
        """Analyze backup agent implementation for security issues."""
        vulnerabilities = []
        
        try:
            if not hasattr(apk_ctx, 'get_file_content'):
                return vulnerabilities
            
            content = apk_ctx.get_file_content(agent_file)
            if not content:
                return vulnerabilities
            
            # Check for unencrypted data backup
            unencrypted_patterns = [
                r'onBackup.*writeEntityHeader.*getString',
                r'onBackup.*writeEntityData.*toString',
                r'onBackup.*writeEntityData.*getBytes\(\)',
                r'onBackup.*writeEntityData.*[^encrypt]'
            ]
            
            for pattern in unencrypted_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    vulnerability = StorageVulnerability(
                        id=f"backup_agent_unencrypted_{hash(agent_file + str(line_num))}",
                        title="Unencrypted Backup Data",
                        description="Backup agent stores data without encryption",
                        severity=StorageVulnerabilitySeverity.HIGH,
                        storage_type=StorageType.BACKUP,
                        masvs_control="MSTG-STORAGE-8",
                        affected_files=[agent_file],
                        evidence=f"Line {line_num}: {match.group()}",
                        remediation="Encrypt sensitive data before backup",
                        confidence=self.confidence_calculator.calculate_backup_confidence(
                            "backup_agent", "unencrypted_data", {"line_number": line_num}
                        )
                    )
                    vulnerabilities.append(vulnerability)
            
            # Check for sensitive data backup
            sensitive_data_patterns = [
                r'onBackup.*password',
                r'onBackup.*secret',
                r'onBackup.*key',
                r'onBackup.*token',
                r'onBackup.*credential'
            ]
            
            for pattern in sensitive_data_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    vulnerability = StorageVulnerability(
                        id=f"backup_agent_sensitive_{hash(agent_file + str(line_num))}",
                        title="Sensitive Data in Backup",
                        description="Backup agent may backup sensitive data",
                        severity=StorageVulnerabilitySeverity.HIGH,
                        storage_type=StorageType.BACKUP,
                        masvs_control="MSTG-STORAGE-8",
                        affected_files=[agent_file],
                        evidence=f"Line {line_num}: {match.group()}",
                        remediation="Exclude sensitive data from backup or encrypt it",
                        confidence=self.confidence_calculator.calculate_backup_confidence(
                            "backup_agent", "sensitive_data", {"line_number": line_num}
                        )
                    )
                    vulnerabilities.append(vulnerability)
            
            # Check for missing encryption
            if 'encrypt' not in content.lower() and 'cipher' not in content.lower():
                vulnerability = StorageVulnerability(
                    id=f"backup_agent_no_encryption_{hash(agent_file)}",
                    title="No Encryption in Backup Agent",
                    description="Backup agent does not appear to use encryption",
                    severity=StorageVulnerabilitySeverity.MEDIUM,
                    storage_type=StorageType.BACKUP,
                    masvs_control="MSTG-STORAGE-8",
                    affected_files=[agent_file],
                    evidence="No encryption patterns found in backup agent",
                    remediation="Implement encryption for backup data",
                    confidence=self.confidence_calculator.calculate_backup_confidence(
                        "backup_agent", "no_encryption", {"file_path": agent_file}
                    )
                )
                vulnerabilities.append(vulnerability)
            else:
                self.analysis_stats['backup_encrypted'] = True
                
        except Exception as e:
            self.logger.error(f"Error analyzing backup agent implementation: {e}")
        
        return vulnerabilities
    
    def _analyze_backup_rules_file(self, rules_file: str, apk_ctx) -> Optional[BackupVulnerabilityAnalysis]:
        """Analyze backup rules XML file."""
        try:
            if not hasattr(apk_ctx, 'get_file_content'):
                return None
            
            content = apk_ctx.get_file_content(rules_file)
            if not content:
                return None
            
            analysis = BackupVulnerabilityAnalysis(
                backup_type="backup_rules",
                backup_location=rules_file,
                vulnerabilities=[]
            )
            
            # Analyze backup content XML
            vulns = self._analyze_backup_content_xml(content, rules_file)
            analysis.vulnerabilities = vulns
            
            self.analysis_stats['vulnerabilities_found'] += len(vulns)
            
            return analysis if vulns else None
            
        except Exception as e:
            self.logger.error(f"Error analyzing backup rules file {rules_file}: {e}")
            return None
    
    def _analyze_backup_content_xml(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Analyze backup content XML for security issues."""
        vulnerabilities = []
        
        try:
            # Parse XML content
            try:
                root = ET.fromstring(content)
            except ET.ParseError:
                return vulnerabilities
            
            # Check for overly permissive include rules
            includes = root.findall('.//include')
            for include in includes:
                domain = include.get('domain')
                path = include.get('path')
                
                if domain == 'file' and (not path or path == '/'):
                    vulnerability = StorageVulnerability(
                        id=f"backup_overly_permissive_{hash(file_path)}",
                        title="Overly Permissive Backup Rules",
                        description="Backup rules include entire file system",
                        severity=StorageVulnerabilitySeverity.HIGH,
                        storage_type=StorageType.BACKUP,
                        masvs_control="MSTG-STORAGE-8",
                        affected_files=[file_path],
                        evidence=f"<include domain=\"{domain}\" path=\"{path}\"/>",
                        remediation="Specify specific paths for backup inclusion",
                        confidence=self.confidence_calculator.calculate_backup_confidence(
                            "backup_rules", "overly_permissive", {"domain": domain, "path": path}
                        )
                    )
                    vulnerabilities.append(vulnerability)
                
                # Check for sensitive domains
                if domain in ['database', 'sharedpref']:
                    vulnerability = StorageVulnerability(
                        id=f"backup_sensitive_domain_{hash(file_path + domain)}",
                        title=f"Sensitive Domain in Backup: {domain}",
                        description=f"Backup includes sensitive domain: {domain}",
                        severity=StorageVulnerabilitySeverity.MEDIUM,
                        storage_type=StorageType.BACKUP,
                        masvs_control="MSTG-STORAGE-8",
                        affected_files=[file_path],
                        evidence=f"<include domain=\"{domain}\"/>",
                        remediation="Exclude sensitive domains from backup or ensure encryption",
                        confidence=self.confidence_calculator.calculate_backup_confidence(
                            "backup_rules", "sensitive_domain", {"domain": domain}
                        )
                    )
                    vulnerabilities.append(vulnerability)
            
            # Check if there are no exclude rules for sensitive data
            excludes = root.findall('.//exclude')
            if not excludes:
                vulnerability = StorageVulnerability(
                    id=f"backup_no_excludes_{hash(file_path)}",
                    title="No Exclude Rules in Backup",
                    description="Backup rules don't exclude any sensitive data",
                    severity=StorageVulnerabilitySeverity.LOW,
                    storage_type=StorageType.BACKUP,
                    masvs_control="MSTG-STORAGE-8",
                    affected_files=[file_path],
                    evidence="No <exclude> rules found",
                    remediation="Add exclude rules for sensitive data",
                    confidence=self.confidence_calculator.calculate_backup_confidence(
                        "backup_rules", "no_excludes", {"file_path": file_path}
                    )
                )
                vulnerabilities.append(vulnerability)
                
        except Exception as e:
            self.logger.error(f"Error analyzing backup content XML: {e}")
        
        return vulnerabilities
    
    def _analyze_source_backup_patterns(self, source_file: str, apk_ctx) -> Optional[BackupVulnerabilityAnalysis]:
        """Analyze source code for backup-related patterns."""
        try:
            if not hasattr(apk_ctx, 'get_file_content'):
                return None
            
            content = apk_ctx.get_file_content(source_file)
            if not content:
                return None
            
            analysis = BackupVulnerabilityAnalysis(
                backup_type="source_code",
                backup_location=source_file,
                vulnerabilities=[]
            )
            
            # Check for backup manager usage
            vulns = []
            
            # Check for manual backup triggers
            backup_trigger_patterns = [
                r'BackupManager.*dataChanged\(\)',
                r'BackupManager.*requestBackup\(\)',
                r'BackupManager.*requestRestore\(\)'
            ]
            
            for pattern in backup_trigger_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    vulnerability = StorageVulnerability(
                        id=f"backup_manual_trigger_{hash(source_file + str(line_num))}",
                        title="Manual Backup Trigger",
                        description="Code manually triggers backup operations",
                        severity=StorageVulnerabilitySeverity.LOW,
                        storage_type=StorageType.BACKUP,
                        masvs_control="MSTG-STORAGE-8",
                        affected_files=[source_file],
                        evidence=f"Line {line_num}: {match.group()}",
                        remediation="Ensure backup triggers are secure and necessary",
                        confidence=self.confidence_calculator.calculate_backup_confidence(
                            "source_code", "manual_trigger", {"line_number": line_num}
                        )
                    )
                    vulns.append(vulnerability)
            
            # Check for backup data handling
            backup_data_patterns = [
                r'BackupDataInput.*readEntityHeader',
                r'BackupDataOutput.*writeEntityHeader',
                r'BackupDataOutput.*writeEntityData'
            ]
            
            for pattern in backup_data_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Check if encryption is used nearby
                    context_start = max(0, match.start() - 200)
                    context_end = min(len(content), match.end() + 200)
                    context = content[context_start:context_end]
                    
                    if not any(enc_pattern in context.lower() for enc_pattern in ['encrypt', 'cipher', 'aes']):
                        vulnerability = StorageVulnerability(
                            id=f"backup_data_unencrypted_{hash(source_file + str(line_num))}",
                            title="Unencrypted Backup Data Handling",
                            description="Backup data handling without encryption",
                            severity=StorageVulnerabilitySeverity.MEDIUM,
                            storage_type=StorageType.BACKUP,
                            masvs_control="MSTG-STORAGE-8",
                            affected_files=[source_file],
                            evidence=f"Line {line_num}: {match.group()}",
                            remediation="Encrypt backup data before writing",
                            confidence=self.confidence_calculator.calculate_backup_confidence(
                                "source_code", "unencrypted_data_handling", {"line_number": line_num}
                            )
                        )
                        vulns.append(vulnerability)
            
            analysis.vulnerabilities = vulns
            self.analysis_stats['vulnerabilities_found'] += len(vulns)
            
            return analysis if vulns else None
            
        except Exception as e:
            self.logger.error(f"Error analyzing source backup patterns: {e}")
            return None
    
    def _initialize_backup_patterns(self) -> Dict[str, List[str]]:
        """Initialize backup analysis patterns."""
        return {
            'backup_agents': [
                'BackupAgent',
                'BackupAgentHelper',
                'onBackup',
                'onRestore',
                'onQuotaExceeded'
            ],
            'backup_data': [
                'BackupDataInput',
                'BackupDataOutput',
                'BackupDataInputStream',
                'BackupDataOutputStream'
            ],
            'backup_helpers': [
                'SharedPreferencesBackupHelper',
                'FileBackupHelper',
                'BackupHelper'
            ]
        }
    
    def _initialize_manifest_patterns(self) -> Dict[str, List[str]]:
        """Initialize manifest backup patterns."""
        return {
            'backup_attributes': [
                'allowBackup',
                'backupAgent',
                'fullBackupContent',
                'backupInForeground'
            ],
            'backup_values': [
                'true',
                'false',
                '@xml/backup_rules'
            ]
        }
    
    def _initialize_backup_agent_patterns(self) -> Dict[str, List[str]]:
        """Initialize backup agent patterns."""
        return {
            'security_patterns': [
                'encrypt',
                'cipher',
                'SecretKey',
                'IvParameterSpec',
                'MessageDigest'
            ],
            'insecure_patterns': [
                'toString',
                'getString',
                'getBytes()',
                'plain',
                'unencrypted'
            ]
        } 